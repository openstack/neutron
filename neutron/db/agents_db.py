# Copyright (c) 2013 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import datetime

from eventlet import greenthread
from neutron_lib.api import converters
from neutron_lib import constants
from neutron_lib.db import model_base
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
import oslo_messaging
from oslo_serialization import jsonutils
from oslo_utils import importutils
from oslo_utils import timeutils
import six
import sqlalchemy as sa
from sqlalchemy.orm import exc
from sqlalchemy import sql

from neutron._i18n import _, _LE, _LI, _LW
from neutron.api.rpc.callbacks import version_manager
from neutron.api.v2 import attributes
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import constants as n_const
from neutron import context
from neutron.db import api as db_api
from neutron.extensions import agent as ext_agent
from neutron.extensions import availability_zone as az_ext
from neutron import manager

LOG = logging.getLogger(__name__)

AGENT_OPTS = [
    cfg.IntOpt('agent_down_time', default=75,
               help=_("Seconds to regard the agent is down; should be at "
                      "least twice report_interval, to be sure the "
                      "agent is down for good.")),
    cfg.StrOpt('dhcp_load_type', default='networks',
               choices=['networks', 'subnets', 'ports'],
               help=_('Representing the resource type whose load is being '
                      'reported by the agent. This can be "networks", '
                      '"subnets" or "ports". '
                      'When specified (Default is networks), the server will '
                      'extract particular load sent as part of its agent '
                      'configuration object from the agent report state, '
                      'which is the number of resources being consumed, at '
                      'every report_interval.'
                      'dhcp_load_type can be used in combination with '
                      'network_scheduler_driver = '
                      'neutron.scheduler.dhcp_agent_scheduler.WeightScheduler '
                      'When the network_scheduler_driver is WeightScheduler, '
                      'dhcp_load_type can be configured to represent the '
                      'choice for the resource being balanced. '
                      'Example: dhcp_load_type=networks')),
    cfg.BoolOpt('enable_new_agents', default=True,
                help=_("Agent starts with admin_state_up=False when "
                       "enable_new_agents=False. In the case, user's "
                       "resources will not be scheduled automatically to the "
                       "agent until admin changes admin_state_up to True.")),
]
cfg.CONF.register_opts(AGENT_OPTS)

# this is the ratio from agent_down_time to the time we use to consider
# the agents down for considering their resource versions in the
# version_manager callback
DOWNTIME_VERSIONS_RATIO = 2


class Agent(model_base.BASEV2, model_base.HasId):
    """Represents agents running in neutron deployments."""

    __table_args__ = (
        sa.UniqueConstraint('agent_type', 'host',
                            name='uniq_agents0agent_type0host'),
        model_base.BASEV2.__table_args__
    )

    # L3 agent, DHCP agent, OVS agent, LinuxBridge
    agent_type = sa.Column(sa.String(255), nullable=False)
    binary = sa.Column(sa.String(255), nullable=False)
    # TOPIC is a fanout exchange topic
    topic = sa.Column(sa.String(255), nullable=False)
    # TOPIC.host is a target topic
    host = sa.Column(sa.String(255), nullable=False)
    availability_zone = sa.Column(sa.String(255))
    admin_state_up = sa.Column(sa.Boolean, default=True,
                               server_default=sql.true(), nullable=False)
    # the time when first report came from agents
    created_at = sa.Column(sa.DateTime, nullable=False)
    # the time when first report came after agents start
    started_at = sa.Column(sa.DateTime, nullable=False)
    # updated when agents report
    heartbeat_timestamp = sa.Column(sa.DateTime, nullable=False)
    # description is note for admin user
    description = sa.Column(sa.String(attributes.DESCRIPTION_MAX_LEN))
    # configurations: a json dict string, I think 4095 is enough
    configurations = sa.Column(sa.String(4095), nullable=False)
    # resource_versions: json dict, 8191 allows for ~256 resource versions
    #                    assuming ~32byte length "'name': 'ver',"
    #                    the whole row limit is 65535 bytes in mysql
    resource_versions = sa.Column(sa.String(8191))
    # load - number of resources hosted by the agent
    load = sa.Column(sa.Integer, server_default='0', nullable=False)

    @property
    def is_active(self):
        return not AgentDbMixin.is_agent_down(self.heartbeat_timestamp)


class AgentAvailabilityZoneMixin(az_ext.AvailabilityZonePluginBase):
    """Mixin class to add availability_zone extension to AgentDbMixin."""

    def _list_availability_zones(self, context, filters=None):
        result = {}
        query = self._get_collection_query(context, Agent, filters=filters)
        for agent in query.group_by(Agent.admin_state_up,
                                    Agent.availability_zone,
                                    Agent.agent_type):
            if not agent.availability_zone:
                continue
            if agent.agent_type == constants.AGENT_TYPE_DHCP:
                resource = 'network'
            elif agent.agent_type == constants.AGENT_TYPE_L3:
                resource = 'router'
            else:
                continue
            key = (agent.availability_zone, resource)
            result[key] = agent.admin_state_up or result.get(key, False)
        return result

    def get_availability_zones(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        """Return a list of availability zones."""
        # NOTE(hichihara): 'tenant_id' is dummy for policy check.
        # it is not visible via API.
        return [{'state': 'available' if v else 'unavailable',
                 'name': k[0], 'resource': k[1],
                 'tenant_id': context.tenant_id}
                for k, v in six.iteritems(self._list_availability_zones(
                                           context, filters))]

    def validate_availability_zones(self, context, resource_type,
                                    availability_zones):
        """Verify that the availability zones exist."""
        if not availability_zones:
            return
        if resource_type == 'network':
            agent_type = constants.AGENT_TYPE_DHCP
        elif resource_type == 'router':
            agent_type = constants.AGENT_TYPE_L3
        else:
            return
        query = context.session.query(Agent.availability_zone).filter_by(
                    agent_type=agent_type).group_by(Agent.availability_zone)
        query = query.filter(Agent.availability_zone.in_(availability_zones))
        azs = [item[0] for item in query]
        diff = set(availability_zones) - set(azs)
        if diff:
            raise az_ext.AvailabilityZoneNotFound(availability_zone=diff.pop())


class AgentDbMixin(ext_agent.AgentPluginBase, AgentAvailabilityZoneMixin):
    """Mixin class to add agent extension to db_base_plugin_v2."""

    def _get_agent(self, context, id):
        try:
            agent = self._get_by_id(context, Agent, id)
        except exc.NoResultFound:
            raise ext_agent.AgentNotFound(id=id)
        return agent

    def get_enabled_agent_on_host(self, context, agent_type, host):
        """Return agent of agent_type for the specified host."""
        query = context.session.query(Agent)
        query = query.filter(Agent.agent_type == agent_type,
                             Agent.host == host,
                             Agent.admin_state_up == sql.true())
        try:
            agent = query.one()
        except exc.NoResultFound:
            LOG.debug('No enabled %(agent_type)s agent on host '
                      '%(host)s', {'agent_type': agent_type, 'host': host})
            return
        if self.is_agent_down(agent.heartbeat_timestamp):
            LOG.warning(_LW('%(agent_type)s agent %(agent_id)s is not active'),
                        {'agent_type': agent_type, 'agent_id': agent.id})
        return agent

    @staticmethod
    def is_agent_down(heart_beat_time):
        return timeutils.is_older_than(heart_beat_time,
                                       cfg.CONF.agent_down_time)

    @staticmethod
    def is_agent_considered_for_versions(agent_dict):
        return not timeutils.is_older_than(agent_dict['heartbeat_timestamp'],
                                           cfg.CONF.agent_down_time *
                                           DOWNTIME_VERSIONS_RATIO)

    def get_configuration_dict(self, agent_db):
        return self._get_dict(agent_db, 'configurations')

    def _get_dict(self, agent_db, dict_name, ignore_missing=False):
        json_value = None
        try:
            json_value = getattr(agent_db, dict_name)
            conf = jsonutils.loads(json_value)
        except Exception:
            if json_value or not ignore_missing:
                msg = _LW('Dictionary %(dict_name)s for agent %(agent_type)s '
                          'on host %(host)s is invalid.')
                LOG.warning(msg, {'dict_name': dict_name,
                                  'agent_type': agent_db.agent_type,
                                  'host': agent_db.host})
            conf = {}
        return conf

    def _get_agent_load(self, agent):
        configs = agent.get('configurations', {})
        load_type = None
        load = 0
        if(agent['agent_type'] == constants.AGENT_TYPE_DHCP):
            load_type = cfg.CONF.dhcp_load_type
        if load_type:
            load = int(configs.get(load_type, 0))
        return load

    def _make_agent_dict(self, agent, fields=None):
        attr = ext_agent.RESOURCE_ATTRIBUTE_MAP.get(
            ext_agent.RESOURCE_NAME + 's')
        res = dict((k, agent[k]) for k in attr
                   if k not in ['alive', 'configurations'])
        res['alive'] = not self.is_agent_down(res['heartbeat_timestamp'])
        res['configurations'] = self._get_dict(agent, 'configurations')
        res['resource_versions'] = self._get_dict(agent, 'resource_versions',
                                                  ignore_missing=True)
        res['availability_zone'] = agent['availability_zone']
        return self._fields(res, fields)

    def delete_agent(self, context, id):
        agent = self._get_agent(context, id)
        registry.notify(resources.AGENT, events.BEFORE_DELETE, self,
                        context=context, agent=agent)
        with context.session.begin(subtransactions=True):
            context.session.delete(agent)

    def update_agent(self, context, id, agent):
        agent_data = agent['agent']
        with context.session.begin(subtransactions=True):
            agent = self._get_agent(context, id)
            agent.update(agent_data)
        return self._make_agent_dict(agent)

    def get_agents_db(self, context, filters=None):
        query = self._get_collection_query(context, Agent, filters=filters)
        return query.all()

    def get_agents(self, context, filters=None, fields=None):
        agents = self._get_collection(context, Agent,
                                      self._make_agent_dict,
                                      filters=filters, fields=fields)
        alive = filters and filters.get('alive', None)
        if alive:
            alive = converters.convert_to_boolean(alive[0])
            agents = [agent for agent in agents if agent['alive'] == alive]
        return agents

    def agent_health_check(self):
        """Scan agents and log if some are considered dead."""
        agents = self.get_agents(context.get_admin_context(),
                                 filters={'admin_state_up': [True]})
        dead_agents = [agent for agent in agents if not agent['alive']]
        if dead_agents:
            data = '%20s %20s %s\n' % ('Type', 'Last heartbeat', "host")
            data += '\n'.join(['%20s %20s %s' %
                               (agent['agent_type'],
                                agent['heartbeat_timestamp'],
                                agent['host']) for agent in dead_agents])
            LOG.warning(_LW("Agent healthcheck: found %(count)s dead agents "
                            "out of %(total)s:\n%(data)s"),
                        {'count': len(dead_agents),
                         'total': len(agents),
                         'data': data})
        else:
            LOG.debug("Agent healthcheck: found %s active agents",
                      len(agents))

    def _get_agent_by_type_and_host(self, context, agent_type, host):
        query = self._model_query(context, Agent)
        try:
            agent_db = query.filter(Agent.agent_type == agent_type,
                                    Agent.host == host).one()
            return agent_db
        except exc.NoResultFound:
            raise ext_agent.AgentNotFoundByTypeHost(agent_type=agent_type,
                                                    host=host)
        except exc.MultipleResultsFound:
            raise ext_agent.MultipleAgentFoundByTypeHost(agent_type=agent_type,
                                                         host=host)

    def get_agent(self, context, id, fields=None):
        agent = self._get_agent(context, id)
        return self._make_agent_dict(agent, fields)

    def filter_hosts_with_network_access(
            self, context, network_id, candidate_hosts):
        """Filter hosts with access to network_id.

        This method returns a subset of candidate_hosts with the ones with
        network access to network_id.

        A plugin can overload this method to define its own host network_id
        based filter.
        """
        return candidate_hosts

    def _log_heartbeat(self, state, agent_db, agent_conf):
        if agent_conf.get('log_agent_heartbeats'):
            delta = timeutils.utcnow() - agent_db.heartbeat_timestamp
            LOG.info(_LI("Heartbeat received from %(type)s agent on "
                         "host %(host)s, uuid %(uuid)s after %(delta)s"),
                     {'type': agent_db.agent_type,
                      'host': agent_db.host,
                      'uuid': state.get('uuid'),
                      'delta': delta})

    def _create_or_update_agent(self, context, agent_state):
        """Registers new agent in the database or updates existing.

        Returns agent status from server point of view: alive, new or revived.
        It could be used by agent to do some sync with the server if needed.
        """
        status = n_const.AGENT_ALIVE
        with context.session.begin(subtransactions=True):
            res_keys = ['agent_type', 'binary', 'host', 'topic']
            res = dict((k, agent_state[k]) for k in res_keys)
            if 'availability_zone' in agent_state:
                res['availability_zone'] = agent_state['availability_zone']
            configurations_dict = agent_state.get('configurations', {})
            res['configurations'] = jsonutils.dumps(configurations_dict)
            resource_versions_dict = agent_state.get('resource_versions')
            if resource_versions_dict:
                res['resource_versions'] = jsonutils.dumps(
                    resource_versions_dict)
            res['load'] = self._get_agent_load(agent_state)
            current_time = timeutils.utcnow()
            try:
                agent_db = self._get_agent_by_type_and_host(
                    context, agent_state['agent_type'], agent_state['host'])
                if not agent_db.is_active:
                    status = n_const.AGENT_REVIVED
                    if 'resource_versions' not in agent_state:
                        # updating agent_state with resource_versions taken
                        # from db so that
                        # _update_local_agent_resource_versions() will call
                        # version_manager and bring it up to date
                        agent_state['resource_versions'] = self._get_dict(
                            agent_db, 'resource_versions', ignore_missing=True)
                res['heartbeat_timestamp'] = current_time
                if agent_state.get('start_flag'):
                    res['started_at'] = current_time
                greenthread.sleep(0)
                self._log_heartbeat(agent_state, agent_db, configurations_dict)
                agent_db.update(res)
                event_type = events.AFTER_UPDATE
            except ext_agent.AgentNotFoundByTypeHost:
                greenthread.sleep(0)
                res['created_at'] = current_time
                res['started_at'] = current_time
                res['heartbeat_timestamp'] = current_time
                res['admin_state_up'] = cfg.CONF.enable_new_agents
                agent_db = Agent(**res)
                greenthread.sleep(0)
                context.session.add(agent_db)
                event_type = events.AFTER_CREATE
                self._log_heartbeat(agent_state, agent_db, configurations_dict)
                status = n_const.AGENT_NEW
            greenthread.sleep(0)

        registry.notify(resources.AGENT, event_type, self, context=context,
                        host=agent_state['host'], plugin=self,
                        agent=agent_state)
        return status

    def create_or_update_agent(self, context, agent):
        """Create or update agent according to report."""
        try:
            return self._create_or_update_agent(context, agent)
        except db_exc.DBDuplicateEntry:
            # It might happen that two or more concurrent transactions
            # are trying to insert new rows having the same value of
            # (agent_type, host) pair at the same time (if there has
            # been no such entry in the table and multiple agent status
            # updates are being processed at the moment). In this case
            # having a unique constraint on (agent_type, host) columns
            # guarantees that only one transaction will succeed and
            # insert a new agent entry, others will fail and be rolled
            # back. That means we must retry them one more time: no
            # INSERTs will be issued, because
            # _get_agent_by_type_and_host() will return the existing
            # agent entry, which will be updated multiple times
            return self._create_or_update_agent(context, agent)

    def _get_agents_considered_for_versions(self):
        up_agents = self.get_agents(context.get_admin_context(),
                                    filters={'admin_state_up': [True]})
        return filter(self.is_agent_considered_for_versions, up_agents)

    def get_agents_resource_versions(self, tracker):
        """Get the known agent resource versions and update the tracker.

        This function looks up into the database and updates every agent
        resource versions.
        This method is called from version_manager when the cached information
        has passed TTL.

        :param tracker: receives a version_manager.ResourceConsumerTracker
        """
        for agent in self._get_agents_considered_for_versions():
            resource_versions = agent.get('resource_versions', {})
            consumer = version_manager.AgentConsumer(
                agent_type=agent['agent_type'], host=agent['host'])
            LOG.debug("Update consumer %(consumer)s versions to: "
                      "%(versions)s", {'consumer': consumer,
                                       'versions': resource_versions})
            tracker.set_versions(consumer, resource_versions)


class AgentExtRpcCallback(object):
    """Processes the rpc report in plugin implementations.

    This class implements the server side of an rpc interface.  The client side
    can be found in neutron.agent.rpc.PluginReportStateAPI.  For more
    information on changing rpc interfaces, see doc/source/devref/rpc_api.rst.

    API version history:
        1.0 - Initial version.
        1.1 - report_state now returns agent state.
    """

    target = oslo_messaging.Target(version='1.1',
                                   namespace=n_const.RPC_NAMESPACE_STATE)
    START_TIME = timeutils.utcnow()

    def __init__(self, plugin=None):
        super(AgentExtRpcCallback, self).__init__()
        self.plugin = plugin
        #TODO(ajo): fix the resources circular dependency issue by dynamically
        #           registering object types in the RPC callbacks api
        resources_rpc = importutils.import_module(
            'neutron.api.rpc.handlers.resources_rpc')
        # Initialize RPC api directed to other neutron-servers
        self.server_versions_rpc = resources_rpc.ResourcesPushToServersRpcApi()

    @db_api.retry_db_errors
    def report_state(self, context, **kwargs):
        """Report state from agent to server.

        Returns - agent's status: AGENT_NEW, AGENT_REVIVED, AGENT_ALIVE
        """
        time = kwargs['time']
        time = timeutils.parse_strtime(time)
        agent_state = kwargs['agent_state']['agent_state']
        self._check_clock_sync_on_agent_start(agent_state, time)
        if self.START_TIME > time:
            time_agent = datetime.datetime.isoformat(time)
            time_server = datetime.datetime.isoformat(self.START_TIME)
            log_dict = {'agent_time': time_agent, 'server_time': time_server}
            LOG.debug("Stale message received with timestamp: %(agent_time)s. "
                      "Skipping processing because it's older than the "
                      "server start timestamp: %(server_time)s", log_dict)
            return
        if not self.plugin:
            self.plugin = manager.NeutronManager.get_plugin()
        agent_status = self.plugin.create_or_update_agent(context, agent_state)
        self._update_local_agent_resource_versions(context, agent_state)
        return agent_status

    def _update_local_agent_resource_versions(self, context, agent_state):
        resource_versions_dict = agent_state.get('resource_versions')
        if not resource_versions_dict:
            return

        version_manager.update_versions(
            version_manager.AgentConsumer(agent_type=agent_state['agent_type'],
                                          host=agent_state['host']),
            resource_versions_dict)
        # report other neutron-servers about this quickly
        self.server_versions_rpc.report_agent_resource_versions(
            context, agent_state['agent_type'], agent_state['host'],
            resource_versions_dict)

    def _check_clock_sync_on_agent_start(self, agent_state, agent_time):
        """Checks if the server and the agent times are in sync.

        Method checks if the agent time is in sync with the server time
        on start up. Ignores it, on subsequent re-connects.
        """
        if agent_state.get('start_flag'):
            time_server_now = timeutils.utcnow()
            diff = abs(timeutils.delta_seconds(time_server_now, agent_time))
            if diff > cfg.CONF.agent_down_time:
                agent_name = agent_state['agent_type']
                time_agent = datetime.datetime.isoformat(agent_time)

                host = agent_state['host']
                log_dict = {'host': host,
                            'agent_name': agent_name,
                            'agent_time': time_agent,
                            'threshold': cfg.CONF.agent_down_time,
                            'serv_time': (datetime.datetime.isoformat
                                          (time_server_now)),
                            'diff': diff}
                LOG.error(_LE("Message received from the host: %(host)s "
                              "during the registration of %(agent_name)s has "
                              "a timestamp: %(agent_time)s. This differs from "
                              "the current server timestamp: %(serv_time)s by "
                              "%(diff)s seconds, which is more than the "
                              "threshold agent down"
                              "time: %(threshold)s."), log_dict)
