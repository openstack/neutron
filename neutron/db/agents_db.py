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

import copy
import datetime

from eventlet import greenthread
from neutron_lib.agent import constants as agent_consts
from neutron_lib.api import converters
from neutron_lib.api.definitions import agent as agent_apidef
from neutron_lib.api.definitions import availability_zone_filter as azfil_ext
from neutron_lib.api import extensions
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.db import utils as db_utils
from neutron_lib.exceptions import agent as agent_exc
from neutron_lib.exceptions import availability_zone as az_exc
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_serialization import jsonutils
from oslo_utils import importutils
from oslo_utils import timeutils

from neutron.agent.common import utils
from neutron.api.rpc.callbacks import version_manager
from neutron.conf.agent.database import agents_db
from neutron.extensions import agent as ext_agent
from neutron.extensions import availability_zone as az_ext
from neutron.objects import agent as agent_obj


LOG = logging.getLogger(__name__)

agents_db.register_db_agents_opts()

# this is the ratio from agent_down_time to the time we use to consider
# the agents down for considering their resource versions in the
# version_manager callback
DOWNTIME_VERSIONS_RATIO = 2

RESOURCE_AGENT_TYPE_MAP = {
    'network': constants.AGENT_TYPE_DHCP,
    'router': constants.AGENT_TYPE_L3,
}

AZ_ATTRIBUTE_MAP = {
    'name': {
        'agent_key': 'availability_zone',
        'convert_to': lambda x: x,
    },
    'resource': {
        'agent_key': 'agent_type',
        'convert_to': lambda x: RESOURCE_AGENT_TYPE_MAP.get(x, x),
    }
}


def get_availability_zones_by_agent_type(context, agent_type,
                                         availability_zones):
    """Get list of availability zones based on agent type"""

    agents = agent_obj.Agent.get_agents_by_availability_zones_and_agent_type(
        context, agent_type=agent_type, availability_zones=availability_zones)
    return set(agent.availability_zone for agent in agents)


class AgentAvailabilityZoneMixin(az_ext.AvailabilityZonePluginBase):
    """Mixin class to add availability_zone extension to AgentDbMixin."""

    _is_az_filter_supported = None

    @property
    def is_az_filter_supported(self):
        supported = self._is_az_filter_supported
        if supported is None:
            supported = False
            for plugin in directory.get_plugins().values():
                if extensions.is_extension_supported(plugin, azfil_ext.ALIAS):
                    supported = True
                    break
        self._is_az_filter_supported = supported

        return self._is_az_filter_supported

    def _list_availability_zones(self, context, filters=None):
        result = {}
        filters = filters or {}
        if self._is_az_filter_supported or self.is_az_filter_supported:
            filters = self._adjust_az_filters(filters)
        agents = agent_obj.Agent.get_objects(context, **filters)
        for agent in agents:
            if not agent.availability_zone:
                continue
            if agent.agent_type == constants.AGENT_TYPE_DHCP:
                resource = 'network'
            elif agent.agent_type == constants.AGENT_TYPE_L3:
                resource = 'router'
            else:
                continue
            key = (agent.availability_zone, resource)
            value = agent.admin_state_up or result.get(key, False)
            result[key] = 'available' if value else 'unavailable'
        return result

    def _adjust_az_filters(self, filters):
        # The intersect of sets gets us applicable filter keys (others ignored)
        common_keys = filters.keys() & AZ_ATTRIBUTE_MAP.keys()
        for key in common_keys:
            filter_key = AZ_ATTRIBUTE_MAP[key]['agent_key']
            filter_vals = filters.pop(key)
            if filter_vals:
                filter_vals = [AZ_ATTRIBUTE_MAP[key]['convert_to'](v)
                               for v in filter_vals]
            filters.setdefault(filter_key, [])
            filters[filter_key] += filter_vals
        return filters

    @db_api.retry_if_session_inactive()
    def get_availability_zones(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        """Return a list of availability zones."""
        if self._is_az_filter_supported or self.is_az_filter_supported:
            filter_states = filters.pop('state', [])
            # NOTE(hichihara): 'tenant_id' is dummy for policy check.
            # it is not visible via API.
            return [{'state': v,
                     'name': k[0], 'resource': k[1],
                     'tenant_id': context.tenant_id}
                    for k, v in self._list_availability_zones(
                        context, filters).items()
                    if not filter_states or v in filter_states]
        else:
            # NOTE(hichihara): 'tenant_id' is dummy for policy check.
            # it is not visible via API.
            return [{'state': v,
                     'name': k[0], 'resource': k[1],
                     'tenant_id': context.tenant_id}
                    for k, v in self._list_availability_zones(
                        context, filters).items()]

    @db_api.retry_if_session_inactive()
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
        azs = get_availability_zones_by_agent_type(
            context, agent_type, availability_zones)
        diff = set(availability_zones) - set(azs)
        if diff:
            raise az_exc.AvailabilityZoneNotFound(availability_zone=diff.pop())


class AgentDbMixin(ext_agent.AgentPluginBase, AgentAvailabilityZoneMixin):
    """Mixin class to add agent extension to db_base_plugin_v2."""

    def _get_agent(self, context, id):
        agent = agent_obj.Agent.get_object(context, id=id)
        if not agent:
            raise agent_exc.AgentNotFound(id=id)
        return agent

    @db_api.retry_if_session_inactive()
    def get_enabled_agent_on_host(self, context, agent_type, host):
        """Return agent of agent_type for the specified host."""

        agent = agent_obj.Agent.get_object(context,
                                           agent_type=agent_type,
                                           host=host,
                                           admin_state_up=True)

        if not agent:
            LOG.debug('No enabled %(agent_type)s agent on host '
                      '%(host)s', {'agent_type': agent_type, 'host': host})
            return

        if utils.is_agent_down(agent.heartbeat_timestamp):
            LOG.warning('%(agent_type)s agent %(agent_id)s is not active',
                        {'agent_type': agent_type, 'agent_id': agent.id})
        return agent

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
            # TODO(tuanvu): after all agent_db is converted to agent_obj,
            #               we no longer need this.
            #               Without this check, some unit tests will fail
            #               because some of json_values are dict already
            if not isinstance(json_value, dict):
                conf = jsonutils.loads(json_value)
            else:
                conf = json_value
        except Exception:
            if json_value or not ignore_missing:
                msg = ('Dictionary %(dict_name)s for agent %(agent_type)s '
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
        attr = agent_apidef.RESOURCE_ATTRIBUTE_MAP.get(
            agent_apidef.COLLECTION_NAME)
        res = dict((k, agent[k]) for k in attr
                   if k not in ['alive', 'configurations'])
        res['alive'] = not utils.is_agent_down(
            res['heartbeat_timestamp']
        )
        res['configurations'] = self._get_dict(agent, 'configurations')
        res['resource_versions'] = self._get_dict(agent, 'resource_versions',
                                                  ignore_missing=True)
        res['availability_zone'] = agent['availability_zone']
        res['resources_synced'] = agent['resources_synced']
        return db_utils.resource_fields(res, fields)

    @db_api.retry_if_session_inactive()
    def delete_agent(self, context, id):
        agent = self._get_agent(context, id)
        registry.publish(resources.AGENT, events.BEFORE_DELETE, self,
                         payload=events.DBEventPayload(
                             context, states=(agent,), resource_id=id))
        agent.delete()
        registry.publish(resources.AGENT, events.AFTER_DELETE, self,
                         payload=events.DBEventPayload(
                             context, states=(agent,), resource_id=id))

    @db_api.retry_if_session_inactive()
    def update_agent(self, context, id, agent):
        agent_data = agent['agent']
        with db_api.CONTEXT_WRITER.using(context):
            agent = self._get_agent(context, id)
            agent.update_fields(agent_data)
            agent.update()
        return self._make_agent_dict(agent)

    @db_api.retry_if_session_inactive()
    def get_agent_objects(self, context, filters=None):
        filters = filters or {}
        return agent_obj.Agent.get_objects(context, **filters)

    @db_api.retry_if_session_inactive()
    def get_agents(self, context, filters=None, fields=None):
        filters = filters or {}
        alive = filters and filters.pop('alive', None)
        agents = agent_obj.Agent.get_objects(context, **filters)
        if alive:
            alive = converters.convert_to_boolean(alive[0])
            agents = [agent for agent in agents if agent.is_active == alive]
        return [self._make_agent_dict(agent, fields=fields)
                for agent in agents]

    @db_api.retry_db_errors
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
            LOG.warning("Agent healthcheck: found %(count)s dead agents "
                        "out of %(total)s:\n%(data)s",
                        {'count': len(dead_agents),
                         'total': len(agents),
                         'data': data})
        else:
            LOG.debug("Agent healthcheck: found %s active agents",
                      len(agents))

    def _get_agent_by_type_and_host(self, context, agent_type, host):
        agent_objs = agent_obj.Agent.get_objects(context,
                                                 agent_type=agent_type,
                                                 host=host)
        if not agent_objs:
            raise agent_exc.AgentNotFoundByTypeHost(agent_type=agent_type,
                                                    host=host)
        if len(agent_objs) > 1:
            raise agent_exc.MultipleAgentFoundByTypeHost(
                agent_type=agent_type, host=host)
        return agent_objs[0]

    @db_api.retry_if_session_inactive()
    def get_agent(self, context, id, fields=None):
        agent = self._get_agent(context, id)
        return self._make_agent_dict(agent, fields)

    @db_api.retry_if_session_inactive()
    def filter_hosts_with_network_access(
            self, context, network_id, candidate_hosts):
        """Filter hosts with access to network_id.

        This method returns a subset of candidate_hosts with the ones with
        network access to network_id.

        A plugin can overload this method to define its own host network_id
        based filter.
        """
        return candidate_hosts

    def _log_heartbeat(self, state, agent_db, agent_conf, agent_timestamp):
        if agent_conf.get('log_agent_heartbeats'):
            delta = timeutils.utcnow() - agent_db.heartbeat_timestamp
            LOG.info("Heartbeat received from %(type)s agent on "
                     "host %(host)s, uuid %(uuid)s after %(delta)s, sent at "
                     "%(agent_timestamp)s",
                     {'type': agent_db.agent_type,
                      'host': agent_db.host,
                      'uuid': state.get('uuid'),
                      'delta': delta,
                      'agent_timestamp': agent_timestamp})

    @db_api.retry_if_session_inactive()
    def create_or_update_agent(self, context, agent_state,
                               agent_timestamp=None):
        """Registers new agent in the database or updates existing.

        Returns tuple of agent status and state.
        Status is from server point of view: alive, new or revived.
        It could be used by agent to do some sync with the server if needed.
        """
        status = agent_consts.AGENT_ALIVE
        with db_api.CONTEXT_WRITER.using(context):
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
                agent = self._get_agent_by_type_and_host(
                    context, agent_state['agent_type'], agent_state['host'])
                agent_state_orig = copy.deepcopy(agent_state)
                agent_state_previous = copy.deepcopy(agent)
                if not agent.is_active:
                    status = agent_consts.AGENT_REVIVED
                    if 'resource_versions' not in agent_state:
                        # updating agent_state with resource_versions taken
                        # from db so that
                        # _update_local_agent_resource_versions() will call
                        # version_manager and bring it up to date
                        agent_state['resource_versions'] = self._get_dict(
                            agent, 'resource_versions', ignore_missing=True)
                res['heartbeat_timestamp'] = current_time
                if agent_state.get('start_flag'):
                    res['started_at'] = current_time
                greenthread.sleep(0)
                self._log_heartbeat(agent_state, agent, configurations_dict,
                                    agent_timestamp)
                agent.update_fields(res)
                agent.update()
                event_type = events.AFTER_UPDATE
            except agent_exc.AgentNotFoundByTypeHost:
                agent_state_orig = None
                agent_state_previous = None
                greenthread.sleep(0)
                res['created_at'] = current_time
                res['started_at'] = current_time
                res['heartbeat_timestamp'] = current_time
                res['admin_state_up'] = cfg.CONF.enable_new_agents
                agent = agent_obj.Agent(context=context, **res)
                greenthread.sleep(0)
                agent.create()
                event_type = events.AFTER_CREATE
                self._log_heartbeat(agent_state, agent, configurations_dict,
                                    agent_timestamp)
                status = agent_consts.AGENT_NEW
            greenthread.sleep(0)

        agent_state['agent_status'] = status
        agent_state['admin_state_up'] = agent.admin_state_up
        agent_state['id'] = agent.id
        registry.publish(resources.AGENT, event_type, self,
                         payload=events.DBEventPayload(
                             context=context, metadata={
                                 'host': agent_state['host'],
                                 'plugin': self,
                                 'status': status
                             },
                             states=(agent_state_orig, agent_state_previous),
                             desired_state=agent_state,
                             resource_id=agent.id
                         ))
        return status, agent_state

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
            tracker.set_versions(consumer, resource_versions)


class AgentExtRpcCallback(object):
    """Processes the rpc report in plugin implementations.

    This class implements the server side of an rpc interface.  The client side
    can be found in neutron.agent.rpc.PluginReportStateAPI.  For more
    information on changing rpc interfaces, see
    doc/source/contributor/internals/rpc_api.rst.

    API version history:
        1.0 - Initial version.
        1.1 - report_state now returns agent state.
        1.2 - add method has_alive_neutron_server.
    """

    target = oslo_messaging.Target(version='1.2',
                                   namespace=constants.RPC_NAMESPACE_STATE)
    START_TIME = timeutils.utcnow()

    def __init__(self, plugin=None):
        super(AgentExtRpcCallback, self).__init__()
        self.plugin = plugin
        # TODO(ajo): fix the resources circular dependency issue by dynamically
        #            registering object types in the RPC callbacks api
        resources_rpc = importutils.import_module(
            'neutron.api.rpc.handlers.resources_rpc')
        # Initialize RPC api directed to other neutron-servers
        self.server_versions_rpc = resources_rpc.ResourcesPushToServersRpcApi()

    def has_alive_neutron_server(self, context, **kwargs):
        return True

    @db_api.retry_if_session_inactive()
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
            self.plugin = directory.get_plugin()
        agent_status, agent_state = self.plugin.create_or_update_agent(
            context, agent_state, time)
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
                LOG.error("Message received from the host: %(host)s "
                          "during the registration of %(agent_name)s has "
                          "a timestamp: %(agent_time)s. This differs from "
                          "the current server timestamp: %(serv_time)s by "
                          "%(diff)s seconds, which is more than the "
                          "threshold agent down "
                          "time: %(threshold)s.", log_dict)
