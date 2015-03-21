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

from eventlet import greenthread
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
import oslo_messaging
from oslo_serialization import jsonutils
from oslo_utils import timeutils
import sqlalchemy as sa
from sqlalchemy.orm import exc
from sqlalchemy import sql

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import agent as ext_agent
from neutron.i18n import _LW
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
]
cfg.CONF.register_opts(AGENT_OPTS)


class Agent(model_base.BASEV2, models_v2.HasId):
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
    admin_state_up = sa.Column(sa.Boolean, default=True,
                               server_default=sql.true(), nullable=False)
    # the time when first report came from agents
    created_at = sa.Column(sa.DateTime, nullable=False)
    # the time when first report came after agents start
    started_at = sa.Column(sa.DateTime, nullable=False)
    # updated when agents report
    heartbeat_timestamp = sa.Column(sa.DateTime, nullable=False)
    # description is note for admin user
    description = sa.Column(sa.String(255))
    # configurations: a json dict string, I think 4095 is enough
    configurations = sa.Column(sa.String(4095), nullable=False)
    # load - number of resources hosted by the agent
    load = sa.Column(sa.Integer, server_default='0', nullable=False)

    @property
    def is_active(self):
        return not AgentDbMixin.is_agent_down(self.heartbeat_timestamp)


class AgentDbMixin(ext_agent.AgentPluginBase):
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
            LOG.warn(_LW('%(agent_type)s agent %(agent_id)s is not active'),
                     {'agent_type': agent_type, 'agent_id': agent.id})
        return agent

    @classmethod
    def is_agent_down(cls, heart_beat_time):
        return timeutils.is_older_than(heart_beat_time,
                                       cfg.CONF.agent_down_time)

    def get_configuration_dict(self, agent_db):
        try:
            conf = jsonutils.loads(agent_db.configurations)
        except Exception:
            msg = _LW('Configuration for agent %(agent_type)s on host %(host)s'
                      ' is invalid.')
            LOG.warn(msg, {'agent_type': agent_db.agent_type,
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
        res['alive'] = not AgentDbMixin.is_agent_down(
            res['heartbeat_timestamp'])
        res['configurations'] = self.get_configuration_dict(agent)
        return self._fields(res, fields)

    def delete_agent(self, context, id):
        with context.session.begin(subtransactions=True):
            agent = self._get_agent(context, id)
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
            # alive filter will be a list
            alive = attributes.convert_to_boolean(alive[0])
            agents = [agent for agent in agents if agent['alive'] == alive]
        return agents

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

    def _create_or_update_agent(self, context, agent):
        with context.session.begin(subtransactions=True):
            res_keys = ['agent_type', 'binary', 'host', 'topic']
            res = dict((k, agent[k]) for k in res_keys)

            configurations_dict = agent.get('configurations', {})
            res['configurations'] = jsonutils.dumps(configurations_dict)
            res['load'] = self._get_agent_load(agent)
            current_time = timeutils.utcnow()
            try:
                agent_db = self._get_agent_by_type_and_host(
                    context, agent['agent_type'], agent['host'])
                res['heartbeat_timestamp'] = current_time
                if agent.get('start_flag'):
                    res['started_at'] = current_time
                greenthread.sleep(0)
                agent_db.update(res)
            except ext_agent.AgentNotFoundByTypeHost:
                greenthread.sleep(0)
                res['created_at'] = current_time
                res['started_at'] = current_time
                res['heartbeat_timestamp'] = current_time
                res['admin_state_up'] = True
                agent_db = Agent(**res)
                greenthread.sleep(0)
                context.session.add(agent_db)
            greenthread.sleep(0)

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


class AgentExtRpcCallback(object):
    """Processes the rpc report in plugin implementations.

    This class implements the server side of an rpc interface.  The client side
    can be found in neutron.agent.rpc.PluginReportStateAPI.  For more
    information on changing rpc interfaces, see doc/source/devref/rpc_api.rst.
    """

    target = oslo_messaging.Target(version='1.0',
                                   namespace=constants.RPC_NAMESPACE_STATE)
    START_TIME = timeutils.utcnow()

    def __init__(self, plugin=None):
        super(AgentExtRpcCallback, self).__init__()
        self.plugin = plugin

    def report_state(self, context, **kwargs):
        """Report state from agent to server."""
        time = kwargs['time']
        time = timeutils.parse_strtime(time)
        if self.START_TIME > time:
            LOG.debug("Message with invalid timestamp received")
            return
        agent_state = kwargs['agent_state']['agent_state']
        if not self.plugin:
            self.plugin = manager.NeutronManager.get_plugin()
        self.plugin.create_or_update_agent(context, agent_state)
