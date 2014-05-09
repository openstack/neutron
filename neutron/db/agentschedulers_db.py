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

from oslo.config import cfg
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc
from sqlalchemy.orm import joinedload

from neutron.common import constants
from neutron.common import utils
from neutron.db import agents_db
from neutron.db import model_base
from neutron.extensions import agent as ext_agent
from neutron.extensions import dhcpagentscheduler
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)

AGENTS_SCHEDULER_OPTS = [
    cfg.StrOpt('network_scheduler_driver',
               default='neutron.scheduler.'
                       'dhcp_agent_scheduler.ChanceScheduler',
               help=_('Driver to use for scheduling network to DHCP agent')),
    cfg.BoolOpt('network_auto_schedule', default=True,
                help=_('Allow auto scheduling networks to DHCP agent.')),
    cfg.IntOpt('dhcp_agents_per_network', default=1,
               help=_('Number of DHCP agents scheduled to host a network.')),
]

cfg.CONF.register_opts(AGENTS_SCHEDULER_OPTS)


class NetworkDhcpAgentBinding(model_base.BASEV2):
    """Represents binding between neutron networks and DHCP agents."""

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("networks.id", ondelete='CASCADE'),
                           primary_key=True)
    dhcp_agent = orm.relation(agents_db.Agent)
    dhcp_agent_id = sa.Column(sa.String(36),
                              sa.ForeignKey("agents.id",
                                            ondelete='CASCADE'),
                              primary_key=True)


class AgentSchedulerDbMixin(agents_db.AgentDbMixin):
    """Common class for agent scheduler mixins."""

    # agent notifiers to handle agent update operations;
    # should be updated by plugins;
    agent_notifiers = {
        constants.AGENT_TYPE_DHCP: None,
        constants.AGENT_TYPE_L3: None,
        constants.AGENT_TYPE_LOADBALANCER: None,
    }

    @staticmethod
    def is_eligible_agent(active, agent):
        if active is None:
            # filtering by activeness is disabled, all agents are eligible
            return True
        else:
            # note(rpodolyaka): original behaviour is saved here: if active
            #                   filter is set, only agents which are 'up'
            #                   (i.e. have a recent heartbeat timestamp)
            #                   are eligible, even if active is False
            return not agents_db.AgentDbMixin.is_agent_down(
                agent['heartbeat_timestamp'])

    def update_agent(self, context, id, agent):
        original_agent = self.get_agent(context, id)
        result = super(AgentSchedulerDbMixin, self).update_agent(
            context, id, agent)
        agent_data = agent['agent']
        agent_notifier = self.agent_notifiers.get(original_agent['agent_type'])
        if (agent_notifier and
            'admin_state_up' in agent_data and
            original_agent['admin_state_up'] != agent_data['admin_state_up']):
            agent_notifier.agent_updated(context,
                                         agent_data['admin_state_up'],
                                         original_agent['host'])
        return result


class DhcpAgentSchedulerDbMixin(dhcpagentscheduler
                                .DhcpAgentSchedulerPluginBase,
                                AgentSchedulerDbMixin):
    """Mixin class to add DHCP agent scheduler extension to db_base_plugin_v2.
    """

    network_scheduler = None

    def get_dhcp_agents_hosting_networks(
            self, context, network_ids, active=None):
        if not network_ids:
            return []
        query = context.session.query(NetworkDhcpAgentBinding)
        query = query.options(joinedload('dhcp_agent'))
        if len(network_ids) == 1:
            query = query.filter(
                NetworkDhcpAgentBinding.network_id == network_ids[0])
        elif network_ids:
            query = query.filter(
                NetworkDhcpAgentBinding.network_id in network_ids)
        if active is not None:
            query = (query.filter(agents_db.Agent.admin_state_up == active))

        return [binding.dhcp_agent
                for binding in query
                if AgentSchedulerDbMixin.is_eligible_agent(active,
                                                           binding.dhcp_agent)]

    def add_network_to_dhcp_agent(self, context, id, network_id):
        self._get_network(context, network_id)
        with context.session.begin(subtransactions=True):
            agent_db = self._get_agent(context, id)
            if (agent_db['agent_type'] != constants.AGENT_TYPE_DHCP or
                    not agent_db['admin_state_up']):
                raise dhcpagentscheduler.InvalidDHCPAgent(id=id)
            dhcp_agents = self.get_dhcp_agents_hosting_networks(
                context, [network_id])
            for dhcp_agent in dhcp_agents:
                if id == dhcp_agent.id:
                    raise dhcpagentscheduler.NetworkHostedByDHCPAgent(
                        network_id=network_id, agent_id=id)
            binding = NetworkDhcpAgentBinding()
            binding.dhcp_agent_id = id
            binding.network_id = network_id
            context.session.add(binding)
        dhcp_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_DHCP)
        if dhcp_notifier:
            dhcp_notifier.network_added_to_agent(
                context, network_id, agent_db.host)

    def remove_network_from_dhcp_agent(self, context, id, network_id):
        agent = self._get_agent(context, id)
        with context.session.begin(subtransactions=True):
            try:
                query = context.session.query(NetworkDhcpAgentBinding)
                binding = query.filter(
                    NetworkDhcpAgentBinding.network_id == network_id,
                    NetworkDhcpAgentBinding.dhcp_agent_id == id).one()
            except exc.NoResultFound:
                raise dhcpagentscheduler.NetworkNotHostedByDhcpAgent(
                    network_id=network_id, agent_id=id)

            # reserve the port, so the ip is reused on a subsequent add
            device_id = utils.get_dhcp_agent_device_id(network_id,
                                                       agent['host'])
            filters = dict(device_id=[device_id])
            ports = self.get_ports(context, filters=filters)
            for port in ports:
                port['device_id'] = constants.DEVICE_ID_RESERVED_DHCP_PORT
                self.update_port(context, port['id'], dict(port=port))

            context.session.delete(binding)
        dhcp_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_DHCP)
        if dhcp_notifier:
            dhcp_notifier.network_removed_from_agent(
                context, network_id, agent.host)

    def list_networks_on_dhcp_agent(self, context, id):
        query = context.session.query(NetworkDhcpAgentBinding.network_id)
        query = query.filter(NetworkDhcpAgentBinding.dhcp_agent_id == id)

        net_ids = [item[0] for item in query]
        if net_ids:
            return {'networks':
                    self.get_networks(context, filters={'id': net_ids})}
        else:
            return {'networks': []}

    def list_active_networks_on_active_dhcp_agent(self, context, host):
        try:
            agent = self._get_agent_by_type_and_host(
                context, constants.AGENT_TYPE_DHCP, host)
        except ext_agent.AgentNotFoundByTypeHost:
            LOG.debug("DHCP Agent not found on host %s", host)
            return []

        if not agent.admin_state_up:
            return []
        query = context.session.query(NetworkDhcpAgentBinding.network_id)
        query = query.filter(NetworkDhcpAgentBinding.dhcp_agent_id == agent.id)

        net_ids = [item[0] for item in query]
        if net_ids:
            return self.get_networks(
                context,
                filters={'id': net_ids, 'admin_state_up': [True]}
            )
        else:
            return []

    def list_dhcp_agents_hosting_network(self, context, network_id):
        dhcp_agents = self.get_dhcp_agents_hosting_networks(
            context, [network_id])
        agent_ids = [dhcp_agent.id for dhcp_agent in dhcp_agents]
        if agent_ids:
            return {
                'agents': self.get_agents(context, filters={'id': agent_ids})}
        else:
            return {'agents': []}

    def schedule_network(self, context, created_network):
        if self.network_scheduler:
            return self.network_scheduler.schedule(
                self, context, created_network)

    def auto_schedule_networks(self, context, host):
        if self.network_scheduler:
            self.network_scheduler.auto_schedule_networks(self, context, host)
