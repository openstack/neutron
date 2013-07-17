# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc
from sqlalchemy.orm import joinedload

from neutron.common import constants
from neutron.db import agents_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import dhcpagentscheduler
from neutron.extensions import l3agentscheduler
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


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


class RouterL3AgentBinding(model_base.BASEV2, models_v2.HasId):
    """Represents binding between neutron routers and L3 agents."""

    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey("routers.id", ondelete='CASCADE'))
    l3_agent = orm.relation(agents_db.Agent)
    l3_agent_id = sa.Column(sa.String(36),
                            sa.ForeignKey("agents.id",
                                          ondelete='CASCADE'))


class AgentSchedulerDbMixin(agents_db.AgentDbMixin):
    """Common class for agent scheduler mixins."""

    dhcp_agent_notifier = None
    l3_agent_notifier = None

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
        if ('admin_state_up' in agent_data and
            original_agent['admin_state_up'] != agent_data['admin_state_up']):
            if (original_agent['agent_type'] == constants.AGENT_TYPE_DHCP and
                self.dhcp_agent_notifier):
                self.dhcp_agent_notifier.agent_updated(
                    context, agent_data['admin_state_up'],
                    original_agent['host'])
            elif (original_agent['agent_type'] == constants.AGENT_TYPE_L3 and
                  self.l3_agent_notifier):
                self.l3_agent_notifier.agent_updated(
                    context, agent_data['admin_state_up'],
                    original_agent['host'])
        return result


class L3AgentSchedulerDbMixin(l3agentscheduler.L3AgentSchedulerPluginBase,
                              AgentSchedulerDbMixin):
    """Mixin class to add l3 agent scheduler extension to db_plugin_base_v2."""

    router_scheduler = None

    def add_router_to_l3_agent(self, context, id, router_id):
        """Add a l3 agent to host a router."""
        router = self.get_router(context, router_id)
        with context.session.begin(subtransactions=True):
            agent_db = self._get_agent(context, id)
            if (agent_db['agent_type'] != constants.AGENT_TYPE_L3 or
                not agent_db['admin_state_up'] or
                not self.get_l3_agent_candidates(router, [agent_db])):
                raise l3agentscheduler.InvalidL3Agent(id=id)
            query = context.session.query(RouterL3AgentBinding)
            try:
                binding = query.filter(
                    RouterL3AgentBinding.l3_agent_id == agent_db.id,
                    RouterL3AgentBinding.router_id == router_id).one()
                if binding:
                    raise l3agentscheduler.RouterHostedByL3Agent(
                        router_id=router_id, agent_id=id)
            except exc.NoResultFound:
                pass

            result = self.auto_schedule_routers(context,
                                                agent_db.host,
                                                [router_id])
            if not result:
                raise l3agentscheduler.RouterSchedulingFailed(
                    router_id=router_id, agent_id=id)

        if self.l3_agent_notifier:
            self.l3_agent_notifier.router_added_to_agent(
                context, [router_id], agent_db.host)

    def remove_router_from_l3_agent(self, context, id, router_id):
        """Remove the router from l3 agent.

        After it, the router will be non-hosted until there is update which
        lead to re schedule or be added to another agent manually.
        """
        agent = self._get_agent(context, id)
        with context.session.begin(subtransactions=True):
            query = context.session.query(RouterL3AgentBinding)
            query = query.filter(
                RouterL3AgentBinding.router_id == router_id,
                RouterL3AgentBinding.l3_agent_id == id)
            try:
                binding = query.one()
            except exc.NoResultFound:
                raise l3agentscheduler.RouterNotHostedByL3Agent(
                    router_id=router_id, agent_id=id)
            context.session.delete(binding)
        if self.l3_agent_notifier:
            self.l3_agent_notifier.router_removed_from_agent(
                context, router_id, agent.host)

    def list_routers_on_l3_agent(self, context, id):
        query = context.session.query(RouterL3AgentBinding.router_id)
        query = query.filter(RouterL3AgentBinding.l3_agent_id == id)

        router_ids = [item[0] for item in query]
        if router_ids:
            return {'routers':
                    self.get_routers(context, filters={'id': router_ids})}
        else:
            return {'routers': []}

    def list_active_sync_routers_on_active_l3_agent(
            self, context, host, router_ids):
        agent = self._get_agent_by_type_and_host(
            context, constants.AGENT_TYPE_L3, host)
        if not agent.admin_state_up:
            return []
        query = context.session.query(RouterL3AgentBinding.router_id)
        query = query.filter(
            RouterL3AgentBinding.l3_agent_id == agent.id)

        if not router_ids:
            pass
        else:
            query = query.filter(
                RouterL3AgentBinding.router_id.in_(router_ids))
        router_ids = [item[0] for item in query]
        if router_ids:
            return self.get_sync_data(context, router_ids=router_ids,
                                      active=True)
        else:
            return []

    def get_l3_agents_hosting_routers(self, context, router_ids,
                                      admin_state_up=None,
                                      active=None):
        if not router_ids:
            return []
        query = context.session.query(RouterL3AgentBinding)
        if len(router_ids) > 1:
            query = query.options(joinedload('l3_agent')).filter(
                RouterL3AgentBinding.router_id.in_(router_ids))
        else:
            query = query.options(joinedload('l3_agent')).filter(
                RouterL3AgentBinding.router_id == router_ids[0])
        if admin_state_up is not None:
            query = (query.filter(agents_db.Agent.admin_state_up ==
                                  admin_state_up))
        l3_agents = [binding.l3_agent for binding in query]
        if active is not None:
            l3_agents = [l3_agent for l3_agent in
                         l3_agents if not
                         agents_db.AgentDbMixin.is_agent_down(
                         l3_agent['heartbeat_timestamp'])]
        return l3_agents

    def _get_l3_bindings_hosting_routers(self, context, router_ids):
        if not router_ids:
            return []
        query = context.session.query(RouterL3AgentBinding)
        if len(router_ids) > 1:
            query = query.options(joinedload('l3_agent')).filter(
                RouterL3AgentBinding.router_id.in_(router_ids))
        else:
            query = query.options(joinedload('l3_agent')).filter(
                RouterL3AgentBinding.router_id == router_ids[0])
        return query.all()

    def list_l3_agents_hosting_router(self, context, router_id):
        with context.session.begin(subtransactions=True):
            bindings = self._get_l3_bindings_hosting_routers(
                context, [router_id])
            results = []
            for binding in bindings:
                l3_agent_dict = self._make_agent_dict(binding.l3_agent)
                results.append(l3_agent_dict)
            if results:
                return {'agents': results}
            else:
                return {'agents': []}

    def get_l3_agents(self, context, active=None, filters=None):
        query = context.session.query(agents_db.Agent)
        query = query.filter(
            agents_db.Agent.agent_type == constants.AGENT_TYPE_L3)
        if active is not None:
            query = (query.filter(agents_db.Agent.admin_state_up == active))
        if filters:
            for key, value in filters.iteritems():
                column = getattr(agents_db.Agent, key, None)
                if column:
                    query = query.filter(column.in_(value))

        return [l3_agent
                for l3_agent in query
                if AgentSchedulerDbMixin.is_eligible_agent(active, l3_agent)]

    def get_l3_agent_candidates(self, sync_router, l3_agents):
        """Get the valid l3 agents for the router from a list of l3_agents."""
        candidates = []
        for l3_agent in l3_agents:
            if not l3_agent.admin_state_up:
                continue
            agent_conf = self.get_configuration_dict(l3_agent)
            router_id = agent_conf.get('router_id', None)
            use_namespaces = agent_conf.get('use_namespaces', True)
            handle_internal_only_routers = agent_conf.get(
                'handle_internal_only_routers', True)
            gateway_external_network_id = agent_conf.get(
                'gateway_external_network_id', None)
            if not use_namespaces and router_id != sync_router['id']:
                continue
            ex_net_id = (sync_router['external_gateway_info'] or {}).get(
                'network_id')
            if ((not ex_net_id and not handle_internal_only_routers) or
                (ex_net_id and gateway_external_network_id and
                 ex_net_id != gateway_external_network_id)):
                continue
            candidates.append(l3_agent)
        return candidates

    def auto_schedule_routers(self, context, host, router_ids):
        if self.router_scheduler:
            return self.router_scheduler.auto_schedule_routers(
                self, context, host, router_ids)

    def schedule_router(self, context, router):
        if self.router_scheduler:
            return self.router_scheduler.schedule(
                self, context, router)

    def schedule_routers(self, context, routers):
        """Schedule the routers to l3 agents."""
        for router in routers:
            self.schedule_router(context, router)


class DhcpAgentSchedulerDbMixin(dhcpagentscheduler
                                .DhcpAgentSchedulerPluginBase,
                                AgentSchedulerDbMixin):
    """Mixin class to add DHCP agent scheduler extension to db_plugin_base_v2.
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
        if self.dhcp_agent_notifier:
            self.dhcp_agent_notifier.network_added_to_agent(
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
            context.session.delete(binding)
        if self.dhcp_agent_notifier:
            self.dhcp_agent_notifier.network_removed_from_agent(
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
        agent = self._get_agent_by_type_and_host(
            context, constants.AGENT_TYPE_DHCP, host)
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
            chosen_agent = self.network_scheduler.schedule(
                self, context, created_network)
            if not chosen_agent:
                LOG.warn(_('Fail scheduling network %s'), created_network)
            return chosen_agent

    def auto_schedule_networks(self, context, host):
        if self.network_scheduler:
            self.network_scheduler.auto_schedule_networks(self, context, host)
