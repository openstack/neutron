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

from neutron_lib import constants
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
import oslo_messaging
import six
import sqlalchemy as sa
from sqlalchemy import func
from sqlalchemy import or_
from sqlalchemy import orm
from sqlalchemy.orm import joinedload
from sqlalchemy import sql

from neutron._i18n import _, _LE, _LI, _LW
from neutron.common import constants as n_const
from neutron.common import utils as n_utils
from neutron import context as n_ctx
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import l3_attrs_db
from neutron.db import model_base
from neutron.extensions import l3agentscheduler
from neutron.extensions import router_availability_zone as router_az
from neutron import manager
from neutron.plugins.common import constants as service_constants


LOG = logging.getLogger(__name__)

L3_AGENTS_SCHEDULER_OPTS = [
    cfg.StrOpt('router_scheduler_driver',
               default='neutron.scheduler.l3_agent_scheduler.'
                       'LeastRoutersScheduler',
               help=_('Driver to use for scheduling '
                      'router to a default L3 agent')),
    cfg.BoolOpt('router_auto_schedule', default=True,
                help=_('Allow auto scheduling of routers to L3 agent.')),
    cfg.BoolOpt('allow_automatic_l3agent_failover', default=False,
                help=_('Automatically reschedule routers from offline L3 '
                       'agents to online L3 agents.')),
]

cfg.CONF.register_opts(L3_AGENTS_SCHEDULER_OPTS)


class RouterL3AgentBinding(model_base.BASEV2):
    """Represents binding between neutron routers and L3 agents."""

    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey("routers.id", ondelete='CASCADE'),
                          primary_key=True)
    l3_agent = orm.relation(agents_db.Agent)
    l3_agent_id = sa.Column(sa.String(36),
                            sa.ForeignKey("agents.id", ondelete='CASCADE'),
                            primary_key=True)


class L3AgentSchedulerDbMixin(l3agentscheduler.L3AgentSchedulerPluginBase,
                              agentschedulers_db.AgentSchedulerDbMixin):
    """Mixin class to add l3 agent scheduler extension to plugins
    using the l3 agent for routing.
    """

    router_scheduler = None

    def start_periodic_l3_agent_status_check(self):
        if not cfg.CONF.allow_automatic_l3agent_failover:
            LOG.info(_LI("Skipping period L3 agent status check because "
                         "automatic router rescheduling is disabled."))
            return

        self.add_agent_status_check(
            self.reschedule_routers_from_down_agents)

    def reschedule_routers_from_down_agents(self):
        """Reschedule routers from down l3 agents if admin state is up."""
        agent_dead_limit = self.agent_dead_limit_seconds()
        self.wait_down_agents('L3', agent_dead_limit)
        cutoff = self.get_cutoff_time(agent_dead_limit)

        context = n_ctx.get_admin_context()
        try:
            down_bindings = (
                context.session.query(RouterL3AgentBinding).
                join(agents_db.Agent).
                filter(agents_db.Agent.heartbeat_timestamp < cutoff,
                       agents_db.Agent.admin_state_up).
                outerjoin(l3_attrs_db.RouterExtraAttributes,
                          l3_attrs_db.RouterExtraAttributes.router_id ==
                          RouterL3AgentBinding.router_id).
                filter(sa.or_(l3_attrs_db.RouterExtraAttributes.ha ==
                              sql.false(),
                              l3_attrs_db.RouterExtraAttributes.ha ==
                              sql.null())))

            agents_back_online = set()
            for binding in down_bindings:
                if binding.l3_agent_id in agents_back_online:
                    continue
                else:
                    # we need new context to make sure we use different DB
                    # transaction - otherwise we may fetch same agent record
                    # each time due to REPEATABLE_READ isolation level
                    context = n_ctx.get_admin_context()
                    agent = self._get_agent(context, binding.l3_agent_id)
                    if agent.is_active:
                        agents_back_online.add(binding.l3_agent_id)
                        continue

                LOG.warning(_LW(
                    "Rescheduling router %(router)s from agent %(agent)s "
                    "because the agent did not report to the server in "
                    "the last %(dead_time)s seconds."),
                    {'router': binding.router_id,
                     'agent': binding.l3_agent_id,
                     'dead_time': agent_dead_limit})
                try:
                    self.reschedule_router(context, binding.router_id)
                except (l3agentscheduler.RouterReschedulingFailed,
                        oslo_messaging.RemoteError):
                    # Catch individual router rescheduling errors here
                    # so one broken one doesn't stop the iteration.
                    LOG.exception(_LE("Failed to reschedule router %s"),
                                  binding.router_id)
        except Exception:
            # we want to be thorough and catch whatever is raised
            # to avoid loop abortion
            LOG.exception(_LE("Exception encountered during router "
                              "rescheduling."))

    def _get_agent_mode(self, agent_db):
        agent_conf = self.get_configuration_dict(agent_db)
        return agent_conf.get(n_const.L3_AGENT_MODE,
                              n_const.L3_AGENT_MODE_LEGACY)

    def validate_agent_router_combination(self, context, agent, router):
        """Validate if the router can be correctly assigned to the agent.

        :raises: RouterL3AgentMismatch if attempting to assign DVR router
          to legacy agent.
        :raises: InvalidL3Agent if attempting to assign router to an
          unsuitable agent (disabled, type != L3, incompatible configuration)
        :raises: DVRL3CannotAssignToDvrAgent if attempting to assign a
          router to an agent in 'dvr' mode.
        """
        if agent['agent_type'] != constants.AGENT_TYPE_L3:
            raise l3agentscheduler.InvalidL3Agent(id=agent['id'])

        agent_mode = self._get_agent_mode(agent)

        if agent_mode == n_const.L3_AGENT_MODE_DVR:
            raise l3agentscheduler.DVRL3CannotAssignToDvrAgent()

        if (agent_mode == n_const.L3_AGENT_MODE_LEGACY and
            router.get('distributed')):
            raise l3agentscheduler.RouterL3AgentMismatch(
                router_id=router['id'], agent_id=agent['id'])

        is_suitable_agent = (
            agentschedulers_db.services_available(agent['admin_state_up']) and
            self.get_l3_agent_candidates(context, router,
                                         [agent],
                                         ignore_admin_state=True))
        if not is_suitable_agent:
            raise l3agentscheduler.InvalidL3Agent(id=agent['id'])

    def check_agent_router_scheduling_needed(self, context, agent, router):
        """Check if the router scheduling is needed.

        :raises: RouterHostedByL3Agent if router is already assigned
          to a different agent.
        :returns: True if scheduling is needed, otherwise False
        """
        router_id = router['id']
        agent_id = agent['id']
        query = context.session.query(RouterL3AgentBinding)
        bindings = query.filter_by(router_id=router_id).all()
        if not bindings:
            return True
        for binding in bindings:
            if binding.l3_agent_id == agent_id:
                # router already bound to the agent we need
                return False
        if router.get('ha'):
            return True
        # legacy router case: router is already bound to some agent
        raise l3agentscheduler.RouterHostedByL3Agent(
            router_id=router_id,
            agent_id=bindings[0].l3_agent_id)

    def create_router_to_agent_binding(self, context, agent, router):
        """Create router to agent binding."""
        router_id = router['id']
        agent_id = agent['id']
        if self.router_scheduler:
            try:
                if router.get('ha'):
                    plugin = manager.NeutronManager.get_service_plugins().get(
                        service_constants.L3_ROUTER_NAT)
                    self.router_scheduler.create_ha_port_and_bind(
                        plugin, context, router['id'],
                        router['tenant_id'], agent)
                else:
                    self.router_scheduler.bind_router(
                        context, router_id, agent)
            except db_exc.DBError:
                raise l3agentscheduler.RouterSchedulingFailed(
                    router_id=router_id, agent_id=agent_id)

    def add_router_to_l3_agent(self, context, agent_id, router_id):
        """Add a l3 agent to host a router."""
        with context.session.begin(subtransactions=True):
            router = self.get_router(context, router_id)
            agent = self._get_agent(context, agent_id)
            self.validate_agent_router_combination(context, agent, router)
            if not self.check_agent_router_scheduling_needed(
                    context, agent, router):
                return
        self.create_router_to_agent_binding(context, agent, router)

        l3_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_L3)
        if l3_notifier:
            l3_notifier.router_added_to_agent(
                context, [router_id], agent.host)

    def remove_router_from_l3_agent(self, context, agent_id, router_id):
        """Remove the router from l3 agent.

        After removal, the router will be non-hosted until there is update
        which leads to re-schedule or be added to another agent manually.
        """
        agent = self._get_agent(context, agent_id)
        agent_mode = self._get_agent_mode(agent)
        if agent_mode == n_const.L3_AGENT_MODE_DVR:
            raise l3agentscheduler.DVRL3CannotRemoveFromDvrAgent()

        self._unbind_router(context, router_id, agent_id)

        router = self.get_router(context, router_id)
        plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        if router.get('ha'):
            plugin.delete_ha_interfaces_on_host(context, router_id, agent.host)
        # NOTE(Swami): Need to verify if there are DVR serviceable
        # ports owned by this agent. If owned by this agent, then
        # the routers should be retained. This flag will be used
        # to check if there are valid routers in this agent.
        retain_router = False
        if router.get('distributed'):
            subnet_ids = plugin.get_subnet_ids_on_router(context, router_id)
            if subnet_ids and agent.host:
                retain_router = plugin._check_dvr_serviceable_ports_on_host(
                    context, agent.host, subnet_ids)
        l3_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_L3)
        if retain_router and l3_notifier:
            l3_notifier.routers_updated_on_host(
                context, [router_id], agent.host)
        elif l3_notifier:
            l3_notifier.router_removed_from_agent(
                context, router_id, agent.host)

    def _unbind_router(self, context, router_id, agent_id):
        with context.session.begin(subtransactions=True):
            query = context.session.query(RouterL3AgentBinding)
            query = query.filter(
                RouterL3AgentBinding.router_id == router_id,
                RouterL3AgentBinding.l3_agent_id == agent_id)
            query.delete()

    def _unschedule_router(self, context, router_id, agents_ids):
        with context.session.begin(subtransactions=True):
            for agent_id in agents_ids:
                self._unbind_router(context, router_id, agent_id)

    def reschedule_router(self, context, router_id, candidates=None):
        """Reschedule router to (a) new l3 agent(s)

        Remove the router from the agent(s) currently hosting it and
        schedule it again
        """
        cur_agents = self.list_l3_agents_hosting_router(
            context, router_id)['agents']
        with context.session.begin(subtransactions=True):
            cur_agents_ids = [agent['id'] for agent in cur_agents]
            self._unschedule_router(context, router_id, cur_agents_ids)

            self.schedule_router(context, router_id, candidates=candidates)
            new_agents = self.list_l3_agents_hosting_router(
                context, router_id)['agents']
            if not new_agents:
                raise l3agentscheduler.RouterReschedulingFailed(
                    router_id=router_id)

        self._notify_agents_router_rescheduled(context, router_id,
                                               cur_agents, new_agents)

    def _notify_agents_router_rescheduled(self, context, router_id,
                                          old_agents, new_agents):
        l3_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_L3)
        if not l3_notifier:
            return

        old_hosts = [agent['host'] for agent in old_agents]
        new_hosts = [agent['host'] for agent in new_agents]
        for host in set(old_hosts) - set(new_hosts):
            l3_notifier.router_removed_from_agent(
                context, router_id, host)

        for agent in new_agents:
            try:
                l3_notifier.router_added_to_agent(
                    context, [router_id], agent['host'])
            except oslo_messaging.MessagingException:
                self._unbind_router(context, router_id, agent['id'])
                raise l3agentscheduler.RouterReschedulingFailed(
                    router_id=router_id)

    def list_routers_on_l3_agent(self, context, agent_id):
        query = context.session.query(RouterL3AgentBinding.router_id)
        query = query.filter(RouterL3AgentBinding.l3_agent_id == agent_id)

        router_ids = [item[0] for item in query]
        if router_ids:
            return {'routers':
                    self.get_routers(context, filters={'id': router_ids})}
        else:
            # Exception will be thrown if the requested agent does not exist.
            self._get_agent(context, agent_id)
            return {'routers': []}

    def _get_active_l3_agent_routers_sync_data(self, context, host, agent,
                                               router_ids):
        if n_utils.is_extension_supported(self,
                                          constants.L3_HA_MODE_EXT_ALIAS):
            routers = self.get_ha_sync_data_for_host(context, host, agent,
                                                     router_ids=router_ids,
                                                     active=True)
        else:
            routers = self.get_sync_data(context, router_ids=router_ids,
                                         active=True)
        return self.filter_allocating_and_missing_routers(context, routers)

    def list_router_ids_on_host(self, context, host, router_ids=None):
        agent = self._get_agent_by_type_and_host(
            context, constants.AGENT_TYPE_L3, host)
        if not agentschedulers_db.services_available(agent.admin_state_up):
            return []
        return self._get_router_ids_for_agent(context, agent, router_ids)

    def _get_router_ids_for_agent(self, context, agent, router_ids):
        """Get IDs of routers that the agent should host

        Overridden for DVR to handle agents in 'dvr' mode which have
        no explicit bindings with routers
        """
        query = context.session.query(RouterL3AgentBinding.router_id)
        query = query.filter(
            RouterL3AgentBinding.l3_agent_id == agent.id)

        if router_ids:
            query = query.filter(
                RouterL3AgentBinding.router_id.in_(router_ids))

        return [item[0] for item in query]

    def list_active_sync_routers_on_active_l3_agent(
            self, context, host, router_ids):
        agent = self._get_agent_by_type_and_host(
            context, constants.AGENT_TYPE_L3, host)
        if not agentschedulers_db.services_available(agent.admin_state_up):
            LOG.info(_LI("Agent has its services disabled. Returning "
                         "no active routers. Agent: %s"), agent)
            return []
        scheduled_router_ids = self._get_router_ids_for_agent(
            context, agent, router_ids)
        diff = set(router_ids or []) - set(scheduled_router_ids or [])
        if diff:
            LOG.debug("Agent requested router IDs not scheduled to it. "
                      "Scheduled: %(sched)s. Unscheduled: %(diff)s. "
                      "Agent: %(agent)s.",
                      {'sched': scheduled_router_ids, 'diff': diff,
                       'agent': agent})
        if scheduled_router_ids:
            return self._get_active_l3_agent_routers_sync_data(
                context, host, agent, scheduled_router_ids)
        return []

    def get_l3_agents_hosting_routers(self, context, router_ids,
                                      admin_state_up=None,
                                      active=None):
        if not router_ids:
            return []
        query = context.session.query(RouterL3AgentBinding)
        query = query.options(orm.contains_eager(
                              RouterL3AgentBinding.l3_agent))
        query = query.join(RouterL3AgentBinding.l3_agent)
        query = query.filter(RouterL3AgentBinding.router_id.in_(router_ids))
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
        query = query.options(joinedload('l3_agent')).filter(
            RouterL3AgentBinding.router_id.in_(router_ids))
        return query.all()

    def list_l3_agents_hosting_router(self, context, router_id):
        with context.session.begin(subtransactions=True):
            bindings = self._get_l3_bindings_hosting_routers(
                context, [router_id])

        return {'agents': [self._make_agent_dict(binding.l3_agent) for
                           binding in bindings]}

    def get_l3_agents(self, context, active=None, filters=None):
        query = context.session.query(agents_db.Agent)
        query = query.filter(
            agents_db.Agent.agent_type == constants.AGENT_TYPE_L3)
        if active is not None:
            query = (query.filter(agents_db.Agent.admin_state_up == active))
        if filters:
            for key, value in six.iteritems(filters):
                column = getattr(agents_db.Agent, key, None)
                if column:
                    if not value:
                        return []
                    query = query.filter(column.in_(value))

            agent_modes = filters.get('agent_modes', [])
            if agent_modes:
                agent_mode_key = '\"agent_mode\": \"'
                configuration_filter = (
                    [agents_db.Agent.configurations.contains('%s%s\"' %
                     (agent_mode_key, agent_mode))
                     for agent_mode in agent_modes])
                query = query.filter(or_(*configuration_filter))

        return [l3_agent
                for l3_agent in query
                if agentschedulers_db.AgentSchedulerDbMixin.is_eligible_agent(
                    active, l3_agent)]

    def get_l3_agent_candidates(self, context, sync_router, l3_agents,
                                ignore_admin_state=False):
        """Get the valid l3 agents for the router from a list of l3_agents.

        It will not return agents in 'dvr' mode for a dvr router as dvr
        routers are not explicitly scheduled to l3 agents on compute nodes
        """
        candidates = []
        is_router_distributed = sync_router.get('distributed', False)
        for l3_agent in l3_agents:
            if not ignore_admin_state and not l3_agent.admin_state_up:
                # ignore_admin_state True comes from manual scheduling
                # where admin_state_up judgement is already done.
                continue

            agent_conf = self.get_configuration_dict(l3_agent)
            agent_mode = agent_conf.get(n_const.L3_AGENT_MODE,
                                        n_const.L3_AGENT_MODE_LEGACY)
            if (agent_mode == n_const.L3_AGENT_MODE_DVR or
                    (agent_mode == n_const.L3_AGENT_MODE_LEGACY and
                     is_router_distributed)):
                continue

            router_id = agent_conf.get('router_id', None)
            if router_id and router_id != sync_router['id']:
                continue

            handle_internal_only_routers = agent_conf.get(
                'handle_internal_only_routers', True)
            gateway_external_network_id = agent_conf.get(
                'gateway_external_network_id', None)

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

    def schedule_router(self, context, router, candidates=None):
        if self.router_scheduler:
            return self.router_scheduler.schedule(
                self, context, router, candidates=candidates)

    def schedule_routers(self, context, routers):
        """Schedule the routers to l3 agents."""
        for router in routers:
            self.schedule_router(context, router, candidates=None)

    def get_l3_agent_with_min_routers(self, context, agent_ids):
        """Return l3 agent with the least number of routers."""
        if not agent_ids:
            return None
        query = context.session.query(
            agents_db.Agent,
            func.count(
                RouterL3AgentBinding.router_id
            ).label('count')).outerjoin(RouterL3AgentBinding).group_by(
                agents_db.Agent.id,
                RouterL3AgentBinding.l3_agent_id).order_by('count')
        res = query.filter(agents_db.Agent.id.in_(agent_ids)).first()
        return res[0]

    def get_hosts_to_notify(self, context, router_id):
        """Returns all hosts to send notification about router update"""
        state = agentschedulers_db.get_admin_state_up_filter()
        agents = self.get_l3_agents_hosting_routers(
            context, [router_id], admin_state_up=state, active=True)
        return [a.host for a in agents]


class AZL3AgentSchedulerDbMixin(L3AgentSchedulerDbMixin,
                                router_az.RouterAvailabilityZonePluginBase):
    """Mixin class to add availability_zone supported l3 agent scheduler."""

    def get_router_availability_zones(self, router):
        return list({agent.availability_zone for agent in router.l3_agents})
