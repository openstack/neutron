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

from neutron_lib.api import extensions
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib.exceptions import agent as agent_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
import oslo_messaging

from neutron.agent.common import utils as agent_utils
from neutron.common import _constants as n_const
from neutron.conf.db import l3_agentschedulers_db
from neutron.db import agentschedulers_db
from neutron.extensions import l3agentscheduler
from neutron.extensions import router_availability_zone as router_az
from neutron.objects import agent as ag_obj
from neutron.objects import base as base_obj
from neutron.objects import l3agent as rb_obj
from neutron.objects import router as l3_objs
from neutron.scheduler import base_scheduler


LOG = logging.getLogger(__name__)


l3_agentschedulers_db.register_db_l3agentschedulers_opts()


class L3AgentSchedulerDbMixin(l3agentscheduler.L3AgentSchedulerPluginBase,
                              agentschedulers_db.AgentSchedulerDbMixin):
    """Mixin class to add l3 agent scheduler extension to plugins
    using the l3 agent for routing.
    """

    router_scheduler = None

    def add_periodic_l3_agent_status_check(self):
        if not cfg.CONF.allow_automatic_l3agent_failover:
            LOG.info("Skipping period L3 agent status check because "
                     "automatic router rescheduling is disabled.")
            return

        self.add_agent_status_check_worker(
            self.reschedule_routers_from_down_agents)

    def reschedule_routers_from_down_agents(self):
        """Reschedule routers from down l3 agents if admin state is up."""
        self.reschedule_resources_from_down_agents(
                agent_type='L3',
                get_down_bindings=self.get_down_router_bindings,
                agent_id_attr='l3_agent_id',
                resource_id_attr='router_id',
                resource_name='router',
                reschedule_resource=self.reschedule_router,
                rescheduling_failed=l3agentscheduler.RouterReschedulingFailed)

    def get_down_router_bindings(self, context, agent_dead_limit):
        cutoff = self.get_cutoff_time(agent_dead_limit)
        return rb_obj.RouterL3AgentBinding.get_down_router_bindings(
            context, cutoff)

    def _get_agent_mode(self, agent_db):
        agent_conf = self.get_configuration_dict(agent_db)
        return agent_conf.get(constants.L3_AGENT_MODE,
                              constants.L3_AGENT_MODE_LEGACY)

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

        if agent_mode in [constants.L3_AGENT_MODE_DVR,
                          constants.L3_AGENT_MODE_DVR_NO_EXTERNAL]:
            raise l3agentscheduler.DVRL3CannotAssignToDvrAgent()

        if (agent_mode == constants.L3_AGENT_MODE_LEGACY and
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
        bindings = rb_obj.RouterL3AgentBinding.get_objects(context,
                                                           router_id=router_id)
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
            plugin = directory.get_plugin(plugin_constants.L3)
            try:
                if router.get('ha'):
                    self.router_scheduler.create_ha_port_and_bind(
                        plugin, context, router['id'],
                        router['tenant_id'], agent,
                        is_manual_scheduling=True)
                else:
                    self.router_scheduler.bind_router(
                        plugin, context, router_id, agent.id)
            except db_exc.DBError:
                raise l3agentscheduler.RouterSchedulingFailed(
                    router_id=router_id, agent_id=agent_id)

    def add_router_to_l3_agent(self, context, agent_id, router_id):
        """Add a l3 agent to host a router."""
        if not self.router_supports_scheduling(context, router_id):
            raise l3agentscheduler.RouterDoesntSupportScheduling(
                router_id=router_id)
        with db_api.CONTEXT_WRITER.using(context):
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

    def _check_router_retain_needed(self, context, router, host):
        """Check whether a router needs to be retained on a host.

        Check whether there are DVR serviceable ports owned by the host of
        an l3 agent. If so, then the routers should be retained.
        """
        if not host or not router.get('distributed'):
            return False

        plugin = directory.get_plugin(plugin_constants.L3)
        subnet_ids = plugin.get_subnet_ids_on_router(context, router['id'])
        return plugin._check_dvr_serviceable_ports_on_host(context, host,
                                                           subnet_ids)

    def remove_router_from_l3_agent(self, context, agent_id, router_id):
        """Remove the router from l3 agent.

        After removal, the router will be non-hosted until there is update
        which leads to re-schedule or be added to another agent manually.
        """
        agent = self._get_agent(context, agent_id)
        agent_mode = self._get_agent_mode(agent)
        if agent_mode in [constants.L3_AGENT_MODE_DVR,
                          constants.L3_AGENT_MODE_DVR_NO_EXTERNAL]:
            raise l3agentscheduler.DVRL3CannotRemoveFromDvrAgent()

        self._unbind_router(context, router_id, agent_id)
        router = self.get_router(context, router_id)
        if router.get('ha'):
            plugin = directory.get_plugin(plugin_constants.L3)
            plugin.delete_ha_interfaces_on_host(context, router_id, agent.host)

        l3_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_L3)
        if not l3_notifier:
            return
        # NOTE(Swami): Need to verify if there are DVR serviceable
        # ports owned by this agent. If owned by this agent, then
        # the routers should be retained. This flag will be used
        # to check if there are valid routers in this agent.
        retain_router = self._check_router_retain_needed(context, router,
                                                         agent.host)
        if retain_router:
            l3_notifier.routers_updated_on_host(
                context, [router_id], agent.host)
        else:
            l3_notifier.router_removed_from_agent(
                context, router_id, agent.host)

    def _unbind_router(self, context, router_id, agent_id):
        rb_obj.RouterL3AgentBinding.delete_objects(
                context, router_id=router_id, l3_agent_id=agent_id)

    def _unschedule_router(self, context, router_id, agents_ids):
        with db_api.CONTEXT_WRITER.using(context):
            for agent_id in agents_ids:
                self._unbind_router(context, router_id, agent_id)

    def reschedule_router(self, context, router_id, candidates=None):
        """Reschedule router to (a) new l3 agent(s)

        Remove the router from the agent(s) currently hosting it and
        schedule it again
        """
        cur_agents = self.list_l3_agents_hosting_router(
            context, router_id)['agents']
        with db_api.CONTEXT_WRITER.using(context):
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
        router = self.get_router(context, router_id)
        for host in set(old_hosts) - set(new_hosts):
            retain_router = self._check_router_retain_needed(
                context, router, host)
            if retain_router:
                l3_notifier.routers_updated_on_host(
                    context, [router_id], host)
            else:
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
        binding_objs = rb_obj.RouterL3AgentBinding.get_objects(
                context, l3_agent_id=agent_id)

        router_ids = [item.router_id for item in binding_objs]
        if router_ids:
            return {'routers':
                    self.get_routers(context, filters={'id': router_ids})}
        else:
            # Exception will be thrown if the requested agent does not exist.
            self._get_agent(context, agent_id)
            return {'routers': []}

    def _get_active_l3_agent_routers_sync_data(self, context, host, agent,
                                               router_ids):
        if extensions.is_extension_supported(
                self, constants.L3_HA_MODE_EXT_ALIAS):
            return self.get_ha_sync_data_for_host(context, host, agent,
                                                  router_ids=router_ids,
                                                  active=True)

        return self.get_sync_data(context, router_ids=router_ids, active=True)

    def list_router_ids_on_host(self, context, host, router_ids=None,
                                with_dvr=True):
        try:
            agent = self._get_agent_by_type_and_host(
                context, constants.AGENT_TYPE_L3, host)
        except agent_exc.AgentNotFoundByTypeHost:
            return []
        if not agentschedulers_db.services_available(agent.admin_state_up):
            return []
        return self._get_router_ids_for_agent(context, agent,
                                              router_ids, with_dvr)

    def get_host_ha_router_count(self, context, host):
        router_ids = self.list_router_ids_on_host(context, host,
                                                  with_dvr=False)
        up_routers = l3_objs.Router.get_objects(context, id=router_ids,
                                                admin_state_up=True)
        return len(l3_objs.RouterExtraAttributes.get_objects(
            context, router_id=[obj.id for obj in up_routers], ha=True))

    def _get_router_ids_for_agent(self, context, agent, router_ids,
                                  with_dvr=True):
        """Get IDs of routers that the agent should host

        Overridden for DVR to handle agents in 'dvr' mode which have
        no explicit bindings with routers
        """
        filters = {'l3_agent_id': agent.id}
        if router_ids:
            filters['router_id'] = router_ids
        bindings = rb_obj.RouterL3AgentBinding.get_objects(context, **filters)
        return [item.router_id for item in bindings]

    def list_active_sync_routers_on_active_l3_agent(
            self, context, host, router_ids):
        agent = self._get_agent_by_type_and_host(
            context, constants.AGENT_TYPE_L3, host)
        if not agentschedulers_db.services_available(agent.admin_state_up):
            LOG.info("Agent has its services disabled. Returning "
                     "no active routers. Agent: %s", agent)
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
        record_objs = rb_obj.RouterL3AgentBinding.get_objects(
                context, router_id=router_ids)
        if admin_state_up is not None:
            l3_agents = ag_obj.Agent.get_objects(
                context,
                id=[obj.l3_agent_id for obj in record_objs],
                admin_state_up=admin_state_up)
        else:
            l3_agents = [
                ag_obj.Agent.get_object(context, id=obj.l3_agent_id)
                for obj in record_objs
            ]
        if active is not None:
            l3_agents = [l3_agent for l3_agent in
                         l3_agents if not
                         agent_utils.is_agent_down(
                             l3_agent['heartbeat_timestamp'])]
        return l3_agents

    def _get_l3_agents_hosting_routers(self, context, router_ids):
        if not router_ids:
            return []
        return (
            rb_obj.RouterL3AgentBinding.get_l3_agents_by_router_ids(
                context, router_ids))

    @db_api.CONTEXT_READER
    def list_l3_agents_hosting_router(self, context, router_id):
        agents = self._get_l3_agents_hosting_routers(context, [router_id])
        return {'agents': [self._make_agent_dict(agent)
                           for agent in agents]}

    def get_routers_l3_agents_count(self, context):
        """Return a map between routers and agent counts for all routers."""
        # TODO(sshank): This portion needs Router OVO integration when it is
        # merged.
        l3_model_list = l3_objs.RouterExtraAttributes.get_router_agents_count(
            context)
        return [(self._make_router_dict(router_model),
                 agent_count if agent_count else 0)
                for router_model, agent_count in l3_model_list]

    def get_l3_agents(self, context, active=None, filters=None):
        agent_filters = {'agent_type': constants.AGENT_TYPE_L3}
        if active is not None:
            agent_filters['admin_state_up'] = active
        config_filters = []
        if filters:
            for key, value in filters.items():
                column = ag_obj.Agent.fields.get(key, None)
                if column:
                    if not value:
                        return []

            agent_modes = filters.pop('agent_modes', [])
            if agent_modes:
                config_filters = set('\"agent_mode\": \"%s\"' % agent_mode
                                     for agent_mode in agent_modes)
            agent_filters.update(filters)
        agent_objs = []
        if config_filters:
            for conf_filter in config_filters:
                agent_objs.extend(ag_obj.Agent.get_objects_by_agent_mode(
                    context, conf_filter, **agent_filters))
        else:
            agent_objs = ag_obj.Agent.get_objects(context, **agent_filters)
        return [l3_agent
                for l3_agent in agent_objs
                if agentschedulers_db.AgentSchedulerDbMixin.is_eligible_agent(
                    active, l3_agent)]

    def get_l3_agent_candidates(self, context, sync_router, l3_agents,
                                ignore_admin_state=False):
        """Get the valid l3 agents for the router from a list of l3_agents.

        It will not return agents in 'dvr' mode or in 'dvr_no_external' mode
        for a dvr router as dvr routers are not explicitly scheduled to l3
        agents on compute nodes
        """
        candidates = []
        is_router_distributed = sync_router.get('distributed', False)
        for l3_agent in l3_agents:
            if not ignore_admin_state and not l3_agent.admin_state_up:
                # ignore_admin_state True comes from manual scheduling
                # where admin_state_up judgement is already done.
                continue

            agent_conf = self.get_configuration_dict(l3_agent)
            agent_mode = agent_conf.get(constants.L3_AGENT_MODE,
                                        constants.L3_AGENT_MODE_LEGACY)
            if (agent_mode == constants.L3_AGENT_MODE_DVR or
                agent_mode == constants.L3_AGENT_MODE_DVR_NO_EXTERNAL or
                    (agent_mode == constants.L3_AGENT_MODE_LEGACY and
                     is_router_distributed)):
                continue

            router_id = agent_conf.get('router_id', None)
            if router_id and router_id != sync_router['id']:
                continue

            handle_internal_only_routers = agent_conf.get(
                'handle_internal_only_routers', True)

            ex_net_id = (sync_router['external_gateway_info'] or {}).get(
                'network_id')
            if not ex_net_id and not handle_internal_only_routers:
                continue

            candidates.append(l3_agent)
        return candidates

    def auto_schedule_routers(self, context, host):
        if self.router_scheduler:
            self.router_scheduler.auto_schedule_routers(self, context, host)

    def schedule_router(self, context, router, candidates=None):
        if self.router_scheduler:
            return self.router_scheduler.schedule(
                self, context, router, candidates=candidates)

    def schedule_routers(self, context, routers):
        """Schedule the routers to l3 agents."""
        for router in routers:
            self.schedule_router(context, router, candidates=None)

    def get_l3_agent_with_min_routers(self, context, agent_ids):
        if not agent_ids:
            return None
        agents = ag_obj.Agent.get_l3_agent_with_min_routers(
                context, agent_ids)
        return agents

    def get_hosts_to_notify(self, context, router_id):
        """Returns all hosts to send notification about router update"""
        state = agentschedulers_db.get_admin_state_up_filter()
        agents = self.get_l3_agents_hosting_routers(
            context, [router_id], admin_state_up=state, active=True)
        return [a.host for a in agents]

    def get_vacant_binding_index(self, context, router_id,
                                 is_manual_scheduling=False):
        """Return a vacant binding_index to use and whether or not it exists.

        Each RouterL3AgentBinding has a binding_index which is unique per
        router_id, and when creating a single binding we require to find a
        'vacant' binding_index which isn't yet used - for example if we have
        bindings with indices 1 and 3, then clearly binding_index == 2 is free.

        :returns: binding_index.
        """
        num_agents = self.get_number_of_agents_for_scheduling(context)

        pager = base_obj.Pager(sorts=[('binding_index', True)])
        bindings = rb_obj.RouterL3AgentBinding.get_objects(
                context, _pager=pager, router_id=router_id)
        return base_scheduler.get_vacant_binding_index(
            num_agents, bindings, n_const.LOWEST_AGENT_BINDING_INDEX,
            force_scheduling=is_manual_scheduling)


class AZL3AgentSchedulerDbMixin(L3AgentSchedulerDbMixin,
                                router_az.RouterAvailabilityZonePluginBase):
    """Mixin class to add availability_zone supported l3 agent scheduler."""

    def get_router_availability_zones(self, router):
        return list({agent.availability_zone for agent in router.l3_agents})
