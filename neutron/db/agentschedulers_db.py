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

import collections
import datetime
import secrets
import time

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context as ncontext
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import agent as agent_exc
from neutron_lib.exceptions import dhcpagentscheduler as das_exc
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import timeutils
from sqlalchemy.orm import exc

from neutron.agent.common import utils as agent_utils
from neutron.common import utils
from neutron.conf.agent.database import agentschedulers_db
from neutron.db import agents_db
from neutron.db.availability_zone import network as network_az
from neutron.extensions import dhcpagentscheduler
from neutron.objects import network
from neutron.objects import subnet as subnet_obj
from neutron import worker as neutron_worker


LOG = logging.getLogger(__name__)


agentschedulers_db.register_db_agentschedulers_opts()


class AgentSchedulerDbMixin(agents_db.AgentDbMixin):
    """Common class for agent scheduler mixins."""

    # agent notifiers to handle agent update operations;
    # should be updated by plugins;
    agent_notifiers = {
        constants.AGENT_TYPE_DHCP: None,
        constants.AGENT_TYPE_L3: None,
    }

    @staticmethod
    def is_eligible_agent(active, agent):
        if active is None:
            # filtering by activeness is disabled, all agents are eligible
            return True
        # note(rpodolyaka): original behaviour is saved here: if active
        #                   filter is set, only agents which are 'up'
        #                   (i.e. have a recent heartbeat timestamp)
        #                   are eligible, even if active is False
        if agent_utils.is_agent_down(agent['heartbeat_timestamp']):
            LOG.warning('Agent %(agent)s is down. Type: %(type)s, host: '
                        '%(host)s, heartbeat: %(heartbeat)s',
                        {'agent': agent['id'], 'type': agent['agent_type'],
                         'host': agent['host'],
                         'heartbeat': agent['heartbeat_timestamp']})
            return False
        return True

    def update_agent(self, context, id, agent):
        original_agent = self.get_agent(context, id)
        result = super().update_agent(
            context, id, agent)
        agent_data = agent['agent']
        agent_notifier = self.agent_notifiers.get(original_agent['agent_type'])
        if (agent_notifier and
                'admin_state_up' in agent_data and
                original_agent['admin_state_up'] !=
                agent_data['admin_state_up']):
            agent_notifier.agent_updated(context,
                                         agent_data['admin_state_up'],
                                         original_agent['host'])
        return result

    def add_agent_status_check_worker(self, function):
        # TODO(enikanorov): make interval configurable rather than computed
        interval = max(cfg.CONF.agent_down_time // 2, 1)
        # add random initial delay to allow agents to check in after the
        # neutron server first starts. random to offset multiple servers
        initial_delay = secrets.SystemRandom().randint(interval, interval * 2)

        check_worker = neutron_worker.PeriodicWorker(function, interval,
                                                     initial_delay)
        self.add_worker(check_worker)

    def agent_dead_limit_seconds(self):
        return cfg.CONF.agent_down_time * 2

    def wait_down_agents(self, agent_type, agent_dead_limit):
        """Gives chance for agents to send a heartbeat."""
        # check for an abrupt clock change since last check. if a change is
        # detected, sleep for a while to let the agents check in.
        tdelta = timeutils.utcnow() - getattr(self, '_clock_jump_canary',
                                              timeutils.utcnow())
        if tdelta.total_seconds() > cfg.CONF.agent_down_time:
            LOG.warning("Time since last %s agent reschedule check has "
                        "exceeded the interval between checks. Waiting "
                        "before check to allow agents to send a heartbeat "
                        "in case there was a clock adjustment.",
                        agent_type)
            time.sleep(agent_dead_limit)
        self._clock_jump_canary = timeutils.utcnow()

    def get_cutoff_time(self, agent_dead_limit):
        cutoff = timeutils.utcnow() - datetime.timedelta(
            seconds=agent_dead_limit)
        return cutoff

    def reschedule_resources_from_down_agents(self, agent_type,
                                              get_down_bindings,
                                              agent_id_attr,
                                              resource_id_attr,
                                              resource_name,
                                              reschedule_resource,
                                              rescheduling_failed):
        """Reschedule resources from down neutron agents
        if admin state is up.
        """
        agent_dead_limit = self.agent_dead_limit_seconds()
        self.wait_down_agents(agent_type, agent_dead_limit)

        context = ncontext.get_admin_context()
        try:
            down_bindings = get_down_bindings(context, agent_dead_limit)

            agents_back_online = set()
            for binding in down_bindings:
                binding_agent_id = getattr(binding, agent_id_attr)
                binding_resource_id = getattr(binding, resource_id_attr)
                if binding_agent_id in agents_back_online:
                    continue
                # we need new context to make sure we use different DB
                # transaction - otherwise we may fetch same agent record
                # each time due to REPEATABLE_READ isolation level
                context = ncontext.get_admin_context()
                agent = self._get_agent(context, binding_agent_id)
                if agent.is_active:
                    agents_back_online.add(binding_agent_id)
                    continue

                LOG.warning(
                    "Rescheduling %(resource_name)s %(resource)s from agent "
                    "%(agent)s because the agent did not report to the server "
                    "in the last %(dead_time)s seconds.",
                    {'resource_name': resource_name,
                     'resource': binding_resource_id,
                     'agent': binding_agent_id,
                     'dead_time': agent_dead_limit})
                try:
                    reschedule_resource(context, binding_resource_id)
                except (rescheduling_failed, oslo_messaging.RemoteError):
                    # Catch individual rescheduling errors here
                    # so one broken one doesn't stop the iteration.
                    LOG.exception("Failed to reschedule %(resource_name)s "
                                  "%(resource)s",
                                  {'resource_name': resource_name,
                                   'resource': binding_resource_id})
        except Exception:
            # we want to be thorough and catch whatever is raised
            # to avoid loop abortion
            LOG.exception("Exception encountered during %(resource_name)s "
                          "rescheduling.",
                          {'resource_name': resource_name})


class DhcpAgentSchedulerDbMixin(dhcpagentscheduler
                                .DhcpAgentSchedulerPluginBase,
                                AgentSchedulerDbMixin):
    """Mixin class to add DHCP agent scheduler extension to db_base_plugin_v2.
    """

    network_scheduler = None

    def add_periodic_dhcp_agent_status_check(self):
        if not cfg.CONF.allow_automatic_dhcp_failover:
            LOG.info("Skipping periodic DHCP agent status check because "
                     "automatic network rescheduling is disabled.")
            return

        self.add_agent_status_check_worker(
            self.remove_networks_from_down_agents
        )

    def is_eligible_agent(self, context, active, agent):
        # eligible agent is active or starting up
        return (AgentSchedulerDbMixin.is_eligible_agent(active, agent) or
                self.agent_starting_up(context, agent))

    def agent_starting_up(self, context, agent):
        """Check if agent was just started.

        Method returns True if agent is in its 'starting up' period.
        Return value depends on amount of networks assigned to the agent.
        It doesn't look at latest heartbeat timestamp as it is assumed
        that this method is called for agents that are considered dead.
        """
        agent_dead_limit = datetime.timedelta(
            seconds=self.agent_dead_limit_seconds())
        network_count = network.NetworkDhcpAgentBinding.count(
            context, dhcp_agent_id=agent['id'])
        # amount of networks assigned to agent affect amount of time we give
        # it so startup. Tests show that it's more or less sage to assume
        # that DHCP agent processes each network in less than 2 seconds.
        # So, give it this additional time for each of the networks.
        additional_time = datetime.timedelta(seconds=2 * network_count)
        LOG.debug("Checking if agent starts up and giving it additional %s",
                  additional_time)
        agent_expected_up = (agent['started_at'] + agent_dead_limit +
                             additional_time)
        return agent_expected_up > timeutils.utcnow()

    def _schedule_network(self, context, network_id, dhcp_notifier,
                          candidate_hosts=None):
        LOG.info("Scheduling unhosted network %s", network_id)
        try:
            # TODO(enikanorov): have to issue redundant db query
            # to satisfy scheduling interface
            network = self.get_network(context, network_id)
            if candidate_hosts:
                network['candidate_hosts'] = candidate_hosts
            agents = self.schedule_network(context, network)
            if not agents:
                LOG.info("Failed to schedule network %s, "
                         "no eligible agents or it might be "
                         "already scheduled by another server",
                         network_id)
                return
            if not dhcp_notifier:
                return
            for agent in agents:
                LOG.info("Adding network %(net)s to agent "
                         "%(agent)s on host %(host)s",
                         {'net': network_id,
                          'agent': agent.id,
                          'host': agent.host})
                dhcp_notifier.network_added_to_agent(
                    context, network_id, agent.host)
        except Exception:
            # catching any exception during scheduling
            # so if _schedule_network is invoked in the loop it could
            # continue in any case
            LOG.exception("Failed to schedule network %s", network_id)

    def _filter_bindings(self, context, bindings):
        """Skip bindings for which the agent is dead, but starting up."""

        # to save few db calls: store already checked agents in dict
        # id -> is_agent_starting_up
        checked_agents = {}
        for binding in bindings:
            try:
                agent_id = binding.db_obj.dhcp_agent['id']
                if agent_id not in checked_agents:
                    if self.agent_starting_up(context,
                                              binding.db_obj.dhcp_agent):
                        # When agent starts and it has many networks to process
                        # it may fail to send state reports in defined interval
                        # The server will consider it dead and try to remove
                        # networks from it.
                        checked_agents[agent_id] = True
                        LOG.debug("Agent %s is starting up, skipping",
                                  agent_id)
                    else:
                        checked_agents[agent_id] = False
                if not checked_agents[agent_id]:
                    yield binding
            except exc.ObjectDeletedError:
                # we're not within a transaction, so object can be lost
                # because underlying row is removed, just ignore this issue
                LOG.debug("binding was removed concurrently, skipping it")

    def remove_networks_from_down_agents(self):
        """Remove networks from down DHCP agents if admin state is up.

        Reschedule them if configured so.
        """

        agent_dead_limit = self.agent_dead_limit_seconds()
        self.wait_down_agents('DHCP', agent_dead_limit)
        cutoff = self.get_cutoff_time(agent_dead_limit)

        context = ncontext.get_admin_context()
        try:
            down_bindings = network.NetworkDhcpAgentBinding.get_down_bindings(
                context, cutoff)
            dhcp_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_DHCP)
            dead_bindings = list(self._filter_bindings(context, down_bindings))
            agents = self.get_agent_objects(
                context, {'agent_type': [constants.AGENT_TYPE_DHCP]})
            if not agents:
                # No agents configured so nothing to do.
                return
            active_agents = [agent for agent in agents if
                             self.is_eligible_agent(context, True, agent)]
            if not active_agents:
                LOG.warning("No DHCP agents available, "
                            "skipping rescheduling")
                return
            for binding in dead_bindings:
                LOG.warning("Removing network %(network)s from agent "
                            "%(agent)s because the agent did not report "
                            "to the server in the last %(dead_time)s "
                            "seconds.",
                            {'network': binding.network_id,
                             'agent': binding.dhcp_agent_id,
                             'dead_time': agent_dead_limit})
                # save binding object to avoid ObjectDeletedError
                # in case binding is concurrently deleted from the DB
                saved_binding = {'net': binding.network_id,
                                 'agent': binding.dhcp_agent_id}
                try:
                    # do not notify agent if it considered dead
                    # so when it is restarted it won't see network delete
                    # notifications on its queue
                    self.remove_network_from_dhcp_agent(context,
                                                        binding.dhcp_agent_id,
                                                        binding.network_id,
                                                        notify=False)
                except das_exc.NetworkNotHostedByDhcpAgent:
                    # measures against concurrent operation
                    LOG.debug("Network %(net)s already removed from DHCP "
                              "agent %(agent)s",
                              saved_binding)
                    # still continue and allow concurrent scheduling attempt
                except Exception:
                    LOG.exception("Unexpected exception occurred while "
                                  "removing network %(net)s from agent "
                                  "%(agent)s",
                                  saved_binding)

                if cfg.CONF.network_auto_schedule:
                    self._schedule_network(
                        context, saved_binding['net'], dhcp_notifier)
        except Exception:
            # we want to be thorough and catch whatever is raised
            # to avoid loop abortion
            LOG.exception("Exception encountered during network "
                          "rescheduling")

    def get_dhcp_agents_hosting_networks(
            self, context, network_ids, active=None, admin_state_up=None,
            hosts=None):
        if not network_ids:
            return []
        # get all the NDAB objects, which will also fetch (from DB)
        # the related dhcp_agent objects because of the synthetic field
        bindings = network.NetworkDhcpAgentBinding.get_objects(
            context, network_id=network_ids)
        # get the already fetched dhcp_agent objects
        agent_objs = [binding.db_obj.dhcp_agent for binding in bindings]
        # filter the dhcp_agent objects on admin_state_up
        if admin_state_up is not None:
            agent_objs = [agent for agent in agent_objs
                          if agent.admin_state_up == admin_state_up]
        # filter the dhcp_agent objects on hosts
        if hosts:
            agent_objs = [agent for agent in agent_objs
                          if agent.host in hosts]
        # finally filter if the agents are eligible
        return [agent for agent in agent_objs
                if self.is_eligible_agent(context, active, agent)]

    def add_network_to_dhcp_agent(self, context, id, network_id):
        self._get_network(context, network_id)
        with db_api.CONTEXT_WRITER.using(context):
            agent_db = self._get_agent(context, id)
            if (agent_db['agent_type'] != constants.AGENT_TYPE_DHCP or
                    not services_available(agent_db['admin_state_up'])):
                raise das_exc.InvalidDHCPAgent(id=id)
            dhcp_agents = self.get_dhcp_agents_hosting_networks(
                context, [network_id])
            for dhcp_agent in dhcp_agents:
                if id == dhcp_agent.id:
                    raise das_exc.NetworkHostedByDHCPAgent(
                        network_id=network_id, agent_id=id)
            self.network_scheduler.resource_filter.bind(
                context, [agent_db], network_id, force_scheduling=True)
        dhcp_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_DHCP)
        if dhcp_notifier:
            dhcp_notifier.network_added_to_agent(
                context, network_id, agent_db.host)

    def remove_network_from_dhcp_agent(self, context, id, network_id,
                                       notify=True):
        agent = self._get_agent(context, id)
        deleted_bindings = network.NetworkDhcpAgentBinding.delete_objects(
            context, network_id=network_id, dhcp_agent_id=id)
        if not deleted_bindings:
            raise das_exc.NetworkNotHostedByDhcpAgent(
                network_id=network_id, agent_id=id)

        # reserve the port, so the ip is reused on a subsequent add
        device_id = utils.get_dhcp_agent_device_id(network_id,
                                                   agent['host'])
        filters = dict(device_id=[device_id])
        ports = self.get_ports(context, filters=filters)
        # NOTE(kevinbenton): there should only ever be one port per
        # DHCP agent per network so we don't have to worry about one
        # update_port passing and another failing
        for port in ports:
            port['device_id'] = constants.DEVICE_ID_RESERVED_DHCP_PORT
            try:
                self.update_port(context, port['id'], dict(port=port))
            except n_exc.PortNotFound:
                LOG.debug("DHCP port %s has been deleted concurrently",
                          port['id'])

        if not notify:
            return
        dhcp_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_DHCP)
        if dhcp_notifier:
            dhcp_notifier.network_removed_from_agent(
                context, network_id, agent.host)

    def list_networks_on_dhcp_agent(self, context, id):
        objs = network.NetworkDhcpAgentBinding.get_objects(context,
                                                           dhcp_agent_id=id)
        net_ids = [item.network_id for item in objs]
        if net_ids:
            return {'networks':
                    self.get_networks(context, filters={'id': net_ids})}
        # Exception will be thrown if the requested agent does not exist.
        self._get_agent(context, id)
        return {'networks': []}

    def list_active_networks_on_active_dhcp_agent(self, context, host):
        try:
            agent = self._get_agent_by_type_and_host(
                context, constants.AGENT_TYPE_DHCP, host)
        except agent_exc.AgentNotFoundByTypeHost:
            LOG.debug("DHCP Agent not found on host %s", host)
            return []

        if not services_available(agent.admin_state_up):
            return []

        query = network.NetworkDhcpAgentBinding.get_objects(
            context, dhcp_agent_id=agent.id)

        net_ids = [item.network_id for item in query]
        if net_ids:
            return network.Network.get_objects(context, id=net_ids,
                                               admin_state_up=[True])
        return []

    def list_dhcp_agents_hosting_network(self, context, network_id):
        dhcp_agents = self.get_dhcp_agents_hosting_networks(
            context, [network_id])
        agent_ids = [dhcp_agent.id for dhcp_agent in dhcp_agents]
        if agent_ids:
            return {
                'agents': self.get_agents(context, filters={'id': agent_ids})}
        return {'agents': []}

    def schedule_network(self, context, created_network):
        if self.network_scheduler and cfg.CONF.network_auto_schedule:
            return self.network_scheduler.schedule(
                self, context, created_network)

    def auto_schedule_networks(self, context, host):
        if self.network_scheduler:
            self.network_scheduler.auto_schedule_networks(self, context, host)

    @registry.receives(resources.SEGMENT_HOST_MAPPING, [events.AFTER_CREATE])
    def auto_schedule_new_network_segments(self, resource, event, trigger,
                                           payload=None):
        if not cfg.CONF.network_auto_schedule:
            return
        segment_plugin = directory.get_plugin('segments')
        if not segment_plugin:
            return

        dhcp_notifier = self.agent_notifiers.get(constants.AGENT_TYPE_DHCP)
        segment_ids = payload.metadata.get('current_segment_ids')
        segments = segment_plugin.get_segments(
            payload.context, filters={'id': segment_ids})
        subnets = subnet_obj.Subnet.get_objects(
            payload.context, segment_id=segment_ids)
        network_ids = {s.network_id for s in subnets}

        # pre-compute net-id per segments.
        netsegs = collections.defaultdict(list)
        for s in segments:
            if 'network_id' in s:
                netsegs[s['network_id']].append(s)
        for network_id in network_ids:
            for segment in netsegs.get(network_id, []):
                self._schedule_network(
                    payload.context, network_id, dhcp_notifier,
                    candidate_hosts=segment['hosts'])


class AZDhcpAgentSchedulerDbMixin(DhcpAgentSchedulerDbMixin,
                                  network_az.NetworkAvailabilityZoneMixin):
    """Mixin class to add availability_zone supported DHCP agent scheduler."""

    def get_network_availability_zones(self, network):
        zones = {agent.availability_zone for agent in network.dhcp_agents}
        return list(zones)


# helper functions for readability.
def services_available(admin_state_up):
    if cfg.CONF.enable_services_on_agents_with_admin_state_down:
        # Services are available regardless admin_state_up
        return True
    return admin_state_up


def get_admin_state_up_filter():
    if cfg.CONF.enable_services_on_agents_with_admin_state_down:
        # Avoid filtering on admin_state_up at all
        return None
    # Filters on admin_state_up is True
    return True
