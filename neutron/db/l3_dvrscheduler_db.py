#    (c) Copyright 2014 Hewlett-Packard Development Company, L.P.
#    All Rights Reserved.
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

from neutron_lib.api.definitions import portbindings
from neutron_lib.api import extensions
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const
from neutron_lib.db import api as db_api
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from sqlalchemy import or_

from neutron.common import utils as n_utils
from neutron.conf.db import l3_dvr_db as l3_dvr_db_conf
from neutron.db import agentschedulers_db
from neutron.db import l3_agentschedulers_db as l3agent_sch_db
from neutron.db import l3_dvr_db
from neutron.db.models import l3 as l3_models
from neutron.db import models_v2
from neutron.objects import l3agent as rb_obj
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2 import models as ml2_models

LOG = logging.getLogger(__name__)
l3_dvr_db_conf.register_db_l3_dvr_opts()


class L3_DVRsch_db_mixin(l3agent_sch_db.L3AgentSchedulerDbMixin):
    """Mixin class for L3 DVR scheduler.

    DVR currently supports the following use cases:

     - East/West (E/W) traffic between VMs: this is handled in a
       distributed manner across Compute Nodes without a centralized element.
       This includes E/W traffic between VMs on the same Compute Node.
     - North/South traffic for Floating IPs (FIP N/S): this is supported on the
       distributed routers on Compute Nodes when there is external network
       connectivity and on centralized nodes when the port is not bound or when
       the agent is configured as 'dvr_no_external'.
     - North/South traffic for SNAT (SNAT N/S): this is supported via a
       centralized element that handles the SNAT traffic.

    To support these use cases,  DVR routers rely on an L3 agent that runs on a
    central node (also known as Network Node or Service Node),  as well as, L3
    agents that run individually on each Compute Node of an OpenStack cloud.

    Each L3 agent creates namespaces to route traffic according to the use
    cases outlined above.  The mechanism adopted for creating and managing
    these namespaces is via (Router,  Agent) binding and Scheduling in general.

    The main difference between distributed routers and centralized ones is
    that in the distributed case,  multiple bindings will exist,  one for each
    of the agents participating in the routed topology for the specific router.

    These bindings are created in the following circumstances:

    - A subnet is added to a router via router-interface-add, and that subnet
      has running VM's deployed in it.  A binding will be created between the
      router and any L3 agent whose Compute Node is hosting the VM(s).
    - An external gateway is set to a router via router-gateway-set.  A binding
      will be created between the router and the L3 agent running centrally
      on the Network Node.

    Therefore,  any time a router operation occurs (create, update or delete),
    scheduling will determine whether the router needs to be associated to an
    L3 agent, just like a regular centralized router, with the difference that,
    in the distributed case,  the bindings required are established based on
    the state of the router and the Compute Nodes.
    """

    def dvr_handle_new_service_port(self, context, port,
                                    dest_host=None, unbound_migrate=False,
                                    router_id=None):
        """Handle new dvr service port creation.

        When a new dvr service port is created, this function will
        schedule a dvr router to new compute node if needed and notify
        l3 agent on that node.
        The 'dest_host' will provide the destination host of the port in
        case of service port migration.
        If an unbound port migrates and becomes a bound port, send
        notification to the snat_agents and to the bound host.
        """
        port_host = dest_host or port[portbindings.HOST_ID]
        l3_agent_on_host = (self.get_l3_agents(
            context, filters={'host': [port_host]}) or [None])[0]
        if not l3_agent_on_host:
            return

        if dest_host and router_id is not None:
            # Make sure we create the floatingip agent gateway port
            # for the destination node if fip is associated with this
            # fixed port
            l3plugin = directory.get_plugin(plugin_constants.L3)
            router = l3plugin._get_router(context, router_id)
            if l3_dvr_db.is_distributed_router(router):
                (l3plugin.
                 check_for_fip_and_create_agent_gw_port_on_host_if_not_exists(
                     context, port, dest_host))
            else:
                LOG.debug("Port-in-Migration: Floating IP has a non-"
                          "distributed router %(router_id)s",
                          {'router_id': router_id})

        subnet_ids = [ip['subnet_id'] for ip in port['fixed_ips']]
        router_ids = self.get_dvr_routers_by_subnet_ids(context, subnet_ids)
        if not router_ids:
            return
        agent_port_host_match = False
        if unbound_migrate:
            # This might be a case were it is migrating from unbound
            # to a bound port.
            # In that case please forward the notification to the
            # snat_nodes hosting the routers.
            # Make a call here to notify the snat nodes.
            snat_agent_list = self.get_dvr_snat_agent_list(context)
            for agent in snat_agent_list:
                LOG.debug('DVR: Handle new unbound migration port, '
                          'host %(host)s, router_ids %(router_ids)s',
                          {'host': agent.host, 'router_ids': router_ids})
                self.l3_rpc_notifier.routers_updated_on_host(
                    context, router_ids, agent.host)
                if agent.host == port_host:
                    agent_port_host_match = True
        if not agent_port_host_match:
            connected_router_ids = set(router_ids)
            for router_id in router_ids:
                connected_router_ids.update(
                    self._get_other_dvr_router_ids_connected_router(
                        context, router_id))

            LOG.debug('DVR: Handle new service port, host %(host)s, '
                      'router ids %(router_ids)s',
                      {'host': port_host,
                       'router_ids': connected_router_ids})
            self.l3_rpc_notifier.routers_updated_on_host(
                context, connected_router_ids, port_host)

    def get_dvr_snat_agent_list(self, context):
        agent_filters = {'agent_modes': [n_const.L3_AGENT_MODE_DVR_SNAT]}
        state = agentschedulers_db.get_admin_state_up_filter()
        return self.get_l3_agents(context, active=state,
                                  filters=agent_filters)

    def get_dvr_routers_by_subnet_ids(self, context, subnet_ids):
        """Gets the dvr routers on vmport subnets."""
        if not subnet_ids:
            return set()

        router_ids = set()
        filter_sub = {'fixed_ips': {'subnet_id': subnet_ids},
                      'device_owner':
                      [n_const.DEVICE_OWNER_DVR_INTERFACE]}
        subnet_ports = self._core_plugin.get_ports(
            context, filters=filter_sub)
        for subnet_port in subnet_ports:
            router_ids.add(subnet_port['device_id'])
        return router_ids

    def get_subnet_ids_on_router(self, context, router_id,
                                 keep_gateway_port=True):
        """Return subnet IDs for interfaces attached to the given router."""
        subnet_ids = set()
        filter_rtr = {'device_id': [router_id]}
        int_ports = self._core_plugin.get_ports(context, filters=filter_rtr)

        for int_port in int_ports:
            if (not keep_gateway_port and
                    int_port['device_owner'] ==
                    n_const.DEVICE_OWNER_ROUTER_GW):
                continue
            int_ips = int_port['fixed_ips']
            if int_ips:
                int_subnet = int_ips[0]['subnet_id']
                subnet_ids.add(int_subnet)
            else:
                LOG.debug('DVR: Could not find a subnet id '
                          'for router %s', router_id)
        return subnet_ids

    def get_dvr_routers_to_remove(self, context, deleted_port,
                                  get_related_hosts_info=True):
        """Returns info about which routers should be removed

        In case dvr serviceable port was deleted we need to check
        if any dvr routers should be removed from l3 agent on port's host
        """
        if not n_utils.is_dvr_serviced(deleted_port['device_owner']):
            return []

        admin_context = context.elevated()
        port_host = deleted_port.get(portbindings.HOST_ID)
        if not port_host:
            return []

        subnet_ids = [ip['subnet_id'] for ip in deleted_port['fixed_ips']]
        router_ids = self.get_dvr_routers_by_subnet_ids(admin_context,
                                                        subnet_ids)
        if not router_ids:
            LOG.debug('No DVR routers for this DVR port %(port)s '
                      'on host %(host)s', {'port': deleted_port['id'],
                                           'host': port_host})
            return []
        agent = self._get_agent_by_type_and_host(
            context, n_const.AGENT_TYPE_L3, port_host)
        removed_router_info = []
        # NOTE(Swami): If host has any serviceable ports,
        # we should not remove the router namespace of the
        # port as well as the connected routers namespace.
        # After all serviceable ports in the host for the
        # connected routers are deleted, then we can remove
        # the router namespace.
        host_has_serviceable_port = False
        for router_id in router_ids:
            if rb_obj.RouterL3AgentBinding.objects_exist(context,
                                                         router_id=router_id,
                                                         l3_agent_id=agent.id):
                # not removing from the agent hosting SNAT for the router
                continue
            if self._check_for_rtr_serviceable_ports(
                    admin_context, router_id, port_host):
                # once we found a serviceable port there is no need to
                # check further
                host_has_serviceable_port = True
                break
            self._unbind_dvr_port_before_delete(context, router_id, port_host)
            info = {'router_id': router_id, 'host': port_host,
                    'agent_id': str(agent.id)}
            removed_router_info.append(info)
        # Now collect the connected router info as well to remove
        # it from the agent, only if there is not a serviceable port.
        if not host_has_serviceable_port:
            related_router_ids = set()
            for router_id in router_ids:
                connected_dvr_router_ids = set(
                    self._get_other_dvr_router_ids_connected_router(
                        context, router_id))
                related_router_ids |= connected_dvr_router_ids
            related_router_ids = [r_id for r_id in related_router_ids
                                  if r_id not in list(router_ids)]
            for router_id in related_router_ids:
                if self._check_for_rtr_serviceable_ports(
                        admin_context, router_id, port_host):
                    # once we found a serviceable port there is no need to
                    # check further
                    host_has_serviceable_port = True
                    break
                self._unbind_dvr_port_before_delete(context, router_id,
                                                    port_host)
                info = {'router_id': router_id, 'host': port_host,
                        'agent_id': str(agent.id)}
                removed_router_info.append(info)
        LOG.debug("Router info to be deleted: %s", removed_router_info)
        return removed_router_info

    def _check_for_rtr_serviceable_ports(
            self, admin_context, router_id, port_host):
        subnet_ids = self.get_subnet_ids_on_router(admin_context,
                                                   router_id,
                                                   keep_gateway_port=False)
        return self._check_dvr_serviceable_ports_on_host(
            admin_context, port_host, subnet_ids)

    def _unbind_dvr_port_before_delete(
            self, context, router_id, port_host):
        filter_rtr = {'device_id': [router_id],
                      'device_owner':
                      [n_const.DEVICE_OWNER_DVR_INTERFACE]}
        int_ports = self._core_plugin.get_ports(
            context.elevated(), filters=filter_rtr)
        for port in int_ports:
            # unbind this port from router
            ml2_db.update_distributed_port_binding_by_host(
                context, port['id'], port_host, None)

    def _get_active_l3_agent_routers_sync_data(self, context, host, agent,
                                               router_ids):
        if extensions.is_extension_supported(
                self, n_const.L3_HA_MODE_EXT_ALIAS):
            return self.get_ha_sync_data_for_host(context, host, agent,
                                                  router_ids=router_ids,
                                                  active=True)
        return self._get_dvr_sync_data(context, host, agent,
                                       router_ids=router_ids, active=True)

    def get_hosts_to_notify(self, context, router_id):
        """Returns all hosts to send notification about router update"""
        hosts = super(L3_DVRsch_db_mixin, self).get_hosts_to_notify(
            context, router_id)
        router = self.get_router(context.elevated(), router_id)
        if router.get('distributed', False):
            dvr_hosts = self._get_dvr_hosts_for_router(context, router_id)
            dvr_hosts = set(dvr_hosts) - set(hosts)
            dvr_hosts |= self._get_other_dvr_hosts(context, router_id)
            state = agentschedulers_db.get_admin_state_up_filter()
            agents = self.get_l3_agents(context, active=state,
                                        filters={'host': dvr_hosts})
            hosts += [a.host for a in agents]

        return hosts

    def _get_dvr_hosts_for_router(self, context, router_id):
        """Get a list of hosts where specified DVR router should be hosted

        It will first get IDs of all subnets connected to the router and then
        get a set of hosts where all dvr serviceable ports on those subnets
        are bound
        """
        subnet_ids = self.get_subnet_ids_on_router(context, router_id)
        hosts = self._get_dvr_hosts_for_subnets(context, subnet_ids)
        LOG.debug('Hosts for router %s: %s', router_id, hosts)
        return hosts

    def _get_other_dvr_hosts(self, context, router_id):
        """Get a list of hosts where specified DVR router should be hosted

        It will search DVR hosts based on other dvr routers connected to the
        router.
        """
        dvr_hosts = set()
        connected_dvr_routers = (
            self._get_other_dvr_router_ids_connected_router(
                context, router_id))
        for dvr_router in connected_dvr_routers:
            dvr_hosts |= set(
                self._get_dvr_hosts_for_router(context, dvr_router))

        LOG.debug('Hosts for other DVR routers connected to router '
                  '%(router_id)s: %(dvr_hosts)s',
                  {'router_id': router_id, 'dvr_hosts': dvr_hosts})
        return dvr_hosts

    @db_api.CONTEXT_READER
    def _get_dvr_hosts_for_subnets(self, context, subnet_ids):
        """Get a list of hosts with DVR serviceable ports on subnet_ids."""
        host_dvr_dhcp = cfg.CONF.host_dvr_for_dhcp
        Binding = ml2_models.PortBinding
        Port = models_v2.Port
        IPAllocation = models_v2.IPAllocation

        query = context.session.query(Binding.host).distinct()
        query = query.join(Binding.port)
        query = query.join(Port.fixed_ips)
        query = query.filter(IPAllocation.subnet_id.in_(subnet_ids))
        owner_filter = or_(
            Port.device_owner.startswith(n_const.DEVICE_OWNER_COMPUTE_PREFIX),
            Port.device_owner.in_(
                n_utils.get_other_dvr_serviced_device_owners(host_dvr_dhcp)))
        query = query.filter(owner_filter)
        hosts = [item[0] for item in query if item[0] != '']
        return hosts

    @db_api.CONTEXT_READER
    def _get_dvr_subnet_ids_on_host_query(self, context, host):
        host_dvr_dhcp = cfg.CONF.host_dvr_for_dhcp
        query = context.session.query(
            models_v2.IPAllocation.subnet_id).distinct()
        query = query.join(models_v2.IPAllocation.port)
        query = query.join(models_v2.Port.port_bindings)
        query = query.filter(ml2_models.PortBinding.host == host)
        owner_filter = or_(
            models_v2.Port.device_owner.startswith(
                n_const.DEVICE_OWNER_COMPUTE_PREFIX),
            models_v2.Port.device_owner.in_(
                n_utils.get_other_dvr_serviced_device_owners(host_dvr_dhcp)))
        query = query.filter(owner_filter)
        return query

    @db_api.CONTEXT_READER
    def _get_dvr_router_ids_for_host(self, context, host):
        subnet_ids_on_host_query = self._get_dvr_subnet_ids_on_host_query(
            context, host)
        query = context.session.query(models_v2.Port.device_id).distinct()
        query = query.filter(
            models_v2.Port.device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE)
        query = query.join(models_v2.Port.fixed_ips)
        query = query.filter(
            models_v2.IPAllocation.subnet_id.in_(subnet_ids_on_host_query))
        router_ids = [item[0] for item in query]
        LOG.debug('DVR routers on host %s: %s', host, router_ids)
        return router_ids

    @db_api.CONTEXT_READER
    def _get_other_dvr_router_ids_connected_router(self, context, router_id):
        # TODO(slaweq): move this method to RouterPort OVO object
        subnet_ids = self.get_subnet_ids_on_router(context, router_id)
        RouterPort = l3_models.RouterPort
        query = context.elevated().session.query(RouterPort.router_id)
        query = query.join(models_v2.Port)
        query = query.join(
            models_v2.Subnet,
            models_v2.Subnet.network_id == models_v2.Port.network_id)
        query = query.filter(
            models_v2.Subnet.id.in_(subnet_ids),
            RouterPort.port_type == n_const.DEVICE_OWNER_DVR_INTERFACE
        ).distinct()
        query = query.filter(RouterPort.router_id != router_id)
        return [item[0] for item in query]

    def _get_router_ids_for_agent(self, context, agent_db, router_ids,
                                  with_dvr=True):
        result_set = set(super(L3_DVRsch_db_mixin,
                               self)._get_router_ids_for_agent(
            context, agent_db, router_ids, with_dvr))
        if not with_dvr:
            return result_set
        LOG.debug("Routers %(router_ids)s bound to L3 agent in host %(host)s",
                  {'router_ids': result_set,
                   'host': agent_db['host']})
        router_ids = set(router_ids or [])
        if router_ids and result_set == router_ids:
            # no need for extra dvr checks if requested routers are
            # explicitly scheduled to the agent
            return list(result_set)

        # dvr routers are not explicitly scheduled to agents on hosts with
        # dvr serviceable ports, so need special handling
        if (self._get_agent_mode(agent_db) in
            [n_const.L3_AGENT_MODE_DVR,
             n_const.L3_AGENT_MODE_DVR_NO_EXTERNAL,
             n_const.L3_AGENT_MODE_DVR_SNAT]):
            dvr_routers = self._get_dvr_router_ids_for_host(context,
                                                            agent_db['host'])
            if not router_ids:
                result_set |= set(dvr_routers)
            else:
                for router_id in (router_ids - result_set):
                    subnet_ids = self.get_subnet_ids_on_router(
                        context, router_id, keep_gateway_port=False)
                    if (subnet_ids and (
                            self._check_dvr_serviceable_ports_on_host(
                                    context, agent_db['host'],
                                    list(subnet_ids)) or
                            self._is_router_related_to_dvr_routers(
                                    context, router_id, dvr_routers))):
                        result_set.add(router_id)

            LOG.debug("Routers %(router_ids)s are scheduled or have "
                      "serviceable ports in host %(host)s",
                      {'router_ids': result_set,
                       'host': agent_db['host']})
            related_routers = set()
            for router_id in result_set:
                related_routers |= set(
                    self._get_other_dvr_router_ids_connected_router(
                        context, router_id))
            result_set |= related_routers

        LOG.debug("Router IDs %(router_ids)s for agent in host %(host)s",
                  {'router_ids': result_set,
                   'host': agent_db['host']})
        return list(result_set)

    @log_helpers.log_method_call
    @db_api.CONTEXT_READER
    def _check_dvr_serviceable_ports_on_host(self, context, host, subnet_ids):
        """Check for existence of dvr serviceable ports on host

        :param context: request context
        :param host: host to look ports on
        :param subnet_ids: IDs of subnets to look ports on
        :return: return True if dvr serviceable port exists on host,
                 otherwise return False
        """
        # db query will return ports for all subnets if subnet_ids is empty,
        # so need to check first
        if not subnet_ids:
            return False

        # The port binding profile filter for host performs a "contains"
        # operation. This produces a LIKE expression targeting a sub-string
        # match: column LIKE '%' || <host> || '%'.
        # Add quotes to force an exact match of the host name in the port
        # binding profile dictionary.
        profile_host = "\"%s\"" % host

        Binding = ml2_models.PortBinding
        IPAllocation = models_v2.IPAllocation
        Port = models_v2.Port

        host_dvr_dhcp = cfg.CONF.host_dvr_for_dhcp
        query = context.session.query(Binding)
        query = query.join(Binding.port)
        query = query.join(Port.fixed_ips)
        query = query.filter(
            IPAllocation.subnet_id.in_(subnet_ids))
        query = query.filter(
            ml2_models.PortBinding.status == n_const.ACTIVE)
        device_filter = or_(
            models_v2.Port.device_owner.startswith(
                n_const.DEVICE_OWNER_COMPUTE_PREFIX),
            models_v2.Port.device_owner.in_(
                n_utils.get_other_dvr_serviced_device_owners(host_dvr_dhcp)))
        query = query.filter(device_filter)
        host_filter = or_(
            ml2_models.PortBinding.host == host,
            ml2_models.PortBinding.profile.contains(profile_host))
        query = query.filter(host_filter)
        return query.first() is not None

    @log_helpers.log_method_call
    def _is_router_related_to_dvr_routers(self, context, router_id,
                                          dvr_routers):
        related_routers = self._get_other_dvr_router_ids_connected_router(
            context, router_id)
        return any([r in dvr_routers for r in related_routers])


def _dvr_handle_unbound_allowed_addr_pair_add(
        plugin, context, port, allowed_address_pair):
    plugin.update_arp_entry_for_dvr_service_port(context, port)


def _dvr_handle_unbound_allowed_addr_pair_del(
        plugin, context, port, allowed_address_pair):
    aa_fixed_ips = plugin._get_allowed_address_pair_fixed_ips(context, port)
    if aa_fixed_ips:
        plugin.delete_arp_entry_for_dvr_service_port(
            context, port, fixed_ips_to_delete=aa_fixed_ips)


def _notify_l3_agent_new_port(resource, event, trigger, payload=None):
    LOG.debug('Received %(resource)s %(event)s', {
        'resource': resource,
        'event': event})
    port = payload.latest_state
    if not port:
        return

    if n_utils.is_dvr_serviced(port['device_owner']):
        l3plugin = directory.get_plugin(plugin_constants.L3)
        context = payload.context
        l3plugin.dvr_handle_new_service_port(context, port)
        l3plugin.update_arp_entry_for_dvr_service_port(context, port)


def _notify_port_delete(event, resource, trigger, payload):
    context = payload.context
    port = payload.latest_state
    get_related_hosts_info = payload.metadata.get(
                                 "get_related_hosts_info", True)
    l3plugin = directory.get_plugin(plugin_constants.L3)
    if port:
        port_host = port.get(portbindings.HOST_ID)
        allowed_address_pairs_list = port.get('allowed_address_pairs')
        if allowed_address_pairs_list and port_host:
            for address_pair in allowed_address_pairs_list:
                _dvr_handle_unbound_allowed_addr_pair_del(
                    l3plugin, context, port, address_pair)
    l3plugin.delete_arp_entry_for_dvr_service_port(context, port)
    removed_routers = l3plugin.get_dvr_routers_to_remove(
        context, port, get_related_hosts_info)
    for info in removed_routers:
        l3plugin.l3_rpc_notifier.router_removed_from_agent(
            context, info['router_id'], info['host'])


def _notify_l3_agent_port_update(resource, event, trigger, payload):
    new_port = payload.latest_state
    original_port = payload.states[0]

    is_fixed_ips_changed = n_utils.port_ip_changed(new_port, original_port)

    if (original_port['device_owner'] in
            [n_const.DEVICE_OWNER_HA_REPLICATED_INT,
             n_const.DEVICE_OWNER_ROUTER_SNAT,
             n_const.DEVICE_OWNER_ROUTER_GW] and
            not is_fixed_ips_changed):
        return

    if new_port and original_port:
        l3plugin = directory.get_plugin(plugin_constants.L3)
        context = payload.context
        new_port_host = new_port.get(portbindings.HOST_ID)
        original_port_host = original_port.get(portbindings.HOST_ID)
        is_new_port_binding_changed = (
            new_port_host and
            new_port_host != original_port_host)
        is_bound_port_moved = (
            original_port_host and
            original_port_host != new_port_host)
        fip_router_id = None
        dest_host = None
        new_port_profile = new_port.get(portbindings.PROFILE)
        if new_port_profile:
            dest_host = new_port_profile.get('migrating_to')
        if is_new_port_binding_changed or is_bound_port_moved or dest_host:
            fips = l3plugin._get_floatingips_by_port_id(
                    context, port_id=original_port['id'])
            fip = fips[0] if fips else None
            if fip:
                fip_router_id = fip['router_id']
        if is_bound_port_moved:
            removed_routers = l3plugin.get_dvr_routers_to_remove(
                context,
                original_port,
                get_related_hosts_info=False)
            if removed_routers:
                _notify_port_delete(
                    event, resource, trigger,
                    payload=events.DBEventPayload(
                        context,
                        metadata={'removed_routers': removed_routers,
                                  'get_related_hosts_info': False},
                        states=(original_port,)))

            def _should_notify_on_fip_update():
                if not fip_router_id:
                    return False
                for info in removed_routers:
                    if info['router_id'] == fip_router_id:
                        return False
                try:
                    router = l3plugin._get_router(context, fip_router_id)
                except l3_exc.RouterNotFound:
                    return False
                return l3_dvr_db.is_distributed_router(router)

            if _should_notify_on_fip_update():
                l3plugin.l3_rpc_notifier.routers_updated_on_host(
                    context, [fip_router_id],
                    original_port[portbindings.HOST_ID])
        # If dest_host is set, then the port profile has changed
        # and this port is in migration. The call below will
        # pre-create the router on the new host
        # If the original_port is None, then it is a migration
        # from unbound to bound.
        if (is_new_port_binding_changed or dest_host):
            if (not original_port[portbindings.HOST_ID] and
                    not original_port['device_owner']):
                l3plugin.dvr_handle_new_service_port(context, new_port,
                                                     unbound_migrate=True)
            else:
                l3plugin.dvr_handle_new_service_port(
                    context, new_port,
                    dest_host=dest_host,
                    router_id=fip_router_id)
            l3plugin.update_arp_entry_for_dvr_service_port(
                context, new_port)
            return
        # Check for allowed_address_pairs and port state
        new_port_host = new_port.get(portbindings.HOST_ID)
        allowed_address_pairs_list = new_port.get('allowed_address_pairs')
        if allowed_address_pairs_list and new_port_host:
            new_port_state = new_port.get('admin_state_up')
            original_port_state = original_port.get('admin_state_up')
            if new_port_state:
                # Case were we activate the port from inactive state,
                # or the same port has additional address_pairs added.
                for address_pair in allowed_address_pairs_list:
                    _dvr_handle_unbound_allowed_addr_pair_add(
                        l3plugin, context, new_port, address_pair)
                return
            elif original_port_state:
                # Case were we deactivate the port from active state.
                for address_pair in allowed_address_pairs_list:
                    _dvr_handle_unbound_allowed_addr_pair_del(
                        l3plugin, context, original_port, address_pair)
                return

        if payload.metadata.get('mac_address_updated') or is_fixed_ips_changed:
            l3plugin.update_arp_entry_for_dvr_service_port(
                context, new_port)


def subscribe():
    registry.subscribe(
        _notify_l3_agent_port_update, resources.PORT, events.AFTER_UPDATE)
    registry.subscribe(
        _notify_l3_agent_new_port, resources.PORT, events.AFTER_CREATE)
    registry.subscribe(
        _notify_port_delete, resources.PORT, events.AFTER_DELETE)
