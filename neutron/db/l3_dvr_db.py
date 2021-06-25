# Copyright (c) 2014 OpenStack Foundation.  All rights reserved.
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

import netaddr
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import portbindings_extended
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import exceptions
from neutron_lib.callbacks import priority_group
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import agent as agent_exc
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.objects import exceptions as o_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as plugin_utils
from oslo_config import cfg
from oslo_log import helpers as log_helper
from oslo_log import log as logging
from oslo_utils import excutils

from neutron._i18n import _
from neutron.api import extensions
from neutron.common import utils as n_utils
from neutron.conf.db import l3_dvr_db
from neutron.db import dvr_mac_db
from neutron.db import l3_attrs_db
from neutron.db import l3_db
from neutron.db.models import allowed_address_pair as aap_models
from neutron.db import models_v2
from neutron.extensions import _admin_state_down_before_update_lib
from neutron.ipam import utils as ipam_utils
from neutron.objects import agent as ag_obj
from neutron.objects import base as base_obj
from neutron.objects import l3agent as rb_obj
from neutron.objects import ports as port_obj
from neutron.objects import router as l3_obj


LOG = logging.getLogger(__name__)
l3_dvr_db.register_db_l3_dvr_opts()
_IS_ADMIN_STATE_DOWN_NECESSARY = None


def is_admin_state_down_necessary():
    global _IS_ADMIN_STATE_DOWN_NECESSARY
    if _IS_ADMIN_STATE_DOWN_NECESSARY is None:
        _IS_ADMIN_STATE_DOWN_NECESSARY = \
            _admin_state_down_before_update_lib.ALIAS in (extensions.
                    PluginAwareExtensionManager.get_instance().extensions)
    return _IS_ADMIN_STATE_DOWN_NECESSARY


# TODO(slaweq): this should be moved to neutron_lib.plugins.utils module
def is_port_bound(port):
    active_binding = plugin_utils.get_port_binding_by_status_and_host(
        port.get("port_bindings", []), const.ACTIVE)
    if not active_binding:
        LOG.warning("Binding for port %s was not found.", port)
        return False
    return active_binding[portbindings_extended.VIF_TYPE] not in [
        portbindings.VIF_TYPE_UNBOUND,
        portbindings.VIF_TYPE_BINDING_FAILED]


@registry.has_registry_receivers
class DVRResourceOperationHandler(object):
    """Contains callbacks for DVR operations.

    This can be implemented as a mixin or can be intantiated as a stand-alone
    object. Either way, it will subscribe itself to the relevant L3 events and
    use the plugin directory to find the L3 plugin to make calls to it as
    necessary.
    """

    related_dvr_router_hosts = {}
    related_dvr_router_routers = {}

    @property
    def l3plugin(self):
        return directory.get_plugin(plugin_constants.L3)

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_CREATE],
                       priority_group.PRIORITY_ROUTER_EXTENDED_ATTRIBUTE)
    def _set_distributed_flag(self, resource, event, trigger, context,
                              router, router_db, **kwargs):
        """Event handler to set distributed flag on creation."""
        dist = is_distributed_router(router)
        router['distributed'] = dist
        self.l3plugin.set_extra_attr_value(context, router_db, 'distributed',
                                           dist)

    def _validate_router_migration(self, context, router_db, router_res,
                                   old_router=None):
        """Allow transition only when admin_state_up=False"""
        admin_state_down_extension_loaded = is_admin_state_down_necessary()
        # to preserve extant API behavior, only check the distributed attribute
        # of old_router when the "router-admin-state-down-before-update" shim
        # API extension is loaded. Don't bother checking if old_router is
        # "None"
        if old_router and admin_state_down_extension_loaded:
            original_distributed_state = old_router.get('distributed')
        else:
            original_distributed_state = router_db.extra_attributes.distributed
        requested_distributed_state = router_res.get('distributed', None)

        distributed_changed = (
            requested_distributed_state is not None and
            requested_distributed_state != original_distributed_state)
        if not distributed_changed:
            return False

        # to preserve old API behavior, only check old_router if shim API
        # extension has been loaded
        if admin_state_down_extension_loaded and old_router:
            # if one OR both routers is still up, the *collective*
            # "admin_state_up" should be True and we should throw the
            # BadRequest exception below.
            admin_state_up = (old_router.get('admin_state_up') or
                              router_db.get('admin_state_up'))
        else:
            admin_state_up = router_db.get('admin_state_up')
        if admin_state_up:
            msg = _("Cannot change the 'distributed' attribute of active "
                    "routers. Please set router admin_state_up to False "
                    "prior to upgrade")
            raise n_exc.BadRequest(resource='router', msg=msg)

        # Notify advanced services of the imminent state transition
        # for the router.
        try:
            kwargs = {'context': context, 'router': router_db}
            registry.notify(
                resources.ROUTER, events.BEFORE_UPDATE, self, **kwargs)
        except exceptions.CallbackFailure as e:
            # NOTE(armax): preserve old check's behavior
            if len(e.errors) == 1:
                raise e.errors[0].error
            raise l3_exc.RouterInUse(router_id=router_db['id'], reason=e)
        return True

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_UPDATE],
                       priority_group.PRIORITY_ROUTER_EXTENDED_ATTRIBUTE)
    def _handle_distributed_migration(self, resource, event,
                                      trigger, payload=None):
        """Event handler for router update migration to distributed."""
        if not self._validate_router_migration(
                payload.context, payload.desired_state,
                payload.request_body, payload.states[0]):
            return

        migrating_to_distributed = (
            not payload.desired_state.extra_attributes.distributed and
            payload.request_body.get('distributed') is True)

        if migrating_to_distributed:
            if payload.states[0]['ha']:
                old_owner = const.DEVICE_OWNER_HA_REPLICATED_INT
            else:
                old_owner = const.DEVICE_OWNER_ROUTER_INTF
            self.l3plugin._migrate_router_ports(
                payload.context, payload.desired_state,
                old_owner=old_owner,
                new_owner=const.DEVICE_OWNER_DVR_INTERFACE)
        else:
            if payload.request_body.get('ha'):
                new_owner = const.DEVICE_OWNER_HA_REPLICATED_INT
            else:
                new_owner = const.DEVICE_OWNER_ROUTER_INTF
            self.l3plugin._migrate_router_ports(
                payload.context, payload.desired_state,
                old_owner=const.DEVICE_OWNER_DVR_INTERFACE,
                new_owner=new_owner)

        cur_agents = self.l3plugin.list_l3_agents_hosting_router(
            payload.context, payload.resource_id)['agents']
        for agent in cur_agents:
            self.l3plugin._unbind_router(
                payload.context, payload.resource_id,
                agent['id'])
        self.l3plugin.set_extra_attr_value(
            payload.context, payload.desired_state,
            'distributed', migrating_to_distributed)

    @registry.receives(resources.ROUTER, [events.AFTER_UPDATE],
                       priority_group.PRIORITY_ROUTER_EXTENDED_ATTRIBUTE)
    def _delete_distributed_port_bindings_after_change(self, resource, event,
                                                       trigger, context,
                                                       router_id, router,
                                                       request_attrs,
                                                       router_db, **kwargs):
        old_router = kwargs['old_router']
        if (old_router and old_router['distributed'] and not
                router['distributed']):
            self._core_plugin.delete_distributed_port_bindings_by_router_id(
                context.elevated(), router_db['id'])

    @registry.receives(resources.ROUTER, [events.AFTER_UPDATE],
                       priority_group.PRIORITY_ROUTER_EXTENDED_ATTRIBUTE)
    def _delete_snat_interfaces_after_change(self, resource, event, trigger,
                                             context, router_id, router,
                                             request_attrs, router_db,
                                             **kwargs):
        if (router.get(l3_apidef.EXTERNAL_GW_INFO) and
                not router['distributed']):
            old_router = kwargs['old_router']
            if old_router and old_router['distributed']:
                self.delete_csnat_router_interface_ports(
                    context.elevated(), router_db)

    @registry.receives(resources.ROUTER,
                       [events.AFTER_CREATE, events.AFTER_UPDATE],
                       priority_group.PRIORITY_ROUTER_EXTENDED_ATTRIBUTE)
    def _create_snat_interfaces_after_change(self, resource, event, trigger,
                                             context, router_id, router,
                                             request_attrs, router_db,
                                             **kwargs):
        if (not router.get(l3_apidef.EXTERNAL_GW_INFO) or
                not router['distributed']):
            # we don't care if it's not distributed or not attached to an
            # external network
            return
        if event == events.AFTER_UPDATE:
            # after an update, we check to see if it was a migration or a
            # gateway attachment
            old_router = kwargs['old_router']
            do_create = (not old_router['distributed'] or
                         not old_router.get(l3_apidef.EXTERNAL_GW_INFO))
            if not do_create:
                return
        if not self._create_snat_intf_ports_if_not_exists(context.elevated(),
                                                          router_db):
            LOG.debug("SNAT interface ports not created: %s",
                      router_db['id'])
        return router_db

    def _get_snat_interface_ports_for_router(self, context, router_id):
        """Return all existing snat_router_interface ports."""
        objs = l3_obj.RouterPort.get_objects(
            context,
            router_id=router_id,
            port_type=const.DEVICE_OWNER_ROUTER_SNAT)

        # TODO(lujinluo): Need Port as synthetic field
        ports = [self.l3plugin._core_plugin._make_port_dict(rp.db_obj.port)
                 for rp in objs]
        return ports

    def _add_csnat_router_interface_port(
            self, context, router, network_id, subnets, do_pop=True):
        """Add SNAT interface to the specified router and subnet."""
        port_data = {'tenant_id': '',
                     'network_id': network_id,
                     'fixed_ips': subnets,
                     'device_id': router.id,
                     'device_owner': const.DEVICE_OWNER_ROUTER_SNAT,
                     'admin_state_up': True,
                     'name': ''}
        snat_port = plugin_utils.create_port(
            self._core_plugin, context, {'port': port_data})
        if not snat_port:
            msg = _("Unable to create the SNAT Interface Port")
            raise n_exc.BadRequest(resource='router', msg=msg)

        with plugin_utils.delete_port_on_error(self.l3plugin._core_plugin,
                                               context.elevated(),
                                               snat_port['id']):
            l3_obj.RouterPort(
                context,
                port_id=snat_port['id'],
                router_id=router.id,
                port_type=const.DEVICE_OWNER_ROUTER_SNAT
            ).create()

            if do_pop:
                return self.l3plugin._populate_mtu_and_subnets_for_ports(
                    context, [snat_port])
            return snat_port

    def _create_snat_intf_ports_if_not_exists(self, context, router):
        """Function to return the snat interface port list.

        This function will return the snat interface port list
        if it exists. If the port does not exist it will create
        new ports and then return the list.
        """
        port_list = self._get_snat_interface_ports_for_router(
            context, router.id)
        if port_list:
            self._populate_mtu_and_subnets_for_ports(context, port_list)
            return port_list

        int_ports = (
            rp.port for rp in router.attached_ports
            if rp.port_type == const.DEVICE_OWNER_DVR_INTERFACE
        )
        LOG.info('SNAT interface port list does not exist, creating one')
        v6_subnets = []
        network = None
        for intf in int_ports:
            if intf.fixed_ips:
                # Passing the subnet for the port to make sure the IP's
                # are assigned on the right subnet if multiple subnet
                # exists
                for fixed_ip in intf['fixed_ips']:
                    ip_version = n_utils.get_ip_version(
                        fixed_ip.get('ip_address'))
                    if ip_version == const.IP_VERSION_4:
                        snat_port = self._add_csnat_router_interface_port(
                            context, router, intf['network_id'],
                            [{'subnet_id': fixed_ip['subnet_id']}],
                            do_pop=False)
                        port_list.append(snat_port)
                    else:
                        v6_subnets.append(
                            {"subnet_id": fixed_ip['subnet_id']})
                        network = intf['network_id']
        if v6_subnets:
            snat_port = self._add_csnat_router_interface_port(
                context, router, network,
                v6_subnets, do_pop=False)
            port_list.append(snat_port)
        if port_list:
            self.l3plugin._populate_mtu_and_subnets_for_ports(
                context, port_list)
        return port_list

    @registry.receives(resources.ROUTER_GATEWAY, [events.AFTER_DELETE])
    def _delete_dvr_internal_ports(self, event, trigger, resource,
                                   payload=None):
        """GW port AFTER_DELETE event handler to cleanup DVR ports.

        This event is emitted when a router gateway port is being deleted,
        so go ahead and delete the csnat ports and the floatingip
        agent gateway port associated with the dvr router.
        """

        if not is_distributed_router(payload.latest_state):
            return
        if not payload.metadata.get('new_network_id'):
            self.delete_csnat_router_interface_ports(
                payload.context.elevated(), payload.latest_state)

        network_id = payload.metadata.get('network_id')
        # NOTE(Swami): Delete the Floatingip agent gateway port
        # on all hosts when it is the last gateway port in the
        # given external network.
        filters = {'network_id': [network_id],
                   'device_owner': [const.DEVICE_OWNER_ROUTER_GW]}
        ext_net_gw_ports = self._core_plugin.get_ports(
            payload.context.elevated(), filters)
        if not ext_net_gw_ports:
            self.delete_floatingip_agent_gateway_port(
                payload.context.elevated(), None, network_id)
            # Send the information to all the L3 Agent hosts
            # to clean up the fip namespace as it is no longer required.
            self.l3plugin.l3_rpc_notifier.delete_fipnamespace_for_ext_net(
                payload.context, network_id)
            # Delete the Floating IP agent gateway port
            # bindings on all hosts
            l3_obj.DvrFipGatewayPortAgentBinding.delete_objects(
                payload.context,
                network_id=network_id)

    def _delete_fip_agent_port(self, context, network_id, host_id):
        try:
            l3_agent_db = self._get_agent_by_type_and_host(
                context, const.AGENT_TYPE_L3, host_id)
        except agent_exc.AgentNotFoundByTypeHost:
            LOG.warning("%(ag)s agent not found for the given host: %(host)s",
                        {'ag': const.AGENT_TYPE_L3,
                         'host': host_id})
            return
        try:
            l3_obj.DvrFipGatewayPortAgentBinding(
                context, network_id=network_id,
                agent_id=l3_agent_db['id']).delete()
        except n_exc.ObjectNotFound:
            pass

    def delete_floatingip_agent_gateway_port(self, context, host_id,
                                             ext_net_id):
        """Function to delete FIP gateway port with given ext_net_id."""
        # delete any fip agent gw port
        device_filter = {'device_owner': [const.DEVICE_OWNER_AGENT_GW],
                         'network_id': [ext_net_id]}
        ports = self._core_plugin.get_ports(context,
                                            filters=device_filter)
        for p in ports:
            if not host_id or p[portbindings.HOST_ID] == host_id:
                self._core_plugin.ipam.delete_port(context, p['id'])
                self._delete_fip_agent_port(
                    context, ext_net_id, p[portbindings.HOST_ID])
                if host_id:
                    return

    @registry.receives(resources.NETWORK, [events.AFTER_DELETE])
    def delete_fip_namespaces_for_ext_net(self, rtype, event, trigger,
                                          context, network, **kwargs):
        if network.get(extnet_apidef.EXTERNAL):
            # Send the information to all the L3 Agent hosts
            # to clean up the fip namespace as it is no longer required.
            self.l3plugin.l3_rpc_notifier.delete_fipnamespace_for_ext_net(
                context, network['id'])

    def _get_ports_for_allowed_address_pair_ip(self, context, network_id,
                                               fixed_ip):
        """Return all active ports associated with the allowed_addr_pair ip."""
        query = context.session.query(
            models_v2.Port).filter(
                models_v2.Port.id == aap_models.AllowedAddressPair.port_id,
                aap_models.AllowedAddressPair.ip_address == fixed_ip,
                models_v2.Port.network_id == network_id,
                models_v2.Port.admin_state_up == True)  # noqa
        return query.all()

    @registry.receives(resources.FLOATING_IP, [events.AFTER_UPDATE])
    def _create_dvr_floating_gw_port(self, resource, event, trigger, context,
                                     router_id, fixed_port_id, floating_ip_id,
                                     floating_network_id, fixed_ip_address,
                                     association_event, **kwargs):
        """Create floating agent gw port for DVR.

        Floating IP Agent gateway port will be created when a
        floatingIP association happens.
        """
        if association_event and router_id:
            admin_ctx = context.elevated()
            router_dict = self.get_router(admin_ctx, router_id)
            # Check if distributed router and then create the
            # FloatingIP agent gateway port
            if router_dict.get('distributed'):
                hostid = self._get_dvr_service_port_hostid(context,
                                                           fixed_port_id)
                if hostid:
                    # FIXME (Swami): This FIP Agent Gateway port should be
                    # created only once and there should not be a duplicate
                    # for the same host. Until we find a good solution for
                    # augmenting multiple server requests we should use the
                    # existing flow.
                    fip_agent_port = (
                        self.create_fip_agent_gw_port_if_not_exists(
                            admin_ctx, floating_network_id, hostid))
                    LOG.debug("FIP Agent gateway port: %s", fip_agent_port)
                else:
                    # If not hostid check if the fixed ip provided has to
                    # deal with allowed_address_pairs for a given service
                    # port. Get the port_dict, inherit the service port host
                    # and device owner(if it does not exist).
                    port = self._core_plugin.get_port(
                        admin_ctx, fixed_port_id)
                    allowed_device_owners = (
                        n_utils.get_dvr_allowed_address_pair_device_owners())
                    # NOTE: We just need to deal with ports that do not
                    # have a device_owner and ports that are owned by the
                    # dvr service ports except for the compute port and
                    # dhcp port.
                    if (port['device_owner'] == "" or
                            port['device_owner'] in allowed_device_owners):
                        addr_pair_active_service_port_list = (
                            self._get_ports_for_allowed_address_pair_ip(
                                admin_ctx, port['network_id'],
                                fixed_ip_address))
                        if not addr_pair_active_service_port_list:
                            return
                        self._inherit_service_port_and_arp_update(
                            context, addr_pair_active_service_port_list[0])

    def _inherit_service_port_and_arp_update(self, context, service_port):
        """Function inherits port host bindings for allowed_address_pair."""
        service_port_dict = self.l3plugin._core_plugin._make_port_dict(
            service_port)
        address_pair_list = service_port_dict.get('allowed_address_pairs')
        for address_pair in address_pair_list:
            self.update_arp_entry_for_dvr_service_port(context,
                                                       service_port_dict)

    @registry.receives(resources.ROUTER_INTERFACE, [events.BEFORE_CREATE])
    @db_api.retry_if_session_inactive()
    def _add_csnat_on_interface_create(self, resource, event, trigger,
                                       context, router_db, port, **kwargs):
        """Event handler to for csnat port creation on interface creation."""
        if not router_db.extra_attributes.distributed or not router_db.gw_port:
            return
        admin_context = context.elevated()
        self._add_csnat_router_interface_port(
            admin_context, router_db, port['network_id'],
            [{'subnet_id': port['fixed_ips'][-1]['subnet_id']}])

    @registry.receives(resources.ROUTER_INTERFACE, [events.AFTER_CREATE])
    @db_api.retry_if_session_inactive()
    def _update_snat_v6_addrs_after_intf_update(self, resource, event, trigger,
                                                context, subnets, port,
                                                router_id, new_interface,
                                                **kwargs):
        if new_interface:
            # _add_csnat_on_interface_create handler deals with new ports
            return
        # if not a new interface, the interface was added to a new subnet,
        # which is the first in this list
        subnet = subnets[0]
        if not subnet or subnet['ip_version'] != 6:
            return
        # NOTE: For IPv6 additional subnets added to the same
        # network we need to update the CSNAT port with respective
        # IPv6 subnet
        # Add new prefix to an existing ipv6 csnat port with the
        # same network id if one exists
        admin_ctx = context.elevated()
        router = self.l3plugin._get_router(admin_ctx, router_id)
        cs_port = self._find_v6_router_port_by_network_and_device_owner(
            router, subnet['network_id'], const.DEVICE_OWNER_ROUTER_SNAT)
        if not cs_port:
            return
        new_fixed_ip = {'subnet_id': subnet['id']}
        fixed_ips = list(cs_port['fixed_ips'])
        fixed_ips.append(new_fixed_ip)
        try:
            updated_port = self._core_plugin.update_port(
                admin_ctx, cs_port['id'], {'port': {'fixed_ips': fixed_ips}})
        except Exception:
            with excutils.save_and_reraise_exception():
                # we need to try to undo the updated router
                # interface from above so it's not out of sync
                # with the csnat port.
                # TODO(kevinbenton): switch to taskflow to manage
                # these rollbacks.
                @db_api.retry_db_errors
                def revert():
                    # TODO(kevinbenton): even though we get the
                    # port each time, there is a potential race
                    # where we update the port with stale IPs if
                    # another interface operation is occurring at
                    # the same time. This can be fixed in the
                    # future with a compare-and-swap style update
                    # using the revision number of the port.
                    p = self._core_plugin.get_port(admin_ctx, port['id'])
                    rollback_fixed_ips = [ip for ip in p['fixed_ips']
                                          if ip['subnet_id'] != subnet['id']]
                    upd = {'port': {'fixed_ips': rollback_fixed_ips}}
                    self._core_plugin.update_port(admin_ctx, port['id'], upd)
                try:
                    revert()
                except Exception:
                    LOG.exception("Failed to revert change "
                                  "to router port %s.",
                                  port['id'])
        LOG.debug("CSNAT port updated for IPv6 subnet: %s", updated_port)

    def _find_v6_router_port_by_network_and_device_owner(self, router, net_id,
                                                         device_owner):
        for port in router.attached_ports:
            p = port['port']
            if (p['network_id'] == net_id and
                    p['device_owner'] == device_owner and
                    self.l3plugin._port_has_ipv6_address(p)):
                return self.l3plugin._core_plugin._make_port_dict(p)

    def _check_for_multiprefix_csnat_port_and_update(self, context, router,
                                                     network_id, subnet_id):
        """Checks if the csnat port contains multiple ipv6 prefixes.

        If the csnat port contains multiple ipv6 prefixes for the given
        network when a router interface is deleted, make sure we don't
        delete the port when a single subnet is deleted and just update
        it with the right fixed_ip.
        This function returns true if it is a multiprefix port.
        """
        if router.gw_port:
            # If router has a gateway port, check if it has IPV6 subnet
            cs_port = (
                self._find_v6_router_port_by_network_and_device_owner(
                    router, network_id, const.DEVICE_OWNER_ROUTER_SNAT))
            if cs_port:
                fixed_ips = (
                    [fixedip for fixedip in
                        cs_port['fixed_ips']
                        if fixedip['subnet_id'] != subnet_id])

                if len(fixed_ips) == len(cs_port['fixed_ips']):
                    # The subnet being detached from router is not part of
                    # ipv6 router port. No need to update the multiprefix.
                    return False

                if fixed_ips:
                    # multiple prefix port - delete prefix from port
                    self.l3plugin._core_plugin.update_port(
                        context.elevated(),
                        cs_port['id'], {'port': {'fixed_ips': fixed_ips}})
                    return True
        return False

    @registry.receives(resources.ROUTER_INTERFACE, [events.BEFORE_DELETE])
    def _cache_related_dvr_routers_info_before_interface_removal(
            self, resource, event, trigger, payload=None):
        router_id = payload.resource_id
        subnet_id = payload.metadata.get("subnet_id")
        context = payload.context

        router = self.l3plugin._get_router(context, router_id)
        if not router.extra_attributes.distributed:
            return

        cache_key = (router_id, subnet_id)
        existing_hosts = self.related_dvr_router_hosts.pop(cache_key, set())
        other_hosts = set(self._get_other_dvr_hosts(context, router_id))
        self.related_dvr_router_hosts[cache_key] = existing_hosts | other_hosts

        existing_routers = self.related_dvr_router_routers.pop(cache_key,
                                                               set())
        other_routers = set(self._get_other_dvr_router_ids_connected_router(
            context, router_id))
        self.related_dvr_router_routers[cache_key] = (
            existing_routers | other_routers)

    @registry.receives(resources.ROUTER_INTERFACE, [events.AFTER_DELETE])
    @db_api.retry_if_session_inactive()
    def _cleanup_after_interface_removal(self, resource, event, trigger,
                                         context, port, interface_info,
                                         router_id, **kwargs):
        """Handler to cleanup distributed resources after intf removal."""
        router = self.l3plugin._get_router(context, router_id)
        if not router.extra_attributes.distributed:
            return

        # we calculate which hosts to notify by checking the hosts for
        # the removed port's subnets and then subtract out any hosts still
        # hosting the router for the remaining interfaces
        router_hosts_for_removed = self.l3plugin._get_dvr_hosts_for_subnets(
            context, subnet_ids={ip['subnet_id'] for ip in port['fixed_ips']})
        router_hosts_after = self.l3plugin._get_dvr_hosts_for_router(
            context, router_id)
        removed_hosts = set(router_hosts_for_removed) - set(router_hosts_after)
        if removed_hosts:
            # Get hosts where this router is placed as "related" to other dvr
            # routers and don't remove it from such hosts
            related_hosts = self._get_other_dvr_hosts(context, router_id)
            agents = self.l3plugin.get_l3_agents(
                context, filters={'host': removed_hosts})
            bindings = rb_obj.RouterL3AgentBinding.get_objects(
                context, router_id=router_id)
            snat_binding = bindings.pop() if bindings else None
            connected_dvr_routers = set(
                self.l3plugin._get_other_dvr_router_ids_connected_router(
                    context, router_id))
            for agent in agents:
                is_this_snat_agent = (
                    snat_binding and snat_binding.l3_agent_id == agent['id'])
                if (not is_this_snat_agent and
                        agent['host'] not in related_hosts):
                    self.l3plugin.l3_rpc_notifier.router_removed_from_agent(
                        context, router_id, agent['host'])
                    for connected_router_id in connected_dvr_routers:
                        connected_router_hosts = set(
                            self.l3plugin._get_dvr_hosts_for_router(
                                context, connected_router_id))
                        connected_router_hosts |= set(
                            self._get_other_dvr_hosts(
                                context, connected_router_id))
                        if agent['host'] not in connected_router_hosts:
                            self.l3plugin.l3_rpc_notifier.\
                                router_removed_from_agent(
                                    context, connected_router_id,
                                    agent['host'])
        # if subnet_id not in interface_info, request was to remove by port
        sub_id = (interface_info.get('subnet_id') or
                  port['fixed_ips'][0]['subnet_id'])
        self._cleanup_related_hosts_after_interface_removal(
            context, router_id, sub_id)
        self._cleanup_related_routers_after_interface_removal(
            context, router_id, sub_id)
        is_multiple_prefix_csport = (
            self._check_for_multiprefix_csnat_port_and_update(
                context, router, port['network_id'], sub_id))
        if not is_multiple_prefix_csport:
            # Single prefix port - go ahead and delete the port
            self.delete_csnat_router_interface_ports(
                context.elevated(), router, subnet_id=sub_id)

    def _cleanup_related_hosts_after_interface_removal(
            self, context, router_id, subnet_id):
        router_hosts = self.l3plugin._get_dvr_hosts_for_router(
            context, router_id)

        cache_key = (router_id, subnet_id)
        related_dvr_router_hosts_before = self.related_dvr_router_hosts.pop(
            cache_key, set())
        related_dvr_router_hosts_after = set(self._get_other_dvr_hosts(
            context, router_id))
        related_dvr_router_hosts_before -= set(router_hosts)
        related_removed_hosts = (
            related_dvr_router_hosts_before - related_dvr_router_hosts_after)
        if related_removed_hosts:
            agents = self.l3plugin.get_l3_agents(
                context, filters={'host': related_removed_hosts})
            bindings = rb_obj.RouterL3AgentBinding.get_objects(
                context, router_id=router_id)
            snat_binding = bindings.pop() if bindings else None
            for agent in agents:
                is_this_snat_agent = (
                    snat_binding and snat_binding.l3_agent_id == agent['id'])
                if not is_this_snat_agent:
                    self.l3plugin.l3_rpc_notifier.router_removed_from_agent(
                        context, router_id, agent['host'])

    def _cleanup_related_routers_after_interface_removal(
            self, context, router_id, subnet_id):
        router_hosts = self.l3plugin._get_dvr_hosts_for_router(
            context, router_id)

        cache_key = (router_id, subnet_id)
        related_dvr_routers_before = self.related_dvr_router_routers.pop(
            cache_key, set())
        related_dvr_routers_after = set(
            self._get_other_dvr_router_ids_connected_router(
                context, router_id))
        related_routers_to_remove = (
            related_dvr_routers_before - related_dvr_routers_after)

        for related_router in related_routers_to_remove:
            related_router_hosts = self.l3plugin._get_dvr_hosts_for_router(
                context, related_router)
            hosts_to_remove = set(router_hosts) - set(related_router_hosts)
            for host in hosts_to_remove:
                self.l3plugin.l3_rpc_notifier.router_removed_from_agent(
                    context, related_router, host)

    def delete_csnat_router_interface_ports(self, context,
                                            router, subnet_id=None):
        # Each csnat router interface port is associated
        # with a subnet, so we need to pass the subnet id to
        # delete the right ports.
        filters = {'device_owner': [const.DEVICE_OWNER_ROUTER_SNAT],
                   'device_id': [router.id]}
        c_snat_ports = self.l3plugin._core_plugin.get_ports(
            context,
            filters=filters
        )
        for p in c_snat_ports:
            if subnet_id is None or not p['fixed_ips']:
                if not p['fixed_ips']:
                    LOG.info("CSNAT port has no IPs: %s", p)
                self.l3plugin._core_plugin.delete_port(context,
                                                       p['id'],
                                                       l3_port_check=False)
            else:
                if p['fixed_ips'][0]['subnet_id'] == subnet_id:
                    LOG.debug("Subnet matches: %s", subnet_id)
                    self.l3plugin._core_plugin.delete_port(context,
                                                           p['id'],
                                                           l3_port_check=False)

    def _get_ext_nets_by_host(self, context, host):
        ext_nets = set()
        ports_ids = port_obj.Port.get_ports_by_host(context, host)
        for port_id in ports_ids:
            fips = self._get_floatingips_by_port_id(context, port_id)
            for fip in fips:
                ext_nets.add(fip.floating_network_id)
        return ext_nets

    @registry.receives(resources.AGENT, [events.AFTER_CREATE])
    def create_fip_agent_gw_ports(self, resource, event,
                                  trigger, payload=None):
        """Create floating agent gw ports for DVR L3 agent.

        Create floating IP Agent gateway ports when an L3 agent is created.
        """
        if not payload:
            return
        agent = payload.latest_state
        if agent.get('agent_type') != const.AGENT_TYPE_L3:
            return
        # NOTE(slaweq) agent is passed in payload as dict so to avoid getting
        # again from db, lets just get configuration from this dict directly
        l3_agent_mode = agent.get('configurations', {}).get('agent_mode')
        if l3_agent_mode not in [const.L3_AGENT_MODE_DVR,
                                 const.L3_AGENT_MODE_DVR_SNAT]:
            return

        host = agent['host']
        context = payload.context.elevated()
        for ext_net in self._get_ext_nets_by_host(context, host):
            self.create_fip_agent_gw_port_if_not_exists(
                context, ext_net, host)

    @registry.receives(resources.AGENT, [events.AFTER_DELETE])
    def delete_fip_agent_gw_ports(self, resource, event,
                                  trigger, payload=None):
        """Delete floating agent gw ports for DVR.

        Delete floating IP Agent gateway ports from host when an L3 agent is
        deleted.
        """
        if not payload:
            return
        agent = payload.latest_state
        if agent.get('agent_type') != const.AGENT_TYPE_L3:
            return
        if self._get_agent_mode(agent) not in [const.L3_AGENT_MODE_DVR,
                                               const.L3_AGENT_MODE_DVR_SNAT]:
            return

        agent_gw_ports = self._get_agent_gw_ports(payload.context, agent['id'])
        for gw_port in agent_gw_ports:
            self._core_plugin.delete_port(payload.context, gw_port['id'])


class _DVRAgentInterfaceMixin(object):
    """Contains calls made by the DVR scheduler and RPC interface.

    Must be instantiated as a mixin with the L3 plugin.
    """

    def _get_snat_sync_interfaces(self, context, router_ids):
        """Query router interfaces that relate to list of router_ids."""
        if not router_ids:
            return []
        objs = l3_obj.RouterPort.get_objects(
            context,
            router_id=router_ids,
            port_type=const.DEVICE_OWNER_ROUTER_SNAT)

        interfaces = collections.defaultdict(list)
        for rp in objs:
            # TODO(lujinluo): Need Port as synthetic field
            interfaces[rp.router_id].append(
                self._core_plugin._make_port_dict(rp.db_obj.port))
        LOG.debug("Return the SNAT ports: %s", interfaces)
        return interfaces

    def _get_gateway_port_host(self, context, router, gw_ports):
        binding_objs = rb_obj.RouterL3AgentBinding.get_objects(
            context, router_id=[router['id']])
        if not binding_objs:
            return

        gw_port_id = router['gw_port_id']
        # Collect gw ports only if available
        if gw_port_id and gw_ports.get(gw_port_id):
            l3_agent = ag_obj.Agent.get_object(context,
                                               id=binding_objs[0].l3_agent_id)
            return l3_agent.host

    def _build_routers_list(self, context, routers, gw_ports):
        # Perform a single query up front for all routers
        routers = super(_DVRAgentInterfaceMixin, self)._build_routers_list(
            context, routers, gw_ports)
        for router in routers:
            gw_port_host = self._get_gateway_port_host(
                context, router, gw_ports)
            LOG.debug("Set router %s gateway port host: %s",
                      router['id'], gw_port_host)
            router['gw_port_host'] = gw_port_host

        return routers

    def _process_routers(self, context, routers, agent):
        routers_dict = {}
        snat_intfs_by_router_id = self._get_snat_sync_interfaces(
            context, [r['id'] for r in routers])
        fip_agent_gw_ports = None
        LOG.debug("FIP Agent: %s ", agent.id)
        for router in routers:
            routers_dict[router['id']] = router
            if router['gw_port_id']:
                snat_router_intfs = snat_intfs_by_router_id[router['id']]
                LOG.debug("SNAT ports returned: %s ", snat_router_intfs)
                router[const.SNAT_ROUTER_INTF_KEY] = snat_router_intfs
                if not fip_agent_gw_ports:
                    fip_agent_gw_ports = self._get_fip_agent_gw_ports(
                        context, agent.id)
                    LOG.debug("FIP Agent ports: %s", fip_agent_gw_ports)
                router[const.FLOATINGIP_AGENT_INTF_KEY] = (
                    fip_agent_gw_ports)

        return routers_dict

    @staticmethod
    def _get_floating_ip_host(floating_ip):
        """Function to return floating IP host binding state

        By default, floating IPs are not bound to any host.  Instead
        of using the empty string to denote this use a constant.
        """
        return floating_ip.get('host', const.FLOATING_IP_HOST_UNBOUND)

    def _process_floating_ips_dvr(self, context, routers_dict,
                                  floating_ips, host, agent):
        LOG.debug("FIP Agent : %s ", agent.id)
        for floating_ip in floating_ips:
            router = routers_dict.get(floating_ip['router_id'])
            if router:
                if router['distributed']:
                    if self._skip_floating_ip_for_mismatched_agent_or_host(
                            floating_ip, agent, host):
                        continue
                router_floatingips = router.get(const.FLOATINGIP_KEY, [])
                router_floatingips.append(floating_ip)
                router[const.FLOATINGIP_KEY] = router_floatingips

    def _skip_floating_ip_for_mismatched_agent_or_host(self, floating_ip,
                                                       agent, host):
        """Function to check if floating IP processing can be skipped."""
        fip_host = self._get_floating_ip_host(floating_ip)

        # Skip if it is unbound
        if fip_host == const.FLOATING_IP_HOST_UNBOUND:
            return True

        # Skip if the given agent is in the wrong mode - SNAT bound
        # requires DVR_SNAT agent.
        agent_mode = self._get_agent_mode(agent)
        if (agent_mode in [const.L3_AGENT_MODE_LEGACY,
                           const.L3_AGENT_MODE_DVR] and
                floating_ip.get(const.DVR_SNAT_BOUND)):
            return True

        # Skip if it is bound, but not to the given host
        fip_dest_host = floating_ip.get('dest_host')
        if (fip_host != const.FLOATING_IP_HOST_NEEDS_BINDING and
                fip_host != host and fip_dest_host is None):
            return True

        # not being skipped, log host
        LOG.debug("Floating IP host: %s", fip_host)
        return False

    def _get_fip_agent_gw_ports(self, context, fip_agent_id):
        """Return list of floating agent gateway ports for the agent."""
        if not fip_agent_id:
            return []
        filters = {'device_id': [fip_agent_id],
                   'device_owner': [const.DEVICE_OWNER_AGENT_GW]}
        ports = self._core_plugin.get_ports(context.elevated(), filters)
        LOG.debug("Return the FIP ports: %s ", ports)
        return ports

    @log_helper.log_method_call
    def _get_dvr_sync_data(self, context, host, agent, router_ids=None,
                           active=None):
        routers, interfaces, floating_ips = self._get_router_info_list(
            context, router_ids=router_ids, active=active,
            device_owners=const.ROUTER_INTERFACE_OWNERS)
        dvr_router_ids = set(router['id'] for router in routers
                             if is_distributed_router(router))
        floating_ip_port_ids = [fip['port_id'] for fip in floating_ips
                                if fip['router_id'] in dvr_router_ids]
        if floating_ip_port_ids:
            port_filter = {'id': floating_ip_port_ids}
            ports = self._core_plugin.get_ports(context, port_filter)
            port_dict = {}
            for port in ports:
                # Make sure that we check for cases were the port
                # might be in a pre-live migration state or also
                # check for the portbinding profile 'migrating_to'
                # key for the host.
                port_profile = port.get(portbindings.PROFILE)
                port_in_migration = (
                    port_profile and
                    port_profile.get('migrating_to') == host)
                # All unbound ports with floatingip irrespective of
                # the device owner should be included as valid ports
                # and updated.
                if port_in_migration or self._is_unbound_port(port):
                    port_dict.update({port['id']: port})
                    continue
                port_host = port[portbindings.HOST_ID]
                if port_host:
                    l3_agent_on_host = self.get_l3_agents(
                        context,
                        filters={'host': [port_host]})
                    l3_agent_mode = ''
                    if len(l3_agent_on_host):
                        l3_agent_mode = self._get_agent_mode(
                            l3_agent_on_host[0])
                    requesting_agent_mode = self._get_agent_mode(agent)
                    # Consider the ports where the portbinding host and
                    # request host match.
                    if port_host == host:
                        # Check for agent type before adding the port_dict.
                        # For VMs that are hosted on the dvr_no_external
                        # agent and if the request is coming from the same
                        # agent on re-syncs then we need to add the appropriate
                        # port['agent'] before updating the dict.
                        if (l3_agent_mode == (
                            const.L3_AGENT_MODE_DVR_NO_EXTERNAL) and
                            requesting_agent_mode == (
                                const.L3_AGENT_MODE_DVR_NO_EXTERNAL)):
                            port['agent'] = (
                                const.L3_AGENT_MODE_DVR_NO_EXTERNAL)

                        port_dict.update({port['id']: port})
                    # Consider the ports where the portbinding host and
                    # request host does not match.
                    else:
                        # If the agent requesting is dvr_snat but
                        # the portbinding host resides in dvr_no_external
                        # agent then include the port.
                        if (l3_agent_mode == (
                            const.L3_AGENT_MODE_DVR_NO_EXTERNAL) and
                            requesting_agent_mode == (
                                const.L3_AGENT_MODE_DVR_SNAT)):
                            port['agent'] = (
                                const.L3_AGENT_MODE_DVR_NO_EXTERNAL)
                            port_dict.update({port['id']: port})
            # Add the port binding host to the floatingip dictionary
            for fip in floating_ips:
                # Assume no host binding required
                fip['host'] = const.FLOATING_IP_HOST_UNBOUND
                vm_port = port_dict.get(fip['port_id'], None)
                if vm_port:
                    # Default value if host port-binding required
                    fip['host'] = const.FLOATING_IP_HOST_NEEDS_BINDING
                    port_host = vm_port[portbindings.HOST_ID]
                    if port_host:
                        fip['dest_host'] = (
                            self._get_dvr_migrating_service_port_hostid(
                                context, fip['port_id'], port=vm_port))
                        vm_port_agent_mode = vm_port.get('agent', None)
                        if (vm_port_agent_mode !=
                                const.L3_AGENT_MODE_DVR_NO_EXTERNAL):
                            # For floatingip configured on ports that do not
                            # reside on a 'dvr_no_external' agent, add the
                            # fip host binding, else it will be created
                            # in the 'dvr_snat' agent.
                            fip['host'] = port_host
                    # Handle the case were there is no host binding
                    # for the private ports that are associated with
                    # floating ip.
                    if fip['host'] == const.FLOATING_IP_HOST_NEEDS_BINDING:
                        fip[const.DVR_SNAT_BOUND] = True
        routers_dict = self._process_routers(context, routers, agent)
        self._process_floating_ips_dvr(context, routers_dict,
                                       floating_ips, host, agent)
        ports_to_populate = []
        for router in routers_dict.values():
            if router.get('gw_port'):
                ports_to_populate.append(router['gw_port'])
            if router.get(const.FLOATINGIP_AGENT_INTF_KEY):
                ports_to_populate += router[const.FLOATINGIP_AGENT_INTF_KEY]
            if router.get(const.SNAT_ROUTER_INTF_KEY):
                ports_to_populate += router[const.SNAT_ROUTER_INTF_KEY]
        ports_to_populate += interfaces
        self._populate_mtu_and_subnets_for_ports(context, ports_to_populate)
        self._process_interfaces(routers_dict, interfaces)
        return list(routers_dict.values())

    def _is_unbound_port(self, port):
        """Check for port-bindings irrespective of device_owner."""
        return not port[portbindings.HOST_ID]

    def _get_dvr_service_port_hostid(self, context, port_id, port=None):
        """Returns the portbinding host_id for dvr service port."""
        port_db = port or self._core_plugin.get_port(context, port_id)
        return port_db[portbindings.HOST_ID] or None

    def _get_dvr_migrating_service_port_hostid(self, context, port_id,
                                               port=None):
        """Returns the migrating host_id from the migrating profile."""
        port_db = port or self._core_plugin.get_port(context, port_id)
        port_profile = port_db.get(portbindings.PROFILE)
        port_dest_host = None
        if port_profile:
            port_dest_host = port_profile.get('migrating_to')
            return port_dest_host

    def _get_agent_gw_ports_exist_for_network(
            self, context, network_id, host, agent_id):
        """Return agent gw port if exist, or None otherwise."""
        if not network_id:
            LOG.debug("Network not specified")
            return

        filters = {
            'network_id': [network_id],
            'device_id': [agent_id],
            'device_owner': [const.DEVICE_OWNER_AGENT_GW]
        }
        ports = self._core_plugin.get_ports(context, filters)
        if ports:
            return ports[0]

    def _get_agent_gw_ports(self, context, agent_id):
        """Return agent gw ports."""
        filters = {
            'device_id': [agent_id],
            'device_owner': [const.DEVICE_OWNER_AGENT_GW]
        }
        return self._core_plugin.get_ports(context, filters)

    def check_for_fip_and_create_agent_gw_port_on_host_if_not_exists(
            self, context, port, host):
        """Create fip agent_gw_port on host if not exists"""
        fips = self._get_floatingips_by_port_id(context, port['id'])
        if not fips:
            return
        fip = fips[0]
        network_id = fip.get('floating_network_id')
        self.create_fip_agent_gw_port_if_not_exists(
            context.elevated(), network_id, host)

    def create_fip_agent_gw_port_if_not_exists(self, context, network_id,
                                               host):
        """Function to return the FIP Agent GW port.

        This function will create a FIP Agent GW port
        if required. If the port already exists, it
        will return the existing port and will not
        create a new one.
        """
        try:
            l3_agent_db = self._get_agent_by_type_and_host(
                context, const.AGENT_TYPE_L3, host)
        except agent_exc.AgentNotFoundByTypeHost:
            LOG.warning("%(ag)s agent not found for the given host: %(host)s",
                        {'ag': const.AGENT_TYPE_L3,
                         'host': host})
            return

        l3_agent_mode = self._get_agent_mode(l3_agent_db)
        if l3_agent_mode == const.L3_AGENT_MODE_DVR_NO_EXTERNAL:
            return

        LOG.debug("Agent ID exists: %s", l3_agent_db['id'])
        agent_port = self._get_agent_gw_ports_exist_for_network(
            context, network_id, host, l3_agent_db['id'])
        if not agent_port:
            LOG.info("Floating IP Agent Gateway port for network %(network)s "
                     "does not exist on host %(host)s. Creating one.",
                     {'network': network_id,
                      'host': host})
            fip_agent_port_obj = l3_obj.DvrFipGatewayPortAgentBinding(
                context,
                network_id=network_id,
                agent_id=l3_agent_db['id']
            )
            try:
                fip_agent_port_obj.create()
            except o_exc.NeutronDbObjectDuplicateEntry:
                LOG.debug("Floating IP Gateway port agent binding for network "
                          "%(network)s already exists on host %(host)s. "
                          "Probably it was just created by other worker.",
                          {'network': network_id,
                           'host': host})
                agent_port = self._get_agent_gw_ports_exist_for_network(
                    context, network_id, host, l3_agent_db['id'])
            if agent_port:
                LOG.debug("Floating IP Agent Gateway port %(gw)s found "
                          "for the destination host: %(dest_host)s",
                          {'gw': agent_port,
                           'dest_host': host})
            else:
                port_data = {'tenant_id': '',
                             'network_id': network_id,
                             'device_id': l3_agent_db['id'],
                             'device_owner': const.DEVICE_OWNER_AGENT_GW,
                             portbindings.HOST_ID: host,
                             'admin_state_up': True,
                             'name': ''}
                agent_port = plugin_utils.create_port(
                    self._core_plugin, context, {'port': port_data})
                if not agent_port:
                    fip_agent_port_obj.delete()
                    msg = _("Unable to create Floating IP Agent Gateway port")
                    raise n_exc.BadRequest(resource='router', msg=msg)
                LOG.debug("Floating IP Agent Gateway port %(gw)s created "
                          "for the destination host: %(dest_host)s",
                          {'gw': agent_port,
                           'dest_host': host})

        self._populate_mtu_and_subnets_for_ports(context, [agent_port])
        return agent_port

    def _generate_arp_table_and_notify_agent(self, context, fixed_ip,
                                             mac_address, notifier):
        """Generates the arp table entry and notifies the l3 agent."""
        ip_address = fixed_ip['ip_address']
        subnet = fixed_ip['subnet_id']
        arp_table = {'ip_address': ip_address,
                     'mac_address': mac_address,
                     'subnet_id': subnet}
        filters = {'fixed_ips': {'subnet_id': [subnet]},
                   'device_owner': [const.DEVICE_OWNER_DVR_INTERFACE]}
        ports = self._core_plugin.get_ports(context, filters=filters)
        routers = [port['device_id'] for port in ports]
        for router_id in routers:
            notifier(context, router_id, arp_table)

    def _get_subnet_id_for_given_fixed_ip(self, context, fixed_ip, port_dict):
        """Returns the subnet_id that matches the fixedip on a network."""
        filters = {'network_id': [port_dict['network_id']]}
        subnets = self._core_plugin.get_subnets(context, filters)
        for subnet in subnets:
            if ipam_utils.check_subnet_ip(subnet['cidr'], fixed_ip):
                return subnet['id']

    def _get_allowed_address_pair_fixed_ips(self, context, port_dict):
        """Returns all fixed_ips associated with the allowed_address_pair."""
        aa_pair_fixed_ips = []
        if port_dict.get('allowed_address_pairs'):
            for address_pair in port_dict['allowed_address_pairs']:
                aap_ip_cidr = address_pair['ip_address'].split("/")
                if len(aap_ip_cidr) == 1 or int(aap_ip_cidr[1]) == 32:
                    subnet_id = self._get_subnet_id_for_given_fixed_ip(
                        context, aap_ip_cidr[0], port_dict)
                    if subnet_id is not None:
                        fixed_ip = {'subnet_id': subnet_id,
                                    'ip_address': aap_ip_cidr[0]}
                        aa_pair_fixed_ips.append(fixed_ip)
                    else:
                        LOG.debug("Subnet does not match for the given "
                                  "fixed_ip %s for arp update", aap_ip_cidr[0])
        return aa_pair_fixed_ips

    def update_arp_entry_for_dvr_service_port(self, context, port_dict):
        """Notify L3 agents of ARP table entry for dvr service port.

        When a dvr service port goes up, look for the DVR router on
        the port's subnet, and send the ARP details to all
        L3 agents hosting the router to add it.
        If there are any allowed_address_pairs associated with the port
        those fixed_ips should also be updated in the ARP table.
        """
        fixed_ips = port_dict['fixed_ips']
        if not fixed_ips:
            return
        allowed_address_pair_fixed_ips = (
            self._get_allowed_address_pair_fixed_ips(context, port_dict))
        changed_fixed_ips = fixed_ips + allowed_address_pair_fixed_ips
        for fixed_ip in changed_fixed_ips:
            self._generate_arp_table_and_notify_agent(
                context, fixed_ip, port_dict['mac_address'],
                self.l3_rpc_notifier.add_arp_entry)

    def delete_arp_entry_for_dvr_service_port(self, context, port_dict,
                                              fixed_ips_to_delete=None):
        """Notify L3 agents of ARP table entry for dvr service port.

        When a dvr service port goes down, look for the DVR
        router on the port's subnet, and send the ARP details to all
        L3 agents hosting the router to delete it.
        If there are any allowed_address_pairs associated with the
        port, those fixed_ips should be removed from the ARP table.
        """
        fixed_ips = port_dict['fixed_ips']
        if not fixed_ips:
            return
        if not fixed_ips_to_delete:
            allowed_address_pair_fixed_ips = (
                self._get_allowed_address_pair_fixed_ips(context, port_dict))
            fixed_ips_to_delete = fixed_ips + allowed_address_pair_fixed_ips
        for fixed_ip in fixed_ips_to_delete:
            self._generate_arp_table_and_notify_agent(
                context, fixed_ip, port_dict['mac_address'],
                self.l3_rpc_notifier.del_arp_entry)

    def _get_address_pair_active_port_with_fip(
            self, context, port_dict, port_addr_pair_ip):
        port_valid_state = (port_dict['admin_state_up'] or
                            port_dict['status'] == const.PORT_STATUS_ACTIVE)
        if not port_valid_state:
            return
        fips = l3_obj.FloatingIP.get_objects(
            context, _pager=base_obj.Pager(limit=1),
            fixed_ip_address=netaddr.IPAddress(port_addr_pair_ip))
        return self._core_plugin.get_port(
            context, fips[0].fixed_port_id) if fips else None


class L3_NAT_with_dvr_db_mixin(_DVRAgentInterfaceMixin,
                               DVRResourceOperationHandler,
                               l3_attrs_db.ExtraAttributesMixin,
                               l3_db.L3_NAT_db_mixin):
    """Mixin class to enable DVR support."""
    router_device_owners = (
        l3_db.L3_NAT_db_mixin.router_device_owners +
        (const.DEVICE_OWNER_DVR_INTERFACE,
         const.DEVICE_OWNER_ROUTER_SNAT,
         const.DEVICE_OWNER_AGENT_GW))

    def _get_device_owner(self, context, router=None):
        """Get device_owner for the specified router."""
        router_is_uuid = isinstance(router, str)
        if router_is_uuid:
            router = self._get_router(context, router)
        if is_distributed_router(router):
            return const.DEVICE_OWNER_DVR_INTERFACE
        return super(L3_NAT_with_dvr_db_mixin,
                     self)._get_device_owner(context, router)

    @db_api.retry_if_session_inactive()
    def create_floatingip(self, context, floatingip,
                          initial_status=const.FLOATINGIP_STATUS_ACTIVE):
        floating_ip = self._create_floatingip(
            context, floatingip, initial_status)
        self._notify_floating_ip_change(context, floating_ip)
        return floating_ip

    def get_dvr_agent_on_host(self, context, fip_host):
        agent_filters = {'host': [fip_host]}
        return self.get_l3_agents(context, filters=agent_filters)

    def _notify_floating_ip_change(self, context, floating_ip):
        router_id = floating_ip['router_id']
        fixed_port_id = floating_ip['port_id']
        # we need to notify agents only in case Floating IP is associated
        if not router_id or not fixed_port_id:
            return

        try:
            # using admin context as router may belong to admin tenant
            router = self._get_router(context.elevated(), router_id)
        except l3_exc.RouterNotFound:
            LOG.warning("Router %s was not found. "
                        "Skipping agent notification.",
                        router_id)
            return

        if is_distributed_router(router):
            host = self._get_dvr_service_port_hostid(context, fixed_port_id)
            dest_host = self._get_dvr_migrating_service_port_hostid(
                context, fixed_port_id)
            if host is not None:
                l3_agent_on_host = self.get_dvr_agent_on_host(
                    context, host)
                if not l3_agent_on_host:
                    LOG.warning("No valid L3 agent found for the given host: "
                                "%s", host)
                    return
                agent_mode = self._get_agent_mode(l3_agent_on_host[0])
                if agent_mode == const.L3_AGENT_MODE_DVR_NO_EXTERNAL:
                    # If the agent hosting the fixed port is in
                    # 'dvr_no_external' mode, then set the host to None,
                    # since we would be centralizing the floatingip for
                    # those fixed_ports.
                    host = None

            if host is not None:
                self.l3_rpc_notifier.routers_updated_on_host(
                    context, [router_id], host)
                if dest_host and dest_host != host:
                    self.l3_rpc_notifier.routers_updated_on_host(
                        context, [router_id], dest_host)
            else:
                centralized_agent_list = self.list_l3_agents_hosting_router(
                    context.elevated(), router_id)['agents']
                for agent in centralized_agent_list:
                    self.l3_rpc_notifier.routers_updated_on_host(
                        context, [router_id], agent['host'])
        else:
            self.notify_router_updated(context, router_id)

    @db_api.retry_if_session_inactive()
    def update_floatingip(self, context, id, floatingip):
        old_floatingip, floatingip = self._update_floatingip(
            context, id, floatingip)
        self._notify_floating_ip_change(context, old_floatingip)
        if (floatingip['router_id'] != old_floatingip['router_id'] or
                floatingip['port_id'] != old_floatingip['port_id']):
            self._notify_floating_ip_change(context, floatingip)
        return floatingip

    @db_api.retry_if_session_inactive()
    def delete_floatingip(self, context, id):
        floating_ip = self._delete_floatingip(context, id)
        self._notify_floating_ip_change(context, floating_ip)

    @db_api.retry_if_session_inactive()
    def is_router_distributed(self, context, router_id):
        if router_id:
            return is_distributed_router(
                self.get_router(context.elevated(), router_id))
        return False

    def get_ports_under_dvr_connected_subnet(self, context, subnet_id):
        query = dvr_mac_db.get_ports_query_by_subnet_and_ip(context, subnet_id)
        ports = [p for p in query.all() if is_port_bound(p)]
        # TODO(slaweq): if there would be way to pass to neutron-lib only
        # list of extensions which actually should be processed, than setting
        # process_extensions=True below could avoid that second loop and
        # getting allowed_address_pairs for each of the ports
        ports_list = [
            self.l3plugin._core_plugin._make_port_dict(
                port, process_extensions=False)
            for port in ports
        ]
        ports_ids = [p['id'] for p in ports_list]
        allowed_address_pairs = (
            self._core_plugin.get_allowed_address_pairs_for_ports(
                context, ports_ids))
        for port in ports_list:
            port['allowed_address_pairs'] = allowed_address_pairs.get(
                port['id'], [])
        return ports_list


def is_distributed_router(router):
    """Return True if router to be handled is distributed."""
    # See if router is a request body
    if isinstance(router, dict):
        requested_router_type = router.get('distributed')
    # If not, see if router DB or OVO object contains Extra Attributes
    elif router.extra_attributes:
        requested_router_type = router.extra_attributes.distributed
    else:
        requested_router_type = None
    if validators.is_attr_set(requested_router_type):
        return requested_router_type
    return cfg.CONF.router_distributed
