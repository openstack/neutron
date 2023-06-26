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
#

from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib.api.definitions import qos_fip as qos_fip_apidef
from neutron_lib.api.definitions import qos_gateway_ip as qos_gateway_ip_apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const
from neutron_lib import context as n_context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import availability_zone as az_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from oslo_log import log
from oslo_utils import excutils

from neutron._i18n import _
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import extensions
from neutron.common.ovn import utils
from neutron.common import utils as common_utils
from neutron.db.availability_zone import router as router_az_db
from neutron.db import dns_db
from neutron.db import extraroute_db
from neutron.db import l3_fip_pools_db
from neutron.db import l3_fip_port_details
from neutron.db import l3_fip_qos
from neutron.db import l3_gateway_ip_qos
from neutron.db import l3_gwmode_db
from neutron.db.models import l3 as l3_models
from neutron.db import ovn_revision_numbers_db as db_rev
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_client
from neutron.quota import resource_registry
from neutron.scheduler import l3_ovn_scheduler
from neutron.services.ovn_l3 import exceptions as ovn_l3_exc
from neutron.services.portforwarding.drivers.ovn import driver \
    as port_forwarding


LOG = log.getLogger(__name__)


@registry.has_registry_receivers
class OVNL3RouterPlugin(service_base.ServicePluginBase,
                        extraroute_db.ExtraRoute_dbonly_mixin,
                        l3_gwmode_db.L3_NAT_db_mixin,
                        dns_db.DNSDbMixin,
                        l3_fip_port_details.Fip_port_details_db_mixin,
                        router_az_db.RouterAvailabilityZoneMixin,
                        l3_fip_qos.FloatingQoSDbMixin,
                        l3_gateway_ip_qos.L3_gw_ip_qos_db_mixin,
                        l3_fip_pools_db.FloatingIPPoolsMixin,
                        ):
    """Implementation of the OVN L3 Router Service Plugin.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    """

    # TODO(mjozefcz): Start consuming it from neutron-lib
    # once available.
    _supported_extension_aliases = (
        extensions.ML2_SUPPORTED_API_EXTENSIONS_OVN_L3)
    __filter_validation_support = True

    @resource_registry.tracked_resources(router=l3_models.Router,
                                         floatingip=l3_models.FloatingIP)
    def __init__(self):
        LOG.info("Starting OVNL3RouterPlugin")
        super(OVNL3RouterPlugin, self).__init__()
        self._plugin_property = None
        self._mech = None
        self._ovn_client_inst = None
        self.scheduler = l3_ovn_scheduler.get_scheduler()
        self.port_forwarding = port_forwarding.OVNPortForwarding(self)
        self._register_precommit_callbacks()

    def _register_precommit_callbacks(self):
        registry.subscribe(
            self.create_router_precommit, resources.ROUTER,
            events.PRECOMMIT_CREATE)
        registry.subscribe(
            self.create_floatingip_precommit, resources.FLOATING_IP,
            events.PRECOMMIT_CREATE)

    @staticmethod
    def _disable_qos_extensions_by_extension_drivers(aliases):
        qos_service_plugin = directory.get_plugin(plugin_constants.QOS)
        qos_fip_in_aliases = qos_fip_apidef.ALIAS in aliases
        qos_gwip_in_aliases = qos_gateway_ip_apidef.ALIAS in aliases
        if not qos_service_plugin and qos_fip_in_aliases:
            aliases.remove(qos_fip_apidef.ALIAS)
        if not qos_service_plugin and qos_gwip_in_aliases:
            aliases.remove(qos_gateway_ip_apidef.ALIAS)

    @property
    def supported_extension_aliases(self):
        if not hasattr(self, '_aliases'):
            self._aliases = self._supported_extension_aliases[:]
            self._disable_qos_extensions_by_extension_drivers(self._aliases)
        return self._aliases

    @property
    def _ovn_client(self):
        if self._ovn_client_inst is None:
            self._ovn_client_inst = ovn_client.OVNClient(self._nb_ovn,
                                                         self._sb_ovn)
        return self._ovn_client_inst

    @property
    def _nb_ovn(self):
        return self._plugin_driver.nb_ovn

    @property
    def _sb_ovn(self):
        return self._plugin_driver.sb_ovn

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    @property
    def _plugin_driver(self):
        if self._mech is None:
            drivers = ('ovn', 'ovn-sync')
            for driver in drivers:
                try:
                    self._mech = self._plugin.mechanism_manager.mech_drivers[
                        driver].obj
                    break
                except KeyError:
                    pass
            else:
                raise ovn_l3_exc.MechanismDriverNotFound(
                        mechanism_drivers=drivers)
        return self._mech

    def get_plugin_type(self):
        return plugin_constants.L3

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("L3 Router Service Plugin for basic L3 forwarding"
                " using OVN")

    def create_router_precommit(self, resource, event, trigger, payload):
        context = payload.context
        router_id = payload.resource_id
        router_db = payload.metadata['router_db']

        db_rev.create_initial_revision(
            context, router_id, ovn_const.TYPE_ROUTERS,
            std_attr_id=router_db.standard_attr.id)

    def create_router(self, context, router):
        router = super(OVNL3RouterPlugin, self).create_router(context, router)
        try:
            self._ovn_client.create_router(context, router)
        except Exception:
            with excutils.save_and_reraise_exception():
                # Delete the logical router
                LOG.error('Unable to create lrouter for %s', router['id'])
                super(OVNL3RouterPlugin, self).delete_router(context,
                                                             router['id'])
        return router

    def update_router(self, context, id, router):
        original_router = self.get_router(context, id)
        result = super(OVNL3RouterPlugin, self).update_router(context, id,
                                                              router)
        try:
            self._ovn_client.update_router(context, result,
                                           original_router)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception('Unable to update lrouter for %s', id)
                revert_router = {'router': original_router}
                super(OVNL3RouterPlugin, self).update_router(context, id,
                                                             revert_router)
        return result

    def delete_router(self, context, id):
        original_router = self.get_router(context, id)
        super(OVNL3RouterPlugin, self).delete_router(context, id)
        try:
            self._ovn_client.delete_router(context, id)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(OVNL3RouterPlugin, self).create_router(
                    context, {'router': original_router})

    def _add_neutron_router_interface(self, context, router_id,
                                      interface_info, may_exist=False):
        try:
            router_interface_info = (
                super(OVNL3RouterPlugin, self).add_router_interface(
                    context, router_id, interface_info))
        except n_exc.PortInUse:
            if not may_exist:
                raise
            # NOTE(lucasagomes): If the port is already being used it means
            # the interface has been created already, let's just fetch it from
            # the database. Perhaps the code below should live in Neutron
            # itself, a get_router_interface() method in the main class
            # would be handy
            port = self._plugin.get_port(context, interface_info['port_id'])
            subnets = [self._plugin.get_subnet(context, s)
                       for s in utils.get_port_subnet_ids(port)]
            router_interface_info = (
                self._make_router_interface_info(
                    router_id, port['tenant_id'], port['id'],
                    port['network_id'], subnets[0]['id'],
                    [subnet['id'] for subnet in subnets]))

        return router_interface_info

    def add_router_interface(self, context, router_id, interface_info=None):
        router_interface_info = self._add_neutron_router_interface(
            context, router_id, interface_info)
        try:
            self._ovn_client.create_router_port(
                context, router_id, router_interface_info)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(OVNL3RouterPlugin, self).remove_router_interface(
                    context, router_id, router_interface_info)

        return router_interface_info

    def remove_router_interface(self, context, router_id, interface_info):
        router_interface_info = (
            super(OVNL3RouterPlugin, self).remove_router_interface(
                context, router_id, interface_info))
        try:
            port_id = router_interface_info['port_id']
            subnet_ids = router_interface_info.get('subnet_ids')
            self._ovn_client.delete_router_port(
                context, port_id, router_id=router_id, subnet_ids=subnet_ids)
        except Exception:
            with excutils.save_and_reraise_exception():
                super(OVNL3RouterPlugin, self).add_router_interface(
                    context, router_id, interface_info)
        return router_interface_info

    def create_floatingip_precommit(self, resource, event, trigger, payload):
        context = payload.context
        floatingip_id = payload.resource_id
        floatingip_db = payload.desired_state

        db_rev.create_initial_revision(
            context, floatingip_id, ovn_const.TYPE_FLOATINGIPS,
            std_attr_id=floatingip_db.standard_attr.id)

    def create_floatingip(self, context, floatingip,
                          initial_status=n_const.FLOATINGIP_STATUS_DOWN):
        fip = super(OVNL3RouterPlugin, self).create_floatingip(
            context, floatingip, initial_status)
        self._ovn_client.create_floatingip(context, fip)
        return fip

    def delete_floatingip(self, context, id):
        super(OVNL3RouterPlugin, self).delete_floatingip(context, id)
        self._ovn_client.delete_floatingip(context, id)

    def update_floatingip(self, context, id, floatingip):
        fip = super(OVNL3RouterPlugin, self).update_floatingip(context, id,
                                                               floatingip)
        self._ovn_client.update_floatingip(context, fip, floatingip)
        return fip

    def update_floatingip_status(self, context, floatingip_id, status):
        fip = self.update_floatingip_status_retry(
            context, floatingip_id, status)
        self._ovn_client.update_floatingip_status(context, fip)
        return fip

    @db_api.retry_if_session_inactive()
    def update_floatingip_status_retry(self, context, floatingip_id, status):
        with db_api.CONTEXT_WRITER.using(context):
            return super(OVNL3RouterPlugin, self).update_floatingip_status(
                context, floatingip_id, status)

    def disassociate_floatingips(self, context, port_id, do_notify=True):
        fips = self.get_floatingips(context.elevated(),
                                    filters={'port_id': [port_id]})
        router_ids = super(OVNL3RouterPlugin, self).disassociate_floatingips(
            context, port_id, do_notify)
        for fip in fips:
            router_id = fip.get('router_id')
            fixed_ip_address = fip.get('fixed_ip_address')
            if router_id and fixed_ip_address:
                update_fip = {
                    'id': fip['id'],
                    'logical_ip': fixed_ip_address,
                    'external_ip': fip['floating_ip_address'],
                    'floating_network_id': fip['floating_network_id']}
                try:
                    self._ovn_client.disassociate_floatingip(update_fip,
                                                             router_id)
                    self.update_floatingip_status(
                        context, fip['id'], n_const.FLOATINGIP_STATUS_DOWN)
                except Exception as e:
                    LOG.error('Error in disassociating floatingip %(id)s: '
                              '%(error)s', {'id': fip['id'], 'error': e})
        return router_ids

    def _get_gateway_port_physnet_mapping(self):
        # This function returns all gateway ports with corresponding
        # external network's physnet
        net_physnet_dict = {}
        port_physnet_dict = {}
        l3plugin = directory.get_plugin(plugin_constants.L3)
        if not l3plugin:
            return port_physnet_dict
        context = n_context.get_admin_context()
        for net in l3plugin._plugin.get_networks(
                context, {external_net.EXTERNAL: [True]}):
            if net.get(pnet.NETWORK_TYPE) in [n_const.TYPE_FLAT,
                                              n_const.TYPE_VLAN]:
                net_physnet_dict[net['id']] = net.get(pnet.PHYSICAL_NETWORK)
        for port in l3plugin._plugin.get_ports(context, filters={
                'device_owner': [n_const.DEVICE_OWNER_ROUTER_GW]}):
            port_physnet_dict[port['id']] = net_physnet_dict.get(
                port['network_id'])
        return port_physnet_dict

    def update_router_gateway_port_bindings(self, router, host):
        status = (n_const.PORT_STATUS_ACTIVE if host
                  else n_const.PORT_STATUS_DOWN)
        context = n_context.get_admin_context()
        filters = {'device_id': [router],
                   'device_owner': [n_const.DEVICE_OWNER_ROUTER_GW]}
        for port in self._plugin.get_ports(context, filters=filters):
            # FIXME(lucasagomes): Ideally here we would use only
            # one database transaction for the status and binding the
            # host but, even tho update_port_status() receives a "host"
            # parameter apparently it doesn't work for ports which the
            # device owner is router_gateway. We need to look into it and
            # fix the problem in Neutron before updating it here.
            if host:
                port = self._plugin.update_port(
                    context, port['id'],
                    {'port': {portbindings.HOST_ID: host}})

            if port['status'] != status:
                self._plugin.update_port_status(context, port['id'], status)

    def _get_availability_zones_from_router_port(self, lrp_name):
        """Return the availability zones hints for the router port.

        Return a list of availability zones hints associated with the
        router that the router port belongs to.
        """
        context = n_context.get_admin_context()
        if not self._plugin_driver.list_availability_zones(context):
            return []

        lrp = self._nb_ovn.get_lrouter_port(lrp_name)
        router = self.get_router(
            context, lrp.external_ids[ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY])
        az_hints = common_utils.get_az_hints(router)
        return az_hints

    def schedule_unhosted_gateways(self, event_from_chassis=None):
        # GW ports and its physnets.
        port_physnet_dict = self._get_gateway_port_physnet_mapping()
        # Filter out unwanted ports in case of event.
        if event_from_chassis:
            gw_chassis = self._nb_ovn.get_chassis_gateways(
                chassis_name=event_from_chassis)
            if not gw_chassis:
                return
            ports_impacted = []
            for gwc in gw_chassis:
                try:
                    ports_impacted.append(utils.get_port_id_from_gwc_row(gwc))
                except AttributeError:
                    # Malformed GWC format.
                    pass
            port_physnet_dict = {
                k: v
                for k, v in port_physnet_dict.items()
                if k in ports_impacted}
        if not port_physnet_dict:
            return
        # All chassis with physnets configured.
        chassis_with_physnets = self._sb_ovn.get_chassis_and_physnets()
        # All chassis with enable_as_gw_chassis set
        all_gw_chassis = self._sb_ovn.get_gateway_chassis_from_cms_options()
        chassis_with_azs = self._sb_ovn.get_chassis_and_azs()
        unhosted_gateways = self._nb_ovn.get_unhosted_gateways(
            port_physnet_dict, chassis_with_physnets,
            all_gw_chassis, chassis_with_azs)
        for g_name in unhosted_gateways:
            physnet = port_physnet_dict.get(g_name[len(ovn_const.LRP_PREFIX):])
            # Remove any invalid gateway chassis from the list, otherwise
            # we can have a situation where all existing_chassis are invalid
            existing_chassis = self._nb_ovn.get_gateway_chassis_binding(g_name)
            primary = existing_chassis[0] if existing_chassis else None
            az_hints = self._nb_ovn.get_gateway_chassis_az_hints(g_name)
            existing_chassis = self.scheduler.filter_existing_chassis(
                nb_idl=self._nb_ovn, gw_chassis=all_gw_chassis,
                physnet=physnet, chassis_physnets=chassis_with_physnets,
                existing_chassis=existing_chassis, az_hints=az_hints,
                chassis_with_azs=chassis_with_azs)

            candidates = self._ovn_client.get_candidates_for_scheduling(
                physnet, cms=all_gw_chassis,
                chassis_physnets=chassis_with_physnets,
                availability_zone_hints=az_hints)
            chassis = self.scheduler.select(
                self._nb_ovn, self._sb_ovn, g_name, candidates=candidates,
                existing_chassis=existing_chassis)
            if primary and primary != chassis[0]:
                if primary not in chassis:
                    LOG.debug("Primary gateway chassis %(old)s "
                              "has been removed from the system. Moving "
                              "gateway %(gw)s to other chassis %(new)s.",
                              {'gw': g_name,
                               'old': primary,
                               'new': chassis[0]})
                else:
                    LOG.debug("Gateway %s is hosted at %s.", g_name, primary)
                    # NOTE(mjozefcz): It means scheduler moved primary chassis
                    # to other gw based on scheduling method. But we don't
                    # want network flap - so moving actual primary to be on
                    # the top.
                    index = chassis.index(primary)
                    chassis[0], chassis[index] = chassis[index], chassis[0]
            # NOTE(dalvarez): Let's commit the changes in separate transactions
            # as we will rely on those for scheduling subsequent gateways.
            with self._nb_ovn.transaction(check_error=True) as txn:
                txn.add(self._nb_ovn.update_lrouter_port(
                    g_name, gateway_chassis=chassis))

    @staticmethod
    @registry.receives(resources.SUBNET, [events.AFTER_UPDATE])
    def _subnet_update(resource, event, trigger, payload):
        l3plugin = directory.get_plugin(plugin_constants.L3)
        if not l3plugin:
            return
        context = payload.context
        orig = payload.states[0]
        current = payload.latest_state
        orig_gw_ip = orig['gateway_ip']
        current_gw_ip = current['gateway_ip']
        if orig_gw_ip == current_gw_ip:
            return
        gw_ports = l3plugin._plugin.get_ports(context, filters={
            'network_id': [orig['network_id']],
            'device_owner': [n_const.DEVICE_OWNER_ROUTER_GW],
            'fixed_ips': {'subnet_id': [orig['id']]},
        })
        router_ids = {port['device_id'] for port in gw_ports}
        remove = [{'destination': '0.0.0.0/0', 'nexthop': orig_gw_ip}
                  ] if orig_gw_ip else []
        add = [{'destination': '0.0.0.0/0', 'nexthop': current_gw_ip}
               ] if current_gw_ip else []
        with l3plugin._nb_ovn.transaction(check_error=True) as txn:
            for router_id in router_ids:
                l3plugin._ovn_client.update_router_routes(
                    context, router_id, add, remove, txn=txn)

    @staticmethod
    @registry.receives(
        resources.PORT,
        [events.BEFORE_UPDATE, events.AFTER_UPDATE]
    )
    def _port_update(resource, event, trigger, payload):
        l3plugin = directory.get_plugin(plugin_constants.L3)
        if not l3plugin:
            return

        context = payload.context
        current = payload.latest_state
        original = payload.states[0]

        # The OVN NB DB has a constraint where network has to be
        # greater than 0. Updating it with an empty network would
        # cause a constraint violation error. This problem happens
        # when the last IP of a LRP is deleted, in order to avoid it
        # an exception needs to be thrown before any write is performed
        # to the DB, since if not it would leave the Neutron DB and the
        # OVN DB unsync.
        # https://bugs.launchpad.net/neutron/+bug/1948457
        if (event == events.BEFORE_UPDATE and
                'fixed_ips' in current and not current['fixed_ips'] and
                utils.is_lsp_router_port(original)):
            reason = _("Router port must have at least one IP.")
            raise n_exc.ServicePortInUse(port_id=original['id'], reason=reason)

        if event == events.AFTER_UPDATE and utils.is_lsp_router_port(current):
            # We call the update_router port with if_exists, because neutron,
            # internally creates the port, and then calls update, which will
            # trigger this callback even before we had the chance to create
            # the OVN NB DB side
            l3plugin._ovn_client.update_router_port(context,
                                                    current, if_exists=True)

    def get_router_availability_zones(self, router):
        lr = self._nb_ovn.get_lrouter(router['id'])
        if not lr:
            return []

        return [az.strip() for az in lr.external_ids.get(
                ovn_const.OVN_AZ_HINTS_EXT_ID_KEY, '').split(',')
                if az.strip()]

    def validate_availability_zones(self, context, resource_type,
                                    availability_zones):
        """Verify that the availability zones exist."""
        if not availability_zones or resource_type != 'router':
            return

        azs = {az['name'] for az in
               self._plugin_driver.list_availability_zones(context).values()}
        diff = set(availability_zones) - azs
        if diff:
            raise az_exc.AvailabilityZoneNotFound(
                availability_zone=', '.join(diff))
