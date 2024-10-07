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
from neutron_lib.api.definitions import l3 as l3_apidef
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
from neutron_lib.db import resource_extend
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import availability_zone as az_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from oslo_log import log

from neutron._i18n import _
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import extensions
from neutron.common.ovn import utils
from neutron.db.availability_zone import router as router_az_db
from neutron.db import dns_db
from neutron.db import extraroute_db
from neutron.db import l3_extra_gws_db
from neutron.db import l3_fip_pools_db
from neutron.db import l3_fip_port_details
from neutron.db import l3_fip_qos
from neutron.db import l3_gateway_ip_qos
from neutron.db import l3_gwmode_db
from neutron.db.models import l3 as l3_models
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_client
from neutron.quota import resource_registry
from neutron.scheduler import l3_ovn_scheduler
from neutron.services.ovn_l3 import exceptions as ovn_l3_exc
from neutron.services.ovn_l3.service_providers import driver_controller
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
                        l3_extra_gws_db.ExtraGatewaysDbOnlyMixin,
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
        self._initialize_plugin_driver()
        self._ovn_client_inst = None
        self.scheduler = l3_ovn_scheduler.get_scheduler()
        self.port_forwarding = port_forwarding.OVNPortForwarding(self)
        self.l3_driver_controller = driver_controller.DriverController(self)

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

    def _initialize_plugin_driver(self):
        # This method initializes the mechanism driver variable and checks
        # if any of the valid drivers ('ovn', 'ovn-sync') is loaded.
        drivers = ('ovn', 'ovn-sync')
        for driver in drivers:
            try:
                self._mech = self._plugin.mechanism_manager.mech_drivers[
                    driver].obj
                break
            except KeyError:
                pass
        else:
            raise ovn_l3_exc.MechanismDriverNotFound(mechanism_drivers=drivers)

    @property
    def _plugin_driver(self):
        if self._mech is None:
            self._initialize_plugin_driver()
        return self._mech

    def get_plugin_type(self):
        return plugin_constants.L3

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("L3 Router Service Plugin for basic L3 forwarding"
                " using OVN")

    def _add_neutron_router_interface(self, context, router_id,
                                      interface_info):
        try:
            router_interface_info = (
                super(OVNL3RouterPlugin, self).add_router_interface(
                    context, router_id, interface_info))
        except n_exc.PortInUse:
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

    def create_floatingip(self, context, floatingip,
                          initial_status=n_const.FLOATINGIP_STATUS_DOWN):
        # The OVN L3 plugin creates floating IPs in down status by default,
        # whereas the L3 DB layer creates them in active status. So we keep
        # this method to create the floating IP in the DB with status down,
        # while the flavor drivers are responsible for calling the correct
        # backend to instatiate the floating IP in the data plane
        return super(OVNL3RouterPlugin, self).create_floatingip(
            context, floatingip, initial_status)

    def update_floatingip_status(self, context, floatingip_id, status):
        fip = self.update_floatingip_status_retry(
            context, floatingip_id, status)
        registry.publish(
            resources.FLOATING_IP, events.AFTER_STATUS_UPDATE, self,
            payload=events.DBEventPayload(
                context, states=(fip,),
                resource_id=floatingip_id))
        return fip

    @db_api.retry_if_session_inactive()
    def update_floatingip_status_retry(self, context, floatingip_id, status):
        with db_api.CONTEXT_WRITER.using(context):
            return super(OVNL3RouterPlugin, self).update_floatingip_status(
                context, floatingip_id, status)

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
            if utils.is_ovn_provider_router(
                    l3plugin.get_router(context, port['device_id'])):
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
                # Updates OVN NB database with hostname for lsp router
                # gateway port
                with self._nb_ovn.transaction(check_error=True) as txn:
                    ext_ids = (
                        "external_ids",
                        {ovn_const.OVN_HOST_ID_EXT_ID_KEY: host},
                    )
                    txn.add(
                        self._nb_ovn.db_set(
                            "Logical_Switch_Port", port["id"], ext_ids
                        )
                    )
            if port['status'] != status:
                self._plugin.update_port_status(context, port['id'], status)

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

        self._reschedule_lrps(unhosted_gateways)

    def _reschedule_lrps(self, lrps):
        # GW ports and its physnets.
        port_physnet_dict = self._get_gateway_port_physnet_mapping()
        # All chassis with physnets configured.
        chassis_with_physnets = self._sb_ovn.get_chassis_and_physnets()
        # All chassis with enable_as_gw_chassis set
        all_gw_chassis = self._sb_ovn.get_gateway_chassis_from_cms_options()
        chassis_with_azs = self._sb_ovn.get_chassis_and_azs()

        with self._nb_ovn.transaction(check_error=True) as txn:
            for g_name in lrps:
                # NOTE(fnordahl): Make scheduling decissions in ovsdbapp
                # command so that scheduling is done based on up to date
                # information as the transaction is applied.
                #
                # We pass in a reference to our class instance so that the
                # ovsdbapp command can call the scheduler methods from within
                # its context.
                txn.add(self._nb_ovn.schedule_unhosted_gateways(
                    g_name, self._sb_ovn, self, port_physnet_dict,
                    all_gw_chassis, chassis_with_physnets, chassis_with_azs))

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
        router_ids = {port['device_id'] for port in gw_ports
                      if utils.is_ovn_provider_router(
                          l3plugin.get_router(context, port['device_id']))}
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
                utils.is_lsp_router_port(original) and
                utils.is_ovn_provider_router(
                    l3plugin.get_router(context, original['device_id']))):
            reason = _("Router port must have at least one IP.")
            raise n_exc.ServicePortInUse(port_id=original['id'], reason=reason)

        if (event == events.AFTER_UPDATE and
                utils.is_lsp_router_port(current) and
                utils.is_ovn_provider_router(
                    l3plugin.get_router(context, current['device_id']))):
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

    @staticmethod
    @resource_extend.extends([l3_apidef.ROUTERS])
    def add_flavor_id(router_res, router_db):
        router_res['flavor_id'] = router_db['flavor_id']
