# Copyright 2026 Red Hat, LLC
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

from neutron_lib.api.definitions import evpn as evpn_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import priority_group
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const
from neutron_lib.db import resource_extend
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from oslo_db import exception as db_exc
from oslo_log import log as logging

from neutron.db import evpn_db
from neutron.services.evpn import commands as evpn_ovn
from neutron.services.evpn import exceptions as evpn_exceptions

LOG = logging.getLogger(__name__)


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class EVPNPlugin(service_base.ServicePluginBase):
    """EVPN service plugin.

    This plugin extends the router API with an ``evpn_vni`` attribute
    and the router-interface API with EVPN advertisement controls.

    Router deletion with a VNI is blocked by RESTRICT FK - user must
    explicitly remove the VNI via update_router(evpn_vni=None) first.
    """

    supported_extension_aliases = [evpn_apidef.ALIAS]

    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self):
        super().__init__()
        self._evpn_db = evpn_db.EVPNDbHelper()
        self._ovn_mech_driver = None
        LOG.info("Starting EVPN service plugin")

    @property
    def _mech_driver(self):
        if self._ovn_mech_driver is None:
            plugin = directory.get_plugin()
            self._ovn_mech_driver = (
                plugin.mechanism_manager.mech_drivers['ovn'].obj)
        return self._ovn_mech_driver

    @property
    def _nb_idl(self):
        return self._mech_driver.nb_ovn

    @property
    def _sb_idl(self):
        return self._mech_driver.sb_ovn

    def get_plugin_description(self):
        return "EVPN service plugin"

    @classmethod
    def get_plugin_type(cls):
        return plugin_constants.EVPN

    @staticmethod
    @resource_extend.extends([l3_apidef.ROUTERS])
    def _extend_router_dict(router_res, router_db):
        LOG.debug("EVPN extending router dict router_res: %s "
                  "router_db: %s", router_res, router_db)
        router_res[evpn_apidef.EVPN_VNI] = None
        evpn_instance = router_db.get('evpn_instance')
        if evpn_instance:
            router_res[evpn_apidef.EVPN_VNI] = (
                evpn_instance.mapping.vni_allocation.vni)
        return router_res

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_CREATE])
    def _process_router_create(self, resource, event, trigger, payload):
        """Handle EVPN VNI allocation during router creation.

        If evpn_vni is specified in the request (including 0 for auto),
        allocate the VNI within the same transaction.
        """
        router = payload.latest_state
        router_id = payload.resource_id

        LOG.debug("Processing router create: %s", router)
        requested_vni = router[evpn_apidef.EVPN_VNI]
        if requested_vni is n_const.ATTR_NOT_SPECIFIED:
            LOG.debug("No EVPN VNI requested for router %s", router_id)
            return

        LOG.debug("Allocating EVPN VNI for router %s, requested_vni=%s",
                  router_id, requested_vni)

        vni = self._evpn_db.allocate_vni_for_router(
            payload.context, router_id, requested_vni)
        LOG.info("Allocated EVPN VNI %s for router %s", vni, router_id)

    @registry.receives(resources.ROUTER, [events.AFTER_CREATE],
                       priority=priority_group.PRIORITY_ROUTER_DRIVER)
    def _process_ovn_router_create(self, resource, event, trigger, payload):
        """Create EVPN OVN topology after router creation.

        Sets dynamic-routing options on the logical router so OVN
        treats it as an EVPN VRF.
        """
        router = payload.states[0]
        vni = router.get(evpn_apidef.EVPN_VNI)
        if not vni:
            return

        router_id = payload.resource_id
        vlan = self._evpn_db.get_vlan_for_router(payload.context, router_id)
        gw_chassis = self._sb_idl.get_gateway_chassis_from_cms_options()
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(evpn_ovn.CreateEVPNRouterCommand(
                self._nb_idl, router_id, vni, vlan, gw_chassis))

        LOG.info("Set EVPN dynamic-routing options for router %s VNI %s",
                 router_id, vni)

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_DELETE])
    def _process_router_delete(self, resource, event, trigger, payload):
        """Clean up EVPN VNI before router deletion.

        Must delete evpn_vnis first (CASCADE deletes evpn_router_instances)
        to satisfy RESTRICT FK on router_id before router is deleted.
        """
        context = payload.context
        router_id = payload.resource_id

        LOG.debug("Deallocating EVPN VNI for router %s", router_id)
        self._evpn_db.deallocate_vni_for_router(context, router_id)
        LOG.info("Deallocated EVPN VNI for router %s", router_id)

    @registry.receives(resources.ROUTER, [events.AFTER_DELETE],
                       priority=priority_group.PRIORITY_ROUTER_DRIVER)
    def _process_ovn_router_delete(self, resource, event, trigger, payload):
        """Delete EVPN OVN topology after router deletion.

        Deletes the dummy logical switch for the VNI bridge domain.
        The LR and its LRP are already deleted by the OvnDriver.
        """
        router = payload.states[0]
        vni = router.get(evpn_apidef.EVPN_VNI)
        if not vni:
            return

        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(evpn_ovn.DeleteEVPNRouterCommand(
                self._nb_idl, payload.resource_id, vni))

        LOG.info("Deleted EVPN OVN topology for router %s VNI %s",
                 payload.resource_id, vni)

    @registry.receives(resources.ROUTER_INTERFACE, [events.BEFORE_CREATE])
    def _process_router_interface_create(self, resource, event, trigger,
                                         payload):
        """Handle router interface addition for EVPN advertisement.

        If advertise_host is requested in the interface_info, create
        evpn_networks and evpn_advertised_ports entries within the same
        transaction as the router interface creation.
        """
        context = payload.context
        router_id = payload.resource_id
        interface_info = payload.metadata.get('interface_info', {})

        if not interface_info.get(evpn_apidef.ADVERTISE_HOST):
            LOG.debug("EVPN interface create no advertise_host requested: %s",
                     interface_info.get(evpn_apidef.ADVERTISE_HOST))
            return

        port = payload.metadata['port']
        network_id = port['network_id']
        port_id = port['id']

        try:
            self._evpn_db.advertise_port(
                context, port_id, network_id, router_id)
        except db_exc.DBReferenceError:
            raise evpn_exceptions.EVPNVNINotFound(router_id=router_id)
        LOG.info("EVPN advertise_host enabled for port %s on router %s and "
                 "network %s", port_id, router_id, network_id)

    @registry.receives(resources.ROUTER_INTERFACE, [events.AFTER_CREATE],
                       priority=priority_group.PRIORITY_ROUTER_DRIVER)
    def _process_ovn_router_interface_create(self, resource, event, trigger,
                                             payload):
        """Set advertise-host on the OVN logical router port.

        Sets dynamic-routing-redistribute=connected-as-host on the LRP
        so OVN adds host routes from this subnet to the EVPN VRF.
        """
        interface_info = payload.metadata.get('interface_info', {})
        if not interface_info.get(evpn_apidef.ADVERTISE_HOST):
            return

        port_id = payload.metadata['port']['id']
        with self._nb_idl.transaction(check_error=True) as txn:
            txn.add(evpn_ovn.AdvertiseHostCommand(
                self._nb_idl, port_id))

        LOG.info("Set EVPN advertise-host on LRP for port %s", port_id)

    @registry.receives(resources.ROUTER_INTERFACE, [events.BEFORE_DELETE])
    def _process_router_interface_delete(self, resource, event, trigger,
                                         payload):
        """Remove evpn_networks entry when subnet is detached from router.

        This ensures the RESTRICT FK on evpn_networks.network_id does not
        block future network deletion.
        """
        context = payload.context
        subnet_id = payload.metadata['subnet_id']
        LOG.debug("Removing EVPN network entry for subnet %s", subnet_id)
        self._evpn_db.remove_evpn_network_by_subnet(context, subnet_id)
        LOG.info("Removed EVPN network entry for subnet %s", subnet_id)
