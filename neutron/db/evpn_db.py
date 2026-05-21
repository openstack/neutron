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

from neutron_lib import constants as n_const
from neutron_lib.db import api as db_api
from oslo_log import log as logging

from neutron.db.models import evpn as evpn_models
from neutron.db import models_v2
from neutron.db import vni_vlan_allocator
from neutron.services.evpn import exceptions as evpn_exc


LOG = logging.getLogger(__name__)

_EVPN_PHYSNET = 'ovn-evpn'
_MIN_VNI = 1
_MAX_VNI = n_const.MAX_VXLAN_VNI
_MIN_VLAN = n_const.MIN_VLAN_TAG
_MAX_VLAN = n_const.MAX_VLAN_TAG


class EVPNDbHelper:
    """Database helper for EVPN allocation operations.

    This class provides VNI/VLAN allocation/deallocation for routers.
    It delegates to VNIVLANAllocator for the generic allocation logic
    and owns the EVPN-specific L3 instance lifecycle.
    Designed to be used via composition rather than inheritance.
    """

    def __init__(self):
        self._allocator = vni_vlan_allocator.VNIVLANAllocator(
            vni_exhausted_exc=evpn_exc.EVPNNoVniAvailable,
            vlan_exhausted_exc=evpn_exc.EVPNNoVlanAvailable,
            vni_in_use_exc=evpn_exc.EVPNVNIInUse,
        )

    @db_api.retry_if_session_inactive()
    @db_api.CONTEXT_WRITER
    def allocate_vni_for_router(self, context, router_id, vni):
        """Allocate a VNI for a router.

        The physical network is the hardcoded _EVPN_PHYSNET constant.

        :param context: Neutron request context (with active session)
        :param router_id: UUID of the router
        :param vni: VNI to allocate; 0 means auto-allocate
        :returns: The allocated VNI (integer)
        :raises EVPNVNIInUse: If VNI is already allocated
        """
        if vni:
            return self._allocate_specific_vni(context, router_id, vni)
        return self._allocate_auto_vni(context, router_id)

    def _allocate_specific_vni(self, context, router_id, vni):
        """Allocate a specific VNI and a VLAN for a router.

        :param context: Neutron request context (with active session)
        :param router_id: UUID of the router
        :param vni: VNI to allocate
        :returns: The allocated VNI (integer)
        :raises EVPNVNIInUse: If VNI is already allocated
        """
        mapping_id, vni, _vlan_id = self._allocator.allocate_specific_vni(
            context, vni, _MIN_VLAN, _MAX_VLAN, _EVPN_PHYSNET)

        instance = evpn_models.EVPNL3Instance(
            router_id=router_id,
            mapping_id=mapping_id)
        context.session.add(instance)

        LOG.debug("Allocated EVPN VNI %s for router %s", vni, router_id)
        return vni

    def _allocate_auto_vni(self, context, router_id):
        """Auto-allocate a VNI for a router from the configured range.

        :param context: Neutron request context (with active session)
        :param router_id: UUID of the router
        :returns: The allocated VNI (integer)
        :raises EVPNNoVniAvailable: if no VNI remains in the range
        """
        mapping_id, vni, _vlan_id = self._allocator.allocate(
            context, _MIN_VNI, _MAX_VNI, _MIN_VLAN, _MAX_VLAN, _EVPN_PHYSNET)

        instance = evpn_models.EVPNL3Instance(
            router_id=router_id,
            mapping_id=mapping_id)
        context.session.add(instance)

        LOG.debug("Auto-allocated EVPN VNI %s for router %s", vni, router_id)
        return vni

    @db_api.retry_if_session_inactive()
    @db_api.CONTEXT_WRITER
    def deallocate_vni_for_router(self, context, router_id):
        """Remove VNI/VLAN allocation for a router.

        Delegates to VNIVLANAllocator.deallocate which deletes the mapping
        (CASCADE removes evpn_l3_instances) and both allocation rows.
        Safe to call if no VNI was allocated (e.g. router without EVPN).

        :param context: Neutron request context (with active session)
        :param router_id: UUID of the router
        """
        instance = context.session.query(
            evpn_models.EVPNL3Instance
        ).filter_by(router_id=router_id).first()
        if not instance:
            return

        mapping_id = instance.mapping_id
        context.session.delete(instance)

        self._allocator.deallocate(context, mapping_id)
        LOG.debug("Deallocated EVPN VNI for router %s", router_id)

    @db_api.retry_if_session_inactive()
    @db_api.CONTEXT_WRITER
    def remove_evpn_network_by_subnet(self, context, subnet_id):
        """Remove evpn_networks entry for the network owning a subnet.

        Called when a router interface is detached. Looks up the network_id
        from the subnet, then deletes the corresponding evpn_networks row.
        CASCADE will delete any evpn_advertised_ports for that network.
        Safe to call if no evpn_networks entry exists.

        :param context: Neutron request context
        :param subnet_id: UUID of the subnet being detached
        """
        context.session.query(
            evpn_models.EVPNNetwork
        ).filter(
            evpn_models.EVPNNetwork.network_id == context.session.query(
                models_v2.Subnet.network_id
            ).filter(
                models_v2.Subnet.id == subnet_id
            ).correlate(None).scalar_subquery()
        ).delete(synchronize_session=False)

        LOG.debug("Removed EVPN network entry for subnet %s", subnet_id)

    @db_api.retry_if_session_inactive()
    @db_api.CONTEXT_WRITER
    def advertise_port(self, context, port_id, network_id, router_id):
        """Enable EVPN advertisement for a port.

        Creates evpn_networks and evpn_advertised_ports entries. If the
        router has no EVPN L3 instance, the FK constraint on
        evpn_networks.router_id will cause the insert to fail.

        :param context: Neutron request context
        :param port_id: UUID of the port to advertise
        :param network_id: UUID of the port's network
        :param router_id: UUID of the router
        """
        evpn_network = evpn_models.EVPNNetwork(
            network_id=network_id,
            router_id=router_id)
        context.session.add(evpn_network)
        context.session.flush()

        advertised_port = evpn_models.EVPNAdvertisedPort(
            port_id=port_id,
            network_id=network_id)
        context.session.add(advertised_port)

        LOG.debug("EVPN advertise port %s on network %s for router %s",
                  port_id, network_id, router_id)

    @db_api.retry_if_session_inactive()
    @db_api.CONTEXT_READER
    def get_vni_for_router(self, context, router_id):
        """Get the VNI allocated to a router, or None if not allocated.

        :param context: Neutron request context
        :param router_id: UUID of the router
        :returns: VNI (integer) or None
        """
        instance = context.session.query(
            evpn_models.EVPNL3Instance
        ).filter_by(router_id=router_id).first()
        if not instance:
            return None
        return instance.mapping.vni_allocation.vni

    @db_api.retry_if_session_inactive()
    @db_api.CONTEXT_READER
    def get_vlan_for_router(self, context, router_id):
        """Get the VLAN ID allocated to a router.

        :param context: Neutron request context
        :param router_id: UUID of the router
        :returns: VLAN ID (integer)
        :raises EVPNVNINotFound: if no EVPN instance exists for the router
        """
        instance = context.session.query(
            evpn_models.EVPNL3Instance
        ).filter_by(router_id=router_id).first()
        if not instance:
            raise evpn_exc.EVPNVNINotFound(router_id=router_id)
        return instance.mapping.vlan_allocation.vlan_id
