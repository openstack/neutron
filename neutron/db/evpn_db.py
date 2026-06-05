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

from neutron_lib.db import api as db_api
from oslo_db import exception as os_db_exc
from oslo_log import log as logging

from neutron._i18n import _
from neutron.db.models import evpn as evpn_models
from neutron.db.models import vxlan_vlan_allocations as alloc_models
from neutron.db import models_v2
from neutron.services.evpn import exceptions as evpn_exc


LOG = logging.getLogger(__name__)

_EVPN_PHYSNET = 'ovn-evpn'


class EVPNVNIDbHelper:
    """Database helper for EVPN VNI allocation operations.

    This class provides VNI allocation/deallocation for routers. It is
    designed to be used via composition rather than inheritance.
    """

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

        Creates VNI allocation, VLAN allocation, mapping, and
        EVPN L3 instance in the correct order.

        :param context: Neutron request context (with active session)
        :param router_id: UUID of the router
        :param vni: VNI to allocate
        :returns: The allocated VNI (integer)
        :raises EVPNVNIInUse: If VNI is already allocated
        """
        vni_allocation = alloc_models.VNIAllocation(
            vni=vni, physnet=_EVPN_PHYSNET)
        context.session.add(vni_allocation)

        try:
            context.session.flush()
        except os_db_exc.DBDuplicateEntry:
            raise evpn_exc.EVPNVNIInUse(vni=vni)

        # TODO(jlibosva): Auto-allocate VLAN from range (Patch 2).
        # For now, use the VNI value as a placeholder VLAN ID.
        vlan_allocation = alloc_models.VLANAllocation(
            vlan_id=vni, physnet=_EVPN_PHYSNET)
        context.session.add(vlan_allocation)
        context.session.flush()

        mapping = alloc_models.VNIVLANMapping(
            vni_allocation_id=vni_allocation.id,
            vlan_allocation_id=vlan_allocation.id)
        context.session.add(mapping)
        context.session.flush()

        instance = evpn_models.EVPNL3Instance(
            router_id=router_id,
            mapping_id=mapping.id)
        context.session.add(instance)

        LOG.debug("Allocated EVPN VNI %s for router %s", vni, router_id)
        return vni

    def _allocate_auto_vni(self, context, router_id):
        """Auto-allocate a VNI for a router from the configured range.

        :param context: Neutron request context (with active session)
        :param router_id: UUID of the router
        :returns: The allocated VNI (integer)
        """
        # TODO(jlibosva): Implement auto-allocation from configured range
        raise NotImplementedError(
            _("EVPN VNI auto-allocation not yet implemented. "
              "Specify an explicit VNI."))

    @db_api.CONTEXT_WRITER
    def deallocate_vni_for_router(self, context, router_id):
        """Remove VNI/VLAN allocation for a router.

        Deletes the mapping row (CASCADE removes evpn_l3_instances),
        then deletes both allocation rows (RESTRICT is now clear).
        Safe to call if no VNI was allocated (e.g. router without EVPN).

        :param context: Neutron request context (with active session)
        :param router_id: UUID of the router
        """
        instance = context.session.query(
            evpn_models.EVPNL3Instance
        ).filter_by(router_id=router_id).first()
        if not instance:
            return

        mapping = instance.mapping
        vni_alloc_id = mapping.vni_allocation_id
        vlan_alloc_id = mapping.vlan_allocation_id

        context.session.query(
            alloc_models.VNIVLANMapping
        ).filter_by(id=mapping.id).delete(synchronize_session=False)

        context.session.query(
            alloc_models.VNIAllocation
        ).filter_by(id=vni_alloc_id).delete(synchronize_session=False)

        context.session.query(
            alloc_models.VLANAllocation
        ).filter_by(id=vlan_alloc_id).delete(synchronize_session=False)

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

        This is a standalone read method that can be called outside of
        callbacks.

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
