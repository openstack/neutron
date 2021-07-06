# Copyright 2018 Ericsson
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron_lib import constants as nlib_const
from neutron_lib.placement import utils as place_utils
import os_resource_classes as orc
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class DeferredCall(object):
    '''Store a callable for later calling.

    This is hardly more than a parameterless lambda, but this way it's much
    easier to add a __str__ method to help logging.
    '''

    def __init__(self, func, *args, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def __str__(self):
        return '%s(%s)' % (
            self.func.__name__,
            ', '.join([repr(x) for x in self.args] +
                      ['%s=%s' % (k, repr(v))
                       for k, v in self.kwargs.items()]))

    def execute(self):
        return self.func(*self.args, **self.kwargs)


class PlacementState(object):
    '''Represents the desired state of the Placement DB.

    This represents the state of one Neutron agent
    and the physical devices handled by it.

    The sync operation is one-way from Neutron to Placement.
    The state known by Neutron always overrides what was previously stored
    in Placement.

    In order to sync the state known to us on top of another state
    known to Placement the most generic solution would entail:
    * Storing state as returned by 'show' methods.
    * Diffing two state objects and representing the diff results in terms of
      create/update/delete methods as appropriate.
    * Maybe having an alternate constructor so we can express the current state
      known to Placement (and queried by us via 'show' methods) as a
      PlacementState object. That way we could diff between either two
      heartbeats following each other, or a heartbeat and Placement contents.

    Fortunately the Placement API has update methods for many of its
    resources with create-or-update-all semantics. Therefore we have a chance
    to make this class simpler and only know about 'update' methods. This also
    avoids the diffing logic.

    By ignoring 'delete' here, we leave a few cleanup operations for the admin,
    that needs to be documented. For example deleting no longer used physnet
    traits.

    The methods below return DeferredCall objects containing a code reference
    to one of the Placement client lib methods plus the arguments to be passed
    to those methods. So you can just execute() those DeferredCalls when
    appropriate.
    '''

    def __init__(self,
                 rp_bandwidths,
                 rp_inventory_defaults,
                 rp_pkt_processing,
                 rp_pkt_processing_inventory_defaults,
                 driver_uuid_namespace,
                 agent_type,
                 hypervisor_rps,
                 device_mappings,
                 supported_vnic_types,
                 client):
        self._rp_bandwidths = rp_bandwidths
        self._rp_inventory_defaults = rp_inventory_defaults
        self._rp_pp = rp_pkt_processing
        self._rp_pp_inventory_defaults = rp_pkt_processing_inventory_defaults
        self._driver_uuid_namespace = driver_uuid_namespace
        self._agent_type = agent_type
        self._hypervisor_rps = hypervisor_rps
        self._device_mappings = device_mappings
        self._supported_vnic_types = supported_vnic_types
        self._client = client

    def _deferred_update_physnet_traits(self):
        traits = []
        for physnet, devices in self._device_mappings.items():
            for device in devices:
                if device in self._rp_bandwidths:
                    traits.append(
                        DeferredCall(
                            self._client.update_trait,
                            name=place_utils.physnet_trait(physnet)))
        return traits

    def _deferred_update_vnic_type_traits(self):
        traits = []
        for vnic_type in self._supported_vnic_types:
            traits.append(
                DeferredCall(
                    self._client.update_trait,
                    name=place_utils.vnic_type_trait(vnic_type)))
        return traits

    def deferred_update_traits(self):
        traits = []
        traits += self._deferred_update_physnet_traits()
        traits += self._deferred_update_vnic_type_traits()
        return traits

    def _deferred_create_agent_rps(self):
        # While an instance of this class represents a single agent,
        # that agent is allowed to handle devices of multiple hypervisors.
        # Since each hypervisor has its own root resource provider
        # we must create an agent RP under each hypervisor RP.
        rps = []
        for hypervisor in self._hypervisor_rps.values():
            agent_rp_name = '%s:%s' % (hypervisor['name'], self._agent_type)
            agent_rp_uuid = place_utils.agent_resource_provider_uuid(
                self._driver_uuid_namespace, hypervisor['name'])
            rps.append(
                DeferredCall(
                    self._client.ensure_resource_provider,
                    resource_provider={
                        'name': agent_rp_name,
                        'uuid': agent_rp_uuid,
                        'parent_provider_uuid': hypervisor['uuid']}))
        return rps

    def _deferred_create_device_rps(self):
        rps = []
        for device in self._rp_bandwidths:
            hypervisor = self._hypervisor_rps[device]
            rp_name = '%s:%s:%s' % (
                hypervisor['name'], self._agent_type, device)
            rp_uuid = place_utils.device_resource_provider_uuid(
                self._driver_uuid_namespace,
                hypervisor['name'],
                device)
            agent_rp_uuid = place_utils.agent_resource_provider_uuid(
                self._driver_uuid_namespace, hypervisor['name'])
            rps.append(
                DeferredCall(
                    self._client.ensure_resource_provider,
                    {'name': rp_name,
                     'uuid': rp_uuid,
                     'parent_provider_uuid': agent_rp_uuid}))
        return rps

    def deferred_create_resource_providers(self):
        agent_rps = self._deferred_create_agent_rps()
        device_rps = self._deferred_create_device_rps()

        rps = []
        rps.extend(agent_rps)
        rps.extend(device_rps)
        return rps

    def _deferred_update_agent_rp_traits(self, traits_):
        agent_rp_traits = []

        if not traits_:
            return agent_rp_traits

        # Remove hypervisor duplicates to avoid calling placement API multiple
        # times for the same hypervisor.
        hypervisors = set(h['name'] for h in self._hypervisor_rps.values())
        for hypervisor in hypervisors:
            agent_rp_uuid = place_utils.agent_resource_provider_uuid(
                self._driver_uuid_namespace, hypervisor)
            agent_rp_traits.append(
                DeferredCall(
                    self._client.update_resource_provider_traits,
                    resource_provider_uuid=agent_rp_uuid,
                    traits=traits_))

        return agent_rp_traits

    def deferred_update_resource_provider_traits(self):
        rp_traits = []

        physnet_trait_mappings = {}
        for physnet, devices in self._device_mappings.items():
            for device in devices:
                physnet_trait_mappings[device] = place_utils.physnet_trait(
                    physnet)
        vnic_type_traits = [place_utils.vnic_type_trait(vnic_type)
                            for vnic_type
                            in self._supported_vnic_types]
        for device in self._rp_bandwidths:
            rp_uuid = place_utils.device_resource_provider_uuid(
                self._driver_uuid_namespace,
                self._hypervisor_rps[device]['name'],
                device)
            traits = []
            traits.append(physnet_trait_mappings[device])
            traits.extend(vnic_type_traits)
            rp_traits.append(
                DeferredCall(
                    self._client.update_resource_provider_traits,
                    resource_provider_uuid=rp_uuid,
                    traits=traits))

        rp_traits += self._deferred_update_agent_rp_traits(vnic_type_traits)

        return rp_traits

    def _deferred_update_rp_pp_inventory(self):
        agent_rp_inventories = []

        for hypervisor, pp_values in self._rp_pp.items():
            agent_rp_uuid = place_utils.agent_resource_provider_uuid(
                self._driver_uuid_namespace, hypervisor)

            inventories = {}
            for direction, rp_class in (
                    (nlib_const.EGRESS_DIRECTION,
                     orc.NET_PACKET_RATE_EGR_KILOPACKET_PER_SEC),
                    (nlib_const.INGRESS_DIRECTION,
                     orc.NET_PACKET_RATE_IGR_KILOPACKET_PER_SEC),
                    (nlib_const.ANY_DIRECTION,
                     orc.NET_PACKET_RATE_KILOPACKET_PER_SEC)):
                if pp_values.get(direction):
                    inventory = dict(self._rp_pp_inventory_defaults)
                    inventory['total'] = pp_values[direction]
                    inventories[rp_class] = inventory

            if inventories:
                agent_rp_inventories.append(
                    DeferredCall(
                        self._client.update_resource_provider_inventories,
                        resource_provider_uuid=agent_rp_uuid,
                        inventories=inventories))

        return agent_rp_inventories

    def _deferred_update_rp_bw_inventory(self):
        rp_inventories = []

        for device, bw_values in self._rp_bandwidths.items():
            rp_uuid = place_utils.device_resource_provider_uuid(
                self._driver_uuid_namespace,
                self._hypervisor_rps[device]['name'],
                device)

            inventories = {}
            for direction, rp_class in (
                    (nlib_const.EGRESS_DIRECTION,
                     orc.NET_BW_EGR_KILOBIT_PER_SEC),
                    (nlib_const.INGRESS_DIRECTION,
                     orc.NET_BW_IGR_KILOBIT_PER_SEC)):
                if bw_values.get(direction):
                    inventory = dict(self._rp_inventory_defaults)
                    inventory['total'] = bw_values[direction]
                    inventories[rp_class] = inventory

            if inventories:
                rp_inventories.append(
                    DeferredCall(
                        self._client.update_resource_provider_inventories,
                        resource_provider_uuid=rp_uuid,
                        inventories=inventories))

        return rp_inventories

    def deferred_update_resource_provider_inventories(self):
        bw_inventory = self._deferred_update_rp_bw_inventory()
        pp_inventory = self._deferred_update_rp_pp_inventory()

        inventories = []
        inventories.extend(bw_inventory)
        inventories.extend(pp_inventory)
        return inventories

    def deferred_sync(self):
        state = []
        state += self.deferred_update_traits()
        state += self.deferred_create_resource_providers()
        state += self.deferred_update_resource_provider_traits()
        state += self.deferred_update_resource_provider_inventories()
        return state
