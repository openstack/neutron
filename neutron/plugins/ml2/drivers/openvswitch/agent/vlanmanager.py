# Copyright 2016 Red Hat, Inc
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

from collections import defaultdict

from neutron_lib import exceptions

from neutron._i18n import _


class VifIdNotFound(exceptions.NeutronException):
    message = _('VIF ID %(vif_id)s not found in any network managed by '
                'VLAN Manager')


class MappingAlreadyExists(exceptions.NeutronException):
    message = _('VLAN mapping for network with id %(net_id)s and '
                'segmentation id %(seg_id)s already exists')


class MappingNotFound(exceptions.NeutronException):
    message = _('Mapping VLAN for network %(net_id)s with segmentation id '
                '%(seg_id)s not found.')


class NotUniqMapping(exceptions.NeutronException):
    message = _('Mapping VLAN for network %(net_id)s should be unique.')


class LocalVLANMapping:
    def __init__(self, vlan, network_type, physical_network, segmentation_id,
                 vif_ports=None, tun_ofports=None):
        self.vlan = vlan
        self.network_type = network_type
        self.physical_network = physical_network
        self.segmentation_id = segmentation_id
        self.vif_ports = vif_ports or {}
        # set of tunnel ports on which packets should be flooded
        self.tun_ofports = tun_ofports or set()

    def __str__(self):
        return ("lv-id = %s type = %s phys-net = %s phys-id = %s "
                "tun_ofports = %s" %
                (self.vlan, self.network_type, self.physical_network,
                 self.segmentation_id, self.tun_ofports))

    def __eq__(self, other):
        return all(hasattr(other, a) and getattr(self, a) == getattr(other, a)
                   for a in ['vlan',
                             'network_type',
                             'physical_network',
                             'segmentation_id',
                             'vif_ports'])

    def __hash__(self):
        return id(self)


class LocalVlanManager:
    """Singleton manager that maps internal VLAN mapping to external network
    segmentation ids.
    """

    def __new__(cls):
        if not hasattr(cls, '_instance'):
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'mapping'):
            self.mapping = defaultdict(dict)

    def __contains__(self, key):
        return key in self.mapping

    def __iter__(self):
        yield from list(self.mapping.values())

    def items(self):
        yield from self.mapping.items()

    def add(self, net_id, vlan, network_type, physical_network,
            segmentation_id, vif_ports=None, tun_ofports=None):
        try:
            if self.get(net_id, segmentation_id):
                raise MappingAlreadyExists(
                    net_id=net_id, seg_id=segmentation_id)
        except MappingNotFound:
            pass
        self.mapping[net_id][segmentation_id] = LocalVLANMapping(
            vlan, network_type, physical_network, segmentation_id, vif_ports,
            tun_ofports)

    def get_net_and_segmentation_id(self, vif_id, net_uuid=None):
        # TODO(sahid): We should improve algorithm if net_uuid is passed.
        for network_id, vlan_mappings in self.mapping.items():
            for segmentation_id, vlan_mapping in vlan_mappings.items():
                if vif_id in vlan_mapping.vif_ports:
                    return network_id, segmentation_id
        raise VifIdNotFound(vif_id=vif_id)

    def get(self, net_id, segmentation_id):
        if net_id in self.mapping and segmentation_id in self.mapping[net_id]:
            return self.mapping[net_id][segmentation_id]
        raise MappingNotFound(net_id=net_id, seg_id=segmentation_id)

    def get_segments(self, net_id):
        if net_id not in self.mapping:
            raise MappingNotFound(net_id=net_id, seg_id="<all>")
        return self.mapping[net_id]

    def pop(self, net_id, segmentation_id):
        if self.get(net_id, segmentation_id):
            ret = self.mapping[net_id].pop(segmentation_id)
            # if it's the last seg id for a network, let's removed the network
            # entry as-well.
            if len(self.mapping[net_id]) == 0:
                del self.mapping[net_id]
            return ret

    def update_segmentation_id(self, net_id, segmentation_id):
        """Returns tuple with segmentation id, lvm in success or None, None"""
        if len(self.get_segments(net_id)) != 1:
            # Update of segmentation id can work only if network has one
            # segment. This is a design issue that should be fixed in
            # future. We should not accept segmentation update for a network.
            raise NotUniqMapping(net_id=net_id)
        mapping = list(self.mapping[net_id].values())[0]
        if mapping.segmentation_id == segmentation_id:
            # No need to update
            return None, None
        old = mapping.segmentation_id
        del self.mapping[net_id][old]
        mapping.segmentation_id = segmentation_id
        self.mapping[net_id][segmentation_id] = mapping
        return old, mapping
