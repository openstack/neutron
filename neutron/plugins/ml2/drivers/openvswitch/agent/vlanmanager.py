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

from neutron_lib import exceptions

from neutron._i18n import _


class VifIdNotFound(exceptions.NeutronException):
    message = _('VIF ID %(vif_id)s not found in any network managed by '
                'VLAN Manager')


class MappingAlreadyExists(exceptions.NeutronException):
    message = _('VLAN mapping for network with id %(net_id)s already exists')


class MappingNotFound(exceptions.NeutronException):
    message = _('Mapping for network %(net_id)s not found.')


class LocalVLANMapping(object):
    def __init__(self, vlan, network_type, physical_network, segmentation_id,
                 vif_ports=None):
        self.vlan = vlan
        self.network_type = network_type
        self.physical_network = physical_network
        self.segmentation_id = segmentation_id
        self.vif_ports = vif_ports or {}
        # set of tunnel ports on which packets should be flooded
        self.tun_ofports = set()

    def __str__(self):
        return ("lv-id = %s type = %s phys-net = %s phys-id = %s" %
                (self.vlan, self.network_type, self.physical_network,
                 self.segmentation_id))

    def __eq__(self, other):
        return all(hasattr(other, a) and getattr(self, a) == getattr(other, a)
                   for a in ['vlan',
                             'network_type',
                             'physical_network',
                             'segmentation_id',
                             'vif_ports'])

    def __hash__(self):
        return id(self)


class LocalVlanManager(object):
    """Singleton manager that maps internal VLAN mapping to external network
    segmentation ids.
    """

    def __new__(cls):
        if not hasattr(cls, '_instance'):
            cls._instance = super(LocalVlanManager, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'mapping'):
            self.mapping = {}

    def __contains__(self, key):
        return key in self.mapping

    def __iter__(self):
        for value in list(self.mapping.values()):
            yield value

    def items(self):
        for item in self.mapping.items():
            yield item

    def add(self, net_id, vlan, network_type, physical_network,
            segmentation_id, vif_ports=None):
        if net_id in self.mapping:
            raise MappingAlreadyExists(net_id=net_id)
        self.mapping[net_id] = LocalVLANMapping(
            vlan, network_type, physical_network, segmentation_id, vif_ports)

    def get_net_uuid(self, vif_id):
        for network_id, vlan_mapping in self.mapping.items():
            if vif_id in vlan_mapping.vif_ports:
                return network_id
        raise VifIdNotFound(vif_id=vif_id)

    def get(self, net_id):
        try:
            return self.mapping[net_id]
        except KeyError:
            raise MappingNotFound(net_id=net_id)

    def pop(self, net_id):
        try:
            return self.mapping.pop(net_id)
        except KeyError:
            raise MappingNotFound(net_id=net_id)
