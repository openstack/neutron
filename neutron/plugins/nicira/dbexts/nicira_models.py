# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira, Inc.
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


from sqlalchemy import Column, Enum, ForeignKey, Integer, String

from neutron.db.models_v2 import model_base


class NvpNetworkBinding(model_base.BASEV2):
    """Represents a binding of a virtual network with a transport zone.

    This model class associates a Neutron network with a transport zone;
    optionally a vlan ID might be used if the binding type is 'bridge'
    """
    __tablename__ = 'nvp_network_bindings'

    network_id = Column(String(36),
                        ForeignKey('networks.id', ondelete="CASCADE"),
                        primary_key=True)
    # 'flat', 'vlan', stt' or 'gre'
    binding_type = Column(Enum('flat', 'vlan', 'stt', 'gre', 'l3_ext',
                               name='nvp_network_bindings_binding_type'),
                          nullable=False)
    phy_uuid = Column(String(36))
    vlan_id = Column(Integer)

    def __init__(self, network_id, binding_type, phy_uuid, vlan_id):
        self.network_id = network_id
        self.binding_type = binding_type
        self.phy_uuid = phy_uuid
        self.vlan_id = vlan_id

    def __repr__(self):
        return "<NetworkBinding(%s,%s,%s,%s)>" % (self.network_id,
                                                  self.binding_type,
                                                  self.phy_uuid,
                                                  self.vlan_id)


class NeutronNvpPortMapping(model_base.BASEV2):
    """Represents the mapping between neutron and nvp port uuids."""

    __tablename__ = 'quantum_nvp_port_mapping'
    quantum_id = Column(String(36),
                        ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    nvp_id = Column(String(36))

    def __init__(self, quantum_id, nvp_id):
        self.quantum_id = quantum_id
        self.nvp_id = nvp_id
