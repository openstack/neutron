# Copyright 2013 VMware, Inc.
#
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

from neutron.db import model_base


class TzNetworkBinding(model_base.BASEV2):
    """Represents a binding of a virtual network with a transport zone.

    This model class associates a Neutron network with a transport zone;
    optionally a vlan ID might be used if the binding type is 'bridge'
    """
    __tablename__ = 'tz_network_bindings'

    # TODO(arosen) - it might be worth while refactoring the how this data
    # is stored later so every column does not need to be a primary key.
    network_id = Column(String(36),
                        ForeignKey('networks.id', ondelete="CASCADE"),
                        primary_key=True)
    # 'flat', 'vlan', stt' or 'gre'
    binding_type = Column(Enum('flat', 'vlan', 'stt', 'gre', 'l3_ext',
                               name='tz_network_bindings_binding_type'),
                          nullable=False, primary_key=True)
    phy_uuid = Column(String(36), primary_key=True, default='')
    vlan_id = Column(Integer, primary_key=True, autoincrement=False, default=0)

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


class NeutronNsxNetworkMapping(model_base.BASEV2):
    """Maps neutron network identifiers to NSX identifiers.

    Because of chained logical switches more than one mapping might exist
    for a single Neutron network.
    """
    __tablename__ = 'neutron_nsx_network_mappings'
    neutron_id = Column(String(36),
                        ForeignKey('networks.id', ondelete='CASCADE'),
                        primary_key=True)
    nsx_id = Column(String(36), primary_key=True)


class NeutronNsxSecurityGroupMapping(model_base.BASEV2):
    """Backend mappings for Neutron Security Group identifiers.

    This class maps a neutron security group identifier to the corresponding
    NSX security profile identifier.
    """

    __tablename__ = 'neutron_nsx_security_group_mappings'
    neutron_id = Column(String(36),
                        ForeignKey('securitygroups.id', ondelete="CASCADE"),
                        primary_key=True)
    nsx_id = Column(String(36), primary_key=True)


class NeutronNsxPortMapping(model_base.BASEV2):
    """Represents the mapping between neutron and nsx port uuids."""

    __tablename__ = 'neutron_nsx_port_mappings'
    neutron_id = Column(String(36),
                        ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    nsx_switch_id = Column(String(36))
    nsx_port_id = Column(String(36), nullable=False)

    def __init__(self, neutron_id, nsx_switch_id, nsx_port_id):
        self.neutron_id = neutron_id
        self.nsx_switch_id = nsx_switch_id
        self.nsx_port_id = nsx_port_id


class NeutronNsxRouterMapping(model_base.BASEV2):
    """Maps neutron router identifiers to NSX identifiers."""
    __tablename__ = 'neutron_nsx_router_mappings'
    neutron_id = Column(String(36),
                        ForeignKey('routers.id', ondelete='CASCADE'),
                        primary_key=True)
    nsx_id = Column(String(36))


class MultiProviderNetworks(model_base.BASEV2):
    """Networks provisioned through multiprovider extension."""

    __tablename__ = 'multi_provider_networks'
    network_id = Column(String(36),
                        ForeignKey('networks.id', ondelete="CASCADE"),
                        primary_key=True)

    def __init__(self, network_id):
        self.network_id = network_id
