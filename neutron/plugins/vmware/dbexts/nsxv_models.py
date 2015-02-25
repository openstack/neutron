# Copyright 2015 VMware, Inc.
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


import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db import l3_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.plugins.vmware.common import nsxv_constants


class NsxvRouterBinding(model_base.BASEV2, models_v2.HasStatusDescription):
    """Represents the mapping between neutron router and vShield Edge."""

    __tablename__ = 'nsxv_router_bindings'

    # no ForeignKey to routers.id because for now, a router can be removed
    # from routers when delete_router is executed, but the binding is only
    # removed after the Edge is deleted
    router_id = sa.Column(sa.String(36),
                          primary_key=True)
    edge_id = sa.Column(sa.String(36),
                        nullable=True)
    lswitch_id = sa.Column(sa.String(36),
                           nullable=True)
    appliance_size = sa.Column(sa.Enum(
        nsxv_constants.COMPACT,
        nsxv_constants.LARGE,
        nsxv_constants.XLARGE,
        nsxv_constants.QUADLARGE,
        name='nsxv_router_bindings_appliance_size'))
    edge_type = sa.Column(sa.Enum(nsxv_constants.SERVICE_EDGE,
                                  nsxv_constants.VDR_EDGE,
                                  name='nsxv_router_bindings_edge_type'))


class NsxvEdgeVnicBinding(model_base.BASEV2):
    """Represents mapping between vShield Edge vnic and neutron netowrk."""

    __tablename__ = 'nsxv_edge_vnic_bindings'

    edge_id = sa.Column(sa.String(36),
                        primary_key=True)
    vnic_index = sa.Column(sa.Integer(),
                           primary_key=True)
    tunnel_index = sa.Column(sa.Integer(),
                             primary_key=True)
    network_id = sa.Column(sa.String(36), nullable=True)


class NsxvEdgeDhcpStaticBinding(model_base.BASEV2):
    """Represents mapping between mac addr and bindingId."""

    __tablename__ = 'nsxv_edge_dhcp_static_bindings'

    edge_id = sa.Column(sa.String(36), primary_key=True)
    mac_address = sa.Column(sa.String(32), primary_key=True)
    binding_id = sa.Column(sa.String(36), nullable=False)


class NsxvInternalNetworks(model_base.BASEV2):
    """Represents internal networks between NSXV plugin elements."""

    __tablename__ = 'nsxv_internal_networks'

    network_purpose = sa.Column(
        sa.Enum(nsxv_constants.INTER_EDGE_PURPOSE,
                name='nsxv_internal_networks_purpose'),
        primary_key=True)
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("networks.id", ondelete="CASCADE"),
                           nullable=True)


class NsxvInternalEdges(model_base.BASEV2):
    """Represents internal Edge appliances for NSXV plugin operations."""

    __tablename__ = 'nsxv_internal_edges'

    ext_ip_address = sa.Column(sa.String(64), primary_key=True)
    router_id = sa.Column(sa.String(36), nullable=True)
    purpose = sa.Column(
        sa.Enum(nsxv_constants.INTER_EDGE_PURPOSE,
                name='nsxv_internal_edges_purpose'))


class NsxvSecurityGroupSectionMapping(model_base.BASEV2):
    """Backend mappings for Neutron Rule Sections.

    This class maps a neutron security group identifier to the corresponding
    NSX layer 3 section.
    """

    __tablename__ = 'nsxv_security_group_section_mappings'
    neutron_id = sa.Column(sa.String(36),
                           sa.ForeignKey('securitygroups.id',
                                         ondelete="CASCADE"),
                           primary_key=True)
    ip_section_id = sa.Column(sa.String(100))


class NsxvRuleMapping(model_base.BASEV2):
    """Backend mappings for Neutron Rule Sections.

    This class maps a neutron security group identifier to the corresponding
    NSX layer 3 and layer 2 sections.
    """

    __tablename__ = 'nsxv_rule_mappings'

    neutron_id = sa.Column(sa.String(36),
                           sa.ForeignKey('securitygrouprules.id',
                                         ondelete="CASCADE"),
                           primary_key=True)
    nsx_rule_id = sa.Column(sa.String(36), primary_key=True)


class NsxvPortVnicMapping(model_base.BASEV2):
    """Maps neutron port to NSXv VM Vnic Id."""

    __tablename__ = 'nsxv_port_vnic_mappings'

    neutron_id = sa.Column(sa.String(36),
                           sa.ForeignKey('ports.id', ondelete="CASCADE"),
                           primary_key=True)
    nsx_id = sa.Column(sa.String(42), primary_key=True)


class NsxvRouterExtAttributes(model_base.BASEV2):
    """Router attributes managed by NSX plugin extensions."""

    __tablename__ = 'nsxv_router_ext_attributes'

    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True)
    distributed = sa.Column(sa.Boolean, default=False, nullable=False)
    router_type = sa.Column(
        sa.Enum('shared', 'exclusive',
                name='nsxv_router_type'),
        default='exclusive', nullable=False)
    service_router = sa.Column(sa.Boolean, default=False, nullable=False)
    # Add a relationship to the Router model in order to instruct
    # SQLAlchemy to eagerly load this association
    router = orm.relationship(
        l3_db.Router,
        backref=orm.backref("nsx_attributes", lazy='joined',
                            uselist=False, cascade='delete'))


class NsxvTzNetworkBinding(model_base.BASEV2):
    """Represents a binding of a virtual network with a transport zone.

    This model class associates a Neutron network with a transport zone;
    optionally a vlan ID might be used if the binding type is 'bridge'
    """

    __tablename__ = 'nsxv_tz_network_bindings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    binding_type = sa.Column(
        sa.Enum('flat', 'vlan', 'portgroup',
                name='nsxv_tz_network_bindings_binding_type'),
        nullable=False, primary_key=True)
    phy_uuid = sa.Column(sa.String(36), primary_key=True, nullable=True)
    vlan_id = sa.Column(sa.Integer, primary_key=True, nullable=True,
                        autoincrement=False)

    def __init__(self, network_id, binding_type, phy_uuid, vlan_id):
        self.network_id = network_id
        self.binding_type = binding_type
        self.phy_uuid = phy_uuid
        self.vlan_id = vlan_id

    def __repr__(self):
        return "<NsxvTzNetworkBinding(%s,%s,%s,%s)>" % (self.network_id,
                                                        self.binding_type,
                                                        self.phy_uuid,
                                                        self.vlan_id)


class NsxvPortIndexMapping(model_base.BASEV2):
    """Associates attached Neutron ports with the instance VNic index."""

    __tablename__ = 'nsxv_port_index_mappings'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    device_id = sa.Column(sa.String(255), nullable=False)
    index = sa.Column(sa.Integer, nullable=False)
    __table_args__ = (sa.UniqueConstraint(device_id, index),
                      model_base.BASEV2.__table_args__)

    # Add a relationship to the Port model in order to instruct SQLAlchemy to
    # eagerly read port vnic-index
    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref("vnic_index", lazy='joined',
                            uselist=False, cascade='delete'))


class NsxvEdgeFirewallRuleBinding(model_base.BASEV2):
    """Mapping between firewall rule and edge firewall rule_id."""

    __tablename__ = 'nsxv_firewall_rule_bindings'

    rule_id = sa.Column(sa.String(36),
                        primary_key=True)
    edge_id = sa.Column(sa.String(36), primary_key=True)
    rule_vse_id = sa.Column(sa.String(36))


class NsxvSpoofGuardPolicyNetworkMapping(model_base.BASEV2):
    """Mapping between SpoofGuard and neutron networks"""

    __tablename__ = 'nsxv_spoofguard_policy_network_mappings'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete='CASCADE'),
                           primary_key=True,
                           nullable=False)
    policy_id = sa.Column(sa.String(36), nullable=False)
