# Copyright 2015 VMware, Inc.
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

"""
NSX data models.

This module defines data models used by the VMware NSX plugin family.

"""

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy import sql

from neutron.db import model_base
from neutron.db import models_v2


class TzNetworkBinding(model_base.BASEV2):
    """Represents a binding of a virtual network with a transport zone.

    This model class associates a Neutron network with a transport zone;
    optionally a vlan ID might be used if the binding type is 'bridge'
    """
    __tablename__ = 'tz_network_bindings'

    # TODO(arosen) - it might be worth while refactoring the how this data
    # is stored later so every column does not need to be a primary key.
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    # 'flat', 'vlan', stt' or 'gre'
    binding_type = sa.Column(sa.Enum('flat', 'vlan', 'stt', 'gre', 'l3_ext',
                             name='tz_network_bindings_binding_type'),
                             nullable=False, primary_key=True)
    phy_uuid = sa.Column(sa.String(36), primary_key=True, default='')
    vlan_id = sa.Column(sa.Integer, primary_key=True,
                        autoincrement=False, default=0)

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
    neutron_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete='CASCADE'),
                           primary_key=True)
    nsx_id = sa.Column(sa.String(36), primary_key=True)


class NeutronNsxSecurityGroupMapping(model_base.BASEV2):
    """Backend mappings for Neutron Security Group identifiers.

    This class maps a neutron security group identifier to the corresponding
    NSX security profile identifier.
    """

    __tablename__ = 'neutron_nsx_security_group_mappings'
    neutron_id = sa.Column(sa.String(36),
                           sa.ForeignKey('securitygroups.id',
                                         ondelete="CASCADE"),
                           primary_key=True)
    nsx_id = sa.Column(sa.String(36), primary_key=True)


class NeutronNsxPortMapping(model_base.BASEV2):
    """Represents the mapping between neutron and nsx port uuids."""

    __tablename__ = 'neutron_nsx_port_mappings'
    neutron_id = sa.Column(sa.String(36),
                           sa.ForeignKey('ports.id', ondelete="CASCADE"),
                           primary_key=True)
    nsx_switch_id = sa.Column(sa.String(36))
    nsx_port_id = sa.Column(sa.String(36), nullable=False)

    def __init__(self, neutron_id, nsx_switch_id, nsx_port_id):
        self.neutron_id = neutron_id
        self.nsx_switch_id = nsx_switch_id
        self.nsx_port_id = nsx_port_id


class NeutronNsxRouterMapping(model_base.BASEV2):
    """Maps neutron router identifiers to NSX identifiers."""
    __tablename__ = 'neutron_nsx_router_mappings'
    neutron_id = sa.Column(sa.String(36),
                           sa.ForeignKey('routers.id', ondelete='CASCADE'),
                           primary_key=True)
    nsx_id = sa.Column(sa.String(36))


class MultiProviderNetworks(model_base.BASEV2):
    """Networks provisioned through multiprovider extension."""

    __tablename__ = 'multi_provider_networks'
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)

    def __init__(self, network_id):
        self.network_id = network_id


class NetworkConnection(model_base.BASEV2, models_v2.HasTenant):
    """Defines a connection between a network gateway and a network."""
    # We use port_id as the primary key as one can connect a gateway
    # to a network in multiple ways (and we cannot use the same port form
    # more than a single gateway)
    network_gateway_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('networkgateways.id',
                                                 ondelete='CASCADE'))
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete='CASCADE'))
    segmentation_type = sa.Column(
        sa.Enum('flat', 'vlan',
                name='networkconnections_segmentation_type'))
    segmentation_id = sa.Column(sa.Integer)
    __table_args__ = (sa.UniqueConstraint(network_gateway_id,
                                          segmentation_type,
                                          segmentation_id),
                      model_base.BASEV2.__table_args__)
    # Also, storing port id comes back useful when disconnecting a network
    # from a gateway
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete='CASCADE'),
                        primary_key=True)


class NetworkGatewayDeviceReference(model_base.BASEV2):
    id = sa.Column(sa.String(36), primary_key=True)
    network_gateway_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('networkgateways.id',
                                                 ondelete='CASCADE'),
                                   primary_key=True)
    interface_name = sa.Column(sa.String(64), primary_key=True)


class NetworkGatewayDevice(model_base.BASEV2, models_v2.HasId,
                           models_v2.HasTenant):
    nsx_id = sa.Column(sa.String(36))
    # Optional name for the gateway device
    name = sa.Column(sa.String(255))
    # Transport connector type. Not using enum as range of
    # connector types might vary with backend version
    connector_type = sa.Column(sa.String(10))
    # Transport connector IP Address
    connector_ip = sa.Column(sa.String(64))
    # operational status
    status = sa.Column(sa.String(16))


class NetworkGateway(model_base.BASEV2, models_v2.HasId,
                     models_v2.HasTenant):
    """Defines the data model for a network gateway."""
    name = sa.Column(sa.String(255))
    # Tenant id is nullable for this resource
    tenant_id = sa.Column(sa.String(36))
    default = sa.Column(sa.Boolean())
    devices = orm.relationship(NetworkGatewayDeviceReference,
                               backref='networkgateways',
                               cascade='all,delete')
    network_connections = orm.relationship(NetworkConnection, lazy='joined')


class MacLearningState(model_base.BASEV2):

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    mac_learning_enabled = sa.Column(sa.Boolean(), nullable=False)

    # Add a relationship to the Port model using the backref attribute.
    # This will instruct SQLAlchemy to eagerly load this association.
    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref("mac_learning_state", lazy='joined',
                            uselist=False, cascade='delete'))


class LsnPort(models_v2.model_base.BASEV2):

    __tablename__ = 'lsn_port'

    lsn_port_id = sa.Column(sa.String(36), primary_key=True)

    lsn_id = sa.Column(sa.String(36),
                       sa.ForeignKey('lsn.lsn_id', ondelete="CASCADE"),
                       nullable=False)
    sub_id = sa.Column(sa.String(36), nullable=False, unique=True)
    mac_addr = sa.Column(sa.String(32), nullable=False, unique=True)

    def __init__(self, lsn_port_id, subnet_id, mac_address, lsn_id):
        self.lsn_port_id = lsn_port_id
        self.lsn_id = lsn_id
        self.sub_id = subnet_id
        self.mac_addr = mac_address


class Lsn(models_v2.model_base.BASEV2):
    __tablename__ = 'lsn'

    lsn_id = sa.Column(sa.String(36), primary_key=True)
    net_id = sa.Column(sa.String(36), nullable=False)

    def __init__(self, net_id, lsn_id):
        self.net_id = net_id
        self.lsn_id = lsn_id


class QoSQueue(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    name = sa.Column(sa.String(255))
    default = sa.Column(sa.Boolean, default=False, server_default=sql.false())
    min = sa.Column(sa.Integer, nullable=False)
    max = sa.Column(sa.Integer, nullable=True)
    qos_marking = sa.Column(sa.Enum('untrusted', 'trusted',
                                    name='qosqueues_qos_marking'))
    dscp = sa.Column(sa.Integer)


class PortQueueMapping(model_base.BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey("ports.id", ondelete="CASCADE"),
                        primary_key=True)

    queue_id = sa.Column(sa.String(36), sa.ForeignKey("qosqueues.id"),
                         primary_key=True)

    # Add a relationship to the Port model adding a backref which will
    # allow SQLAlchemy for eagerly load the queue binding
    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref("qos_queue", uselist=False,
                            cascade='delete', lazy='joined'))


class NetworkQueueMapping(model_base.BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("networks.id", ondelete="CASCADE"),
                           primary_key=True)

    queue_id = sa.Column(sa.String(36), sa.ForeignKey("qosqueues.id",
                                                      ondelete="CASCADE"))

    # Add a relationship to the Network model adding a backref which will
    # allow SQLAlcremy for eagerly load the queue binding
    network = orm.relationship(
        models_v2.Network,
        backref=orm.backref("qos_queue", uselist=False,
                            cascade='delete', lazy='joined'))
