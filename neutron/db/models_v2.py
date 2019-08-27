# Copyright (c) 2012 OpenStack Foundation.
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

from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import subnet as subnet_def
from neutron_lib.api.definitions import subnetpool as subnetpool_def
from neutron_lib import constants
from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy import sql

from neutron.db.network_dhcp_agent_binding import models as ndab_model
from neutron.db import rbac_db_models
from neutron.db import standard_attr


class IPAllocationPool(model_base.BASEV2, model_base.HasId):
    """Representation of an allocation pool in a Neutron subnet."""

    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id',
                                                       ondelete="CASCADE"),
                          nullable=True)
    first_ip = sa.Column(sa.String(64), nullable=False)
    last_ip = sa.Column(sa.String(64), nullable=False)

    def __repr__(self):
        return "%s - %s" % (self.first_ip, self.last_ip)


class IPAllocation(model_base.BASEV2):
    """Internal representation of allocated IP addresses in a Neutron subnet.
    """

    port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id',
                                                     ondelete="CASCADE"),
                        nullable=True)
    ip_address = sa.Column(sa.String(64), nullable=False, primary_key=True)
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id',
                                                       ondelete="CASCADE"),
                          nullable=False, primary_key=True)
    network_id = sa.Column(sa.String(36), sa.ForeignKey("networks.id",
                                                        ondelete="CASCADE"),
                           nullable=False, primary_key=True)
    revises_on_change = ('port', )


class Route(object):
    """mixin of a route."""

    destination = sa.Column(sa.String(64), nullable=False, primary_key=True)
    nexthop = sa.Column(sa.String(64), nullable=False, primary_key=True)


class SubnetRoute(model_base.BASEV2, Route):

    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id',
                                        ondelete="CASCADE"),
                          primary_key=True)


class Port(standard_attr.HasStandardAttributes, model_base.BASEV2,
           model_base.HasId, model_base.HasProject):
    """Represents a port on a Neutron v2 network."""

    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    network_id = sa.Column(sa.String(36), sa.ForeignKey("networks.id"),
                           nullable=False)
    fixed_ips = orm.relationship(IPAllocation,
                                 backref=orm.backref('port',
                                                     load_on_pending=True),
                                 lazy='subquery',
                                 cascade='all, delete-orphan',
                                 order_by=(IPAllocation.ip_address,
                                           IPAllocation.subnet_id))

    mac_address = sa.Column(sa.String(32), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    status = sa.Column(sa.String(16), nullable=False)
    device_id = sa.Column(sa.String(db_const.DEVICE_ID_FIELD_SIZE),
                          nullable=False)
    device_owner = sa.Column(sa.String(db_const.DEVICE_OWNER_FIELD_SIZE),
                             nullable=False)
    ip_allocation = sa.Column(sa.String(16))

    __table_args__ = (
        sa.Index(
            'ix_ports_network_id_mac_address', 'network_id', 'mac_address'),
        sa.Index(
            'ix_ports_network_id_device_owner', 'network_id', 'device_owner'),
        sa.Index('ix_ports_device_id', 'device_id'),
        sa.UniqueConstraint(
            network_id, mac_address,
            name='uniq_ports0network_id0mac_address'),
        model_base.BASEV2.__table_args__
    )
    api_collections = [port_def.COLLECTION_NAME]
    collection_resource_map = {port_def.COLLECTION_NAME:
                               port_def.RESOURCE_NAME}
    tag_support = True

    def __init__(self, id=None, tenant_id=None, project_id=None, name=None,
                 network_id=None, mac_address=None, admin_state_up=None,
                 status=None, device_id=None, device_owner=None,
                 fixed_ips=None, **kwargs):
        super(Port, self).__init__(**kwargs)
        self.id = id
        self.project_id = project_id or tenant_id
        self.name = name
        self.network_id = network_id
        self.mac_address = mac_address
        self.admin_state_up = admin_state_up
        self.device_owner = device_owner
        self.device_id = device_id
        # Since this is a relationship only set it if one is passed in.
        if fixed_ips:
            self.fixed_ips = fixed_ips

        # NOTE(arosen): status must be set last as an event is triggered on!
        self.status = status


class DNSNameServer(model_base.BASEV2):
    """Internal representation of a DNS nameserver."""

    address = sa.Column(sa.String(128), nullable=False, primary_key=True)
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id',
                                        ondelete="CASCADE"),
                          primary_key=True)
    order = sa.Column(sa.Integer, nullable=False, server_default='0')


class Subnet(standard_attr.HasStandardAttributes, model_base.BASEV2,
             model_base.HasId, model_base.HasProject):
    """Represents a neutron subnet.

    When a subnet is created the first and last entries will be created. These
    are used for the IP allocation.
    """

    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id'),
                           nullable=False)
    # Added by the segments service plugin
    segment_id = sa.Column(sa.String(36), sa.ForeignKey('networksegments.id'))
    subnetpool_id = sa.Column(sa.String(36), index=True)
    # NOTE: Explicitly specify join conditions for the relationship because
    # subnetpool_id in subnet might be 'prefix_delegation' when the IPv6 Prefix
    # Delegation is enabled
    subnetpool = orm.relationship(
        'SubnetPool', lazy='joined',
        foreign_keys='Subnet.subnetpool_id',
        primaryjoin='Subnet.subnetpool_id==SubnetPool.id')
    ip_version = sa.Column(sa.Integer, nullable=False)
    cidr = sa.Column(sa.String(64), nullable=False)
    gateway_ip = sa.Column(sa.String(64))
    network_standard_attr = orm.relationship(
        'StandardAttribute', lazy='subquery', viewonly=True,
        secondary='networks', uselist=False,
        load_on_pending=True)
    revises_on_change = ('network_standard_attr', )
    allocation_pools = orm.relationship(IPAllocationPool,
                                        backref='subnet',
                                        lazy="subquery",
                                        cascade='delete')
    enable_dhcp = sa.Column(sa.Boolean())
    dns_nameservers = orm.relationship(DNSNameServer,
                                       backref='subnet',
                                       cascade='all, delete, delete-orphan',
                                       order_by=DNSNameServer.order,
                                       lazy='subquery')
    routes = orm.relationship(SubnetRoute,
                              backref='subnet',
                              cascade='all, delete, delete-orphan',
                              lazy='subquery')
    ipv6_ra_mode = sa.Column(sa.Enum(constants.IPV6_SLAAC,
                                     constants.DHCPV6_STATEFUL,
                                     constants.DHCPV6_STATELESS,
                                     name='ipv6_ra_modes'),
                             nullable=True)
    ipv6_address_mode = sa.Column(sa.Enum(constants.IPV6_SLAAC,
                                          constants.DHCPV6_STATEFUL,
                                          constants.DHCPV6_STATELESS,
                                          name='ipv6_address_modes'),
                                  nullable=True)
    # subnets don't have their own rbac_entries, they just inherit from
    # the network rbac entries
    rbac_entries = orm.relationship(
        rbac_db_models.NetworkRBAC, lazy='subquery', uselist=True,
        foreign_keys='Subnet.network_id',
        primaryjoin='Subnet.network_id==NetworkRBAC.object_id')
    api_collections = [subnet_def.COLLECTION_NAME]
    collection_resource_map = {subnet_def.COLLECTION_NAME:
                               subnet_def.RESOURCE_NAME}
    tag_support = True


class SubnetPoolPrefix(model_base.BASEV2):
    """Represents a neutron subnet pool prefix
    """

    __tablename__ = 'subnetpoolprefixes'

    cidr = sa.Column(sa.String(64), nullable=False, primary_key=True)
    subnetpool_id = sa.Column(sa.String(36),
                              sa.ForeignKey('subnetpools.id',
                                            ondelete='CASCADE'),
                              nullable=False,
                              primary_key=True)


class SubnetPool(standard_attr.HasStandardAttributes, model_base.BASEV2,
                 model_base.HasId, model_base.HasProject):
    """Represents a neutron subnet pool.
    """

    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    ip_version = sa.Column(sa.Integer, nullable=False)
    default_prefixlen = sa.Column(sa.Integer, nullable=False)
    min_prefixlen = sa.Column(sa.Integer, nullable=False)
    max_prefixlen = sa.Column(sa.Integer, nullable=False)
    shared = sa.Column(sa.Boolean, nullable=False)
    is_default = sa.Column(sa.Boolean, nullable=False,
                           server_default=sql.false())
    default_quota = sa.Column(sa.Integer, nullable=True)
    hash = sa.Column(sa.String(36), nullable=False, server_default='')
    address_scope_id = sa.Column(sa.String(36), nullable=True)
    prefixes = orm.relationship(SubnetPoolPrefix,
                                backref='subnetpools',
                                cascade='all, delete, delete-orphan',
                                lazy='subquery')
    api_collections = [subnetpool_def.COLLECTION_NAME]
    collection_resource_map = {subnetpool_def.COLLECTION_NAME:
                               subnetpool_def.RESOURCE_NAME}
    tag_support = True


class Network(standard_attr.HasStandardAttributes, model_base.BASEV2,
              model_base.HasId, model_base.HasProject):
    """Represents a v2 neutron network."""

    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    subnets = orm.relationship(
        Subnet,
        lazy="subquery")
    status = sa.Column(sa.String(16))
    admin_state_up = sa.Column(sa.Boolean)
    vlan_transparent = sa.Column(sa.Boolean, nullable=True)
    rbac_entries = orm.relationship(rbac_db_models.NetworkRBAC,
                                    backref=orm.backref('network',
                                                        load_on_pending=True),
                                    lazy='subquery',
                                    cascade='all, delete, delete-orphan')
    availability_zone_hints = sa.Column(sa.String(255))
    # TODO(ihrachys) provide data migration path to fill in mtus for existing
    # networks in Queens when all controllers run Pike+ code
    mtu = sa.Column(sa.Integer, nullable=True)
    dhcp_agents = orm.relationship(
        'Agent', lazy='subquery', viewonly=True,
        secondary=ndab_model.NetworkDhcpAgentBinding.__table__)
    api_collections = [net_def.COLLECTION_NAME]
    collection_resource_map = {net_def.COLLECTION_NAME: net_def.RESOURCE_NAME}
    tag_support = True
