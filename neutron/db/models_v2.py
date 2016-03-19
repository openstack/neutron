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

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy import sql

from neutron.api.v2 import attributes as attr
from neutron.common import constants
from neutron.db import agentschedulers_db as agt
from neutron.db import model_base
from neutron.db import rbac_db_models


# NOTE(kevinbenton): these are here for external projects that expect them
# to be found in this module.
HasTenant = model_base.HasTenant
HasId = model_base.HasId
HasStatusDescription = model_base.HasStatusDescription


class IPAvailabilityRange(model_base.BASEV2):
    """Internal representation of available IPs for Neutron subnets.

    Allocation - first entry from the range will be allocated.
    If the first entry is equal to the last entry then this row
    will be deleted.
    Recycling ips involves reading the IPAllocationPool and IPAllocation tables
    and inserting ranges representing available ips.  This happens after the
    final allocation is pulled from this table and a new ip allocation is
    requested.  Any contiguous ranges of available ips will be inserted as a
    single range.
    """

    allocation_pool_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('ipallocationpools.id',
                                                 ondelete="CASCADE"),
                                   nullable=False,
                                   primary_key=True)
    first_ip = sa.Column(sa.String(64), nullable=False, primary_key=True)
    last_ip = sa.Column(sa.String(64), nullable=False, primary_key=True)
    __table_args__ = (
        sa.UniqueConstraint(
            first_ip, allocation_pool_id,
            name='uniq_ipavailabilityranges0first_ip0allocation_pool_id'),
        sa.UniqueConstraint(
            last_ip, allocation_pool_id,
            name='uniq_ipavailabilityranges0last_ip0allocation_pool_id'),
        model_base.BASEV2.__table_args__
    )

    def __repr__(self):
        return "%s - %s" % (self.first_ip, self.last_ip)


class IPAllocationPool(model_base.BASEV2, HasId):
    """Representation of an allocation pool in a Neutron subnet."""

    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id',
                                                       ondelete="CASCADE"),
                          nullable=True)
    first_ip = sa.Column(sa.String(64), nullable=False)
    last_ip = sa.Column(sa.String(64), nullable=False)
    available_ranges = orm.relationship(IPAvailabilityRange,
                                        backref='ipallocationpool',
                                        lazy="select",
                                        cascade='all, delete-orphan')

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


class Route(object):
    """mixin of a route."""

    destination = sa.Column(sa.String(64), nullable=False, primary_key=True)
    nexthop = sa.Column(sa.String(64), nullable=False, primary_key=True)


class SubnetRoute(model_base.BASEV2, Route):

    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id',
                                        ondelete="CASCADE"),
                          primary_key=True)


class Port(model_base.HasStandardAttributes, model_base.BASEV2,
           HasId, HasTenant):
    """Represents a port on a Neutron v2 network."""

    name = sa.Column(sa.String(attr.NAME_MAX_LEN))
    network_id = sa.Column(sa.String(36), sa.ForeignKey("networks.id"),
                           nullable=False)
    fixed_ips = orm.relationship(IPAllocation, backref='port', lazy='joined',
                                 cascade='all, delete-orphan')

    mac_address = sa.Column(sa.String(32), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    status = sa.Column(sa.String(16), nullable=False)
    device_id = sa.Column(sa.String(attr.DEVICE_ID_MAX_LEN), nullable=False)
    device_owner = sa.Column(sa.String(attr.DEVICE_OWNER_MAX_LEN),
                             nullable=False)
    dns_name = sa.Column(sa.String(255), nullable=True)
    __table_args__ = (
        sa.Index(
            'ix_ports_network_id_mac_address', 'network_id', 'mac_address'),
        sa.Index(
            'ix_ports_network_id_device_owner', 'network_id', 'device_owner'),
        sa.UniqueConstraint(
            network_id, mac_address,
            name='uniq_ports0network_id0mac_address'),
        model_base.BASEV2.__table_args__
    )

    def __init__(self, id=None, tenant_id=None, name=None, network_id=None,
                 mac_address=None, admin_state_up=None, status=None,
                 device_id=None, device_owner=None, fixed_ips=None,
                 dns_name=None, **kwargs):
        super(Port, self).__init__(**kwargs)
        self.id = id
        self.tenant_id = tenant_id
        self.name = name
        self.network_id = network_id
        self.mac_address = mac_address
        self.admin_state_up = admin_state_up
        self.device_owner = device_owner
        self.device_id = device_id
        self.dns_name = dns_name
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


class Subnet(model_base.HasStandardAttributes, model_base.BASEV2,
             HasId, HasTenant):
    """Represents a neutron subnet.

    When a subnet is created the first and last entries will be created. These
    are used for the IP allocation.
    """

    name = sa.Column(sa.String(attr.NAME_MAX_LEN))
    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id'))
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
    allocation_pools = orm.relationship(IPAllocationPool,
                                        backref='subnet',
                                        lazy="joined",
                                        cascade='delete')
    enable_dhcp = sa.Column(sa.Boolean())
    dns_nameservers = orm.relationship(DNSNameServer,
                                       backref='subnet',
                                       cascade='all, delete, delete-orphan',
                                       order_by=DNSNameServer.order,
                                       lazy='joined')
    routes = orm.relationship(SubnetRoute,
                              backref='subnet',
                              cascade='all, delete, delete-orphan',
                              lazy='joined')
    ipv6_ra_mode = sa.Column(sa.Enum(constants.IPV6_SLAAC,
                                     constants.DHCPV6_STATEFUL,
                                     constants.DHCPV6_STATELESS,
                                     name='ipv6_ra_modes'), nullable=True)
    ipv6_address_mode = sa.Column(sa.Enum(constants.IPV6_SLAAC,
                                  constants.DHCPV6_STATEFUL,
                                  constants.DHCPV6_STATELESS,
                                  name='ipv6_address_modes'), nullable=True)
    # subnets don't have their own rbac_entries, they just inherit from
    # the network rbac entries
    rbac_entries = orm.relationship(
        rbac_db_models.NetworkRBAC, lazy='joined', uselist=True,
        foreign_keys='Subnet.network_id',
        primaryjoin='Subnet.network_id==NetworkRBAC.object_id')


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


class SubnetPool(model_base.HasStandardAttributes, model_base.BASEV2,
                 HasId, HasTenant):
    """Represents a neutron subnet pool.
    """

    name = sa.Column(sa.String(attr.NAME_MAX_LEN))
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
                                lazy='joined')


class Network(model_base.HasStandardAttributes, model_base.BASEV2,
              HasId, HasTenant):
    """Represents a v2 neutron network."""

    name = sa.Column(sa.String(attr.NAME_MAX_LEN))
    ports = orm.relationship(Port, backref='networks')
    subnets = orm.relationship(
        Subnet, backref=orm.backref('networks', lazy='joined'),
        lazy="joined")
    status = sa.Column(sa.String(16))
    admin_state_up = sa.Column(sa.Boolean)
    mtu = sa.Column(sa.Integer, nullable=True)
    vlan_transparent = sa.Column(sa.Boolean, nullable=True)
    rbac_entries = orm.relationship(rbac_db_models.NetworkRBAC,
                                    backref='network', lazy='joined',
                                    cascade='all, delete, delete-orphan')
    availability_zone_hints = sa.Column(sa.String(255))
    dhcp_agents = orm.relationship(
        'Agent', lazy='joined', viewonly=True,
        secondary=agt.NetworkDhcpAgentBinding.__table__)
