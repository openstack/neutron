# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sqlalchemy as sa
from sqlalchemy import orm

from quantum.common import utils
from quantum.db import model_base


class HasTenant(object):
    """Tenant mixin, add to subclasses that have a tenant."""
    # NOTE(jkoelker) tenant_id is just a free form string ;(
    tenant_id = sa.Column(sa.String(255))


class HasId(object):
    """id mixin, add to subclasses that have an id."""
    id = sa.Column(sa.String(36), primary_key=True, default=utils.str_uuid)


class IPAvailabilityRange(model_base.BASEV2):
    """Internal representation of available IPs for Quantum subnets.

    Allocation - first entry from the range will be allocated.
    If the first entry is equal to the last entry then this row
    will be deleted.
    Recycling ips involves appending to existing ranges. This is
    only done if the range is contiguous. If not, the first_ip will be
    the same as the last_ip. When adjacent ips are recycled the ranges
    will be merged.

    """
    allocation_pool_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('ipallocationpools.id',
                                                 ondelete="CASCADE"),
                                   nullable=True,
                                   primary_key=True)
    first_ip = sa.Column(sa.String(64), nullable=False, primary_key=True)
    last_ip = sa.Column(sa.String(64), nullable=False, primary_key=True)

    def __repr__(self):
        return "%s - %s" % (self.first_ip, self.last_ip)


class IPAllocationPool(model_base.BASEV2, HasId):
    """Representation of an allocation pool in a Quantum subnet."""

    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id',
                                                       ondelete="CASCADE"),
                          nullable=True)
    first_ip = sa.Column(sa.String(64), nullable=False)
    last_ip = sa.Column(sa.String(64), nullable=False)
    available_ranges = orm.relationship(IPAvailabilityRange,
                                        backref='ipallocationpool',
                                        lazy="dynamic")

    def __repr__(self):
        return "%s - %s" % (self.first_ip, self.last_ip)


class IPAllocation(model_base.BASEV2):
    """Internal representation of allocated IP addresses in a Quantum subnet.
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
    expiration = sa.Column(sa.DateTime, nullable=True)


class Port(model_base.BASEV2, HasId, HasTenant):
    """Represents a port on a quantum v2 network."""
    name = sa.Column(sa.String(255))
    network_id = sa.Column(sa.String(36), sa.ForeignKey("networks.id"),
                           nullable=False)
    fixed_ips = orm.relationship(IPAllocation, backref='ports', lazy="dynamic")
    mac_address = sa.Column(sa.String(32), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    status = sa.Column(sa.String(16), nullable=False)
    device_id = sa.Column(sa.String(255), nullable=False)
    device_owner = sa.Column(sa.String(255), nullable=False)


class DNSNameServer(model_base.BASEV2):
    """Internal representation of a DNS nameserver."""
    address = sa.Column(sa.String(128), nullable=False, primary_key=True)
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id',
                                        ondelete="CASCADE"),
                          primary_key=True)


class Route(model_base.BASEV2):
    """Represents a route for a subnet or port."""
    destination = sa.Column(sa.String(64), nullable=False, primary_key=True)
    nexthop = sa.Column(sa.String(64), nullable=False, primary_key=True)
    subnet_id = sa.Column(sa.String(36),
                          sa.ForeignKey('subnets.id',
                                        ondelete="CASCADE"),
                          primary_key=True)


class Subnet(model_base.BASEV2, HasId, HasTenant):
    """Represents a quantum subnet.

    When a subnet is created the first and last entries will be created. These
    are used for the IP allocation.
    """
    name = sa.Column(sa.String(255))
    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id'))
    ip_version = sa.Column(sa.Integer, nullable=False)
    cidr = sa.Column(sa.String(64), nullable=False)
    gateway_ip = sa.Column(sa.String(64))
    allocation_pools = orm.relationship(IPAllocationPool,
                                        backref='subnet',
                                        lazy="dynamic")
    enable_dhcp = sa.Column(sa.Boolean())
    dns_nameservers = orm.relationship(DNSNameServer,
                                       backref='subnet',
                                       cascade='delete')
    routes = orm.relationship(Route,
                              backref='subnet',
                              cascade='delete')
    shared = sa.Column(sa.Boolean)


class Network(model_base.BASEV2, HasId, HasTenant):
    """Represents a v2 quantum network."""
    name = sa.Column(sa.String(255))
    ports = orm.relationship(Port, backref='networks')
    subnets = orm.relationship(Subnet, backref='networks')
    status = sa.Column(sa.String(16))
    admin_state_up = sa.Column(sa.Boolean)
    shared = sa.Column(sa.Boolean)
