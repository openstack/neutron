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

from quantum.db import model_base


class HasTenant(object):
    """Tenant mixin, add to subclasses that have a tenant."""
    # NOTE(jkoelker) tenant_id is just a free form string ;(
    tenant_id = sa.Column(sa.String(255))


class IPAllocation(model_base.BASEV2):
    """Internal representation of a IP address allocation in a Quantum
       subnet
    """
    port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'))
    address = sa.Column(sa.String(16), nullable=False, primary_key=True)
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id'),
                            primary_key=True)
    allocated = sa.Column(sa.Boolean(), nullable=False)


class Port(model_base.BASEV2, HasTenant):
    """Represents a port on a quantum v2 network"""
    network_id = sa.Column(sa.String(36), sa.ForeignKey("networks.id"),
                             nullable=False)
    fixed_ips = orm.relationship(IPAllocation, backref='ports')
    mac_address = sa.Column(sa.String(32), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    op_status = sa.Column(sa.String(16), nullable=False)
    device_id = sa.Column(sa.String(255), nullable=False)


class Subnet(model_base.BASEV2, HasTenant):
    """Represents a quantum subnet"""
    network_id = sa.Column(sa.String(36), sa.ForeignKey('networks.id'))
    allocations = orm.relationship(IPAllocation,
                                   backref=orm.backref('subnet',
                                                       uselist=False))
    ip_version = sa.Column(sa.Integer, nullable=False)
    prefix = sa.Column(sa.String(255), nullable=False)
    gateway_ip = sa.Column(sa.String(255))

    #TODO(danwent):
    # - dns_namservers
    # - excluded_ranges
    # - additional_routes


class Network(model_base.BASEV2, HasTenant):
    """Represents a v2 quantum network"""
    name = sa.Column(sa.String(255))
    ports = orm.relationship(Port, backref='networks')
    subnets = orm.relationship(Subnet, backref='networks')
    op_status = sa.Column(sa.String(16))
    admin_state_up = sa.Column(sa.Boolean)
