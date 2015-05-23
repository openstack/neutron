# Copyright 2015 OpenStack LLC.
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
from sqlalchemy import orm as sa_orm

from neutron.db import model_base
from neutron.db import models_v2

# Database models used by the neutron DB IPAM driver


# NOTE(salv-orlando): This is meant to replace the class
# neutron.db.models_v2.IPAvailabilityRange.
class IpamAvailabilityRange(model_base.BASEV2):
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
                                   sa.ForeignKey('ipamallocationpools.id',
                                                 ondelete="CASCADE"),
                                   nullable=False,
                                   primary_key=True)
    first_ip = sa.Column(sa.String(64), nullable=False, primary_key=True)
    last_ip = sa.Column(sa.String(64), nullable=False, primary_key=True)
    __table_args__ = (
        sa.Index('ix_ipamavailabilityranges_first_ip_allocation_pool_id',
                 'first_ip', 'allocation_pool_id'),
        sa.Index('ix_ipamavailabilityranges_last_ip_allocation_pool_id',
                 'last_ip', 'allocation_pool_id'),
        model_base.BASEV2.__table_args__
    )

    def __repr__(self):
        return "%s - %s" % (self.first_ip, self.last_ip)


# NOTE(salv-orlando): The following data model creates redundancy with
# models_v2.IPAllocationPool. This level of data redundancy could be tolerated
# considering that the following model is specific to the IPAM driver logic.
# It therefore represents an internal representation of a subnet allocation
# pool and can therefore change in the future, where as
# models_v2.IPAllocationPool is the representation of IP allocation pools in
# the management layer and therefore its evolution is subject to APIs backward
# compatibility policies
class IpamAllocationPool(model_base.BASEV2, models_v2.HasId):
    """Representation of an allocation pool in a Neutron subnet."""

    ipam_subnet_id = sa.Column(sa.String(36),
                               sa.ForeignKey('ipamsubnets.id',
                                             ondelete="CASCADE"),
                               nullable=False)
    first_ip = sa.Column(sa.String(64), nullable=False)
    last_ip = sa.Column(sa.String(64), nullable=False)
    available_ranges = sa_orm.relationship(IpamAvailabilityRange,
                                           backref='allocation_pool',
                                           lazy="joined",
                                           cascade='all, delete-orphan')

    def __repr__(self):
        return "%s - %s" % (self.first_ip, self.last_ip)


class IpamSubnet(model_base.BASEV2, models_v2.HasId):
    """Association between IPAM entities and neutron subnets.

    For subnet data persistency - such as cidr and gateway IP, the IPAM
    driver relies on Neutron's subnet model as source of truth to limit
    data redundancy.
    """
    neutron_subnet_id = sa.Column(sa.String(36),
                                  nullable=True)
    allocation_pools = sa_orm.relationship(IpamAllocationPool,
                                           backref='subnet',
                                           lazy="joined",
                                           cascade='delete')


class IpamAllocation(model_base.BASEV2):
    """Model class for IP Allocation requests. """
    ip_address = sa.Column(sa.String(64), nullable=False, primary_key=True)
    status = sa.Column(sa.String(36))
    # The subnet identifier is redundant but come handy for looking up
    # IP addresses to remove.
    ipam_subnet_id = sa.Column(sa.String(36),
                               sa.ForeignKey('ipamsubnets.id',
                                             ondelete="CASCADE"),
                               primary_key=True,
                               nullable=False)
