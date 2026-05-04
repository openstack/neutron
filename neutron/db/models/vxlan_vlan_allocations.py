# Copyright 2026 Red Hat, LLC
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

from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm


class VNIAllocation(model_base.BASEV2, model_base.HasId):
    """VNI allocation table scoped by physical network.

    Ensures VNI uniqueness per physical network. The surrogate 'id'
    primary key allows other tables to reference an allocation with
    a single-column FK, keeping the schema in 3NF.
    """

    __tablename__ = 'vni_allocations'

    vni = sa.Column(sa.Integer, nullable=False)
    physnet = sa.Column(sa.String(64), nullable=False)

    __table_args__ = (
        sa.UniqueConstraint('vni', 'physnet',
                            name='uniq_vni_allocations0vni0physnet'),
        model_base.BASEV2.__table_args__
    )


class VLANAllocation(model_base.BASEV2, model_base.HasId):
    """VLAN ID allocation table scoped by physical network.

    Ensures VLAN ID uniqueness per physical network. The surrogate 'id'
    primary key allows other tables to reference an allocation with
    a single-column FK, keeping the schema in 3NF.
    """

    __tablename__ = 'vlan_allocations'

    vlan_id = sa.Column(sa.Integer, nullable=False)
    physnet = sa.Column(sa.String(64), nullable=False)

    __table_args__ = (
        sa.UniqueConstraint('vlan_id', 'physnet',
                            name='uniq_vlan_allocations0vlan_id0physnet'),
        model_base.BASEV2.__table_args__
    )


class VNIVLANMapping(model_base.BASEV2, model_base.HasId):
    """Maps a VNI allocation to a VLAN allocation (1:1).

    RESTRICT on both FKs prevents deletion of either allocation while
    the mapping exists. UNIQUE on each allocation_id enforces 1:1.
    """

    __tablename__ = 'vni_vlan_mapping'

    vni_allocation_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('vni_allocations.id', ondelete='RESTRICT'),
        unique=True,
        nullable=False)
    vlan_allocation_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('vlan_allocations.id', ondelete='RESTRICT'),
        unique=True,
        nullable=False)

    vni_allocation = orm.relationship(
        VNIAllocation,
        lazy='joined',
        viewonly=True)

    vlan_allocation = orm.relationship(
        VLANAllocation,
        lazy='joined',
        viewonly=True)
