# Copyright 2019 Red Hat, Inc.
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
from oslo_utils import timeutils
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite


class OVNRevisionNumbers(model_base.BASEV2):
    __tablename__ = 'ovn_revision_numbers'

    standard_attr_id = sa.Column(
        sa.BigInteger().with_variant(sa.Integer(), 'sqlite'),
        sa.ForeignKey('standardattributes.id', ondelete='SET NULL'),
        nullable=True)
    resource_uuid = sa.Column(sa.String(36), nullable=False, index=True)
    resource_type = sa.Column(sa.String(36), nullable=False, index=True)
    revision_number = sa.Column(
        sa.BigInteger().with_variant(sa.Integer(), 'sqlite'),
        server_default='0', default=0, nullable=False)
    created_at = sa.Column(
        sa.DateTime().with_variant(
            sqlite.DATETIME(truncate_microseconds=True), 'sqlite'),
        default=sa.func.now(), nullable=False)
    updated_at = sa.Column(sa.TIMESTAMP, default=sa.func.now(),
                           onupdate=sa.func.now(), nullable=True)

    __table_args__ = (
        sa.PrimaryKeyConstraint(
            resource_uuid, resource_type,
            name='ovn_revision_numbers0resource_uuid0resource_type'),
        model_base.BASEV2.__table_args__
    )


class OVNHashRing(model_base.BASEV2):
    __tablename__ = 'ovn_hash_ring'

    node_uuid = sa.Column(sa.String(36), nullable=False, index=True)
    group_name = sa.Column(sa.String(256), nullable=False, index=True)
    hostname = sa.Column(sa.String(256), nullable=False)
    created_at = sa.Column(sa.DateTime(), default=timeutils.utcnow,
                           nullable=False)
    updated_at = sa.Column(sa.DateTime(), default=timeutils.utcnow,
                           nullable=False)
    __table_args__ = (
        sa.PrimaryKeyConstraint(
            node_uuid, group_name,
            name='ovn_hash_ring0node_uuid0group_name'),
        model_base.BASEV2.__table_args__
    )
