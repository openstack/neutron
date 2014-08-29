# Copyright 2014 OpenStack Foundation
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
#

"""set_server_default

Revision ID: 5446f2a45467
Revises: 2db5203cb7a9
Create Date: 2014-07-07 18:31:30.384522

"""

# revision identifiers, used by Alembic.
revision = '5446f2a45467'
down_revision = '2db5203cb7a9'


import sqlalchemy as sa
import sqlalchemy.sql

from neutron.db import migration
from neutron.plugins.cisco.common import cisco_constants

# This migration will be executed only if then Neutron db contains tables for
# selected plugins and agents.
# required tables and columns are:
# brocade_ports.port_id
# segmentation_id_llocation.allocated
# cisco_n1kv_profile_bindings.tenant_id
# cisco_network_profiles.multicast_ip_index
# cisco_n1kv_vlan_allocations.allocated
# nsxrouterextattributess.service_router
# nsxrouterextattributess.distributed
# qosqueues.default
# agents.admin_state_up
# ml2_gre_allocations.allocated
# ml2_vxlan_allocations.allocated
# This migration will be skipped when executed offline mode.


def upgrade():
    run(True)


def downgrade():
    run()


@migration.skip_if_offline
def run(default=None):
    set_default_ml2(default)
    set_default_mlnx(default)
    set_default_brocade(default)
    set_default_cisco(default)
    set_default_vmware(default)
    set_default_agents(default)


def set_default_brocade(default):
    if default:
        default = ''
    migration.alter_column_if_exists(
        'brocadeports', 'port_id',
        server_default=default,
        existing_type=sa.String(36))


def set_default_mlnx(default):
    if default:
        default = sqlalchemy.sql.false()
    migration.alter_column_if_exists(
        'segmentation_id_allocation', 'allocated',
        server_default=default,
        existing_nullable=False,
        existing_type=sa.Boolean)


def set_default_cisco(default):
    profile_binding_default = (cisco_constants.TENANT_ID_NOT_SET
                               if default else None)
    profile_default = '0' if default else None
    if default:
        default = sqlalchemy.sql.false()
    migration.alter_column_if_exists(
        'cisco_n1kv_profile_bindings', 'tenant_id',
        existing_type=sa.String(length=36),
        server_default=profile_binding_default,
        existing_nullable=False)
    migration.alter_column_if_exists(
        'cisco_network_profiles', 'multicast_ip_index',
        server_default=profile_default,
        existing_type=sa.Integer)
    migration.alter_column_if_exists(
        'cisco_n1kv_vlan_allocations', 'allocated',
        existing_type=sa.Boolean,
        server_default=default,
        existing_nullable=False)


def set_default_vmware(default=None):
    if default:
        default = sqlalchemy.sql.false()
    migration.alter_column_if_exists(
        'nsxrouterextattributess', 'service_router',
        server_default=default,
        existing_nullable=False,
        existing_type=sa.Boolean)
    migration.alter_column_if_exists(
        'nsxrouterextattributess', 'distributed',
        server_default=default,
        existing_nullable=False,
        existing_type=sa.Boolean)
    migration.alter_column_if_exists(
        'qosqueues', 'default',
        server_default=default,
        existing_type=sa.Boolean)


def set_default_agents(default=None):
    if default:
        default = sqlalchemy.sql.true()
    migration.alter_column_if_exists(
        'agents', 'admin_state_up',
        server_default=default,
        existing_nullable=False,
        existing_type=sa.Boolean)


def set_default_ml2(default=None):
    if default:
        default = sqlalchemy.sql.false()
    migration.alter_column_if_exists(
        'ml2_gre_allocations', 'allocated',
        server_default=default,
        existing_nullable=False,
        existing_type=sa.Boolean)
    migration.alter_column_if_exists(
        'ml2_vxlan_allocations', 'allocated',
        server_default=default,
        existing_nullable=False,
        existing_type=sa.Boolean)
