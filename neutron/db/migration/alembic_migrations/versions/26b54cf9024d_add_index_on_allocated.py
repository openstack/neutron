# Copyright 2015 OpenStack Foundation
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

"""Add index on allocated

Revision ID: 26b54cf9024d
Revises: 41662e32bce2
Create Date: 2015-01-20 15:49:46.100172

"""

# revision identifiers, used by Alembic.
revision = '26b54cf9024d'
down_revision = '2a1ee2fb59e0'

from alembic import op


def upgrade():
    op.create_index(
        op.f('ix_ml2_gre_allocations_allocated'),
        'ml2_gre_allocations', ['allocated'], unique=False)
    op.create_index(
        op.f('ix_ml2_vxlan_allocations_allocated'),
        'ml2_vxlan_allocations', ['allocated'], unique=False)
    op.create_index(
        op.f('ix_ml2_vlan_allocations_physical_network_allocated'),
        'ml2_vlan_allocations', ['physical_network', 'allocated'],
        unique=False)
