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

"""Cisco APIC Mechanism Driver

Revision ID: 86d6d9776e2b
Revises: 236b90af57abg
Create Date: 2014-04-23 09:27:08.177021

"""

# revision identifiers, used by Alembic.
revision = '86d6d9776e2b'
down_revision = '236b90af57ab'


from alembic import op
import sqlalchemy as sa


def upgrade():

    op.drop_table('cisco_ml2_apic_contracts')
    op.drop_table('cisco_ml2_apic_epgs')

    op.create_table(
        'cisco_ml2_apic_contracts',
        sa.Column('tenant_id', sa.String(length=255)),
        sa.Column('router_id', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id']),
        sa.PrimaryKeyConstraint('router_id'))
