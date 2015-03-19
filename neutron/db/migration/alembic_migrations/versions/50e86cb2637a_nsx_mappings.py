# Copyright 2013 OpenStack Foundation
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

"""nsx_mappings

Revision ID: 50e86cb2637a
Revises: 1fcfc149aca4
Create Date: 2013-10-26 14:37:30.012149

"""

# revision identifiers, used by Alembic.
revision = '50e86cb2637a'
down_revision = '1fcfc149aca4'

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade():
    op.create_table('neutron_nsx_port_mappings',
                    sa.Column('neutron_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('nsx_port_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('nsx_switch_id', sa.String(length=36),
                              nullable=True),
                    sa.ForeignKeyConstraint(['neutron_id'], ['ports.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('neutron_id'))

    if migration.schema_has_table('quantum_nvp_port_mapping'):
        op.execute(
            "INSERT INTO neutron_nsx_port_mappings SELECT quantum_id as "
            "neutron_id, nvp_id as nsx_port_id, null as nsx_switch_id from"
            " quantum_nvp_port_mapping")
        op.drop_table('quantum_nvp_port_mapping')
