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

from alembic import op
import sqlalchemy as sa
from sqlalchemy import sql

"""Add support for VLAN trunking"""

revision = '5abc0278ca73'
down_revision = '45f8dd33480b'


def upgrade():
    op.create_table(
        'trunks',
        sa.Column('admin_state_up', sa.Boolean(),
                  nullable=False, server_default=sql.true()),
        sa.Column('tenant_id', sa.String(length=255), nullable=True,
                  index=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=16),
                  nullable=False, server_default='ACTIVE'),
        sa.Column('standard_attr_id', sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['standard_attr_id'],
                                ['standardattributes.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('port_id'),
        sa.UniqueConstraint('standard_attr_id')
    )
    op.create_table(
        'subports',
        sa.Column('port_id', sa.String(length=36)),
        sa.Column('trunk_id', sa.String(length=36), nullable=False),
        sa.Column('segmentation_type', sa.String(length=32), nullable=False),
        sa.Column('segmentation_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['trunk_id'], ['trunks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id'),
        sa.UniqueConstraint(
            'trunk_id', 'segmentation_type', 'segmentation_id',
            name='uniq_subport0trunk_id0segmentation_type0segmentation_id')
    )
