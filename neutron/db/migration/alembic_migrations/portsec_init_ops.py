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

# Initial operations for the port security extension


from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'networksecuritybindings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('port_security_enabled', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id'))

    op.create_table(
        'portsecuritybindings',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('port_security_enabled', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id'))
