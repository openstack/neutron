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

from alembic import op
import sqlalchemy as sa

"""quota_reservations

Revision ID: 9859ac9c136
Revises: 48153cb5f051
Create Date: 2015-03-11 06:40:56.775075

"""

# revision identifiers, used by Alembic.
revision = '9859ac9c136'
down_revision = '48153cb5f051'


def upgrade():
    op.create_table(
        'reservations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('expiration', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'resourcedeltas',
        sa.Column('resource', sa.String(length=255), nullable=False),
        sa.Column('reservation_id', sa.String(length=36), nullable=False),
        sa.Column('amount', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['reservation_id'], ['reservations.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('resource', 'reservation_id'))
