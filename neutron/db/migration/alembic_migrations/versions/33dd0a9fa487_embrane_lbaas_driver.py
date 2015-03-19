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

"""embrane_lbaas_driver

Revision ID: 33dd0a9fa487
Revises: 19180cf98af6
Create Date: 2014-02-25 00:15:35.567111

"""

# revision identifiers, used by Alembic.
revision = '33dd0a9fa487'
down_revision = '19180cf98af6'

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade():
    if not migration.schema_has_table('pools'):
        # The lbaas service plugin was not configured.
        return
    op.create_table(
        u'embrane_pool_port',
        sa.Column(u'pool_id', sa.String(length=36), nullable=False),
        sa.Column(u'port_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['pool_id'], [u'pools.id'],
                                name=u'embrane_pool_port_ibfk_1'),
        sa.ForeignKeyConstraint(['port_id'], [u'ports.id'],
                                name=u'embrane_pool_port_ibfk_2'),
        sa.PrimaryKeyConstraint(u'pool_id'))
