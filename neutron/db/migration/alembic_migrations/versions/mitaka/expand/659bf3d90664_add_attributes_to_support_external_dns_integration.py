# Copyright 2016 IBM
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
from neutron_lib.db import constants
import sqlalchemy as sa

"""Add tables and attributes to support external DNS integration

Revision ID: 659bf3d90664
Revises: c3a73f615e4
Create Date: 2015-09-11 00:22:47.618593

"""

# revision identifiers, used by Alembic.
revision = '659bf3d90664'
down_revision = 'c3a73f615e4'


def upgrade():
    op.create_table('networkdnsdomains',
                    sa.Column('network_id',
                              sa.String(length=36),
                              nullable=False,
                              primary_key=True),
                    sa.Column('dns_domain', sa.String(
                        length=constants.FQDN_FIELD_SIZE),
                              nullable=False),
                    sa.ForeignKeyConstraint(['network_id'],
                                            ['networks.id'],
                                            ondelete='CASCADE'))

    op.create_table('floatingipdnses',
                    sa.Column('floatingip_id',
                              sa.String(length=36),
                              nullable=False,
                              primary_key=True),
                    sa.Column('dns_name', sa.String(
                        length=constants.FQDN_FIELD_SIZE),
                              nullable=False),
                    sa.Column('dns_domain', sa.String(
                        length=constants.FQDN_FIELD_SIZE),
                              nullable=False),
                    sa.Column('published_dns_name',
                              sa.String(length=constants.FQDN_FIELD_SIZE),
                              nullable=False),
                    sa.Column('published_dns_domain',
                              sa.String(length=constants.FQDN_FIELD_SIZE),
                              nullable=False),
                    sa.ForeignKeyConstraint(['floatingip_id'],
                                            ['floatingips.id'],
                                            ondelete='CASCADE'))

    op.create_table('portdnses',
                    sa.Column('port_id',
                              sa.String(length=36),
                              nullable=False,
                              primary_key=True),
                    sa.Column('current_dns_name',
                              sa.String(length=constants.FQDN_FIELD_SIZE),
                              nullable=False),
                    sa.Column('current_dns_domain',
                              sa.String(length=constants.FQDN_FIELD_SIZE),
                              nullable=False),
                    sa.Column('previous_dns_name',
                              sa.String(length=constants.FQDN_FIELD_SIZE),
                              nullable=False),
                    sa.Column('previous_dns_domain',
                              sa.String(length=constants.FQDN_FIELD_SIZE),
                              nullable=False),
                    sa.ForeignKeyConstraint(['port_id'],
                                            ['ports.id'],
                                            ondelete='CASCADE'))
