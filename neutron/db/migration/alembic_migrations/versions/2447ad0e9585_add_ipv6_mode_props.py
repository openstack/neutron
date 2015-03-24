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

"""Add IPv6 Subnet properties

Revision ID: 2447ad0e9585
Revises: 33dd0a9fa487
Create Date: 2013-10-23 16:36:44.188904

"""

# revision identifiers, used by Alembic.
revision = '2447ad0e9585'
down_revision = '33dd0a9fa487'

from alembic import op
import sqlalchemy as sa


def upgrade():
    # Workaround for Alembic bug #89
    # https://bitbucket.org/zzzeek/alembic/issue/89
    context = op.get_context()
    if context.bind.dialect.name == 'postgresql':
        op.execute("CREATE TYPE ipv6_ra_modes AS ENUM ('%s', '%s', '%s')"
                   % ('slaac', 'dhcpv6-stateful', 'dhcpv6-stateless'))
        op.execute("CREATE TYPE ipv6_address_modes AS ENUM ('%s', '%s', '%s')"
                   % ('slaac', 'dhcpv6-stateful', 'dhcpv6-stateless'))
    op.add_column('subnets',
                  sa.Column('ipv6_ra_mode',
                            sa.Enum('slaac',
                                    'dhcpv6-stateful',
                                    'dhcpv6-stateless',
                                    name='ipv6_ra_modes'),
                            nullable=True)
                  )
    op.add_column('subnets',
                  sa.Column('ipv6_address_mode',
                            sa.Enum('slaac',
                                    'dhcpv6-stateful',
                                    'dhcpv6-stateless',
                                    name='ipv6_address_modes'),
                            nullable=True)
                  )
