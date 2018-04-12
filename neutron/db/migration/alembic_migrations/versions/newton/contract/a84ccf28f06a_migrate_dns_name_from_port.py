# Copyright 2016 OpenStack Foundation
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

"""migrate dns name from port"""

# revision identifiers, used by Alembic.
revision = 'a84ccf28f06a'
down_revision = 'b67e765a3524'
depends_on = ('a963b38d82f4',)


ports = sa.Table(
    'ports', sa.MetaData(),
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('dns_name', sa.String(length=constants.FQDN_FIELD_SIZE),
              nullable=True))


portdnses = sa.Table('portdnses', sa.MetaData(),
                     sa.Column('port_id', sa.String(36),
                               sa.ForeignKey('ports.id',
                                             ondelete="CASCADE"),
                               primary_key=True, index=True),
                     sa.Column('dns_name', sa.String(length=255),
                               nullable=False),

                     sa.Column('current_dns_name', sa.String(255),
                               nullable=False),
                     sa.Column('current_dns_domain', sa.String(255),
                               nullable=False),
                     sa.Column('previous_dns_name', sa.String(255),
                               nullable=False),
                     sa.Column('previous_dns_domain', sa.String(255),
                               nullable=False))


def migrate_records_for_existing():
    session = sa.orm.Session(bind=op.get_bind())
    with session.begin(subtransactions=True):
        for row in session.query(ports):
            if row[1]:
                res = session.execute(portdnses.update().values(
                    dns_name=row[1]).where(portdnses.c.port_id == row[0]))
                if res.rowcount == 0:
                    session.execute(portdnses.insert().values(
                        port_id=row[0], current_dns_name='',
                        current_dns_domain='', previous_dns_name='',
                        previous_dns_domain='', dns_name=row[1]))
    session.commit()


def upgrade():
    migrate_records_for_existing()
    op.drop_column('ports', 'dns_name')
