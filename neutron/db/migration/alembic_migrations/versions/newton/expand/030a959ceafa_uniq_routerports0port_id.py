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
from neutron_lib import exceptions
import sqlalchemy as sa

from neutron._i18n import _

"""uniq_routerports0port_id

Revision ID: 030a959ceafa
Revises: 3d0e74aa7d37
Create Date: 2016-06-21 11:33:13.043879

"""

# revision identifiers, used by Alembic.
revision = '030a959ceafa'
down_revision = '3d0e74aa7d37'

routerports = sa.Table(
    'routerports', sa.MetaData(),
    sa.Column('router_id', sa.String(36)),
    sa.Column('port_id', sa.String(36)),
    sa.Column('port_type', sa.String(255)))


class DuplicatePortRecordinRouterPortdatabase(exceptions.Conflict):
    message = _("Duplicate port(s) %(port_id)s records exist in routerports "
                "database. Database cannot be upgraded. Please remove all "
                "duplicated records before upgrading the database.")


def upgrade():
    op.create_unique_constraint(
        'uniq_routerports0port_id',
        'routerports',
        ['port_id'])


def check_sanity(connection):
    res = get_duplicate_port_records_in_routerport_database(connection)
    if res:
        raise DuplicatePortRecordinRouterPortdatabase(port_id=",".join(res))


def get_duplicate_port_records_in_routerport_database(connection):
    insp = sa.inspect(connection)
    if 'routerports' not in insp.get_table_names():
        return []
    session = sa.orm.Session(bind=connection)
    query = (session.query(routerports.c.port_id)
             .group_by(routerports.c.port_id)
             .having(sa.func.count() > 1)).all()
    return [q[0] for q in query]
