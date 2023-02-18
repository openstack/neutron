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
from neutron_lib import exceptions
import sqlalchemy as sa

from neutron._i18n import _

"""add_unique_ha_router_agent_port_bindings

Revision ID: 1df244e556f5
Revises: 34af2b5c5a59
Create Date: 2015-10-02 18:06:01.696742

"""

# revision identifiers, used by Alembic.
revision = '1df244e556f5'
down_revision = '659bf3d90664'


UNIQUE_NAME = 'uniq_ha_router_agent_port_bindings0port_id0l3_agent_id'
TABLE_NAME = 'ha_router_agent_port_bindings'

ha_router_agent_port_bindings = sa.Table(
    'ha_router_agent_port_bindings', sa.MetaData(),
    sa.Column('port_id', sa.String(36)),
    sa.Column('router_id', sa.String(36)),
    sa.Column('l3_agent_id', sa.String(36)))


class DuplicateL3HARouterAgentPortBinding(exceptions.Conflict):
    message = _("Duplicate L3HARouterAgentPortBinding is created for "
                "router(s) %(router)s. Database cannot be upgraded. Please, "
                "remove all duplicates before upgrading the database.")


def upgrade():
    op.create_unique_constraint(UNIQUE_NAME, TABLE_NAME,
                                ['router_id', 'l3_agent_id'])


def check_sanity(connection):
    res = get_duplicate_l3_ha_port_bindings(connection)
    if res:
        raise DuplicateL3HARouterAgentPortBinding(router=", ".join(res))


def get_duplicate_l3_ha_port_bindings(connection):
    insp = sa.inspect(connection)
    if 'ha_router_agent_port_bindings' not in insp.get_table_names():
        return {}
    session = sa.orm.Session(bind=connection)
    query = (session.query(ha_router_agent_port_bindings.c.router_id)
             .group_by(ha_router_agent_port_bindings.c.router_id,
                       ha_router_agent_port_bindings.c.l3_agent_id)
             .having(sa.func.count() > 1)).all()
    return [q[0] for q in query]
