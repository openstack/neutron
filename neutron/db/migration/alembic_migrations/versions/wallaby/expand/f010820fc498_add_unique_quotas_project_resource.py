# Copyright 2020 OpenStack Foundation
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


"""add_unique_quotas_project_resource

Revision ID: f010820fc498
Revises: 532aa95457e2
Create Date: 2020-08-28 14:49:50.615623

"""

# revision identifiers, used by Alembic.
revision = 'f010820fc498'
down_revision = '532aa95457e2'
depends_on = ('7d9d8eeec6ad',)


quotas = sa.Table(
    'quotas', sa.MetaData(),
    sa.Column('project_id', sa.String(255)),
    sa.Column('resource', sa.String(255)))


class DuplicateQuotas(exceptions.Conflict):
    message = _("Duplicate Quotas are created for resource(s) %(resources)s. "
                "Database cannot be upgraded. Please, remove all duplicates "
                "before upgrading the database.")


def get_duplicate_quotas(connection):
    insp = sa.inspect(connection)
    if 'quotas' not in insp.get_table_names():
        return []
    session = sa.orm.Session(bind=connection)
    items = (session.query(quotas.c.project_id, quotas.c.resource)
             .group_by(quotas.c.project_id, quotas.c.resource)
             .having(sa.func.count() > 1)).all()
    return items


def check_sanity(connection):
    res = get_duplicate_quotas(connection)
    if res:
        resources = ",".join([":".join(r) for r in res])
        raise DuplicateQuotas(resources=resources)


def upgrade():
    op.create_unique_constraint(
        op.f('uniq_quotas0project_id0resource'),
        'quotas',
        ['project_id', 'resource'])
