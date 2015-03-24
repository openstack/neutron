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

""" Add default security group table

Revision ID: 14be42f3d0a5
Revises: 41662e32bce2
Create Date: 2014-12-12 14:54:11.123635

"""

# revision identifiers, used by Alembic.
revision = '14be42f3d0a5'
down_revision = '26b54cf9024d'

from alembic import op
import sqlalchemy as sa

from neutron.common import exceptions

# Models can change in time, but migration should rely only on exact
# model state at the current moment, so a separate model is created
# here.
security_group = sa.Table('securitygroups', sa.MetaData(),
                          sa.Column('id', sa.String(length=36),
                                    nullable=False),
                          sa.Column('name', sa.String(255)),
                          sa.Column('tenant_id', sa.String(255)))


class DuplicateSecurityGroupsNamedDefault(exceptions.Conflict):
    message = _("Some tenants have more than one security group named "
                "'default': %(duplicates)s. All duplicate 'default' security "
                "groups must be resolved before upgrading the database.")


def upgrade():
    table = op.create_table(
        'default_security_group',
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('security_group_id', sa.String(length=36), nullable=False),
        sa.PrimaryKeyConstraint('tenant_id'),
        sa.ForeignKeyConstraint(['security_group_id'],
                                ['securitygroups.id'],
                                ondelete="CASCADE"))
    sel = (sa.select([security_group.c.tenant_id,
                     security_group.c.id])
           .where(security_group.c.name == 'default'))
    ins = table.insert(inline=True).from_select(['tenant_id',
                                                 'security_group_id'], sel)
    op.execute(ins)


def check_sanity(connection):
    res = get_duplicate_default_security_groups(connection)
    if res:
        raise DuplicateSecurityGroupsNamedDefault(
            duplicates='; '.join('tenant %s: %s' %
                                 (tenant_id, ', '.join(groups))
                                 for tenant_id, groups in res.iteritems()))


def get_duplicate_default_security_groups(connection):
    insp = sa.engine.reflection.Inspector.from_engine(connection)
    if 'securitygroups' not in insp.get_table_names():
        return {}
    session = sa.orm.Session(bind=connection.connect())
    subq = (session.query(security_group.c.tenant_id)
            .filter(security_group.c.name == 'default')
            .group_by(security_group.c.tenant_id)
            .having(sa.func.count() > 1)
            .subquery())

    sg = (session.query(security_group)
          .join(subq, security_group.c.tenant_id == subq.c.tenant_id)
          .filter(security_group.c.name == 'default')
          .all())
    res = {}
    for s in sg:
        res.setdefault(s.tenant_id, []).append(s.id)
    return res
