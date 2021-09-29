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

"""uniq_floatingips0floating_network_id0fixed_port_id0fixed_ip_addr

Revision ID: 6b461a21bcfc
Revises: 67daae611b6e
Create Date: 2016-06-03 16:00:38.273324

"""

# revision identifiers, used by Alembic.
revision = '6b461a21bcfc'
down_revision = '67daae611b6e'


floatingips = sa.Table(
    'floatingips', sa.MetaData(),
    sa.Column('floating_network_id', sa.String(36)),
    sa.Column('fixed_port_id', sa.String(36)),
    sa.Column('fixed_ip_address', sa.String(64)))


class DuplicateFloatingIPforOneFixedIP(exceptions.Conflict):
    message = _("Duplicate Floating IPs were created for fixed IP "
                "addresse(s) %(fixed_ip_address)s. Database cannot "
                "be upgraded. Please remove all duplicate Floating "
                "IPs before upgrading the database.")


def upgrade():
    op.create_unique_constraint(
        'uniq_floatingips0floatingnetworkid0fixedportid0fixedipaddress',
        'floatingips',
        ['floating_network_id', 'fixed_port_id', 'fixed_ip_address'])


def check_sanity(connection):
    res = get_duplicate_floating_ip_for_one_fixed_ip(connection)
    if res:
        raise DuplicateFloatingIPforOneFixedIP(fixed_ip_address=",".join(res))


def get_duplicate_floating_ip_for_one_fixed_ip(connection):
    insp = sa.inspect(connection)
    if 'floatingips' not in insp.get_table_names():
        return []
    session = sa.orm.Session(bind=connection.connect())
    query = (session.query(floatingips.c.fixed_ip_address)
             .group_by(floatingips.c.floating_network_id,
                       floatingips.c.fixed_port_id,
                       floatingips.c.fixed_ip_address)
             .having(sa.func.count() > 1)).all()
    return [q[0] for q in query if q[0] is not None]
