# Copyright 2018 OpenStack Foundation
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

"""modify uniq port forwarding

Revision ID: d72db3e25539
Revises: 867d39095bf4
Create Date: 2018-10-12 19:51:11.981394

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import reflection

from neutron.db import migration

# revision identifiers, used by Alembic.
revision = 'd72db3e25539'
down_revision = '867d39095bf4'

TABLE_NAME = 'portforwardings'


def upgrade():
    inspector = reflection.Inspector.from_engine(op.get_bind())
    foreign_keys = inspector.get_foreign_keys(TABLE_NAME)
    migration.remove_foreign_keys(TABLE_NAME, foreign_keys)

    unique_constraints = inspector.get_unique_constraints(TABLE_NAME)
    for constraint in unique_constraints:
        op.drop_constraint(
            constraint_name=constraint['name'],
            table_name=TABLE_NAME,
            type_="unique"
        )

    op.create_unique_constraint(
        constraint_name=('uniq_port_forwardings0floatingip_id0'
                         'external_port0protocol'),
        table_name=TABLE_NAME,
        columns=['floatingip_id', 'external_port', 'protocol']
    )
    op.create_unique_constraint(
        constraint_name=('uniq_port_forwardings0internal_neutron_port_id0'
                         'socket0protocol'),
        table_name=TABLE_NAME,
        columns=['internal_neutron_port_id', 'socket', 'protocol']
    )

    migration.create_foreign_keys(TABLE_NAME, foreign_keys)


def expand_drop_exceptions():
    """Drop and replace the unique constraints for table portforwardings

    Drop the existing portforwardings foreign key uniq constraints and then
    replace them with new unique constraints with column ``protocol``.
    This is needed to use drop in expand migration to pass test_branches.
    """

    return {
        sa.Constraint: [
            "portforwardings_ibfk_1",
            "portforwardings_ibfk_2",
            "uniq_port_forwardings0floatingip_id0external_port",
            "uniq_port_forwardings0internal_neutron_port_id0socket",
            "portforwardings_floatingip_id_fkey",
            "portforwardings_internal_neutron_port_id_fkey",
        ]
    }
