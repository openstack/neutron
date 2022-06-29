# Copyright 2021 OpenStack Foundation
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
from neutron.db import migration
from neutron_lib.db import constants

import sqlalchemy as sa


"""port forwarding rule description
Revision ID: I43e0b669096
Revises: 34cf8b009713
Create Date: 2021-12-02 10:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = 'I43e0b669096'
down_revision = '34cf8b009713'

PF_TABLE_NAME = 'portforwardings'
pf_table = sa.Table(
    PF_TABLE_NAME, sa.MetaData(),
    sa.Column('id', sa.String(length=constants.UUID_FIELD_SIZE),
              nullable=False),
    sa.Column('socket', sa.String(length=36), nullable=False),
    sa.Column('external_port', sa.Integer(), nullable=False),
    sa.Column('internal_ip_address', sa.String(length=64), nullable=False),
    sa.Column('internal_port_start', sa.Integer(), nullable=False),
    sa.Column('external_port_start', sa.Integer(), nullable=False),
    sa.Column('internal_port_end', sa.Integer(), nullable=False),
    sa.Column('external_port_end', sa.Integer(), nullable=False),
    sa.Column('internal_neutron_port_id', sa.String(constants.UUID_FIELD_SIZE),
              nullable=False),
)


def upgrade():
    op.add_column(PF_TABLE_NAME,
                  sa.Column('internal_ip_address', sa.String(length=64),
                            nullable=False))
    op.add_column(PF_TABLE_NAME, sa.Column('internal_port_start', sa.Integer(),
                  nullable=False))
    op.add_column(PF_TABLE_NAME, sa.Column('internal_port_end', sa.Integer(),
                  nullable=False))
    op.add_column(PF_TABLE_NAME, sa.Column('external_port_start', sa.Integer(),
                  nullable=False))
    op.add_column(PF_TABLE_NAME, sa.Column('external_port_end', sa.Integer(),
                  nullable=False))

    foreign_keys = clear_constraints_and_foreign()
    migrate_values()
    op.create_unique_constraint(
        columns=['floatingip_id', 'protocol',
                 'external_port_start', 'external_port_end'],
        constraint_name='uniq_port_forwardings0floatingip_id0protocol0'
                        'external_ports',
        table_name=PF_TABLE_NAME)

    op.create_unique_constraint(
        columns=['protocol', 'internal_neutron_port_id', 'internal_ip_address',
                 'internal_port_start', 'internal_port_end'],
        constraint_name='uniq_port_forwardings0ptcl0in_prt_id0in_ip_addr0'
                        'in_prts',
        table_name=PF_TABLE_NAME)

    op.drop_column(PF_TABLE_NAME, 'socket')

    op.drop_column(PF_TABLE_NAME, 'external_port')

    migration.create_foreign_keys(PF_TABLE_NAME, foreign_keys)


def clear_constraints_and_foreign():
    inspect = sa.inspect(op.get_bind())
    foreign_keys = inspect.get_foreign_keys(PF_TABLE_NAME)
    migration.remove_foreign_keys(PF_TABLE_NAME,
                                  foreign_keys)
    constraints_name = [
        'uniq_port_forwardings0internal_neutron_port_id0socket0protocol',
        'uniq_port_forwardings0floatingip_id0external_port0protocol']
    for constraint_name in constraints_name:
        op.drop_constraint(
            constraint_name=constraint_name,
            table_name=PF_TABLE_NAME,
            type_='unique'
        )

    return foreign_keys


def migrate_values():
    session = sa.orm.Session(bind=op.get_bind())
    values = []
    for row in session.query(pf_table):
        values.append({'id': row[0],
                       'socket': row[1],
                       'external_port': row[2]})

    with session.begin(subtransactions=True):
        for value in values:
            internal_ip_address, internal_port = str(
                value['socket']).split(':')
            external_port = value['external_port']
            internal_port = int(internal_port)
            session.execute(
                pf_table.update().values(
                    internal_port_start=internal_port,
                    internal_port_end=internal_port,
                    external_port_start=external_port,
                    external_port_end=external_port,
                    internal_ip_address=internal_ip_address).where(
                        pf_table.c.id == value['id']))
    session.commit()


def expand_drop_exceptions():
    """Drop and replace the unique constraints for table portforwardings

    Drop the existing portforwardings foreign key uniq constraints and then
    replace them with new unique constraints with column ``protocol``.
    This is needed to use drop in expand migration to pass test_branches.
    """

    return {
        sa.Column: [
            '%s.socket' % PF_TABLE_NAME,
            '%s.external_port' % PF_TABLE_NAME
        ],
        sa.Constraint: [
            "portforwardings_ibfk_1",
            "portforwardings_ibfk_2",
            "portforwardings_ibfk_3",
            "portforwardings_ibfk_4",
            "uniq_port_forwardings0floatingip_id0external_port0protocol",
            "uniq_port_forwardings0internal_neutron_port_id0socket0protocol",
            "portforwardings_floatingip_id_fkey",
            "portforwardings_internal_neutron_port_id_fkey",
            "portforwardings_standard_attr_id_fkey"
        ]
    }
