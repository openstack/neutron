# Copyright 2019 OpenStack Foundation
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

from collections import defaultdict

from alembic import op
import sqlalchemy as sa


"""Add binding index to NetworkDhcpAgentBindings

Revision ID: c3e9d13c4367
Revises: c613d0b82681
Create Date: 2019-08-20 18:42:39.647676

"""

# revision identifiers, used by Alembic.
revision = 'c3e9d13c4367'
down_revision = 'c613d0b82681'


NETWORK_DHCP_AGENT_BINDING = 'networkdhcpagentbindings'


def upgrade():
    op.add_column(NETWORK_DHCP_AGENT_BINDING,
                  sa.Column('binding_index', sa.Integer(), nullable=False,
                            server_default='1'))

    bindings_table = sa.Table(
        NETWORK_DHCP_AGENT_BINDING,
        sa.MetaData(),
        sa.Column('network_id', sa.String(36)),
        sa.Column('dhcp_agent_id', sa.String(36)),
        sa.Column('binding_index', sa.Integer,
                  nullable=False, server_default='1'),
    )

    networks_to_bindings = defaultdict(list)
    session = sa.orm.Session(bind=op.get_bind())
    for result in session.query(bindings_table):
        networks_to_bindings[result.network_id].append(result)

    for bindings in networks_to_bindings.values():
        for index, result in enumerate(bindings):
            session.execute(bindings_table.update().values(
                binding_index=index + 1).where(
                bindings_table.c.network_id == result.network_id).where(
                bindings_table.c.dhcp_agent_id == result.dhcp_agent_id))
    session.commit()

    op.create_unique_constraint(
        'uniq_network_dhcp_agent_binding0network_id0binding_index0',
        NETWORK_DHCP_AGENT_BINDING, ['network_id', 'binding_index'])
