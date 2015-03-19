# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

"""Cisco CSR VPNaaS

   Revision ID: 24c7ea5160d7
   Revises: 492a106273f8
   Create Date: 2014-02-03 13:06:50.407601
"""

# revision identifiers, used by Alembic.
revision = '24c7ea5160d7'
down_revision = '492a106273f8'

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade():
    if not migration.schema_has_table('ipsec_site_connections'):
        # The vpnaas service plugin was not configured.
        return
    op.create_table(
        'cisco_csr_identifier_map',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('ipsec_site_conn_id', sa.String(length=64),
                  primary_key=True),
        sa.Column('csr_tunnel_id', sa.Integer(), nullable=False),
        sa.Column('csr_ike_policy_id', sa.Integer(), nullable=False),
        sa.Column('csr_ipsec_policy_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['ipsec_site_conn_id'],
                                ['ipsec_site_connections.id'],
                                ondelete='CASCADE')
    )
