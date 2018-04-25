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
import sqlalchemy as sa

"""qos dscp db addition

Revision ID: 45f8dd33480b
Revises: 0e66c5227a8a
Create Date: 2015-12-03 07:16:24.742290

"""

# revision identifiers, used by Alembic.
revision = '45f8dd33480b'
down_revision = '0e66c5227a8a'


def upgrade():

    op.create_table(
        'qos_dscp_marking_rules',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('qos_policy_id', sa.String(length=36),
                  sa.ForeignKey('qos_policies.id', ondelete='CASCADE'),
                  nullable=False, unique=True),
        sa.Column('dscp_mark', sa.Integer()))
