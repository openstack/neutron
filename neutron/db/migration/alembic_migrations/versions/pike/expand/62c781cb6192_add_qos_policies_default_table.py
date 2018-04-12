# Copyright 2017 Intel Corporation
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

"""add is default to qos policies

Revision ID: 62c781cb6192
Revises: 2b42d90729da
Create Date: 2017-02-07 13:28:35.894357

"""

# revision identifiers, used by Alembic.
revision = '62c781cb6192'
down_revision = '2b42d90729da'


def upgrade():
    op.create_table(
        'qos_policies_default',
        sa.Column('qos_policy_id',
                  sa.String(length=36),
                  sa.ForeignKey('qos_policies.id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('project_id',
                  sa.String(length=255),
                  nullable=False,
                  index=True,
                  primary_key=True),
    )
