# Copyright 2016 Huawei Technologies India Pvt. Ltd.
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

"""add_bgp_dragent_model_data

Revision ID: b4caf27aae4
Revises: 15be7321482
Create Date: 2015-08-20 17:05:31.038704

"""

# revision identifiers, used by Alembic.
revision = 'b4caf27aae4'
down_revision = '15be73214821'


def upgrade():

    op.create_table(
        'bgp_speaker_dragent_bindings',
        sa.Column('agent_id',
                  sa.String(length=36),
                  primary_key=True),
        sa.Column('bgp_speaker_id',
                  sa.String(length=36),
                  nullable=False),
        sa.ForeignKeyConstraint(['agent_id'], ['agents.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['bgp_speaker_id'], ['bgp_speakers.id'],
                                ondelete='CASCADE'),
    )
