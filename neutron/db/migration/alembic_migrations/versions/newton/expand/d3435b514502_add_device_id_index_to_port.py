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

"""Add device_id index to Port

Revision ID: d3435b514502
Revises: 5abc0278ca73
Create Date: 2016-04-25 22:13:16.676761

"""

# revision identifiers, used by Alembic.
revision = 'd3435b514502'
down_revision = '5abc0278ca73'

from alembic import op


def upgrade():
    op.create_index('ix_ports_device_id', 'ports', ['device_id'], unique=False)
