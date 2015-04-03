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

"""add index for port

Revision ID: 20c469a5f920
Revises: 28a09af858a8
Create Date: 2015-04-01 04:12:49.898443

"""

# revision identifiers, used by Alembic.
revision = '20c469a5f920'
down_revision = '28a09af858a8'

from alembic import op


def upgrade():
    op.create_index(op.f('ix_ports_network_id_device_owner'),
                    'ports', ['network_id', 'device_owner'], unique=False)
    op.create_index(op.f('ix_ports_network_id_mac_address'),
                    'ports', ['network_id', 'mac_address'], unique=False)
