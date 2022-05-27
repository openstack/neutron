# Copyright 2022 OpenStack Foundation
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


"""add index to ports.network_id

Revision ID: 4e6e655746f6
Revises: I43e0b669096
Create Date: 2022-05-12 13:04:51.831792

"""

# revision identifiers, used by Alembic.
revision = '4e6e655746f6'
down_revision = 'I43e0b669096'


def upgrade():
    index_name = 'ix_ports_network_id'
    op.create_index(index_name, 'ports', ['network_id'], unique=False)
