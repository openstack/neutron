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


"""add index to subnetpools address_scope_id

Revision ID: 659cbedf30a1
Revises: 4e6e655746f6
Create Date: 2022-06-01 13:39:35.303265

"""

# revision identifiers, used by Alembic.
revision = '659cbedf30a1'
down_revision = '4e6e655746f6'


def upgrade():
    index_name = 'ix_subnetpools_address_scope_id'
    op.create_index(index_name, 'subnetpools', ['address_scope_id'],
                    unique=False)
