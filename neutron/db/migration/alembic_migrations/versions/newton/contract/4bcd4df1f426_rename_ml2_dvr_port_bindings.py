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

from alembic import op

"""Rename ml2_dvr_port_bindings

Revision ID: 4bcd4df1f426
Revises: 8fd3918ef6f4
Create Date: 2016-06-02 14:06:04.112998

"""

# revision identifiers, used by Alembic.
revision = '4bcd4df1f426'
down_revision = '8fd3918ef6f4'


OLD_REFERRED_TABLE_NAME = 'ml2_dvr_port_bindings'
NEW_REFERRED_TABLE_NAME = 'ml2_distributed_port_bindings'


def upgrade():
    op.rename_table(OLD_REFERRED_TABLE_NAME, NEW_REFERRED_TABLE_NAME)
