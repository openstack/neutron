# Copyright 2021 OpenStack Foundation
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


"""Add indexes to RBACs

Revision ID: ba859d649675
Revises: c181bb1d89e4
Create Date: 2021-09-20 15:22:04.668376

"""

# revision identifiers, used by Alembic.
revision = 'ba859d649675'
down_revision = 'c181bb1d89e4'

OBJECTS = ('network', 'qospolicy', 'securitygroup', 'addressscope',
           'subnetpool', 'addressgroup')
COLUMNS = ('target_tenant', 'action')


def upgrade():
    for object in OBJECTS:
        table = object + 'rbacs'
        ix = 'ix_' + table + '_'
        for column in COLUMNS:
            op.create_index(op.f(ix + column), table, [column], unique=False)
