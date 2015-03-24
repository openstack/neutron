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

"""Cascade Floating IP Floating Port deletion

Revision ID: f15b1fb526dd
Revises: 57dd745253a6
Create Date: 2014-08-24 21:56:36.422885

"""

# revision identifiers, used by Alembic.
revision = 'f15b1fb526dd'
down_revision = '57dd745253a6'

from alembic import op
from sqlalchemy.engine import reflection


def _drop_constraint():
    inspector = reflection.Inspector.from_engine(op.get_bind())
    fk_name = [fk['name'] for fk in
               inspector.get_foreign_keys('floatingips')
               if 'floating_port_id' in fk['constrained_columns']]
    op.drop_constraint(fk_name[0], 'floatingips', 'foreignkey')


def upgrade():
    _drop_constraint()
    op.create_foreign_key(
        name=None,
        source='floatingips', referent='ports',
        local_cols=['floating_port_id'], remote_cols=['id'], ondelete='CASCADE'
    )
