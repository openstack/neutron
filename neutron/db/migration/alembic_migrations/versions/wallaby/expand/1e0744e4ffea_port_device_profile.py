# Copyright 2020 OpenStack Foundation
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
from neutron_lib.db import constants as db_const
import sqlalchemy as sa


"""port_device_profile

Revision ID: 1e0744e4ffea
Revises: 26d1e9f5c766
Create Date: 2020-12-18 10:12:14.865465

"""

# revision identifiers, used by Alembic.
revision = '1e0744e4ffea'
down_revision = '26d1e9f5c766'


def upgrade():
    op.create_table('portdeviceprofiles',
                    sa.Column('port_id',
                              sa.String(length=db_const.UUID_FIELD_SIZE),
                              sa.ForeignKey('ports.id', ondelete='CASCADE'),
                              primary_key=True),
                    sa.Column('device_profile',
                              sa.String(255),
                              nullable=True)
                    )
