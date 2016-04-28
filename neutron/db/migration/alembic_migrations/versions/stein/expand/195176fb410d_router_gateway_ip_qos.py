# Copyright 2018 OpenStack Foundation
# Copyright 2017 Letv Cloud Computing
# All Rights Reserved.
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

"""router gateway IP QoS

Revision ID: 195176fb410d
Revises: cada2437bf41
Create Date: 2016-04-28 12:38:09.872706

"""
from alembic import op
import sqlalchemy as sa

from neutron_lib.db import constants as db_const

# revision identifiers, used by Alembic.
revision = '195176fb410d'
down_revision = 'cada2437bf41'


def upgrade():
    op.create_table(
        'qos_router_gw_policy_bindings',
        sa.Column('policy_id',
                  sa.String(length=db_const.UUID_FIELD_SIZE),
                  sa.ForeignKey('qos_policies.id', ondelete='CASCADE'),
                  nullable=False, primary_key=True),
        sa.Column('router_id',
                  sa.String(length=db_const.UUID_FIELD_SIZE),
                  sa.ForeignKey('routers.id', ondelete='CASCADE'),
                  nullable=False, unique=True, primary_key=True))
