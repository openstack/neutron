# Copyright 2017 OpenStack Foundation
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

import sqlalchemy as sa

from neutron.common import constants
from neutron.db import migration

"""Add unknown state to HA router

Revision ID: 61663558142c
Revises: 594422d373ee
Create Date: 2017-05-18 14:31:45.725516

"""

revision = '61663558142c'
down_revision = '594422d373ee'


ha_port_bindings_table_name = "ha_router_agent_port_bindings"
new_enum = sa.Enum(
    constants.HA_ROUTER_STATE_ACTIVE,
    constants.HA_ROUTER_STATE_STANDBY,
    constants.HA_ROUTER_STATE_UNKNOWN,
    name='l3_ha_states'
)


def upgrade():
    migration.alter_enum_add_value(ha_port_bindings_table_name, 'state',
                                   new_enum, True, server_default='standby')
