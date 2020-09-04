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

from alembic import op

"""Drop legacy OVS and LB plugin tables

Revision ID: 5498d17be016
Revises: 4ffceebfada
Create Date: 2015-06-25 14:08:30.984419

"""

# revision identifiers, used by Alembic.
revision = '5498d17be016'
down_revision = '4ffceebfada'


def upgrade():
    op.drop_table('ovs_network_bindings')
    op.drop_table('ovs_vlan_allocations')
    op.drop_table('network_bindings')
    op.drop_table('ovs_tunnel_allocations')
    op.drop_table('network_states')
    op.drop_table('ovs_tunnel_endpoints')
