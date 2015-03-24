# Copyright 2014 OpenStack Foundation
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

"""Remove Cisco Nexus Monolithic Plugin

Revision ID: 1680e1f0c4dc
Revises: 3c346828361e
Create Date: 2014-08-31 08:58:37.123992

"""

# revision identifiers, used by Alembic.
revision = '1680e1f0c4dc'
down_revision = '3c346828361e'

from alembic import op


def upgrade():
    op.execute('INSERT INTO cisco_ml2_nexusport_bindings (port_id, '
               'vlan_id, switch_ip, instance_id) SELECT '
               'port_id, vlan_id, switch_ip, instance_id FROM '
               'cisco_nexusport_bindings')
    op.drop_table('cisco_nexusport_bindings')
