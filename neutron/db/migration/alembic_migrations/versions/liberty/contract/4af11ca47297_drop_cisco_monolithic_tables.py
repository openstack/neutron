# Copyright 2015 Cisco Systems, Inc.
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

"""Drop cisco monolithic tables

Revision ID: 4af11ca47297
Revises: 11926bcfe72d
Create Date: 2015-08-13 08:01:19.709839

"""

from alembic import op

from neutron.db import migration


# revision identifiers, used by Alembic.
revision = '4af11ca47297'
down_revision = '11926bcfe72d'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.LIBERTY]


def upgrade():
    op.drop_table('cisco_n1kv_port_bindings')
    op.drop_table('cisco_n1kv_network_bindings')
    op.drop_table('cisco_n1kv_multi_segments')
    op.drop_table('cisco_provider_networks')
    op.drop_table('cisco_n1kv_trunk_segments')
    op.drop_table('cisco_n1kv_vmnetworks')
    op.drop_table('cisco_n1kv_profile_bindings')
    op.drop_table('cisco_qos_policies')
    op.drop_table('cisco_credentials')
    op.drop_table('cisco_n1kv_vlan_allocations')
    op.drop_table('cisco_n1kv_vxlan_allocations')
    op.drop_table('cisco_network_profiles')
    op.drop_table('cisco_policy_profiles')
