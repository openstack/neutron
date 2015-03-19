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

"""Add index on tenant_id column

Revision ID: 4119216b7365
Revises: 28c0ffb8ebbd
Create Date: 2014-12-19 12:21:54.439723

"""

# revision identifiers, used by Alembic.
revision = '4119216b7365'
down_revision = 'bebba223288'

from alembic import op

TABLES = ['floatingips', 'networkconnections', 'networkgatewaydevices',
          'networks', 'packetfilters', 'ports', 'qosqueues', 'routers',
          'securitygrouprules', 'securitygroups', 'subnets', 'meteringlabels',
          'arista_provisioned_nets', 'arista_provisioned_tenants',
          'arista_provisioned_vms', 'cisco_hosting_devices',
          'cisco_ml2_apic_contracts', 'ml2_brocadenetworks',
          'ml2_brocadeports']


def upgrade():
    for table in TABLES:
        op.create_index(op.f('ix_%s_tenant_id' % table),
                        table, ['tenant_id'], unique=False)
