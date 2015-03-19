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

"""scrap_nsx_adv_svcs_models

Revision ID: 57086602ca0a
Revises: 28c0ffb8ebbd
Create Date: 2014-12-17 22:33:30.465392

"""

# revision identifiers, used by Alembic.
revision = '57086602ca0a'
down_revision = '28c0ffb8ebbd'

from alembic import op


def upgrade():
    op.drop_table('vcns_edge_pool_bindings')
    op.drop_table('vcns_firewall_rule_bindings')
    op.drop_table('vcns_edge_monitor_bindings')
    op.drop_table('vcns_edge_vip_bindings')
    op.drop_table(u'routerservicetypebindings')
    op.drop_table(u'servicerouterbindings')
