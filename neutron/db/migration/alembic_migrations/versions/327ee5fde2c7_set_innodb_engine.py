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

"""set_innodb_engine

Revision ID: 327ee5fde2c7
Revises: 2026156eab2f
Create Date: 2014-07-24 12:00:38.791287

"""

# revision identifiers, used by Alembic.
revision = '327ee5fde2c7'
down_revision = '4eba2f05c2f4'


from alembic import op

# This list contain tables that could be deployed before change that converts
# all tables to InnoDB appeared
TABLES = ['router_extra_attributes', 'dvr_host_macs', 'ml2_dvr_port_bindings',
          'csnat_l3_agent_bindings']


def upgrade():
    if op.get_bind().dialect.name == 'mysql':
        for table in TABLES:
            op.execute("ALTER TABLE %s ENGINE=InnoDB" % table)
