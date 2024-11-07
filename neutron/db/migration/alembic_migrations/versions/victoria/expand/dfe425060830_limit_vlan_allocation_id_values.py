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
from neutron_lib import constants


"""limit vlan allocation id values

Revision ID: dfe425060830
Revises: d8bdf05313f4
Create Date: 2020-04-27 16:58:33.110194

"""

# revision identifiers, used by Alembic.
revision = 'dfe425060830'
down_revision = 'd8bdf05313f4'


# NOTE(ralonsoh): "CHECK CONSTRAINT" is a feature heterogeneously implemented
# in different database engines and versions. For example:
# - MySQL: since version 8.0.16 (April 2019)
#   https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-16.html
# - MariaDB: since version 10.2.1 (July 2016)
#   https://mariadb.com/kb/en/mariadb-1021-release-notes/
#
# If the DB engine does not support yet this feature, it will be ignored. The
# VLAN tag constraint is enforced in the Neutron API. This extra enforcement
# in the DB engine wants to mimic the limitation imposed in the API side and
# avoid any spurious modification.

def upgrade():
    # https://docs.sqlalchemy.org/en/13/core/constraints.html#check-constraint
    constraint = ('vlan_id>=%(min_vlan)s AND vlan_id<=%(max_vlan)s' %
                  {'min_vlan': constants.MIN_VLAN_TAG,
                   'max_vlan': constants.MAX_VLAN_TAG})
    op.create_check_constraint(
        constraint_name='check_ml2_vlan_allocations0vlan_id',
        table_name='ml2_vlan_allocations',
        condition=constraint)
