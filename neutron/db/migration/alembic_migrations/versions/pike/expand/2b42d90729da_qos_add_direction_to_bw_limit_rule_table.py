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

from alembic import op
from neutron_lib import constants
import sqlalchemy as sa

from neutron.db import migration

"""qos add direction to bw_limit_rule table

Revision ID: 2b42d90729da
Revises: 804a3c76314c
Create Date: 2017-04-03 20:56:00.169599

"""

# revision identifiers, used by Alembic.
revision = '2b42d90729da'
down_revision = '804a3c76314c'


policies_table_name = "qos_policies"
bw_limit_table_name = "qos_bandwidth_limit_rules"
direction_enum = sa.Enum(
    constants.EGRESS_DIRECTION, constants.INGRESS_DIRECTION,
    name="directions"
)


def upgrade():
    if op.get_context().bind.dialect.name == 'postgresql':
        direction_enum.create(op.get_bind(), checkfirst=True)

    with migration.remove_fks_from_table(bw_limit_table_name,
                                         remove_unique_constraints=True):
        op.add_column(bw_limit_table_name,
                      sa.Column("direction", direction_enum,
                                server_default=constants.EGRESS_DIRECTION,
                                nullable=False))

        op.create_unique_constraint(
            op.f('qos_bandwidth_rules0qos_policy_id0direction'),
            bw_limit_table_name,
            ['qos_policy_id', 'direction'])


def expand_drop_exceptions():
    """Drop and replace the QoS policy foreign key contraint

    Drop the existing QoS policy foreign key uniq constraint and then replace
    it with new unique constraint for pair (policy_id, direction).

    As names of constraints are different in MySQL and PGSQL there is need to
    add both variants to drop exceptions.
    """

    # TODO(slaweq): replace hardcoded constaints names with names get directly
    # from database model after bug
    # https://bugs.launchpad.net/neutron/+bug/1685352 will be closed
    return {
        sa.ForeignKeyConstraint: [
            "qos_bandwidth_limit_rules_ibfk_1",  # MySQL name
            "qos_bandwidth_limit_rules_qos_policy_id_fkey"  # PGSQL name
        ],
        sa.UniqueConstraint: [
            "qos_policy_id",  # MySQL name
            "qos_bandwidth_limit_rules_qos_policy_id_key"  # PGSQL name
        ]
    }
