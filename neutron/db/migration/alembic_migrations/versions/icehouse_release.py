# Copyright 2014 Yahoo! Inc.
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

"""icehouse

Revision ID: icehouse
Revises: 5ac1c354a051
Create Date: 2013-03-28 00:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = 'icehouse'
down_revision = '5ac1c354a051'


def upgrade():
    """A no-op migration for marking the Icehouse release."""
    pass


def downgrade():
    # We are purging all downgrade methods from icehouse to havana because:
    # 1) havana is going to become unsupported during Kilo cycle.
    # 2) most people will upgrade from icehouse, while a minor percentage
    #    from havana
    # 3) downgrade use cases are mostly to revert after failed upgrades
    # See discussion in https://review.openstack.org/109952 for details

    raise NotImplementedError("Downgrade from icehouse to havana not "
                              "supported")
