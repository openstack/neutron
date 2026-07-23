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

from neutron.db import migration

"""Remove availability ranges.

The tables dropped here (ipavailabilityranges, ipamavailabilityranges) are no
longer created by core_init_ops or 599c6a226151, so this migration is now a
no-op.  The revision is kept so that alembic can still resolve it in databases
that already ran the original migration.
"""


revision = '5c85685d616d'
down_revision = '2e0d7a8a1586'

# milestone identifier, used by neutron-db-manage
neutron_milestone = [migration.NEWTON]


def upgrade():
    # NOTE(ralonsoh): since [1], this is a no-op migration script. Because it
    # is the last contract migration script, is is needed to keep this file
    # and the revision number is the CONTRACT file.
    # [1] https://review.opendev.org/c/openstack/neutron/+/996246
    pass
