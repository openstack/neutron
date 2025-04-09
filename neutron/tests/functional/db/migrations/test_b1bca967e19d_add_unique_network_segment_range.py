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

import random

from oslo_db.sqlalchemy import utils as db_utils
from oslo_utils import uuidutils

from neutron.tests.functional.db import test_migrations


class NetworkSegmentRangesUniqueUpgrade(test_migrations.TestWalkMigrations):
    """Validates migration that adds unique constraints for
       network segment ranges.
    """

    _standard_attribute_id = 0

    def _gen_attr_id(self, type):
        self._standard_attribute_id = random.randint(100000, 2000000)
        standardattributes = db_utils.get_table(
            self.engine, 'standardattributes')
        with self.engine.connect() as conn, conn.begin():
            conn.execute(standardattributes.insert().values({
                'id': self._standard_attribute_id,
                'resource_type': type}))
        return self._standard_attribute_id

    def _create_network_segment_ranges(self, data):
        network_segment_ranges = db_utils.get_table(
            self.engine, 'network_segment_ranges')
        with self.engine.connect() as conn, conn.begin():
            for item in data:
                range_dict = {
                    'id': uuidutils.generate_uuid(),
                    'standard_attr_id': self._gen_attr_id(
                        'network_segment_ranges'),
                }
                range_dict.update(**item)
                conn.execute(
                    network_segment_ranges.insert().values(range_dict))

    def _pre_upgrade_b1bca967e19d(self, engine):
        duplicate_data = [
            {
                'name': '',
                'default': True,
                'shared': True,
                'network_type': 'vlan',
                'physical_network': 'default',
                'minimum': 100,
                'maximum': 200
            },
            {
                'name': '',
                'default': True,
                'shared': True,
                'network_type': 'vlan',
                'physical_network': 'default',
                'minimum': 100,
                'maximum': 200
            },
            {
                'name': '',
                'default': True,
                'shared': True,
                'network_type': 'vxlan',
                'minimum': 1000,
                'maximum': 2000
            },
            {
                'name': '',
                'default': True,
                'shared': True,
                'network_type': 'vxlan',
                'minimum': 1000,
                'maximum': 2000
            },
        ]
        self._create_network_segment_ranges(duplicate_data)
        # Ensure there are two duplicate ranges data
        range_table = db_utils.get_table(self.engine, 'network_segment_ranges')
        with self.engine.connect() as conn, conn.begin():
            rows = conn.execute(range_table.select()).fetchall()
            self.assertEqual(4, len(rows))
        return True

    def _check_b1bca967e19d(self, engine, data):
        range_table = db_utils.get_table(self.engine, 'network_segment_ranges')
        # check duplicate data is deleted
        with self.engine.connect() as conn, conn.begin():
            vlan = conn.execute(range_table.select().where(
                range_table.c.network_type == 'vlan')).fetchall()
            self.assertEqual(1, len(vlan))
            vxlan = conn.execute(range_table.select().where(
                range_table.c.network_type == 'vxlan')).fetchall()
            self.assertEqual(1, len(vxlan))
