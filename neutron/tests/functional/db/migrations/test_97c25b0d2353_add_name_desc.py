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

from oslo_db.sqlalchemy import utils as db_utils
from oslo_utils import uuidutils

from neutron.tests.functional.db import test_migrations


def _create_record_with_sa(engine, resource_type, attributes):
    """Create a record with standard attributes."""
    sa_table = db_utils.get_table(engine, 'standardattributes')
    sa_record = engine.execute(sa_table.insert().values(
        {'resource_type': resource_type}))
    attributes['standard_attr_id'] = sa_record.inserted_primary_key[0]
    resource_table = db_utils.get_table(engine, resource_type)
    engine.execute(resource_table.insert().values(attributes))


class NetworkSegmentNameAndDescriptionMixin(object):
    """Validates migration that adds name and description ."""

    def _pre_upgrade_97c25b0d2353(self, engine):
        # Create a network for segments to belong to
        net_id = uuidutils.generate_uuid()
        _create_record_with_sa(engine, 'networks', {
            'id': net_id, 'name': '97c25b0d2353'})

        # Create some segments with old model
        ns_table = db_utils.get_table(engine, 'networksegments')
        for s in range(5):
            engine.execute(ns_table.insert().values({
                'id': uuidutils.generate_uuid(),
                'network_id': net_id,
                'network_type': 'flat'}))
        return True  # Return True so check function is invoked after migrate

    def _check_97c25b0d2353(self, engine, data):
        ns_table = db_utils.get_table(engine, 'networksegments')
        sa_table = db_utils.get_table(engine, 'standardattributes')
        for segment in engine.execute(ns_table.select()).fetchall():

            # Ensure a stdattr record was created for this old segment
            standard_id = segment.standard_attr_id
            rows = engine.execute(sa_table.select().where(
                    sa_table.c.id == standard_id)).fetchall()
            self.assertEqual(1, len(rows))

            # Ensure this old segment can now be named
            engine.execute(ns_table.update().values(name='Zeus').where(
                ns_table.c.standard_attr_id == standard_id))


class TestNetworkSegmentNameDescMySql(NetworkSegmentNameAndDescriptionMixin,
                                      test_migrations.TestWalkMigrationsMysql):
    pass


class TestNetworkSegmentNameDescPsql(NetworkSegmentNameAndDescriptionMixin,
                                     test_migrations.TestWalkMigrationsPsql):
    pass
