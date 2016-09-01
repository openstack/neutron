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


from oslo_db.sqlalchemy import utils as db_utils
from oslo_utils import uuidutils

from neutron.tests.functional.db import test_migrations


class QosStandardAttrMixin(object):
    """Validates qos standard attr migration."""

    def _create_qos_pol(self, pol_id, description):
        otable = db_utils.get_table(self.engine, 'qos_policies')
        values = {'id': pol_id, 'description': description}
        self.engine.execute(otable.insert().values(values))

    def _create_policies_with_descriptions(self, engine):
        for i in range(10):
            pol_id = uuidutils.generate_uuid()
            self._create_qos_pol(pol_id, 'description-%s' % pol_id)

    def _pre_upgrade_b12a3ef66e62(self, engine):
        self._create_policies_with_descriptions(engine)
        return True  # return True so check function is invoked after migrate

    def _check_b12a3ef66e62(self, engine, data):
        qp = db_utils.get_table(engine, 'qos_policies')
        sa = db_utils.get_table(engine, 'standardattributes')
        for qos_pol in engine.execute(qp.select()).fetchall():
            # ensure standard attributes model was created
            standard_id = qos_pol.standard_attr_id
            rows = engine.execute(
                sa.select().where(sa.c.id == standard_id)).fetchall()
            self.assertEqual(1, len(rows))
            # ensure description got moved over
            self.assertEqual('description-%s' % qos_pol.id,
                             rows[0].description)


class TestQosStandardAttrMysql(QosStandardAttrMixin,
                               test_migrations.TestWalkMigrationsMysql):
    pass


class TestQosStandardAttrPsql(QosStandardAttrMixin,
                              test_migrations.TestWalkMigrationsPsql):
    pass
