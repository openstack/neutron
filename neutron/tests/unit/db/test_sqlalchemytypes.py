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

import abc
import netaddr

from oslo_db import exception
from oslo_db.sqlalchemy import test_base
import six
import sqlalchemy as sa

from neutron import context
from neutron.db import sqlalchemytypes


@six.add_metaclass(abc.ABCMeta)
class SqlAlchemyTypesBaseTestCase(test_base.DbTestCase):
    def setUp(self):
        super(SqlAlchemyTypesBaseTestCase, self).setUp()
        meta = sa.MetaData(bind=self.engine)
        self.test_table = self._get_test_table(meta)
        self.test_table.create()
        self.addCleanup(meta.drop_all)
        self.ctxt = context.get_admin_context()

    @abc.abstractmethod
    def _get_test_table(self, meta):
        """Returns a new sa.Table() object for this test case."""

    def _add_row(self, **kargs):
        self.engine.execute(self.test_table.insert().values(**kargs))

    def _get_all(self):
        rows_select = self.test_table.select()
        return self.engine.execute(rows_select).fetchall()

    def _update_row(self, **kargs):
        self.engine.execute(self.test_table.update().values(**kargs))

    def _delete_rows(self):
        self.engine.execute(self.test_table.delete())

    def _validate_crud(self, data_field_name, expected=None):
        objs = self._get_all()
        self.assertEqual(len(expected) if expected else 0, len(objs))
        if expected:
            for obj in objs:
                name = obj['id']
                self.assertEqual(expected[name], obj[data_field_name])


class IPAddressTestCase(SqlAlchemyTypesBaseTestCase):

    def _get_test_table(self, meta):
        return sa.Table(
            'fakeipaddressmodels',
            meta,
            sa.Column('id', sa.String(36), primary_key=True, nullable=False),
            sa.Column('ip', sqlalchemytypes.IPAddress))

    def _validate_ip_address(self, data_field_name, expected=None):
        objs = self._get_all()
        self.assertEqual(len(expected) if expected else 0, len(objs))
        if expected:
            for obj in objs:
                name = obj['id']
                self.assertEqual(expected[name], obj[data_field_name])

    def _test_crud(self, ip_addresses):
        ip = netaddr.IPAddress(ip_addresses[0])
        self._add_row(id='fake_id', ip=ip)
        self._validate_ip_address(data_field_name='ip',
                                  expected={'fake_id': ip})

        ip2 = netaddr.IPAddress(ip_addresses[1])
        self._update_row(ip=ip2)
        self._validate_ip_address(data_field_name='ip',
                                  expected={'fake_id': ip2})

        self._delete_rows()
        self._validate_ip_address(data_field_name='ip', expected=None)

    def test_crud(self):
        ip_addresses = ["10.0.0.1", "10.0.0.2"]
        self._test_crud(ip_addresses)

        ip_addresses = [
                        "2210::ffff:ffff:ffff:ffff",
                        "2120::ffff:ffff:ffff:ffff"
                       ]
        self._test_crud(ip_addresses)

    def test_wrong_type(self):
        self.assertRaises(exception.DBError, self._add_row,
                          id='fake_id', ip="")
        self.assertRaises(exception.DBError, self._add_row,
                          id='fake_id', ip="10.0.0.5")

    def _test_multiple_create(self, entries):
        reference = {}
        for entry in entries:
            ip = netaddr.IPAddress(entry['ip'])
            name = entry['name']
            self._add_row(id=name, ip=ip)
            reference[name] = ip

        self._validate_ip_address(data_field_name='ip', expected=reference)
        self._delete_rows()
        self._validate_ip_address(data_field_name='ip', expected=None)

    def test_multiple_create(self):
        ip_addresses = [
                        {'name': 'fake_id1', 'ip': "10.0.0.5"},
                        {'name': 'fake_id2', 'ip': "10.0.0.1"},
                        {'name': 'fake_id3',
                         'ip': "2210::ffff:ffff:ffff:ffff"},
                        {'name': 'fake_id4',
                         'ip': "2120::ffff:ffff:ffff:ffff"}
                       ]
        self._test_multiple_create(ip_addresses)
