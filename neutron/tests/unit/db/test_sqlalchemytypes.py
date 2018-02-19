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
from neutron_lib import context
from neutron_lib.utils import net
from oslo_db import exception
from oslo_db.sqlalchemy import enginefacade
from oslo_db.sqlalchemy import test_fixtures
from oslo_utils import timeutils
from oslo_utils import uuidutils
from oslotest import base as test_base
import six
import sqlalchemy as sa

from neutron.db import sqlalchemytypes
from neutron.tests import tools


@six.add_metaclass(abc.ABCMeta)
class SqlAlchemyTypesBaseTestCase(test_fixtures.OpportunisticDBTestMixin,
                                  test_base.BaseTestCase):
    def setUp(self):
        super(SqlAlchemyTypesBaseTestCase, self).setUp()
        self.engine = enginefacade.writer.get_engine()
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


class CIDRTestCase(SqlAlchemyTypesBaseTestCase):

    def _get_test_table(self, meta):
        return sa.Table(
            'fakecidrmodels',
            meta,
            sa.Column('id', sa.String(36), primary_key=True, nullable=False),
            sa.Column('cidr', sqlalchemytypes.CIDR)
        )

    def _get_one(self, value):
        row_select = self.test_table.select().\
            where(self.test_table.c.cidr == value)
        return self.engine.execute(row_select).first()

    def _update_row(self, key, cidr):
        self.engine.execute(
            self.test_table.update().values(cidr=cidr).
            where(self.test_table.c.cidr == key))

    def test_crud(self):
        cidrs = ["10.0.0.0/24", "10.123.250.9/32", "2001:db8::/42",
                 "fe80::21e:67ff:fed0:56f0/64"]

        for cidr_str in cidrs:
            cidr = netaddr.IPNetwork(cidr_str)
            self._add_row(id=uuidutils.generate_uuid(), cidr=cidr)
            obj = self._get_one(cidr)
            self.assertEqual(cidr, obj['cidr'])
            random_cidr = netaddr.IPNetwork(tools.get_random_cidr())
            self._update_row(cidr, random_cidr)
            obj = self._get_one(random_cidr)
            self.assertEqual(random_cidr, obj['cidr'])

        objs = self._get_all()
        self.assertEqual(len(cidrs), len(objs))
        self._delete_rows()
        objs = self._get_all()
        self.assertEqual(0, len(objs))

    def test_wrong_cidr(self):
        wrong_cidrs = ["10.500.5.0/24", "10.0.0.1/40", "10.0.0.10.0/24",
                       "cidr", "", '2001:db8:5000::/64', '2001:db8::/130']
        for cidr in wrong_cidrs:
            self.assertRaises(exception.DBError, self._add_row,
                              id=uuidutils.generate_uuid(), cidr=cidr)


class MACAddressTestCase(SqlAlchemyTypesBaseTestCase):

    def _get_test_table(self, meta):
        return sa.Table(
            'fakemacaddressmodels',
            meta,
            sa.Column('id', sa.String(36), primary_key=True, nullable=False),
            sa.Column('mac', sqlalchemytypes.MACAddress)
        )

    def _get_one(self, value):
        row_select = self.test_table.select().\
            where(self.test_table.c.mac == value)
        return self.engine.execute(row_select).first()

    def _get_all(self):
        rows_select = self.test_table.select()
        return self.engine.execute(rows_select).fetchall()

    def _update_row(self, key, mac):
        self.engine.execute(
            self.test_table.update().values(mac=mac).
            where(self.test_table.c.mac == key))

    def _delete_row(self):
        self.engine.execute(
            self.test_table.delete())

    def test_crud(self):
        mac_addresses = ['FA:16:3E:00:00:01', 'FA:16:3E:00:00:02']

        for mac in mac_addresses:
            mac = netaddr.EUI(mac)
            self._add_row(id=uuidutils.generate_uuid(), mac=mac)
            obj = self._get_one(mac)
            self.assertEqual(mac, obj['mac'])
            random_mac = netaddr.EUI(net.get_random_mac(
                ['fe', '16', '3e', '00', '00', '00']))
            self._update_row(mac, random_mac)
            obj = self._get_one(random_mac)
            self.assertEqual(random_mac, obj['mac'])

        objs = self._get_all()
        self.assertEqual(len(mac_addresses), len(objs))
        self._delete_rows()
        objs = self._get_all()
        self.assertEqual(0, len(objs))

    def test_wrong_mac(self):
        wrong_macs = ["fake", "", -1,
                      "FK:16:3E:00:00:02",
                      "FA:16:3E:00:00:020"]
        for mac in wrong_macs:
            self.assertRaises(exception.DBError, self._add_row,
                              id=uuidutils.generate_uuid(), mac=mac)


class TruncatedDateTimeTestCase(SqlAlchemyTypesBaseTestCase):

    def _get_test_table(self, meta):
        return sa.Table(
            'timetable',
            meta,
            sa.Column('id', sa.String(36), primary_key=True, nullable=False),
            sa.Column('thetime', sqlalchemytypes.TruncatedDateTime)
        )

    def test_microseconds_truncated(self):
        tstamp = timeutils.utcnow()
        tstamp_low = tstamp.replace(microsecond=111111)
        tstamp_high = tstamp.replace(microsecond=999999)
        self._add_row(id=1, thetime=tstamp_low)
        self._add_row(id=2, thetime=tstamp_high)
        rows = self._get_all()
        self.assertEqual(2, len(rows))
        self.assertEqual(rows[0].thetime, rows[1].thetime)
