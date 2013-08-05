# Copyright 2014 VMware, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from sqlalchemy import orm

from neutron import context
from neutron.plugins.vmware.common import exceptions as p_exc
from neutron.plugins.vmware.dbexts import lsn_db
from neutron.tests.unit import testlib_api


class LSNTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(LSNTestCase, self).setUp()
        self.ctx = context.get_admin_context()
        self.net_id = 'foo_network_id'
        self.lsn_id = 'foo_lsn_id'
        self.lsn_port_id = 'foo_port_id'
        self.subnet_id = 'foo_subnet_id'
        self.mac_addr = 'aa:bb:cc:dd:ee:ff'

    def test_lsn_add(self):
        lsn_db.lsn_add(self.ctx, self.net_id, self.lsn_id)
        lsn = (self.ctx.session.query(lsn_db.Lsn).
               filter_by(lsn_id=self.lsn_id).one())
        self.assertEqual(self.lsn_id, lsn.lsn_id)

    def test_lsn_remove(self):
        lsn_db.lsn_add(self.ctx, self.net_id, self.lsn_id)
        lsn_db.lsn_remove(self.ctx, self.lsn_id)
        q = self.ctx.session.query(lsn_db.Lsn).filter_by(lsn_id=self.lsn_id)
        self.assertRaises(orm.exc.NoResultFound, q.one)

    def test_lsn_remove_for_network(self):
        lsn_db.lsn_add(self.ctx, self.net_id, self.lsn_id)
        lsn_db.lsn_remove_for_network(self.ctx, self.net_id)
        q = self.ctx.session.query(lsn_db.Lsn).filter_by(lsn_id=self.lsn_id)
        self.assertRaises(orm.exc.NoResultFound, q.one)

    def test_lsn_get_for_network(self):
        result = lsn_db.lsn_get_for_network(self.ctx, self.net_id,
                                            raise_on_err=False)
        self.assertIsNone(result)

    def test_lsn_get_for_network_raise_not_found(self):
        self.assertRaises(p_exc.LsnNotFound,
                          lsn_db.lsn_get_for_network,
                          self.ctx, self.net_id)

    def test_lsn_port_add(self):
        lsn_db.lsn_add(self.ctx, self.net_id, self.lsn_id)
        lsn_db.lsn_port_add_for_lsn(self.ctx, self.lsn_port_id,
                                    self.subnet_id, self.mac_addr, self.lsn_id)
        result = (self.ctx.session.query(lsn_db.LsnPort).
                  filter_by(lsn_port_id=self.lsn_port_id).one())
        self.assertEqual(self.lsn_port_id, result.lsn_port_id)

    def test_lsn_port_get_for_mac(self):
        lsn_db.lsn_add(self.ctx, self.net_id, self.lsn_id)
        lsn_db.lsn_port_add_for_lsn(self.ctx, self.lsn_port_id,
                                    self.subnet_id, self.mac_addr, self.lsn_id)
        result = lsn_db.lsn_port_get_for_mac(self.ctx, self.mac_addr)
        self.assertEqual(self.mac_addr, result.mac_addr)

    def test_lsn_port_get_for_mac_raise_not_found(self):
        self.assertRaises(p_exc.LsnPortNotFound,
                          lsn_db.lsn_port_get_for_mac,
                          self.ctx, self.mac_addr)

    def test_lsn_port_get_for_subnet(self):
        lsn_db.lsn_add(self.ctx, self.net_id, self.lsn_id)
        lsn_db.lsn_port_add_for_lsn(self.ctx, self.lsn_port_id,
                                    self.subnet_id, self.mac_addr, self.lsn_id)
        result = lsn_db.lsn_port_get_for_subnet(self.ctx, self.subnet_id)
        self.assertEqual(self.subnet_id, result.sub_id)

    def test_lsn_port_get_for_subnet_raise_not_found(self):
        self.assertRaises(p_exc.LsnPortNotFound,
                          lsn_db.lsn_port_get_for_subnet,
                          self.ctx, self.mac_addr)

    def test_lsn_port_remove(self):
        lsn_db.lsn_add(self.ctx, self.net_id, self.lsn_id)
        lsn_db.lsn_port_remove(self.ctx, self.lsn_port_id)
        q = (self.ctx.session.query(lsn_db.LsnPort).
             filter_by(lsn_port_id=self.lsn_port_id))
        self.assertRaises(orm.exc.NoResultFound, q.one)
