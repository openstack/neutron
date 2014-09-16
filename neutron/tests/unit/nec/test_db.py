# Copyright 2012 NEC Corporation.  All rights reserved.
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

import contextlib
import random

from neutron.common import constants as q_const
from neutron.openstack.common import uuidutils
from neutron.plugins.nec.common import exceptions as nexc
from neutron.plugins.nec.db import api as ndb
from neutron.tests.unit.nec import test_nec_plugin


class NECPluginV2DBTestBase(test_nec_plugin.NecPluginV2TestCase):
    """Class conisting of NECPluginV2 DB unit tests."""

    def setUp(self):
        """Setup for tests."""
        super(NECPluginV2DBTestBase, self).setUp()
        self.session = self.context.session

    def get_ofc_item_random_params(self):
        """create random parameters for ofc_item test."""
        ofc_id = uuidutils.generate_uuid()
        neutron_id = uuidutils.generate_uuid()
        none = uuidutils.generate_uuid()
        return ofc_id, neutron_id, none

    @contextlib.contextmanager
    def portinfo_random_params(self):
        with self.port() as port:
            params = {'port_id': port['port']['id'],
                      'datapath_id': hex(random.randint(0, 0xffffffff)),
                      'port_no': random.randint(1, 100),
                      'vlan_id': random.randint(q_const.MIN_VLAN_TAG,
                                                q_const.MAX_VLAN_TAG),
                      'mac': ':'.join(["%02x" % random.randint(0, 0xff)
                                       for x in range(6)])
                      }
            yield params


class NECPluginV2DBOfcMappingTest(NECPluginV2DBTestBase):

    def test_add_ofc_item(self):
        """test add OFC item."""
        o, q, n = self.get_ofc_item_random_params()
        tenant = ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        self.assertEqual(tenant.ofc_id, o)
        self.assertEqual(tenant.neutron_id, q)

    def test_add_ofc_item_duplicate_entry(self):
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        self.assertRaises(nexc.NECDBException,
                          ndb.add_ofc_item,
                          self.session, 'ofc_tenant', q, o)

    def test_get_ofc_item(self):
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        tenant = ndb.get_ofc_item(self.session, 'ofc_tenant', q)
        self.assertEqual(tenant.ofc_id, o)
        self.assertEqual(tenant.neutron_id, q)

    def test_get_ofc_item_for_nonexisting_entry(self):
        self.assertIsNone(
            ndb.get_ofc_item(self.session, 'ofc_tenant', 'non-exist-id'))

    def test_get_ofc_id(self):
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        tenant_id = ndb.get_ofc_id(self.session, 'ofc_tenant', q)
        self.assertEqual(tenant_id, o)

    def test_get_ofc_id_for_nonexisting_entry(self):
        self.assertRaises(nexc.OFCMappingNotFound,
                          ndb.get_ofc_id,
                          self.session, 'ofc_tenant', 'non-exist-id')

    def test_exists_ofc_item(self):
        o, q, n = self.get_ofc_item_random_params()
        self.assertFalse(ndb.exists_ofc_item(self.session, 'ofc_tenant', q))

        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        self.assertTrue(ndb.exists_ofc_item(self.session, 'ofc_tenant', q))

        ndb.del_ofc_item(self.session, 'ofc_tenant', q)
        self.assertFalse(ndb.exists_ofc_item(self.session, 'ofc_tenant', q))

    def test_find_ofc_item(self):
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        tenant = ndb.find_ofc_item(self.session, 'ofc_tenant', o)
        self.assertEqual(tenant.ofc_id, o)
        self.assertEqual(tenant.neutron_id, q)

    def test_find_ofc_item_for_nonexisting_entry(self):
        self.assertIsNone(
            ndb.find_ofc_item(self.session, 'ofc_tenant', 'non-existi-id'))

    def test_del_ofc_item(self):
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        self.assertTrue(ndb.del_ofc_item(self.session, 'ofc_tenant', q))

        self.assertIsNone(ndb.get_ofc_item(self.session, 'ofc_tenant', q))
        self.assertIsNone(ndb.find_ofc_item(self.session, 'ofc_tenant', o))

    def test_del_ofc_item_for_nonexisting_entry(self):
        self.assertFalse(
            ndb.del_ofc_item(self.session, 'ofc_tenant', 'non-existi-id'))


class NECPluginV2DBPortInfoTest(NECPluginV2DBTestBase):

    def _compare_portinfo(self, portinfo, expected):
        self.assertEqual(portinfo.id, expected['port_id'])
        self.assertEqual(portinfo.datapath_id, expected['datapath_id'])
        self.assertEqual(portinfo.port_no, expected['port_no'])
        self.assertEqual(portinfo.vlan_id, expected['vlan_id'])
        self.assertEqual(portinfo.mac, expected['mac'])

    def _add_portinfo(self, session, params):
        return ndb.add_portinfo(session, params['port_id'],
                                params['datapath_id'], params['port_no'],
                                params['vlan_id'], params['mac'])

    def testd_add_portinfo(self):
        """test add portinfo."""
        with self.portinfo_random_params() as params:
            portinfo = self._add_portinfo(self.session, params)
            self._compare_portinfo(portinfo, params)

            exception_raised = False
            try:
                self._add_portinfo(self.session, params)
            except nexc.NECDBException:
                exception_raised = True
            self.assertTrue(exception_raised)

    def teste_get_portinfo(self):
        """test get portinfo."""
        with self.portinfo_random_params() as params:
            self._add_portinfo(self.session, params)
            portinfo = ndb.get_portinfo(self.session, params['port_id'])
            self._compare_portinfo(portinfo, params)

            nonexist_id = uuidutils.generate_uuid()
            portinfo_none = ndb.get_portinfo(self.session, nonexist_id)
            self.assertIsNone(portinfo_none)

    def testf_del_portinfo(self):
        """test delete portinfo."""
        with self.portinfo_random_params() as params:
            self._add_portinfo(self.session, params)
            portinfo = ndb.get_portinfo(self.session, params['port_id'])
            self.assertEqual(portinfo.id, params['port_id'])
            ndb.del_portinfo(self.session, params['port_id'])
            portinfo_none = ndb.get_portinfo(self.session, params['port_id'])
            self.assertIsNone(portinfo_none)
