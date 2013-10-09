# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
# @author: Ryota MIBU

import contextlib
import random

from neutron.common import constants as q_const
from neutron.openstack.common import uuidutils
from neutron.plugins.nec.common import exceptions as nexc
from neutron.plugins.nec.db import api as ndb
from neutron.plugins.nec.db import models as nmodels  # noqa
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


class NECPluginV2DBTest(NECPluginV2DBTestBase):

    def testa_add_ofc_item(self):
        """test add OFC item."""
        o, q, n = self.get_ofc_item_random_params()
        tenant = ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        self.assertEqual(tenant.ofc_id, o)
        self.assertEqual(tenant.quantum_id, q)

        self.assertRaises(nexc.NECDBException,
                          ndb.add_ofc_item,
                          self.session, 'ofc_tenant', q, o)

    def testb_get_ofc_item(self):
        """test get OFC item."""
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        tenant = ndb.get_ofc_item(self.session, 'ofc_tenant', q)
        self.assertEqual(tenant.ofc_id, o)
        self.assertEqual(tenant.quantum_id, q)

        tenant_none = ndb.get_ofc_item(self.session, 'ofc_tenant', n)
        self.assertIsNone(tenant_none)

    def testb_get_ofc_id(self):
        """test get OFC d."""
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        tenant_id = ndb.get_ofc_id(self.session, 'ofc_tenant', q)
        self.assertEqual(tenant_id, o)

        tenant_none = ndb.get_ofc_item(self.session, 'ofc_tenant', n)
        self.assertIsNone(tenant_none)

    def testb_exists_ofc_item(self):
        """test get OFC d."""
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        ret = ndb.exists_ofc_item(self.session, 'ofc_tenant', q)
        self.assertTrue(ret)

        tenant_none = ndb.get_ofc_item(self.session, 'ofc_tenant', n)
        self.assertIsNone(tenant_none)

    def testc_find_ofc_item(self):
        """test find OFC item."""
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        tenant = ndb.find_ofc_item(self.session, 'ofc_tenant', o)
        self.assertEqual(tenant.ofc_id, o)
        self.assertEqual(tenant.quantum_id, q)

        tenant_none = ndb.find_ofc_item(self.session, 'ofc_tenant', n)
        self.assertIsNone(tenant_none)

    def testc_del_ofc_item(self):
        """test delete OFC item."""
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o)
        ndb.del_ofc_item(self.session, 'ofc_tenant', q)

        tenant_none = ndb.get_ofc_item(self.session,
                                       'ofc_tenant', q)
        self.assertIsNone(tenant_none)
        tenant_none = ndb.find_ofc_item(self.session,
                                        'ofc_tenant', o)
        self.assertIsNone(tenant_none)

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


class NECPluginV2DBOldMappingTest(NECPluginV2DBTestBase):
    """Test related to old ID mapping."""

    # Mapping Table mode
    OLD = True
    NEW = False

    def test_add_ofc_item_new(self):
        o, q, n = self.get_ofc_item_random_params()
        ret = ndb.add_ofc_item(self.session, 'ofc_tenant', q, o, self.NEW)
        self.assertEqual(ret.ofc_id, o)
        self.assertEqual(ret.quantum_id, q)

        ret = ndb.get_ofc_item(self.session, 'ofc_tenant', q, self.NEW)
        self.assertEqual(ret.ofc_id, o)
        self.assertEqual(ret.quantum_id, q)
        ret = ndb.get_ofc_item(self.session, 'ofc_tenant', q, self.OLD)
        self.assertIsNone(ret)

    def test_add_ofc_item_old(self):
        o, q, n = self.get_ofc_item_random_params()
        ret = ndb.add_ofc_item(self.session, 'ofc_tenant', q, o, self.OLD)
        self.assertEqual(ret.id, o)
        self.assertEqual(ret.quantum_id, q)

        ret = ndb.get_ofc_item(self.session, 'ofc_tenant', q, self.NEW)
        self.assertIsNone(ret)
        ret = ndb.get_ofc_item(self.session, 'ofc_tenant', q, self.OLD)
        self.assertEqual(ret.id, o)
        self.assertEqual(ret.quantum_id, q)

    def _check_new_old_item(self, method, q_id, exp_new, exp_old):
        ret = method(self.session, 'ofc_tenant', q_id, self.NEW)
        self.assertEqual(ret, exp_new)
        ret = method(self.session, 'ofc_tenant', q_id, self.OLD)
        self.assertEqual(ret, exp_old)

    def test_get_ofc_id_new(self):
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o, self.NEW)
        self._check_new_old_item(ndb.get_ofc_id, q, o, None)
        ret = ndb.get_ofc_id_lookup_both(self.session, 'ofc_tenant', q)
        self.assertEqual(ret, o)

    def test_get_ofc_id_old(self):
        o, q, n = self.get_ofc_item_random_params()
        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o, self.OLD)
        self._check_new_old_item(ndb.get_ofc_id, q, None, o)
        ret = ndb.get_ofc_id_lookup_both(self.session, 'ofc_tenant', q)
        self.assertEqual(ret, o)

    def _check_exists_ofc_item(self, mode, exp_new, exp_old):
        o, q, n = self.get_ofc_item_random_params()
        self._check_new_old_item(ndb.exists_ofc_item, q, False, False)
        self.assertFalse(ndb.exists_ofc_item_lookup_both(
            self.session, 'ofc_tenant', q))

        ndb.add_ofc_item(self.session, 'ofc_tenant', q, o, mode)
        self._check_new_old_item(ndb.exists_ofc_item, q, exp_new, exp_old)
        self.assertTrue(ndb.exists_ofc_item_lookup_both(
            self.session, 'ofc_tenant', q))

        ndb.del_ofc_item(self.session, 'ofc_tenant', q, mode)
        self._check_new_old_item(ndb.exists_ofc_item, q, False, False)
        self.assertFalse(ndb.exists_ofc_item_lookup_both(
            self.session, 'ofc_tenant', q))

    def test_exists_ofc_item_new(self):
        self._check_exists_ofc_item(self.NEW, True, False)

    def test_exists_ofc_item_old(self):
        self._check_exists_ofc_item(self.OLD, False, True)

    def _check_delete_ofc_item(self, mode, detect_mode=False):
        o, q, n = self.get_ofc_item_random_params()
        ret = ndb.add_ofc_item(self.session, 'ofc_tenant', q, o, mode)
        ofc_id = ret.ofc_id if mode == self.NEW else ret.id
        self.assertEqual(ofc_id, o)
        self.assertEqual(ret.quantum_id, q)
        ret = ndb.get_ofc_item(self.session, 'ofc_tenant', q, mode)
        ofc_id = ret.ofc_id if mode == self.NEW else ret.id
        self.assertEqual(ofc_id, o)
        self.assertEqual(ret.quantum_id, q)

        if detect_mode:
            ndb.del_ofc_item_lookup_both(self.session, 'ofc_tenant', q)
        else:
            ndb.del_ofc_item(self.session, 'ofc_tenant', q, mode)

        ret = ndb.get_ofc_item(self.session, 'ofc_tenant', q, self.NEW)
        self.assertIsNone(ret)
        ret = ndb.get_ofc_item(self.session, 'ofc_tenant', q, self.OLD)
        self.assertIsNone(ret)

    def test_delete_ofc_item_new(self):
        self._check_delete_ofc_item(self.NEW)

    def test_delete_ofc_item_old(self):
        self._check_delete_ofc_item(self.OLD)

    def test_delete_ofc_item_with_auto_detect_new(self):
        self._check_delete_ofc_item(self.NEW, detect_mode=True)

    def test_delete_ofc_item_old_auto_detect_new(self):
        self._check_delete_ofc_item(self.OLD, detect_mode=True)
