# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest2

from quantum.common import exceptions as q_exc
from quantum.db import api as db
from quantum.db import models_v2
from quantum.plugins.openvswitch.common import config
from quantum.openstack.common import cfg
from quantum.plugins.openvswitch import ovs_db_v2

VLAN_MIN = 10
VLAN_MAX = 19


class OVSVlanIdsTest(unittest2.TestCase):
    def setUp(self):
        cfg.CONF.set_override('vlan_min', VLAN_MIN, group='OVS')
        cfg.CONF.set_override('vlan_max', VLAN_MAX, group='OVS')

        options = {"sql_connection": cfg.CONF.DATABASE.sql_connection}
        options.update({'base': models_v2.model_base.BASEV2})
        sql_max_retries = cfg.CONF.DATABASE.sql_max_retries
        options.update({"sql_max_retries": sql_max_retries})
        reconnect_interval = cfg.CONF.DATABASE.reconnect_interval
        options.update({"reconnect_interval": reconnect_interval})
        db.configure_db(options)

        ovs_db_v2.update_vlan_id_pool()

    def tearDown(self):
        db.clear_db()
        cfg.CONF.reset()

    def test_update_vlan_id_pool(self):
        self.assertIsNone(ovs_db_v2.get_vlan_id(VLAN_MIN - 1))
        self.assertFalse(ovs_db_v2.get_vlan_id(VLAN_MIN).vlan_used)
        self.assertFalse(ovs_db_v2.get_vlan_id(VLAN_MIN + 1).vlan_used)
        self.assertFalse(ovs_db_v2.get_vlan_id(VLAN_MAX).vlan_used)
        self.assertIsNone(ovs_db_v2.get_vlan_id(VLAN_MAX + 1))

        cfg.CONF.set_override('vlan_min', VLAN_MIN + 5, group='OVS')
        cfg.CONF.set_override('vlan_max', VLAN_MAX + 5, group='OVS')
        ovs_db_v2.update_vlan_id_pool()

        self.assertIsNone(ovs_db_v2.get_vlan_id(VLAN_MIN + 5 - 1))
        self.assertFalse(ovs_db_v2.get_vlan_id(VLAN_MIN + 5).vlan_used)
        self.assertFalse(ovs_db_v2.get_vlan_id(VLAN_MIN + 5 + 1).vlan_used)
        self.assertFalse(ovs_db_v2.get_vlan_id(VLAN_MAX + 5).vlan_used)
        self.assertIsNone(ovs_db_v2.get_vlan_id(VLAN_MAX + 5 + 1))

    def test_vlan_id_pool(self):
        vlan_ids = set()
        for x in xrange(VLAN_MIN, VLAN_MAX + 1):
            vlan_id = ovs_db_v2.reserve_vlan_id()
            self.assertGreaterEqual(vlan_id, VLAN_MIN)
            self.assertLessEqual(vlan_id, VLAN_MAX)
            vlan_ids.add(vlan_id)

        with self.assertRaises(q_exc.NoNetworkAvailable):
            vlan_id = ovs_db_v2.reserve_vlan_id()

        for vlan_id in vlan_ids:
            ovs_db_v2.release_vlan_id(vlan_id)

    def test_invalid_specific_vlan_id(self):
        with self.assertRaises(q_exc.InvalidInput):
            vlan_id = ovs_db_v2.reserve_specific_vlan_id(0)

        with self.assertRaises(q_exc.InvalidInput):
            vlan_id = ovs_db_v2.reserve_specific_vlan_id(4095)

    def test_specific_vlan_id_inside_pool(self):
        vlan_id = VLAN_MIN + 5
        self.assertFalse(ovs_db_v2.get_vlan_id(vlan_id).vlan_used)
        ovs_db_v2.reserve_specific_vlan_id(vlan_id)
        self.assertTrue(ovs_db_v2.get_vlan_id(vlan_id).vlan_used)

        with self.assertRaises(q_exc.VlanIdInUse):
            ovs_db_v2.reserve_specific_vlan_id(vlan_id)

        ovs_db_v2.release_vlan_id(vlan_id)
        self.assertFalse(ovs_db_v2.get_vlan_id(vlan_id).vlan_used)

    def test_specific_vlan_id_outside_pool(self):
        vlan_id = VLAN_MAX + 5
        self.assertIsNone(ovs_db_v2.get_vlan_id(vlan_id))
        ovs_db_v2.reserve_specific_vlan_id(vlan_id)
        self.assertTrue(ovs_db_v2.get_vlan_id(vlan_id).vlan_used)

        with self.assertRaises(q_exc.VlanIdInUse):
            ovs_db_v2.reserve_specific_vlan_id(vlan_id)

        ovs_db_v2.release_vlan_id(vlan_id)
        self.assertIsNone(ovs_db_v2.get_vlan_id(vlan_id))
