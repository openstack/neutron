# Copyright (c) 2012 OpenStack, LLC.
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

import unittest2

from quantum.common import exceptions as q_exc
from quantum.db import api as db
from quantum.plugins.linuxbridge.db import l2network_db_v2 as lb_db

PHYS_NET = 'physnet1'
PHYS_NET_2 = 'physnet2'
VLAN_MIN = 10
VLAN_MAX = 19
VLAN_RANGES = {PHYS_NET: [(VLAN_MIN, VLAN_MAX)]}
UPDATED_VLAN_RANGES = {PHYS_NET: [(VLAN_MIN + 5, VLAN_MAX + 5)],
                       PHYS_NET_2: [(VLAN_MIN + 20, VLAN_MAX + 20)]}
TEST_NETWORK_ID = 'abcdefghijklmnopqrstuvwxyz'


class NetworkStatesTest(unittest2.TestCase):
    def setUp(self):
        lb_db.initialize()
        lb_db.sync_network_states(VLAN_RANGES)
        self.session = db.get_session()

    def tearDown(self):
        db.clear_db()

    def test_sync_network_states(self):
        self.assertIsNone(lb_db.get_network_state(PHYS_NET,
                                                  VLAN_MIN - 1))
        self.assertFalse(lb_db.get_network_state(PHYS_NET,
                                                 VLAN_MIN).allocated)
        self.assertFalse(lb_db.get_network_state(PHYS_NET,
                                                 VLAN_MIN + 1).allocated)
        self.assertFalse(lb_db.get_network_state(PHYS_NET,
                                                 VLAN_MAX - 1).allocated)
        self.assertFalse(lb_db.get_network_state(PHYS_NET,
                                                 VLAN_MAX).allocated)
        self.assertIsNone(lb_db.get_network_state(PHYS_NET,
                                                  VLAN_MAX + 1))

        lb_db.sync_network_states(UPDATED_VLAN_RANGES)

        self.assertIsNone(lb_db.get_network_state(PHYS_NET,
                                                  VLAN_MIN + 5 - 1))
        self.assertFalse(lb_db.get_network_state(PHYS_NET,
                                                 VLAN_MIN + 5).allocated)
        self.assertFalse(lb_db.get_network_state(PHYS_NET,
                                                 VLAN_MIN + 5 + 1).allocated)
        self.assertFalse(lb_db.get_network_state(PHYS_NET,
                                                 VLAN_MAX + 5 - 1).allocated)
        self.assertFalse(lb_db.get_network_state(PHYS_NET,
                                                 VLAN_MAX + 5).allocated)
        self.assertIsNone(lb_db.get_network_state(PHYS_NET,
                                                  VLAN_MAX + 5 + 1))

        self.assertIsNone(lb_db.get_network_state(PHYS_NET_2,
                                                  VLAN_MIN + 20 - 1))
        self.assertFalse(lb_db.get_network_state(PHYS_NET_2,
                                                 VLAN_MIN + 20).allocated)
        self.assertFalse(lb_db.get_network_state(PHYS_NET_2,
                                                 VLAN_MIN + 20 + 1).allocated)
        self.assertFalse(lb_db.get_network_state(PHYS_NET_2,
                                                 VLAN_MAX + 20 - 1).allocated)
        self.assertFalse(lb_db.get_network_state(PHYS_NET_2,
                                                 VLAN_MAX + 20).allocated)
        self.assertIsNone(lb_db.get_network_state(PHYS_NET_2,
                                                  VLAN_MAX + 20 + 1))

        lb_db.sync_network_states(VLAN_RANGES)

        self.assertIsNone(lb_db.get_network_state(PHYS_NET,
                                                  VLAN_MIN - 1))
        self.assertFalse(lb_db.get_network_state(PHYS_NET,
                                                 VLAN_MIN).allocated)
        self.assertFalse(lb_db.get_network_state(PHYS_NET,
                                                 VLAN_MIN + 1).allocated)
        self.assertFalse(lb_db.get_network_state(PHYS_NET,
                                                 VLAN_MAX - 1).allocated)
        self.assertFalse(lb_db.get_network_state(PHYS_NET,
                                                 VLAN_MAX).allocated)
        self.assertIsNone(lb_db.get_network_state(PHYS_NET,
                                                  VLAN_MAX + 1))

        self.assertIsNone(lb_db.get_network_state(PHYS_NET_2,
                                                  VLAN_MIN + 20))
        self.assertIsNone(lb_db.get_network_state(PHYS_NET_2,
                                                  VLAN_MAX + 20))

    def test_network_pool(self):
        vlan_ids = set()
        for x in xrange(VLAN_MIN, VLAN_MAX + 1):
            physical_network, vlan_id = lb_db.reserve_network(self.session)
            self.assertEqual(physical_network, PHYS_NET)
            self.assertGreaterEqual(vlan_id, VLAN_MIN)
            self.assertLessEqual(vlan_id, VLAN_MAX)
            vlan_ids.add(vlan_id)

        with self.assertRaises(q_exc.NoNetworkAvailable):
            physical_network, vlan_id = lb_db.reserve_network(self.session)

        for vlan_id in vlan_ids:
            lb_db.release_network(self.session, PHYS_NET, vlan_id, VLAN_RANGES)

    def test_specific_network_inside_pool(self):
        vlan_id = VLAN_MIN + 5
        self.assertFalse(lb_db.get_network_state(PHYS_NET,
                                                 vlan_id).allocated)
        lb_db.reserve_specific_network(self.session, PHYS_NET, vlan_id)
        self.assertTrue(lb_db.get_network_state(PHYS_NET,
                                                vlan_id).allocated)

        with self.assertRaises(q_exc.VlanIdInUse):
            lb_db.reserve_specific_network(self.session, PHYS_NET, vlan_id)

        lb_db.release_network(self.session, PHYS_NET, vlan_id, VLAN_RANGES)
        self.assertFalse(lb_db.get_network_state(PHYS_NET,
                                                 vlan_id).allocated)

    def test_specific_network_outside_pool(self):
        vlan_id = VLAN_MAX + 5
        self.assertIsNone(lb_db.get_network_state(PHYS_NET, vlan_id))
        lb_db.reserve_specific_network(self.session, PHYS_NET, vlan_id)
        self.assertTrue(lb_db.get_network_state(PHYS_NET,
                                                vlan_id).allocated)

        with self.assertRaises(q_exc.VlanIdInUse):
            lb_db.reserve_specific_network(self.session, PHYS_NET, vlan_id)

        lb_db.release_network(self.session, PHYS_NET, vlan_id, VLAN_RANGES)
        self.assertIsNone(lb_db.get_network_state(PHYS_NET, vlan_id))


class NetworkBindingsTest(unittest2.TestCase):
    def setUp(self):
        lb_db.initialize()
        self.session = db.get_session()

    def tearDown(self):
        db.clear_db()

    def test_add_network_binding(self):
        self.assertIsNone(lb_db.get_network_binding(self.session,
                                                    TEST_NETWORK_ID))
        lb_db.add_network_binding(self.session, TEST_NETWORK_ID, PHYS_NET,
                                  1234)
        binding = lb_db.get_network_binding(self.session, TEST_NETWORK_ID)
        self.assertIsNotNone(binding)
        self.assertEqual(binding.network_id, TEST_NETWORK_ID)
        self.assertEqual(binding.physical_network, PHYS_NET)
        self.assertEqual(binding.vlan_id, 1234)
