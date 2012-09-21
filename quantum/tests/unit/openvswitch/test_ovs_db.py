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
from quantum.plugins.openvswitch import ovs_db_v2

PHYS_NET = 'physnet1'
PHYS_NET_2 = 'physnet2'
VLAN_MIN = 10
VLAN_MAX = 19
VLAN_RANGES = {PHYS_NET: [(VLAN_MIN, VLAN_MAX)]}
UPDATED_VLAN_RANGES = {PHYS_NET: [(VLAN_MIN + 5, VLAN_MAX + 5)],
                       PHYS_NET_2: [(VLAN_MIN + 20, VLAN_MAX + 20)]}
TUN_MIN = 100
TUN_MAX = 109
TUNNEL_RANGES = [(TUN_MIN, TUN_MAX)]
UPDATED_TUNNEL_RANGES = [(TUN_MIN + 5, TUN_MAX + 5)]
TEST_NETWORK_ID = 'abcdefghijklmnopqrstuvwxyz'


class VlanAllocationsTest(unittest2.TestCase):
    def setUp(self):
        ovs_db_v2.initialize()
        ovs_db_v2.sync_vlan_allocations(VLAN_RANGES)
        self.session = db.get_session()

    def tearDown(self):
        db.clear_db()

    def test_sync_vlan_allocations(self):
        self.assertIsNone(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MIN - 1))
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                       VLAN_MIN).allocated)
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                       VLAN_MIN + 1).allocated)
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                       VLAN_MAX - 1).allocated)
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                       VLAN_MAX).allocated)
        self.assertIsNone(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MAX + 1))

        ovs_db_v2.sync_vlan_allocations(UPDATED_VLAN_RANGES)

        self.assertIsNone(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MIN + 5 - 1))
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                       VLAN_MIN + 5).
                         allocated)
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                       VLAN_MIN + 5 + 1).
                         allocated)
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                       VLAN_MAX + 5 - 1).
                         allocated)
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                       VLAN_MAX + 5).
                         allocated)
        self.assertIsNone(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MAX + 5 + 1))

        self.assertIsNone(ovs_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                        VLAN_MIN + 20 - 1))
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                       VLAN_MIN + 20).
                         allocated)
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                       VLAN_MIN + 20 + 1).
                         allocated)
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                       VLAN_MAX + 20 - 1).
                         allocated)
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                       VLAN_MAX + 20).
                         allocated)
        self.assertIsNone(ovs_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                        VLAN_MAX + 20 + 1))

        ovs_db_v2.sync_vlan_allocations(VLAN_RANGES)

        self.assertIsNone(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MIN - 1))
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                       VLAN_MIN).allocated)
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                       VLAN_MIN + 1).allocated)
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                       VLAN_MAX - 1).allocated)
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                       VLAN_MAX).allocated)
        self.assertIsNone(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                        VLAN_MAX + 1))

        self.assertIsNone(ovs_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                        VLAN_MIN + 20))
        self.assertIsNone(ovs_db_v2.get_vlan_allocation(PHYS_NET_2,
                                                        VLAN_MAX + 20))

    def test_vlan_pool(self):
        vlan_ids = set()
        for x in xrange(VLAN_MIN, VLAN_MAX + 1):
            physical_network, vlan_id = ovs_db_v2.reserve_vlan(self.session)
            self.assertEqual(physical_network, PHYS_NET)
            self.assertGreaterEqual(vlan_id, VLAN_MIN)
            self.assertLessEqual(vlan_id, VLAN_MAX)
            vlan_ids.add(vlan_id)

        with self.assertRaises(q_exc.NoNetworkAvailable):
            physical_network, vlan_id = ovs_db_v2.reserve_vlan(self.session)

        ovs_db_v2.release_vlan(self.session, PHYS_NET, vlan_ids.pop(),
                               VLAN_RANGES)
        physical_network, vlan_id = ovs_db_v2.reserve_vlan(self.session)
        self.assertEqual(physical_network, PHYS_NET)
        self.assertGreaterEqual(vlan_id, VLAN_MIN)
        self.assertLessEqual(vlan_id, VLAN_MAX)
        vlan_ids.add(vlan_id)

        for vlan_id in vlan_ids:
            ovs_db_v2.release_vlan(self.session, PHYS_NET, vlan_id,
                                   VLAN_RANGES)

    def test_specific_vlan_inside_pool(self):
        vlan_id = VLAN_MIN + 5
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                       vlan_id).allocated)
        ovs_db_v2.reserve_specific_vlan(self.session, PHYS_NET, vlan_id)
        self.assertTrue(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                      vlan_id).allocated)

        with self.assertRaises(q_exc.VlanIdInUse):
            ovs_db_v2.reserve_specific_vlan(self.session, PHYS_NET, vlan_id)

        ovs_db_v2.release_vlan(self.session, PHYS_NET, vlan_id, VLAN_RANGES)
        self.assertFalse(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                       vlan_id).allocated)

    def test_specific_vlan_outside_pool(self):
        vlan_id = VLAN_MAX + 5
        self.assertIsNone(ovs_db_v2.get_vlan_allocation(PHYS_NET, vlan_id))
        ovs_db_v2.reserve_specific_vlan(self.session, PHYS_NET, vlan_id)
        self.assertTrue(ovs_db_v2.get_vlan_allocation(PHYS_NET,
                                                      vlan_id).allocated)

        with self.assertRaises(q_exc.VlanIdInUse):
            ovs_db_v2.reserve_specific_vlan(self.session, PHYS_NET, vlan_id)

        ovs_db_v2.release_vlan(self.session, PHYS_NET, vlan_id, VLAN_RANGES)
        self.assertIsNone(ovs_db_v2.get_vlan_allocation(PHYS_NET, vlan_id))


class TunnelAllocationsTest(unittest2.TestCase):
    def setUp(self):
        ovs_db_v2.initialize()
        ovs_db_v2.sync_tunnel_allocations(TUNNEL_RANGES)
        self.session = db.get_session()

    def tearDown(self):
        db.clear_db()

    def test_sync_tunnel_allocations(self):
        self.assertIsNone(ovs_db_v2.get_tunnel_allocation(TUN_MIN - 1))
        self.assertFalse(ovs_db_v2.get_tunnel_allocation(TUN_MIN).allocated)
        self.assertFalse(ovs_db_v2.get_tunnel_allocation(TUN_MIN + 1).
                         allocated)
        self.assertFalse(ovs_db_v2.get_tunnel_allocation(TUN_MAX - 1).
                         allocated)
        self.assertFalse(ovs_db_v2.get_tunnel_allocation(TUN_MAX).allocated)
        self.assertIsNone(ovs_db_v2.get_tunnel_allocation(TUN_MAX + 1))

        ovs_db_v2.sync_tunnel_allocations(UPDATED_TUNNEL_RANGES)

        self.assertIsNone(ovs_db_v2.get_tunnel_allocation(TUN_MIN + 5 - 1))
        self.assertFalse(ovs_db_v2.get_tunnel_allocation(TUN_MIN + 5).
                         allocated)
        self.assertFalse(ovs_db_v2.get_tunnel_allocation(TUN_MIN + 5 + 1).
                         allocated)
        self.assertFalse(ovs_db_v2.get_tunnel_allocation(TUN_MAX + 5 - 1).
                         allocated)
        self.assertFalse(ovs_db_v2.get_tunnel_allocation(TUN_MAX + 5).
                         allocated)
        self.assertIsNone(ovs_db_v2.get_tunnel_allocation(TUN_MAX + 5 + 1))

    def test_tunnel_pool(self):
        tunnel_ids = set()
        for x in xrange(TUN_MIN, TUN_MAX + 1):
            tunnel_id = ovs_db_v2.reserve_tunnel(self.session)
            self.assertGreaterEqual(tunnel_id, TUN_MIN)
            self.assertLessEqual(tunnel_id, TUN_MAX)
            tunnel_ids.add(tunnel_id)

        with self.assertRaises(q_exc.NoNetworkAvailable):
            tunnel_id = ovs_db_v2.reserve_tunnel(self.session)

        ovs_db_v2.release_tunnel(self.session, tunnel_ids.pop(), TUNNEL_RANGES)
        tunnel_id = ovs_db_v2.reserve_tunnel(self.session)
        self.assertGreaterEqual(tunnel_id, TUN_MIN)
        self.assertLessEqual(tunnel_id, TUN_MAX)
        tunnel_ids.add(tunnel_id)

        for tunnel_id in tunnel_ids:
            ovs_db_v2.release_tunnel(self.session, tunnel_id, TUNNEL_RANGES)

    def test_specific_tunnel_inside_pool(self):
        tunnel_id = TUN_MIN + 5
        self.assertFalse(ovs_db_v2.get_tunnel_allocation(tunnel_id).allocated)
        ovs_db_v2.reserve_specific_tunnel(self.session, tunnel_id)
        self.assertTrue(ovs_db_v2.get_tunnel_allocation(tunnel_id).allocated)

        with self.assertRaises(q_exc.TunnelIdInUse):
            ovs_db_v2.reserve_specific_tunnel(self.session, tunnel_id)

        ovs_db_v2.release_tunnel(self.session, tunnel_id, TUNNEL_RANGES)
        self.assertFalse(ovs_db_v2.get_tunnel_allocation(tunnel_id).allocated)

    def test_specific_tunnel_outside_pool(self):
        tunnel_id = TUN_MAX + 5
        self.assertIsNone(ovs_db_v2.get_tunnel_allocation(tunnel_id))
        ovs_db_v2.reserve_specific_tunnel(self.session, tunnel_id)
        self.assertTrue(ovs_db_v2.get_tunnel_allocation(tunnel_id).allocated)

        with self.assertRaises(q_exc.TunnelIdInUse):
            ovs_db_v2.reserve_specific_tunnel(self.session, tunnel_id)

        ovs_db_v2.release_tunnel(self.session, tunnel_id, TUNNEL_RANGES)
        self.assertIsNone(ovs_db_v2.get_tunnel_allocation(tunnel_id))


class NetworkBindingsTest(unittest2.TestCase):
    def setUp(self):
        ovs_db_v2.initialize()
        self.session = db.get_session()

    def tearDown(self):
        db.clear_db()

    def test_add_network_binding(self):
        self.assertIsNone(ovs_db_v2.get_network_binding(self.session,
                                                        TEST_NETWORK_ID))
        ovs_db_v2.add_network_binding(self.session, TEST_NETWORK_ID, 'vlan',
                                      PHYS_NET, 1234)
        binding = ovs_db_v2.get_network_binding(self.session, TEST_NETWORK_ID)
        self.assertIsNotNone(binding)
        self.assertEqual(binding.network_id, TEST_NETWORK_ID)
        self.assertEqual(binding.network_type, 'vlan')
        self.assertEqual(binding.physical_network, PHYS_NET)
        self.assertEqual(binding.segmentation_id, 1234)
