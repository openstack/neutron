# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cisco Systems, Inc.
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
# @author: Juergen Brendel, Cisco Systems Inc.
# @author: Abhishek Raut, Cisco Systems Inc.
# @author: Rudrajit Tapadar, Cisco Systems Inc.

from six.moves import xrange
from sqlalchemy.orm import exc as s_exc
from testtools import matchers

from neutron.common import exceptions as n_exc
from neutron import context
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.plugins.cisco.common import cisco_constants
from neutron.plugins.cisco.common import cisco_exceptions as c_exc
from neutron.plugins.cisco.db import n1kv_db_v2
from neutron.plugins.cisco.db import n1kv_models_v2
from neutron.tests import base
from neutron.tests.unit import test_db_plugin as test_plugin


PHYS_NET = 'physnet1'
PHYS_NET_2 = 'physnet2'
VLAN_MIN = 10
VLAN_MAX = 19
VXLAN_MIN = 5000
VXLAN_MAX = 5009
SEGMENT_RANGE = '200-220'
SEGMENT_RANGE_MIN_OVERLAP = '210-230'
SEGMENT_RANGE_MAX_OVERLAP = '190-209'
SEGMENT_RANGE_OVERLAP = '190-230'
TEST_NETWORK_ID = 'abcdefghijklmnopqrstuvwxyz'
TEST_NETWORK_ID2 = 'abcdefghijklmnopqrstuvwxy2'
TEST_NETWORK_ID3 = 'abcdefghijklmnopqrstuvwxy3'
TEST_NETWORK_PROFILE = {'name': 'test_profile',
                        'segment_type': 'vlan',
                        'physical_network': 'physnet1',
                        'segment_range': '10-19'}
TEST_NETWORK_PROFILE_2 = {'name': 'test_profile_2',
                          'segment_type': 'vlan',
                          'physical_network': 'physnet1',
                          'segment_range': SEGMENT_RANGE}
TEST_NETWORK_PROFILE_VXLAN = {'name': 'test_profile',
                              'segment_type': 'overlay',
                              'sub_type': 'native_vxlan',
                              'segment_range': '5000-5009',
                              'multicast_ip_range': '239.0.0.70-239.0.0.80'}
TEST_POLICY_PROFILE = {'id': '4a417990-76fb-11e2-bcfd-0800200c9a66',
                       'name': 'test_policy_profile'}
TEST_NETWORK_PROFILE_MULTI_SEGMENT = {'name': 'test_profile',
                                      'segment_type': 'multi-segment'}
TEST_NETWORK_PROFILE_VLAN_TRUNK = {'name': 'test_profile',
                                   'segment_type': 'trunk',
                                   'sub_type': 'vlan'}
TEST_NETWORK_PROFILE_VXLAN_TRUNK = {'name': 'test_profile',
                                    'segment_type': 'trunk',
                                    'sub_type': 'overlay'}


def _create_test_network_profile_if_not_there(session,
                                              profile=TEST_NETWORK_PROFILE):
    try:
        _profile = session.query(n1kv_models_v2.NetworkProfile).filter_by(
            name=profile['name']).one()
    except s_exc.NoResultFound:
        _profile = n1kv_db_v2.create_network_profile(session, profile)
    return _profile


def _create_test_policy_profile_if_not_there(session,
                                             profile=TEST_POLICY_PROFILE):
    try:
        _profile = session.query(n1kv_models_v2.PolicyProfile).filter_by(
            name=profile['name']).one()
    except s_exc.NoResultFound:
        _profile = n1kv_db_v2.create_policy_profile(profile)
    return _profile


class VlanAllocationsTest(base.BaseTestCase):

    def setUp(self):
        super(VlanAllocationsTest, self).setUp()
        db.configure_db()
        self.session = db.get_session()
        self.net_p = _create_test_network_profile_if_not_there(self.session)
        n1kv_db_v2.sync_vlan_allocations(self.session, self.net_p)
        self.addCleanup(db.clear_db)

    def test_sync_vlan_allocations_outside_segment_range(self):
        self.assertRaises(c_exc.VlanIDNotFound,
                          n1kv_db_v2.get_vlan_allocation,
                          self.session,
                          PHYS_NET,
                          VLAN_MIN - 1)
        self.assertRaises(c_exc.VlanIDNotFound,
                          n1kv_db_v2.get_vlan_allocation,
                          self.session,
                          PHYS_NET,
                          VLAN_MAX + 1)
        self.assertRaises(c_exc.VlanIDNotFound,
                          n1kv_db_v2.get_vlan_allocation,
                          self.session,
                          PHYS_NET_2,
                          VLAN_MIN + 20)
        self.assertRaises(c_exc.VlanIDNotFound,
                          n1kv_db_v2.get_vlan_allocation,
                          self.session,
                          PHYS_NET_2,
                          VLAN_MIN + 20)
        self.assertRaises(c_exc.VlanIDNotFound,
                          n1kv_db_v2.get_vlan_allocation,
                          self.session,
                          PHYS_NET_2,
                          VLAN_MAX + 20)

    def test_sync_vlan_allocations_unallocated_vlans(self):
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(self.session,
                                                        PHYS_NET,
                                                        VLAN_MIN).allocated)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(self.session,
                                                        PHYS_NET,
                                                        VLAN_MIN + 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(self.session,
                                                        PHYS_NET,
                                                        VLAN_MAX - 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(self.session,
                                                        PHYS_NET,
                                                        VLAN_MAX).allocated)

    def test_vlan_pool(self):
        vlan_ids = set()
        for x in xrange(VLAN_MIN, VLAN_MAX + 1):
            (physical_network, seg_type,
             vlan_id, m_ip) = n1kv_db_v2.reserve_vlan(self.session, self.net_p)
            self.assertEqual(physical_network, PHYS_NET)
            self.assertThat(vlan_id, matchers.GreaterThan(VLAN_MIN - 1))
            self.assertThat(vlan_id, matchers.LessThan(VLAN_MAX + 1))
            vlan_ids.add(vlan_id)

        self.assertRaises(n_exc.NoNetworkAvailable,
                          n1kv_db_v2.reserve_vlan,
                          self.session,
                          self.net_p)

        n1kv_db_v2.release_vlan(self.session, PHYS_NET, vlan_ids.pop())
        physical_network, seg_type, vlan_id, m_ip = (n1kv_db_v2.reserve_vlan(
                                                     self.session, self.net_p))
        self.assertEqual(physical_network, PHYS_NET)
        self.assertThat(vlan_id, matchers.GreaterThan(VLAN_MIN - 1))
        self.assertThat(vlan_id, matchers.LessThan(VLAN_MAX + 1))
        vlan_ids.add(vlan_id)

        for vlan_id in vlan_ids:
            n1kv_db_v2.release_vlan(self.session, PHYS_NET, vlan_id)

    def test_specific_vlan_inside_pool(self):
        vlan_id = VLAN_MIN + 5
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(self.session,
                                                        PHYS_NET,
                                                        vlan_id).allocated)
        n1kv_db_v2.reserve_specific_vlan(self.session, PHYS_NET, vlan_id)
        self.assertTrue(n1kv_db_v2.get_vlan_allocation(self.session,
                                                       PHYS_NET,
                                                       vlan_id).allocated)

        self.assertRaises(n_exc.VlanIdInUse,
                          n1kv_db_v2.reserve_specific_vlan,
                          self.session,
                          PHYS_NET,
                          vlan_id)

        n1kv_db_v2.release_vlan(self.session, PHYS_NET, vlan_id)
        self.assertFalse(n1kv_db_v2.get_vlan_allocation(self.session,
                                                        PHYS_NET,
                                                        vlan_id).allocated)

    def test_specific_vlan_outside_pool(self):
        vlan_id = VLAN_MAX + 5
        self.assertRaises(c_exc.VlanIDNotFound,
                          n1kv_db_v2.get_vlan_allocation,
                          self.session,
                          PHYS_NET,
                          vlan_id)
        self.assertRaises(c_exc.VlanIDOutsidePool,
                          n1kv_db_v2.reserve_specific_vlan,
                          self.session,
                          PHYS_NET,
                          vlan_id)


class VxlanAllocationsTest(base.BaseTestCase,
                           n1kv_db_v2.NetworkProfile_db_mixin):

    def setUp(self):
        super(VxlanAllocationsTest, self).setUp()
        db.configure_db()
        self.session = db.get_session()
        self.net_p = _create_test_network_profile_if_not_there(
            self.session, TEST_NETWORK_PROFILE_VXLAN)
        n1kv_db_v2.sync_vxlan_allocations(self.session, self.net_p)
        self.addCleanup(db.clear_db)

    def test_sync_vxlan_allocations_outside_segment_range(self):
        self.assertRaises(c_exc.VxlanIDNotFound,
                          n1kv_db_v2.get_vxlan_allocation,
                          self.session,
                          VXLAN_MIN - 1)
        self.assertRaises(c_exc.VxlanIDNotFound,
                          n1kv_db_v2.get_vxlan_allocation,
                          self.session,
                          VXLAN_MAX + 1)

    def test_sync_vxlan_allocations_unallocated_vxlans(self):
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(self.session,
                                                         VXLAN_MIN).allocated)
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(self.session,
                                                         VXLAN_MIN + 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(self.session,
                                                         VXLAN_MAX - 1).
                         allocated)
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(self.session,
                                                         VXLAN_MAX).allocated)

    def test_vxlan_pool(self):
        vxlan_ids = set()
        for x in xrange(VXLAN_MIN, VXLAN_MAX + 1):
            vxlan = n1kv_db_v2.reserve_vxlan(self.session, self.net_p)
            vxlan_id = vxlan[2]
            self.assertThat(vxlan_id, matchers.GreaterThan(VXLAN_MIN - 1))
            self.assertThat(vxlan_id, matchers.LessThan(VXLAN_MAX + 1))
            vxlan_ids.add(vxlan_id)

        self.assertRaises(n_exc.NoNetworkAvailable,
                          n1kv_db_v2.reserve_vxlan,
                          self.session,
                          self.net_p)
        n1kv_db_v2.release_vxlan(self.session, vxlan_ids.pop())
        vxlan = n1kv_db_v2.reserve_vxlan(self.session, self.net_p)
        vxlan_id = vxlan[2]
        self.assertThat(vxlan_id, matchers.GreaterThan(VXLAN_MIN - 1))
        self.assertThat(vxlan_id, matchers.LessThan(VXLAN_MAX + 1))
        vxlan_ids.add(vxlan_id)

        for vxlan_id in vxlan_ids:
            n1kv_db_v2.release_vxlan(self.session, vxlan_id)
        n1kv_db_v2.delete_network_profile(self.session, self.net_p.id)

    def test_specific_vxlan_inside_pool(self):
        vxlan_id = VXLAN_MIN + 5
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(self.session,
                                                         vxlan_id).allocated)
        n1kv_db_v2.reserve_specific_vxlan(self.session, vxlan_id)
        self.assertTrue(n1kv_db_v2.get_vxlan_allocation(self.session,
                                                        vxlan_id).allocated)

        self.assertRaises(c_exc.VxlanIDInUse,
                          n1kv_db_v2.reserve_specific_vxlan,
                          self.session,
                          vxlan_id)

        n1kv_db_v2.release_vxlan(self.session, vxlan_id)
        self.assertFalse(n1kv_db_v2.get_vxlan_allocation(self.session,
                                                         vxlan_id).allocated)

    def test_specific_vxlan_outside_pool(self):
        vxlan_id = VXLAN_MAX + 5
        self.assertRaises(c_exc.VxlanIDNotFound,
                          n1kv_db_v2.get_vxlan_allocation,
                          self.session,
                          vxlan_id)
        self.assertRaises(c_exc.VxlanIDOutsidePool,
                          n1kv_db_v2.reserve_specific_vxlan,
                          self.session,
                          vxlan_id)


class NetworkBindingsTest(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        super(NetworkBindingsTest, self).setUp()
        db.configure_db()
        self.session = db.get_session()
        self.addCleanup(db.clear_db)

    def test_add_network_binding(self):
        with self.network() as network:
            TEST_NETWORK_ID = network['network']['id']

            self.assertRaises(c_exc.NetworkBindingNotFound,
                              n1kv_db_v2.get_network_binding,
                              self.session,
                              TEST_NETWORK_ID)

            p = _create_test_network_profile_if_not_there(self.session)
            n1kv_db_v2.add_network_binding(
                self.session, TEST_NETWORK_ID, 'vlan',
                PHYS_NET, 1234, '0.0.0.0', p.id, None)
            binding = n1kv_db_v2.get_network_binding(
                self.session, TEST_NETWORK_ID)
            self.assertIsNotNone(binding)
            self.assertEqual(binding.network_id, TEST_NETWORK_ID)
            self.assertEqual(binding.network_type, 'vlan')
            self.assertEqual(binding.physical_network, PHYS_NET)
            self.assertEqual(binding.segmentation_id, 1234)

    def test_create_multi_segment_network(self):
        with self.network() as network:
            TEST_NETWORK_ID = network['network']['id']

            self.assertRaises(c_exc.NetworkBindingNotFound,
                              n1kv_db_v2.get_network_binding,
                              self.session,
                              TEST_NETWORK_ID)

            p = _create_test_network_profile_if_not_there(
                self.session,
                TEST_NETWORK_PROFILE_MULTI_SEGMENT)
            n1kv_db_v2.add_network_binding(
                self.session, TEST_NETWORK_ID, 'multi-segment',
                None, 0, '0.0.0.0', p.id, None)
            binding = n1kv_db_v2.get_network_binding(
                self.session, TEST_NETWORK_ID)
            self.assertIsNotNone(binding)
            self.assertEqual(binding.network_id, TEST_NETWORK_ID)
            self.assertEqual(binding.network_type, 'multi-segment')
            self.assertIsNone(binding.physical_network)
            self.assertEqual(binding.segmentation_id, 0)

    def test_add_multi_segment_binding(self):
        with self.network() as network:
            TEST_NETWORK_ID = network['network']['id']

            self.assertRaises(c_exc.NetworkBindingNotFound,
                              n1kv_db_v2.get_network_binding,
                              self.session,
                              TEST_NETWORK_ID)

            p = _create_test_network_profile_if_not_there(
                self.session,
                TEST_NETWORK_PROFILE_MULTI_SEGMENT)
            n1kv_db_v2.add_network_binding(
                self.session, TEST_NETWORK_ID, 'multi-segment',
                None, 0, '0.0.0.0', p.id,
                [(TEST_NETWORK_ID2, TEST_NETWORK_ID3)])
            binding = n1kv_db_v2.get_network_binding(
                self.session, TEST_NETWORK_ID)
            self.assertIsNotNone(binding)
            self.assertEqual(binding.network_id, TEST_NETWORK_ID)
            self.assertEqual(binding.network_type, 'multi-segment')
            self.assertIsNone(binding.physical_network)
            self.assertEqual(binding.segmentation_id, 0)
            ms_binding = (n1kv_db_v2.get_multi_segment_network_binding(
                          self.session, TEST_NETWORK_ID,
                          (TEST_NETWORK_ID2, TEST_NETWORK_ID3)))
            self.assertIsNotNone(ms_binding)
            self.assertEqual(ms_binding.multi_segment_id, TEST_NETWORK_ID)
            self.assertEqual(ms_binding.segment1_id, TEST_NETWORK_ID2)
            self.assertEqual(ms_binding.segment2_id, TEST_NETWORK_ID3)
            ms_members = (n1kv_db_v2.get_multi_segment_members(
                          self.session, TEST_NETWORK_ID))
            self.assertEqual(ms_members,
                             [(TEST_NETWORK_ID2, TEST_NETWORK_ID3)])
            self.assertTrue(n1kv_db_v2.is_multi_segment_member(
                            self.session, TEST_NETWORK_ID2))
            self.assertTrue(n1kv_db_v2.is_multi_segment_member(
                            self.session, TEST_NETWORK_ID3))
            n1kv_db_v2.del_multi_segment_binding(
                self.session, TEST_NETWORK_ID,
                [(TEST_NETWORK_ID2, TEST_NETWORK_ID3)])
            ms_members = (n1kv_db_v2.get_multi_segment_members(
                          self.session, TEST_NETWORK_ID))
            self.assertEqual(ms_members, [])

    def test_create_vlan_trunk_network(self):
        with self.network() as network:
            TEST_NETWORK_ID = network['network']['id']

            self.assertRaises(c_exc.NetworkBindingNotFound,
                              n1kv_db_v2.get_network_binding,
                              self.session,
                              TEST_NETWORK_ID)

            p = _create_test_network_profile_if_not_there(
                self.session,
                TEST_NETWORK_PROFILE_VLAN_TRUNK)
            n1kv_db_v2.add_network_binding(
                self.session, TEST_NETWORK_ID, 'trunk',
                None, 0, '0.0.0.0', p.id, None)
            binding = n1kv_db_v2.get_network_binding(
                self.session, TEST_NETWORK_ID)
            self.assertIsNotNone(binding)
            self.assertEqual(binding.network_id, TEST_NETWORK_ID)
            self.assertEqual(binding.network_type, 'trunk')
            self.assertIsNone(binding.physical_network)
            self.assertEqual(binding.segmentation_id, 0)

    def test_create_vxlan_trunk_network(self):
        with self.network() as network:
            TEST_NETWORK_ID = network['network']['id']

            self.assertRaises(c_exc.NetworkBindingNotFound,
                              n1kv_db_v2.get_network_binding,
                              self.session,
                              TEST_NETWORK_ID)

            p = _create_test_network_profile_if_not_there(
                self.session,
                TEST_NETWORK_PROFILE_VXLAN_TRUNK)
            n1kv_db_v2.add_network_binding(
                self.session, TEST_NETWORK_ID, 'trunk',
                None, 0, '0.0.0.0', p.id, None)
            binding = n1kv_db_v2.get_network_binding(
                self.session, TEST_NETWORK_ID)
            self.assertIsNotNone(binding)
            self.assertEqual(binding.network_id, TEST_NETWORK_ID)
            self.assertEqual(binding.network_type, 'trunk')
            self.assertIsNone(binding.physical_network)
            self.assertEqual(binding.segmentation_id, 0)

    def test_add_vlan_trunk_binding(self):
        with self.network() as network1:
            with self.network() as network2:
                TEST_NETWORK_ID = network1['network']['id']

                self.assertRaises(c_exc.NetworkBindingNotFound,
                                  n1kv_db_v2.get_network_binding,
                                  self.session,
                                  TEST_NETWORK_ID)
                TEST_NETWORK_ID2 = network2['network']['id']
                self.assertRaises(c_exc.NetworkBindingNotFound,
                                  n1kv_db_v2.get_network_binding,
                                  self.session,
                                  TEST_NETWORK_ID2)
                p_v = _create_test_network_profile_if_not_there(self.session)
                n1kv_db_v2.add_network_binding(
                    self.session, TEST_NETWORK_ID2, 'vlan',
                    PHYS_NET, 1234, '0.0.0.0', p_v.id, None)
                p = _create_test_network_profile_if_not_there(
                    self.session,
                    TEST_NETWORK_PROFILE_VLAN_TRUNK)
                n1kv_db_v2.add_network_binding(
                    self.session, TEST_NETWORK_ID, 'trunk',
                    None, 0, '0.0.0.0', p.id, [(TEST_NETWORK_ID2, 0)])
                binding = n1kv_db_v2.get_network_binding(
                    self.session, TEST_NETWORK_ID)
                self.assertIsNotNone(binding)
                self.assertEqual(binding.network_id, TEST_NETWORK_ID)
                self.assertEqual(binding.network_type, 'trunk')
                self.assertEqual(binding.physical_network, PHYS_NET)
                self.assertEqual(binding.segmentation_id, 0)
                t_binding = (n1kv_db_v2.get_trunk_network_binding(
                             self.session, TEST_NETWORK_ID,
                             (TEST_NETWORK_ID2, 0)))
                self.assertIsNotNone(t_binding)
                self.assertEqual(t_binding.trunk_segment_id, TEST_NETWORK_ID)
                self.assertEqual(t_binding.segment_id, TEST_NETWORK_ID2)
                self.assertEqual(t_binding.dot1qtag, '0')
                t_members = (n1kv_db_v2.get_trunk_members(
                    self.session, TEST_NETWORK_ID))
                self.assertEqual(t_members,
                                 [(TEST_NETWORK_ID2, '0')])
                self.assertTrue(n1kv_db_v2.is_trunk_member(
                                self.session, TEST_NETWORK_ID2))
                n1kv_db_v2.del_trunk_segment_binding(
                    self.session, TEST_NETWORK_ID,
                    [(TEST_NETWORK_ID2, '0')])
                t_members = (n1kv_db_v2.get_multi_segment_members(
                    self.session, TEST_NETWORK_ID))
                self.assertEqual(t_members, [])

    def test_add_vxlan_trunk_binding(self):
        with self.network() as network1:
            with self.network() as network2:
                TEST_NETWORK_ID = network1['network']['id']

                self.assertRaises(c_exc.NetworkBindingNotFound,
                                  n1kv_db_v2.get_network_binding,
                                  self.session,
                                  TEST_NETWORK_ID)
                TEST_NETWORK_ID2 = network2['network']['id']
                self.assertRaises(c_exc.NetworkBindingNotFound,
                                  n1kv_db_v2.get_network_binding,
                                  self.session,
                                  TEST_NETWORK_ID2)
                p_v = _create_test_network_profile_if_not_there(
                    self.session, TEST_NETWORK_PROFILE_VXLAN_TRUNK)
                n1kv_db_v2.add_network_binding(
                    self.session, TEST_NETWORK_ID2, 'overlay',
                    None, 5100, '224.10.10.10', p_v.id, None)
                p = _create_test_network_profile_if_not_there(
                    self.session,
                    TEST_NETWORK_PROFILE_VXLAN_TRUNK)
                n1kv_db_v2.add_network_binding(
                    self.session, TEST_NETWORK_ID, 'trunk',
                    None, 0, '0.0.0.0', p.id,
                    [(TEST_NETWORK_ID2, 5)])
                binding = n1kv_db_v2.get_network_binding(
                    self.session, TEST_NETWORK_ID)
                self.assertIsNotNone(binding)
                self.assertEqual(binding.network_id, TEST_NETWORK_ID)
                self.assertEqual(binding.network_type, 'trunk')
                self.assertIsNone(binding.physical_network)
                self.assertEqual(binding.segmentation_id, 0)
                t_binding = (n1kv_db_v2.get_trunk_network_binding(
                             self.session, TEST_NETWORK_ID,
                             (TEST_NETWORK_ID2, '5')))
                self.assertIsNotNone(t_binding)
                self.assertEqual(t_binding.trunk_segment_id, TEST_NETWORK_ID)
                self.assertEqual(t_binding.segment_id, TEST_NETWORK_ID2)
                self.assertEqual(t_binding.dot1qtag, '5')
                t_members = (n1kv_db_v2.get_trunk_members(
                    self.session, TEST_NETWORK_ID))
                self.assertEqual(t_members,
                                 [(TEST_NETWORK_ID2, '5')])
                self.assertTrue(n1kv_db_v2.is_trunk_member(
                    self.session, TEST_NETWORK_ID2))
                n1kv_db_v2.del_trunk_segment_binding(
                    self.session, TEST_NETWORK_ID,
                    [(TEST_NETWORK_ID2, '5')])
                t_members = (n1kv_db_v2.get_multi_segment_members(
                    self.session, TEST_NETWORK_ID))
                self.assertEqual(t_members, [])


class NetworkProfileTests(base.BaseTestCase,
                          n1kv_db_v2.NetworkProfile_db_mixin):

    def setUp(self):
        super(NetworkProfileTests, self).setUp()
        db.configure_db()
        self.session = db.get_session()
        self.addCleanup(db.clear_db)

    def test_create_network_profile(self):
        _db_profile = n1kv_db_v2.create_network_profile(self.session,
                                                        TEST_NETWORK_PROFILE)
        self.assertIsNotNone(_db_profile)
        db_profile = (self.session.query(n1kv_models_v2.NetworkProfile).
                      filter_by(name=TEST_NETWORK_PROFILE['name']).one())
        self.assertIsNotNone(db_profile)
        self.assertEqual(_db_profile.id, db_profile.id)
        self.assertEqual(_db_profile.name, db_profile.name)
        self.assertEqual(_db_profile.segment_type, db_profile.segment_type)
        self.assertEqual(_db_profile.segment_range, db_profile.segment_range)
        self.assertEqual(_db_profile.multicast_ip_index,
                         db_profile.multicast_ip_index)
        self.assertEqual(_db_profile.multicast_ip_range,
                         db_profile.multicast_ip_range)
        n1kv_db_v2.delete_network_profile(self.session, _db_profile.id)

    def test_create_multi_segment_network_profile(self):
        _db_profile = (n1kv_db_v2.create_network_profile(
                       self.session, TEST_NETWORK_PROFILE_MULTI_SEGMENT))
        self.assertIsNotNone(_db_profile)
        db_profile = (
            self.session.query(
                n1kv_models_v2.NetworkProfile).filter_by(
                    name=TEST_NETWORK_PROFILE_MULTI_SEGMENT['name'])
            .one())
        self.assertIsNotNone(db_profile)
        self.assertEqual(_db_profile.id, db_profile.id)
        self.assertEqual(_db_profile.name, db_profile.name)
        self.assertEqual(_db_profile.segment_type, db_profile.segment_type)
        self.assertEqual(_db_profile.segment_range, db_profile.segment_range)
        self.assertEqual(_db_profile.multicast_ip_index,
                         db_profile.multicast_ip_index)
        self.assertEqual(_db_profile.multicast_ip_range,
                         db_profile.multicast_ip_range)
        n1kv_db_v2.delete_network_profile(self.session, _db_profile.id)

    def test_create_vlan_trunk_network_profile(self):
        _db_profile = (n1kv_db_v2.create_network_profile(
                       self.session, TEST_NETWORK_PROFILE_VLAN_TRUNK))
        self.assertIsNotNone(_db_profile)
        db_profile = (self.session.query(n1kv_models_v2.NetworkProfile).
                      filter_by(name=TEST_NETWORK_PROFILE_VLAN_TRUNK['name']).
                      one())
        self.assertIsNotNone(db_profile)
        self.assertEqual(_db_profile.id, db_profile.id)
        self.assertEqual(_db_profile.name, db_profile.name)
        self.assertEqual(_db_profile.segment_type, db_profile.segment_type)
        self.assertEqual(_db_profile.segment_range, db_profile.segment_range)
        self.assertEqual(_db_profile.multicast_ip_index,
                         db_profile.multicast_ip_index)
        self.assertEqual(_db_profile.multicast_ip_range,
                         db_profile.multicast_ip_range)
        self.assertEqual(_db_profile.sub_type, db_profile.sub_type)
        n1kv_db_v2.delete_network_profile(self.session, _db_profile.id)

    def test_create_vxlan_trunk_network_profile(self):
        _db_profile = (n1kv_db_v2.create_network_profile(
                       self.session, TEST_NETWORK_PROFILE_VXLAN_TRUNK))
        self.assertIsNotNone(_db_profile)
        db_profile = (self.session.query(n1kv_models_v2.NetworkProfile).
                      filter_by(name=TEST_NETWORK_PROFILE_VXLAN_TRUNK['name']).
                      one())
        self.assertIsNotNone(db_profile)
        self.assertEqual(_db_profile.id, db_profile.id)
        self.assertEqual(_db_profile.name, db_profile.name)
        self.assertEqual(_db_profile.segment_type, db_profile.segment_type)
        self.assertEqual(_db_profile.segment_range, db_profile.segment_range)
        self.assertEqual(_db_profile.multicast_ip_index,
                         db_profile.multicast_ip_index)
        self.assertEqual(_db_profile.multicast_ip_range,
                         db_profile.multicast_ip_range)
        self.assertEqual(_db_profile.sub_type, db_profile.sub_type)
        n1kv_db_v2.delete_network_profile(self.session, _db_profile.id)

    def test_create_network_profile_overlap(self):
        _db_profile = n1kv_db_v2.create_network_profile(self.session,
                                                        TEST_NETWORK_PROFILE_2)
        ctx = context.get_admin_context()
        TEST_NETWORK_PROFILE_2['name'] = 'net-profile-min-overlap'
        TEST_NETWORK_PROFILE_2['segment_range'] = SEGMENT_RANGE_MIN_OVERLAP
        test_net_profile = {'network_profile': TEST_NETWORK_PROFILE_2}
        self.assertRaises(n_exc.InvalidInput,
                          self.create_network_profile,
                          ctx,
                          test_net_profile)

        TEST_NETWORK_PROFILE_2['name'] = 'net-profile-max-overlap'
        TEST_NETWORK_PROFILE_2['segment_range'] = SEGMENT_RANGE_MAX_OVERLAP
        test_net_profile = {'network_profile': TEST_NETWORK_PROFILE_2}
        self.assertRaises(n_exc.InvalidInput,
                          self.create_network_profile,
                          ctx,
                          test_net_profile)

        TEST_NETWORK_PROFILE_2['name'] = 'net-profile-overlap'
        TEST_NETWORK_PROFILE_2['segment_range'] = SEGMENT_RANGE_OVERLAP
        test_net_profile = {'network_profile': TEST_NETWORK_PROFILE_2}
        self.assertRaises(n_exc.InvalidInput,
                          self.create_network_profile,
                          ctx,
                          test_net_profile)
        n1kv_db_v2.delete_network_profile(self.session, _db_profile.id)

    def test_delete_network_profile(self):
        try:
            profile = (self.session.query(n1kv_models_v2.NetworkProfile).
                       filter_by(name=TEST_NETWORK_PROFILE['name']).one())
        except s_exc.NoResultFound:
            profile = n1kv_db_v2.create_network_profile(self.session,
                                                        TEST_NETWORK_PROFILE)

        n1kv_db_v2.delete_network_profile(self.session, profile.id)
        try:
            self.session.query(n1kv_models_v2.NetworkProfile).filter_by(
                name=TEST_NETWORK_PROFILE['name']).one()
        except s_exc.NoResultFound:
            pass
        else:
            self.fail("Network Profile (%s) was not deleted" %
                      TEST_NETWORK_PROFILE['name'])

    def test_update_network_profile(self):
        TEST_PROFILE_1 = {'name': 'test_profile_1'}
        profile = _create_test_network_profile_if_not_there(self.session)
        updated_profile = n1kv_db_v2.update_network_profile(self.session,
                                                            profile.id,
                                                            TEST_PROFILE_1)
        self.assertEqual(updated_profile.name, TEST_PROFILE_1['name'])
        n1kv_db_v2.delete_network_profile(self.session, profile.id)

    def test_get_network_profile(self):
        profile = n1kv_db_v2.create_network_profile(self.session,
                                                    TEST_NETWORK_PROFILE)
        got_profile = n1kv_db_v2.get_network_profile(self.session, profile.id)
        self.assertEqual(profile.id, got_profile.id)
        self.assertEqual(profile.name, got_profile.name)
        n1kv_db_v2.delete_network_profile(self.session, profile.id)

    def test_get_network_profiles(self):
        test_profiles = [{'name': 'test_profile1',
                          'segment_type': 'vlan',
                          'physical_network': 'phys1',
                          'segment_range': '200-210'},
                         {'name': 'test_profile2',
                          'segment_type': 'vlan',
                          'physical_network': 'phys1',
                          'segment_range': '211-220'},
                         {'name': 'test_profile3',
                          'segment_type': 'vlan',
                          'physical_network': 'phys1',
                          'segment_range': '221-230'},
                         {'name': 'test_profile4',
                          'segment_type': 'vlan',
                          'physical_network': 'phys1',
                          'segment_range': '231-240'},
                         {'name': 'test_profile5',
                          'segment_type': 'vlan',
                          'physical_network': 'phys1',
                          'segment_range': '241-250'},
                         {'name': 'test_profile6',
                          'segment_type': 'vlan',
                          'physical_network': 'phys1',
                          'segment_range': '251-260'},
                         {'name': 'test_profile7',
                          'segment_type': 'vlan',
                          'physical_network': 'phys1',
                          'segment_range': '261-270'}]
        [n1kv_db_v2.create_network_profile(self.session, p)
         for p in test_profiles]
        # TODO(abhraut): Fix this test to work with real tenant_td
        profiles = n1kv_db_v2._get_network_profiles(db_session=self.session)
        self.assertEqual(len(test_profiles), len(list(profiles)))


class PolicyProfileTests(base.BaseTestCase):

    def setUp(self):
        super(PolicyProfileTests, self).setUp()
        db.configure_db()
        self.session = db.get_session()
        self.addCleanup(db.clear_db)

    def test_create_policy_profile(self):
        _db_profile = n1kv_db_v2.create_policy_profile(TEST_POLICY_PROFILE)
        self.assertIsNotNone(_db_profile)
        db_profile = (self.session.query(n1kv_models_v2.PolicyProfile).
                      filter_by(name=TEST_POLICY_PROFILE['name']).one)()
        self.assertIsNotNone(db_profile)
        self.assertTrue(_db_profile.id == db_profile.id)
        self.assertTrue(_db_profile.name == db_profile.name)

    def test_delete_policy_profile(self):
        profile = _create_test_policy_profile_if_not_there(self.session)
        n1kv_db_v2.delete_policy_profile(profile.id)
        try:
            self.session.query(n1kv_models_v2.PolicyProfile).filter_by(
                name=TEST_POLICY_PROFILE['name']).one()
        except s_exc.NoResultFound:
            pass
        else:
            self.fail("Policy Profile (%s) was not deleted" %
                      TEST_POLICY_PROFILE['name'])

    def test_update_policy_profile(self):
        TEST_PROFILE_1 = {'name': 'test_profile_1'}
        profile = _create_test_policy_profile_if_not_there(self.session)
        updated_profile = n1kv_db_v2.update_policy_profile(self.session,
                                                           profile.id,
                                                           TEST_PROFILE_1)
        self.assertEqual(updated_profile.name, TEST_PROFILE_1['name'])

    def test_get_policy_profile(self):
        profile = _create_test_policy_profile_if_not_there(self.session)
        got_profile = n1kv_db_v2.get_policy_profile(self.session, profile.id)
        self.assertEqual(profile.id, got_profile.id)
        self.assertEqual(profile.name, got_profile.name)


class ProfileBindingTests(base.BaseTestCase,
                          n1kv_db_v2.NetworkProfile_db_mixin,
                          db_base_plugin_v2.CommonDbMixin):

    def setUp(self):
        super(ProfileBindingTests, self).setUp()
        db.configure_db()
        self.session = db.get_session()
        self.addCleanup(db.clear_db)

    def _create_test_binding_if_not_there(self, tenant_id, profile_id,
                                          profile_type):
        try:
            _binding = (self.session.query(n1kv_models_v2.ProfileBinding).
                        filter_by(profile_type=profile_type,
                                  tenant_id=tenant_id,
                                  profile_id=profile_id).one())
        except s_exc.NoResultFound:
            _binding = n1kv_db_v2.create_profile_binding(self.session,
                                                         tenant_id,
                                                         profile_id,
                                                         profile_type)
        return _binding

    def test_create_profile_binding(self):
        test_tenant_id = "d434dd90-76ec-11e2-bcfd-0800200c9a66"
        test_profile_id = "dd7b9741-76ec-11e2-bcfd-0800200c9a66"
        test_profile_type = "network"
        n1kv_db_v2.create_profile_binding(self.session,
                                          test_tenant_id,
                                          test_profile_id,
                                          test_profile_type)
        try:
            self.session.query(n1kv_models_v2.ProfileBinding).filter_by(
                profile_type=test_profile_type,
                tenant_id=test_tenant_id,
                profile_id=test_profile_id).one()
        except s_exc.MultipleResultsFound:
            self.fail("Bindings must be unique")
        except s_exc.NoResultFound:
            self.fail("Could not create Profile Binding")

    def test_get_profile_binding(self):
        test_tenant_id = "d434dd90-76ec-11e2-bcfd-0800200c9a66"
        test_profile_id = "dd7b9741-76ec-11e2-bcfd-0800200c9a66"
        test_profile_type = "network"
        self._create_test_binding_if_not_there(test_tenant_id,
                                               test_profile_id,
                                               test_profile_type)
        binding = n1kv_db_v2.get_profile_binding(self.session,
                                                 test_tenant_id,
                                                 test_profile_id)
        self.assertEqual(binding.tenant_id, test_tenant_id)
        self.assertEqual(binding.profile_id, test_profile_id)
        self.assertEqual(binding.profile_type, test_profile_type)

    def test_get_profile_binding_not_found(self):
        self.assertRaises(
            c_exc.ProfileTenantBindingNotFound,
            n1kv_db_v2.get_profile_binding, self.session, "123", "456")

    def test_delete_profile_binding(self):
        test_tenant_id = "d434dd90-76ec-11e2-bcfd-0800200c9a66"
        test_profile_id = "dd7b9741-76ec-11e2-bcfd-0800200c9a66"
        test_profile_type = "network"
        self._create_test_binding_if_not_there(test_tenant_id,
                                               test_profile_id,
                                               test_profile_type)
        n1kv_db_v2.delete_profile_binding(self.session,
                                          test_tenant_id,
                                          test_profile_id)
        q = (self.session.query(n1kv_models_v2.ProfileBinding).filter_by(
             profile_type=test_profile_type,
             tenant_id=test_tenant_id,
             profile_id=test_profile_id))
        self.assertFalse(q.count())

    def test_default_tenant_replace(self):
        ctx = context.get_admin_context()
        ctx.tenant_id = "d434dd90-76ec-11e2-bcfd-0800200c9a66"
        test_profile_id = "AAAAAAAA-76ec-11e2-bcfd-0800200c9a66"
        test_profile_type = "policy"
        n1kv_db_v2.create_profile_binding(self.session,
                                          cisco_constants.TENANT_ID_NOT_SET,
                                          test_profile_id,
                                          test_profile_type)
        network_profile = {"network_profile": TEST_NETWORK_PROFILE}
        self.create_network_profile(ctx, network_profile)
        binding = n1kv_db_v2.get_profile_binding(self.session,
                                                 ctx.tenant_id,
                                                 test_profile_id)
        self.assertRaises(
            c_exc.ProfileTenantBindingNotFound,
            n1kv_db_v2.get_profile_binding,
            self.session,
            cisco_constants.TENANT_ID_NOT_SET,
            test_profile_id)
        self.assertNotEqual(binding.tenant_id,
                            cisco_constants.TENANT_ID_NOT_SET)
