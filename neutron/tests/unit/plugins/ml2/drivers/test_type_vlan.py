# Copyright (c) 2014 Thales Services SAS
# All Rights Reserved.
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

from unittest import mock

from neutron_lib import constants as p_const
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as exc
from neutron_lib.plugins.ml2 import api
from neutron_lib.plugins import utils as plugin_utils
from oslo_config import cfg
from testtools import matchers

from neutron.objects import network_segment_range as obj_network_segment_range
from neutron.objects.plugins.ml2 import vlanallocation as vlan_alloc_obj
from neutron.plugins.ml2.drivers import type_vlan
from neutron.tests.unit import testlib_api

PROVIDER_NET = 'phys_net1'
TENANT_NET = 'phys_net2'
UNCONFIGURED_NET = 'no_net'
VLAN_MIN = 200
VLAN_MAX = 209
TENANT_VLAN_RANGES = ["%s:%s:%s" % (TENANT_NET, VLAN_MIN, VLAN_MAX)]
NETWORK_VLAN_RANGES = [PROVIDER_NET] + TENANT_VLAN_RANGES
UPDATED_VLAN_RANGES = {
    PROVIDER_NET: [(p_const.MIN_VLAN_TAG, p_const.MAX_VLAN_TAG)],
    TENANT_NET: [(VLAN_MIN + 5, VLAN_MAX + 5)],
}
EMPTY_VLAN_RANGES = {
    PROVIDER_NET: [(p_const.MIN_VLAN_TAG, p_const.MAX_VLAN_TAG)]
}
NETWORK_VLAN_RANGES_WITH_UNCONFIG = {
    PROVIDER_NET: [(p_const.MIN_VLAN_TAG, p_const.MAX_VLAN_TAG)],
    TENANT_NET: [(VLAN_MIN + 5, VLAN_MAX + 5)],
    UNCONFIGURED_NET: [(VLAN_MIN, VLAN_MAX)]
}

CORE_PLUGIN = 'ml2'
SERVICE_PLUGIN_KLASS = ('neutron.services.network_segment_range.plugin.'
                        'NetworkSegmentRangePlugin')


class VlanTypeTest(testlib_api.SqlTestCase):

    def setUp(self):
        super(VlanTypeTest, self).setUp()
        cfg.CONF.set_override('network_vlan_ranges',
                              NETWORK_VLAN_RANGES,
                              group='ml2_type_vlan')
        self.network_vlan_ranges = plugin_utils.parse_network_vlan_ranges(
            NETWORK_VLAN_RANGES)
        self.driver = type_vlan.VlanTypeDriver()
        self.driver._sync_vlan_allocations()
        self.context = context.Context()
        self.driver.physnet_mtus = []
        self.setup_coreplugin(CORE_PLUGIN)

    def test_parse_network_exception_handling(self):
        with mock.patch.object(plugin_utils,
                               'parse_network_vlan_ranges') as parse_ranges:
            parse_ranges.side_effect = Exception('any exception')
            self.assertRaises(SystemExit,
                              self.driver._parse_network_vlan_ranges)

    @db_api.CONTEXT_READER
    def _get_allocation(self, context, segment):
        return vlan_alloc_obj.VlanAllocation.get_object(
            context,
            physical_network=segment[api.PHYSICAL_NETWORK],
            vlan_id=segment[api.SEGMENTATION_ID])

    def test_partial_segment_is_partial_segment(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN}
        self.assertTrue(self.driver.is_partial_segment(segment))

    def test_specific_segment_is_not_partial_segment(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: PROVIDER_NET,
                   api.SEGMENTATION_ID: 1}
        self.assertFalse(self.driver.is_partial_segment(segment))

    def test_validate_provider_segment(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: PROVIDER_NET,
                   api.SEGMENTATION_ID: 1}
        self.assertIsNone(self.driver.validate_provider_segment(segment))

    def test_validate_provider_segment_without_segmentation_id(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: TENANT_NET}
        self.driver.validate_provider_segment(segment)

    def test_validate_provider_segment_without_physical_network(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN}
        self.driver.validate_provider_segment(segment)

    def test_validate_provider_segment_no_phys_network_seg_id_0(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.SEGMENTATION_ID: 0}
        self.assertRaises(exc.InvalidInput,
                          self.driver.validate_provider_segment,
                          segment)

    def test_validate_provider_segment_with_missing_physical_network(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.SEGMENTATION_ID: 1}
        self.assertRaises(exc.InvalidInput,
                          self.driver.validate_provider_segment,
                          segment)

    def test_validate_provider_segment_with_invalid_physical_network(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: 'other_phys_net',
                   api.SEGMENTATION_ID: 1}
        self.assertRaises(exc.InvalidInput,
                          self.driver.validate_provider_segment,
                          segment)

    def test_validate_provider_segment_with_invalid_segmentation_id(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: PROVIDER_NET}
        segmentation_ids = [
            p_const.MIN_VLAN_TAG - 1,
            p_const.MAX_VLAN_TAG + 1]
        for segmentation_id in segmentation_ids:
            segment[api.SEGMENTATION_ID] = segmentation_id
            self.assertRaises(exc.InvalidInput,
                              self.driver.validate_provider_segment,
                              segment)

    def test_validate_provider_segment_with_invalid_input(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: PROVIDER_NET,
                   api.SEGMENTATION_ID: 1,
                   'invalid': 1}
        self.assertRaises(exc.InvalidInput,
                          self.driver.validate_provider_segment,
                          segment)

    def test_sync_vlan_allocations(self):
        def check_in_ranges(network_vlan_ranges):
            vlan_min, vlan_max = network_vlan_ranges[TENANT_NET][0]
            segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                       api.PHYSICAL_NETWORK: TENANT_NET}

            segment[api.SEGMENTATION_ID] = vlan_min - 1
            self.assertIsNone(
                self._get_allocation(self.context, segment))
            segment[api.SEGMENTATION_ID] = vlan_max + 1
            self.assertIsNone(
                self._get_allocation(self.context, segment))

            segment[api.SEGMENTATION_ID] = vlan_min
            self.assertFalse(
                self._get_allocation(self.context, segment).allocated)
            segment[api.SEGMENTATION_ID] = vlan_max
            self.assertFalse(
                self._get_allocation(self.context, segment).allocated)

        check_in_ranges(self.network_vlan_ranges)

        self.driver.network_vlan_ranges = UPDATED_VLAN_RANGES
        self.driver._sync_vlan_allocations()
        check_in_ranges(UPDATED_VLAN_RANGES)

        self.driver.network_vlan_ranges = NETWORK_VLAN_RANGES_WITH_UNCONFIG
        self.driver._sync_vlan_allocations()
        self.driver.network_vlan_ranges = UPDATED_VLAN_RANGES
        with mock.patch.object(type_vlan.LOG, 'debug') as mock_debug:
            self.driver._sync_vlan_allocations()
            mock_debug.assert_called_once_with(
                'Removing any VLAN register on physical networks %s',
                {UNCONFIGURED_NET})
        check_in_ranges(UPDATED_VLAN_RANGES)

        self.driver.network_vlan_ranges = EMPTY_VLAN_RANGES
        self.driver._sync_vlan_allocations()

        vlan_min, vlan_max = UPDATED_VLAN_RANGES[TENANT_NET][0]
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: TENANT_NET}
        segment[api.SEGMENTATION_ID] = vlan_min
        self.assertIsNone(
            self._get_allocation(self.context, segment))
        segment[api.SEGMENTATION_ID] = vlan_max
        self.assertIsNone(
            self._get_allocation(self.context, segment))

    def test_reserve_provider_segment(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: PROVIDER_NET,
                   api.SEGMENTATION_ID: 101}
        alloc = self._get_allocation(self.context, segment)
        expected = vlan_alloc_obj.VlanAllocation(
            allocated=False, physical_network=PROVIDER_NET, vlan_id=101)
        self.assertEqual(expected.__repr__(), alloc.__repr__())
        observed = self.driver.reserve_provider_segment(self.context, segment)
        alloc = self._get_allocation(self.context, observed)
        self.assertTrue(alloc.allocated)

    def test_reserve_provider_segment_already_allocated(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: PROVIDER_NET,
                   api.SEGMENTATION_ID: 101}
        observed = self.driver.reserve_provider_segment(self.context, segment)
        self.assertRaises(exc.VlanIdInUse,
                          self.driver.reserve_provider_segment,
                          self.context,
                          observed)

    def test_reserve_provider_segment_in_tenant_pools(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: TENANT_NET,
                   api.SEGMENTATION_ID: VLAN_MIN}
        alloc = self._get_allocation(self.context, segment)
        self.assertFalse(alloc.allocated)
        observed = self.driver.reserve_provider_segment(self.context, segment)
        alloc = self._get_allocation(self.context, observed)
        self.assertTrue(alloc.allocated)

    def test_reserve_provider_segment_without_segmentation_id(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: TENANT_NET}
        observed = self.driver.reserve_provider_segment(self.context, segment)
        alloc = self._get_allocation(self.context, observed)
        self.assertTrue(alloc.allocated)
        vlan_id = observed[api.SEGMENTATION_ID]
        self.assertThat(vlan_id, matchers.GreaterThan(VLAN_MIN - 1))
        self.assertThat(vlan_id, matchers.LessThan(VLAN_MAX + 1))

    def test_reserve_provider_segment_without_physical_network(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN}
        observed = self.driver.reserve_provider_segment(self.context, segment)
        alloc = self._get_allocation(self.context, observed)
        self.assertTrue(alloc.allocated)
        if observed[api.PHYSICAL_NETWORK] == PROVIDER_NET:
            self.assertIn(observed[api.SEGMENTATION_ID],
                          range(p_const.MIN_VLAN_TAG,
                                p_const.MAX_VLAN_TAG + 1))
        elif observed[api.PHYSICAL_NETWORK] == TENANT_NET:
            self.assertIn(observed[api.SEGMENTATION_ID],
                          range(VLAN_MIN, VLAN_MAX + 1))
        else:
            self.fail('The observed physical network %s does not match with '
                      'any configured' % [api.PHYSICAL_NETWORK])

    def test_get_mtu(self):
        cfg.CONF.set_override('global_physnet_mtu', 1475)
        cfg.CONF.set_override('path_mtu', 1400, group='ml2')
        self.driver.physnet_mtus = {'physnet1': 1450, 'physnet2': 1400}
        self.assertEqual(1450, self.driver.get_mtu('physnet1'))

        cfg.CONF.set_override('global_physnet_mtu', 1375)
        cfg.CONF.set_override('path_mtu', 1400, group='ml2')
        self.driver.physnet_mtus = {'physnet1': 1450, 'physnet2': 1400}
        self.assertEqual(1375, self.driver.get_mtu('physnet1'))

        cfg.CONF.set_override('global_physnet_mtu', 0)
        cfg.CONF.set_override('path_mtu', 1400, group='ml2')
        self.driver.physnet_mtus = {'physnet1': 1450, 'physnet2': 1400}
        self.assertEqual(1450, self.driver.get_mtu('physnet1'))

        cfg.CONF.set_override('global_physnet_mtu', 0)
        cfg.CONF.set_override('path_mtu', 0, group='ml2')
        self.driver.physnet_mtus = {}
        self.assertEqual(0, self.driver.get_mtu('physnet1'))

    def test_allocate_tenant_segment(self):
        cfg.CONF.set_override('network_vlan_ranges', TENANT_VLAN_RANGES,
                              group='ml2_type_vlan')
        driver = type_vlan.VlanTypeDriver()
        driver._sync_vlan_allocations()
        for __ in range(VLAN_MIN, VLAN_MAX + 1):
            segment = self.driver.allocate_tenant_segment(self.context)
            alloc = self._get_allocation(self.context, segment)
            self.assertTrue(alloc.allocated)
            vlan_id = segment[api.SEGMENTATION_ID]
            self.assertGreater(vlan_id, VLAN_MIN - 1)
            self.assertLess(vlan_id, VLAN_MAX + 1)
            self.assertEqual(TENANT_NET, segment[api.PHYSICAL_NETWORK])

    def test_allocate_tenant_segment_no_available(self):
        cfg.CONF.set_override('network_vlan_ranges', TENANT_VLAN_RANGES,
                              group='ml2_type_vlan')
        driver = type_vlan.VlanTypeDriver()
        driver._sync_vlan_allocations()
        for __ in range(VLAN_MIN, VLAN_MAX + 1):
            driver.allocate_tenant_segment(self.context)
        self.assertIsNone(driver.allocate_tenant_segment(self.context))

    def test_release_segment(self):
        segment = self.driver.allocate_tenant_segment(self.context)
        self.driver.release_segment(self.context, segment)
        alloc = self._get_allocation(self.context, segment)
        self.assertFalse(alloc.allocated)

    def test_release_segment_unallocated(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: 'non_existing_physnet',
                   api.SEGMENTATION_ID: 101}
        with mock.patch.object(type_vlan.LOG, 'warning') as log_warn:
            self.driver.release_segment(self.context, segment)
            log_warn.assert_called_once_with(
                "No vlan_id %(vlan_id)s found on physical network "
                "%(physical_network)s",
                {'vlan_id': 101, 'physical_network': 'non_existing_physnet'})


class VlanTypeAllocationTest(testlib_api.SqlTestCase):

    def test_allocate_tenant_segment_in_order_of_config(self):
        ranges = NETWORK_VLAN_RANGES + ['phys_net3:20:30']
        cfg.CONF.set_override('network_vlan_ranges',
                              ranges,
                              group='ml2_type_vlan')
        driver = type_vlan.VlanTypeDriver()
        driver.physnet_mtus = []
        driver._sync_vlan_allocations()
        # swap config order from DB order after sync has happened to
        # ensure config order is followed and not DB order
        cfg.CONF.set_override('network_vlan_ranges',
                              list(reversed(ranges)),
                              group='ml2_type_vlan')
        driver._parse_network_vlan_ranges()
        ctx = context.Context()
        for vlan in range(11):
            # all of physnet3 should be exhausted first
            self.assertEqual(
                {'network_type': 'vlan', 'physical_network': 'phys_net3',
                 'segmentation_id': mock.ANY, 'mtu': 1500},
                driver.allocate_tenant_segment(ctx))
        for vlan in range(10):
            # then physnet2
            self.assertEqual(
                {'network_type': 'vlan', 'physical_network': TENANT_NET,
                 'segmentation_id': mock.ANY, 'mtu': 1500},
                driver.allocate_tenant_segment(ctx))
        # NOTE(ralonsoh): to save time, this test won't allocate 4094 segments
        # for PROVIDER_NET.
        self.assertEqual(
                {'network_type': 'vlan', 'physical_network': PROVIDER_NET,
                 'segmentation_id': mock.ANY, 'mtu': 1500},
                driver.allocate_tenant_segment(ctx))


class VlanTypeTestWithNetworkSegmentRange(testlib_api.SqlTestCase):

    def setUp(self):
        super(VlanTypeTestWithNetworkSegmentRange, self).setUp()
        cfg.CONF.set_override('network_vlan_ranges',
                              NETWORK_VLAN_RANGES,
                              group='ml2_type_vlan')
        cfg.CONF.set_override('service_plugins', [SERVICE_PLUGIN_KLASS])
        self.network_vlan_ranges = plugin_utils.parse_network_vlan_ranges(
            NETWORK_VLAN_RANGES)
        self.driver = type_vlan.VlanTypeDriver()
        self.driver._sync_vlan_allocations()
        self.context = context.Context()
        self.setup_coreplugin(CORE_PLUGIN)

    def test__populate_new_default_network_segment_ranges(self):
        # _populate_new_default_network_segment_ranges will be called when
        # the type driver initializes with `network_segment_range` loaded as
        # one of the `service_plugins`
        ret = obj_network_segment_range.NetworkSegmentRange.get_objects(
            self.context)
        self.assertEqual(2, len(ret))
        network_segment_range = ret[0]
        self.assertTrue(network_segment_range.default)
        self.assertTrue(network_segment_range.shared)
        self.assertIsNone(network_segment_range.project_id)
        self.assertEqual(p_const.TYPE_VLAN, network_segment_range.network_type)
        self.assertEqual(PROVIDER_NET, network_segment_range.physical_network)
        self.assertEqual(p_const.MIN_VLAN_TAG, network_segment_range.minimum)
        self.assertEqual(p_const.MAX_VLAN_TAG, network_segment_range.maximum)
        network_segment_range = ret[1]
        self.assertTrue(network_segment_range.default)
        self.assertTrue(network_segment_range.shared)
        self.assertIsNone(network_segment_range.project_id)
        self.assertEqual(p_const.TYPE_VLAN, network_segment_range.network_type)
        self.assertEqual(TENANT_NET, network_segment_range.physical_network)
        self.assertEqual(VLAN_MIN, network_segment_range.minimum)
        self.assertEqual(VLAN_MAX, network_segment_range.maximum)

    def test__delete_expired_default_network_segment_ranges(self):
        self.driver._delete_expired_default_network_segment_ranges()
        ret = obj_network_segment_range.NetworkSegmentRange.get_objects(
            self.context)
        self.assertEqual(0, len(ret))
