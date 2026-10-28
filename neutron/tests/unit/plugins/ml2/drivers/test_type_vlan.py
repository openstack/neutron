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

import random
from unittest import mock

from neutron_lib import constants as p_const
from neutron_lib import context
from neutron_lib import exceptions as exc
from neutron_lib.plugins.ml2 import api
from neutron_lib.plugins import utils as plugin_utils
from oslo_config import cfg
from oslo_utils import uuidutils
from testtools import matchers

from neutron.common import wsgi_utils
from neutron.conf.plugins.ml2 import config as ml2_config
from neutron.objects import network as net_obj
from neutron.objects import network_segment_range as obj_network_segment_range
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2.drivers import type_vlan
from neutron.tests.unit import testlib_api


PROVIDER_NET = 'phys_net1'
TENANT_NET = 'phys_net2'
VLAN_MIN = 200
VLAN_MAX = 209
TENANT_VLAN_RANGES = [f"{TENANT_NET}:{VLAN_MIN}:{VLAN_MAX}"]
NETWORK_VLAN_RANGES = [PROVIDER_NET] + TENANT_VLAN_RANGES
UNCONFIGURED_NET = 'phys_net3'

CORE_PLUGIN = 'ml2'
SERVICE_PLUGIN_KLASS = ('neutron.services.network_segment_range.plugin.'
                        'NetworkSegmentRangePlugin')


class VlanTypeTest(testlib_api.SqlTestCase):

    def setUp(self):
        super().setUp()
        cfg.CONF.set_override('network_vlan_ranges',
                              NETWORK_VLAN_RANGES,
                              group='ml2_type_vlan')
        self._network_vlan_ranges = plugin_utils.parse_network_vlan_ranges(
            NETWORK_VLAN_RANGES)
        self.driver = type_vlan.VlanTypeDriver()
        self.context = context.Context()
        self.driver.physnet_mtus = {}
        self.setup_coreplugin(CORE_PLUGIN)

    def _create_used_segment(self, physical_network, segmentation_id):
        network = net_obj.Network(
            self.context, name='test-net', id=uuidutils.generate_uuid(),
            project_id=uuidutils.generate_uuid())
        network.create()
        segment = net_obj.NetworkSegment(
            self.context,
            network_id=network.id,
            network_type=p_const.TYPE_VLAN,
            physical_network=physical_network,
            segmentation_id=segmentation_id,
            id=uuidutils.generate_uuid())
        segment.create()

    def test_parse_network_exception_handling(self):
        with mock.patch.object(plugin_utils,
                               'parse_network_vlan_ranges') as parse_ranges:
            parse_ranges.side_effect = Exception('any exception')
            self.assertRaises(SystemExit,
                              self.driver._parse_network_vlan_ranges)

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

    def test_reserve_provider_segment(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: PROVIDER_NET,
                   api.SEGMENTATION_ID: 101}
        observed = self.driver.reserve_provider_segment(self.context, segment)
        self.assertEqual(
            {api.NETWORK_TYPE: p_const.TYPE_VLAN,
             api.PHYSICAL_NETWORK: PROVIDER_NET,
             api.SEGMENTATION_ID: 101,
             api.MTU: self.driver.get_mtu(PROVIDER_NET)},
            observed)

    def test_reserve_provider_segment_already_allocated(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: PROVIDER_NET,
                   api.SEGMENTATION_ID: 101}
        self._create_used_segment(PROVIDER_NET, 101)
        self.assertRaises(exc.VlanIdInUse,
                          self.driver.reserve_provider_segment,
                          self.context,
                          segment)

    def test_reserve_provider_segment_in_tenant_pools(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: TENANT_NET,
                   api.SEGMENTATION_ID: VLAN_MIN}
        observed = self.driver.reserve_provider_segment(self.context, segment)
        self.assertEqual(VLAN_MIN, observed[api.SEGMENTATION_ID])
        self.assertEqual(TENANT_NET, observed[api.PHYSICAL_NETWORK])

    def test_reserve_provider_segment_without_segmentation_id(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                   api.PHYSICAL_NETWORK: TENANT_NET}
        observed = self.driver.reserve_provider_segment(self.context, segment)
        vlan_id = observed[api.SEGMENTATION_ID]
        self.assertThat(vlan_id, matchers.GreaterThan(VLAN_MIN - 1))
        self.assertThat(vlan_id, matchers.LessThan(VLAN_MAX + 1))

    def test_reserve_provider_segment_without_physical_network(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_VLAN}
        observed = self.driver.reserve_provider_segment(self.context, segment)
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

    def test_allocate_project_segment(self):
        cfg.CONF.set_override('network_vlan_ranges', TENANT_VLAN_RANGES,
                              group='ml2_type_vlan')
        driver = type_vlan.VlanTypeDriver()
        for __ in range(VLAN_MIN, VLAN_MAX + 1):
            segment = driver.allocate_tenant_segment(self.context)
            vlan_id = segment[api.SEGMENTATION_ID]
            self.assertGreater(vlan_id, VLAN_MIN - 1)
            self.assertLess(vlan_id, VLAN_MAX + 1)
            self.assertEqual(TENANT_NET, segment[api.PHYSICAL_NETWORK])
            self._create_used_segment(TENANT_NET, vlan_id)

    def test_allocate_project_segment_no_available(self):
        cfg.CONF.set_override('network_vlan_ranges', TENANT_VLAN_RANGES,
                              group='ml2_type_vlan')
        driver = type_vlan.VlanTypeDriver()
        for vlan_id in range(VLAN_MIN, VLAN_MAX + 1):
            self._create_used_segment(TENANT_NET, vlan_id)
        self.assertIsNone(driver.allocate_tenant_segment(self.context))

    def test_release_segment(self):
        segment = self.driver.allocate_tenant_segment(self.context)
        with mock.patch.object(type_vlan.LOG, 'debug') as log_debug:
            self.driver.release_segment(self.context, segment)
            log_debug.assert_called_once()


class VlanTypeAllocationTest(testlib_api.SqlTestCase):

    def _create_used_segment(self, ctx, physical_network, segmentation_id):
        network = net_obj.Network(
            ctx, name='test-net', id=uuidutils.generate_uuid(),
            project_id=uuidutils.generate_uuid())
        network.create()
        segment = net_obj.NetworkSegment(
            ctx,
            network_id=network.id,
            network_type=p_const.TYPE_VLAN,
            physical_network=physical_network,
            segmentation_id=segmentation_id,
            id=uuidutils.generate_uuid())
        segment.create()

    def test_allocate_project_segment_in_order_of_config(self):
        ranges = NETWORK_VLAN_RANGES + ['phys_net3:20:30']
        cfg.CONF.set_override('network_vlan_ranges',
                              ranges,
                              group='ml2_type_vlan')
        driver = type_vlan.VlanTypeDriver()
        driver.physnet_mtus = {}
        # swap config order from DB order after sync has happened to
        # ensure config order is followed and not DB order
        cfg.CONF.set_override('network_vlan_ranges',
                              list(reversed(ranges)),
                              group='ml2_type_vlan')
        driver._parse_network_vlan_ranges()
        ctx = context.Context()
        for __ in range(11):
            # all of physnet3 should be exhausted first
            segment = driver.allocate_tenant_segment(ctx)
            self.assertEqual(
                {'network_type': 'vlan', 'physical_network': 'phys_net3',
                 'segmentation_id': mock.ANY, 'mtu': 1500},
                segment)
            self._create_used_segment(
                ctx, segment['physical_network'], segment['segmentation_id'])
        for __ in range(10):
            # then physnet2
            segment = driver.allocate_tenant_segment(ctx)
            self.assertEqual(
                {'network_type': 'vlan', 'physical_network': TENANT_NET,
                 'segmentation_id': mock.ANY, 'mtu': 1500},
                segment)
            self._create_used_segment(
                ctx, segment['physical_network'], segment['segmentation_id'])
        # NOTE(ralonsoh): to save time, this test won't allocate 4094 segments
        # for PROVIDER_NET.
        segment = driver.allocate_tenant_segment(ctx)
        self.assertEqual(
                {'network_type': 'vlan', 'physical_network': PROVIDER_NET,
                 'segmentation_id': mock.ANY, 'mtu': 1500},
                segment)


class VlanTypeTestWithNetworkSegmentRange(testlib_api.SqlTestCase):

    def setUp(self):
        ml2_config.register_ml2_plugin_opts()
        mock.patch.object(wsgi_utils, 'is_first_api_worker',
                          return_value=True).start()
        super().setUp()
        cfg.CONF.set_override('network_vlan_ranges',
                              NETWORK_VLAN_RANGES,
                              group='ml2_type_vlan')
        cfg.CONF.set_override('service_plugins', [SERVICE_PLUGIN_KLASS])
        self._network_vlan_ranges = plugin_utils.parse_network_vlan_ranges(
            NETWORK_VLAN_RANGES)
        self.driver = type_vlan.VlanTypeDriver()
        self.context = context.Context()
        self.setup_coreplugin(CORE_PLUGIN)
        self.start_time = random.randint(10**5, 10**6)

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

    def _allocate(self, physical_network, vlan_id):
        network = net_obj.Network(
            self.context, name='test-net', id=uuidutils.generate_uuid(),
            project_id=uuidutils.generate_uuid())
        network.create()
        segment = net_obj.NetworkSegment(
            self.context,
            network_id=network.id,
            network_type=p_const.TYPE_VLAN,
            physical_network=physical_network,
            segmentation_id=vlan_id,
            id=uuidutils.generate_uuid())
        segment.create()

    def _default_ranges_for(self, physical_network):
        return sorted(
            (obj.minimum, obj.maximum)
            for obj in obj_network_segment_range.NetworkSegmentRange.
            get_objects(self.context, network_type=p_const.TYPE_VLAN,
                        default=True, physical_network=physical_network))

    def test_narrowing_config_ranges_over_an_allocation_refuses_to_start(self):
        # phys_net2 is configured as 200:209 and a segment holds 205; the
        # operator narrows the config file to 200:204
        self._allocate(TENANT_NET, VLAN_MAX)
        self.driver._network_vlan_ranges = {
            PROVIDER_NET: [(p_const.MIN_VLAN_TAG, p_const.MAX_VLAN_TAG)],
            TENANT_NET: [(VLAN_MIN, VLAN_MAX - 5)]}

        exc_raised = self.assertRaises(
            ml2_exc.VlanAllocationOutsideConfiguredRanges,
            self.driver.initialize_network_segment_range_support,
            self.start_time)

        self.assertIn(TENANT_NET, str(exc_raised))
        self.assertIn(str(VLAN_MAX), str(exc_raised))
        # the raise happened inside the transaction, so the previous default
        # registers survive and the next start reaches the same verdict
        self.assertEqual([(VLAN_MIN, VLAN_MAX)],
                         self._default_ranges_for(TENANT_NET))

    def test_dropping_a_physnet_from_config_over_an_allocation_refuses(self):
        self._allocate(TENANT_NET, VLAN_MIN)
        self.driver._network_vlan_ranges = {
            PROVIDER_NET: [(p_const.MIN_VLAN_TAG, p_const.MAX_VLAN_TAG)]}

        self.assertRaises(
            ml2_exc.VlanAllocationOutsideConfiguredRanges,
            self.driver.initialize_network_segment_range_support,
            self.start_time)

        self.assertEqual([(VLAN_MIN, VLAN_MAX)],
                         self._default_ranges_for(TENANT_NET))

    def test_allocation_still_covered_by_config_starts(self):
        self._allocate(TENANT_NET, VLAN_MIN)
        self.driver._network_vlan_ranges = {
            PROVIDER_NET: [(p_const.MIN_VLAN_TAG, p_const.MAX_VLAN_TAG)],
            TENANT_NET: [(VLAN_MIN, VLAN_MAX - 5)]}

        self.driver.initialize_network_segment_range_support(self.start_time)

        self.assertEqual([(VLAN_MIN, VLAN_MAX - 5)],
                         self._default_ranges_for(TENANT_NET))

    def test_allocation_on_an_api_managed_range_does_not_refuse(self):
        # an operator shrinking a range through the API must not be able to
        # stop Neutron from starting: they could not reach the API to undo it
        obj_network_segment_range.NetworkSegmentRange(
            self.context, network_type=p_const.TYPE_VLAN,
            physical_network=UNCONFIGURED_NET, minimum=VLAN_MIN,
            maximum=VLAN_MAX, default=False, shared=True).create()
        self._allocate(UNCONFIGURED_NET, VLAN_MIN)
        self.driver._network_vlan_ranges = {
            PROVIDER_NET: [(p_const.MIN_VLAN_TAG, p_const.MAX_VLAN_TAG)],
            TENANT_NET: [(VLAN_MIN, VLAN_MAX)]}

        self.driver.initialize_network_segment_range_support(self.start_time)

    def test__delete_expired_default_network_segment_ranges(self):
        self.driver._delete_expired_default_network_segment_ranges(
            self.context, self.start_time)
        ret = obj_network_segment_range.NetworkSegmentRange.get_objects(
            self.context, network_type=self.driver.get_type())
        self.assertEqual(0, len(ret))

    def test_try_to_create_duplicate_network_segment_ranges(self):
        self.driver.initialize_network_segment_range_support(self.start_time)
        ret = obj_network_segment_range.NetworkSegmentRange.get_objects(
            self.context)
        self.assertEqual(2, len(ret))

        self.driver._populate_new_default_network_segment_ranges(
            self.context, self.start_time)
        ret = obj_network_segment_range.NetworkSegmentRange.get_objects(
            self.context)
        self.assertEqual(2, len(ret))
