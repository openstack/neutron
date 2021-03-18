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

from neutron_lib import context
from neutron_lib.plugins import utils as plugin_utils
from oslo_config import cfg
from oslo_db import exception as exc
from sqlalchemy.orm import query

from neutron.plugins.ml2.drivers import type_vlan
from neutron.tests.unit import testlib_api


TENANT_NET = 'phys_net2'
VLAN_MIN = 200
VLAN_MAX = 209
VLAN_OUTSIDE = 100
NETWORK_VLAN_RANGES = {
    TENANT_NET: [(VLAN_MIN, VLAN_MAX)],
}
NETWORK_VLAN_RANGES_CFG_ENTRIES = ["%s:%s:%s" %
                                   (TENANT_NET, VLAN_MIN, VLAN_MAX)]
SERVICE_PLUGIN_KLASS = ('neutron.services.network_segment_range.plugin.'
                        'NetworkSegmentRangePlugin')


class HelpersTest(testlib_api.SqlTestCase):

    def setUp(self):
        super(HelpersTest, self).setUp()
        self.driver = type_vlan.VlanTypeDriver()
        self.driver.network_vlan_ranges = NETWORK_VLAN_RANGES
        self.driver._sync_vlan_allocations()
        self.context = context.get_admin_context()

    def check_raw_segment(self, expected, observed):
        for key, value in expected.items():
            self.assertEqual(value, observed[key])

    def test_primary_keys(self):
        self.assertEqual(set(['physical_network', 'vlan_id']),
                         self.driver.primary_keys)

    def test_allocate_specific_unallocated_segment_in_pools(self):
        expected = dict(physical_network=TENANT_NET, vlan_id=VLAN_MIN)
        observed = self.driver.allocate_fully_specified_segment(self.context,
                                                                **expected)
        self.check_raw_segment(expected, observed)

    def test_allocate_specific_allocated_segment_in_pools(self):
        raw_segment = dict(physical_network=TENANT_NET, vlan_id=VLAN_MIN)
        self.driver.allocate_fully_specified_segment(self.context,
                                                     **raw_segment)
        observed = self.driver.allocate_fully_specified_segment(self.context,
                                                                **raw_segment)
        self.assertIsNone(observed)

    def test_allocate_specific_finally_allocated_segment_in_pools(self):
        # Test case: allocate a specific unallocated segment in pools but
        # the segment is allocated concurrently between select and update

        raw_segment = dict(physical_network=TENANT_NET, vlan_id=VLAN_MIN)
        with mock.patch.object(query.Query, 'update', return_value=0):
            observed = self.driver.allocate_fully_specified_segment(
                self.context, **raw_segment)
            self.assertIsNone(observed)

    def test_allocate_specific_unallocated_segment_outside_pools(self):
        expected = dict(physical_network=TENANT_NET, vlan_id=VLAN_OUTSIDE)
        observed = self.driver.allocate_fully_specified_segment(self.context,
                                                                **expected)
        self.check_raw_segment(expected, observed)

    def test_allocate_specific_allocated_segment_outside_pools(self):
        raw_segment = dict(physical_network=TENANT_NET, vlan_id=VLAN_OUTSIDE)
        self.driver.allocate_fully_specified_segment(self.context,
                                                     **raw_segment)
        observed = self.driver.allocate_fully_specified_segment(self.context,
                                                                **raw_segment)
        self.assertIsNone(observed)

    def test_allocate_specific_finally_unallocated_segment_outside_pools(self):
        # Test case: allocate a specific allocated segment in pools but
        # the segment is concurrently unallocated after select or update

        expected = dict(physical_network=TENANT_NET, vlan_id=VLAN_MIN)
        with mock.patch.object(self.driver.model, 'save'):
            observed = self.driver.allocate_fully_specified_segment(
                self.context, **expected)
            self.check_raw_segment(expected, observed)

    def test_allocate_partial_segment_without_filters(self):
        expected = dict(physical_network=TENANT_NET)
        observed = self.driver.allocate_partially_specified_segment(
            self.context)
        self.check_raw_segment(expected, observed)

    def test_allocate_partial_segment_with_filter(self):
        expected = dict(physical_network=TENANT_NET)
        observed = self.driver.allocate_partially_specified_segment(
            self.context, **expected)
        self.check_raw_segment(expected, observed)

    def test_allocate_partial_segment_no_resource_available(self):
        for i in range(VLAN_MIN, VLAN_MAX + 1):
            self.driver.allocate_partially_specified_segment(self.context)
        observed = self.driver.allocate_partially_specified_segment(
            self.context)
        self.assertIsNone(observed)

    def test_allocate_partial_segment_outside_pools(self):
        raw_segment = dict(physical_network='other_phys_net')
        observed = self.driver.allocate_partially_specified_segment(
            self.context, **raw_segment)
        self.assertIsNone(observed)

    def test_allocate_partial_segment_first_attempt_fails(self):
        expected = dict(physical_network=TENANT_NET)
        with mock.patch.object(query.Query, 'update', side_effect=[0, 1]):
            self.assertRaises(
                exc.RetryRequest,
                self.driver.allocate_partially_specified_segment,
                self.context, **expected)
            observed = self.driver.allocate_partially_specified_segment(
                self.context, **expected)
            self.check_raw_segment(expected, observed)


class HelpersTestWithNetworkSegmentRange(HelpersTest):

    def setUp(self):
        super(HelpersTestWithNetworkSegmentRange, self).setUp()
        cfg.CONF.set_override('network_vlan_ranges',
                              NETWORK_VLAN_RANGES_CFG_ENTRIES,
                              group='ml2_type_vlan')
        cfg.CONF.set_override('service_plugins', [SERVICE_PLUGIN_KLASS])
        self.network_vlan_ranges = plugin_utils.parse_network_vlan_ranges(
            NETWORK_VLAN_RANGES_CFG_ENTRIES)
        self.context = context.get_admin_context()
        self.driver = type_vlan.VlanTypeDriver()
        self.driver.initialize_network_segment_range_support()
        self.driver._sync_vlan_allocations()
