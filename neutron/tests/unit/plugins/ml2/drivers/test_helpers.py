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

from neutron_lib import constants as p_const
from neutron_lib import context
from neutron_lib.plugins import utils as plugin_utils
from oslo_config import cfg
from oslo_utils import timeutils
from oslo_utils import uuidutils

from neutron.common import utils as n_utils
from neutron.objects import network as net_obj
from neutron.plugins.ml2.drivers import type_vlan
from neutron.tests.unit import testlib_api


TENANT_NET = 'phys_net2'
VLAN_MIN = 200
VLAN_MAX = 209
NETWORK_VLAN_RANGES = {
    TENANT_NET: [(VLAN_MIN, VLAN_MAX)],
}
NETWORK_VLAN_RANGES_CFG_ENTRIES = ["%s:%s:%s" %
                                   (TENANT_NET, VLAN_MIN, VLAN_MAX)]
SERVICE_PLUGIN_KLASS = ('neutron.services.network_segment_range.plugin.'
                        'NetworkSegmentRangePlugin')


class HelpersTest(testlib_api.SqlTestCase):

    def setUp(self):
        super().setUp()
        self.driver = type_vlan.VlanTypeDriver()
        self.driver._network_vlan_ranges = NETWORK_VLAN_RANGES
        self.context = context.get_admin_context()

    def _create_segment(self, physical_network, segmentation_id):
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

    def test_allocate_partially_specified_segment(self):
        seg_id = self.driver.allocate_partially_specified_segment(
            self.context, TENANT_NET, NETWORK_VLAN_RANGES[TENANT_NET])
        self.assertIsNotNone(seg_id)
        self.assertGreaterEqual(seg_id, VLAN_MIN)
        self.assertLessEqual(seg_id, VLAN_MAX)

    def test_allocate_partially_specified_segment_no_resource(self):
        for vlan_id in range(VLAN_MIN, VLAN_MAX + 1):
            self._create_segment(TENANT_NET, vlan_id)
        seg_id = self.driver.allocate_partially_specified_segment(
            self.context, TENANT_NET, NETWORK_VLAN_RANGES[TENANT_NET])
        self.assertIsNone(seg_id)

    def test_allocate_partially_specified_segment_skips_used(self):
        self._create_segment(TENANT_NET, VLAN_MIN)
        for _ in range(20):
            seg_id = self.driver.allocate_partially_specified_segment(
                self.context, TENANT_NET,
                NETWORK_VLAN_RANGES[TENANT_NET])
            self.assertIsNotNone(seg_id)
            self.assertNotEqual(VLAN_MIN, seg_id)


class HelpersTestWithNetworkSegmentRange(HelpersTest):

    def setUp(self):
        super().setUp()
        cfg.CONF.set_override('network_vlan_ranges',
                              NETWORK_VLAN_RANGES_CFG_ENTRIES,
                              group='ml2_type_vlan')
        cfg.CONF.set_override('service_plugins', [SERVICE_PLUGIN_KLASS])
        self._network_vlan_ranges = plugin_utils.parse_network_vlan_ranges(
            NETWORK_VLAN_RANGES_CFG_ENTRIES)
        self.context = context.get_admin_context()
        self.driver = type_vlan.VlanTypeDriver()
        start_time = n_utils.datetime_to_ts(timeutils.utcnow())
        self.driver.initialize_network_segment_range_support(start_time)
