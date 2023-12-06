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
from neutron_lib import exceptions as exc
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg

from neutron.objects.plugins.ml2 import flatallocation as flat_obj
from neutron.plugins.ml2.drivers import type_flat
from neutron.tests import base
from neutron.tests.unit import testlib_api


FLAT_NETWORKS = ['flat_net1', 'flat_net2']
CORE_PLUGIN = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class FlatTypeTest(testlib_api.SqlTestCase):

    def setUp(self):
        super(FlatTypeTest, self).setUp()
        self.setup_coreplugin(CORE_PLUGIN)
        cfg.CONF.set_override('flat_networks', FLAT_NETWORKS,
                              group='ml2_type_flat')
        self.driver = type_flat.FlatTypeDriver()
        self.context = context.Context()
        self.driver.physnet_mtus = []

    def _get_allocation(self, context, segment):
        return flat_obj.FlatAllocation.get_object(
            context, physical_network=segment[api.PHYSICAL_NETWORK])

    def test_is_partial_segment(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'flat_net1'}
        self.assertFalse(self.driver.is_partial_segment(segment))

    def test_validate_provider_segment(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'flat_net1'}
        self.driver.validate_provider_segment(segment)

    def test_validate_provider_phynet_name(self):
        self.driver._parse_networks([])
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'flat_net1'}
        self.assertRaises(exc.InvalidInput,
                          self.driver.validate_provider_segment,
                          segment=segment)

    def test_validate_provider_phynet_name_multiple(self):
        self.driver._parse_networks(['flat_net1', 'flat_net2'])
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'flat_net1'}
        self.driver.validate_provider_segment(segment)
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'flat_net2'}
        self.driver.validate_provider_segment(segment)

    def test_validate_provider_segment_without_physnet_restriction(self):
        self.driver._parse_networks('*')
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'other_flat_net'}
        self.driver.validate_provider_segment(segment)

    def test_validate_provider_segment_with_missing_physical_network(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT}
        self.assertRaises(exc.InvalidInput,
                          self.driver.validate_provider_segment,
                          segment)

    def test_validate_provider_segment_with_unsupported_physical_network(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'other_flat_net'}
        self.assertRaises(exc.InvalidInput,
                          self.driver.validate_provider_segment,
                          segment)

    def test_validate_provider_segment_with_unallowed_segmentation_id(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'flat_net1',
                   api.SEGMENTATION_ID: 1234}
        self.assertRaises(exc.InvalidInput,
                          self.driver.validate_provider_segment,
                          segment)

    def test_reserve_provider_segment(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'flat_net1'}
        observed = self.driver.reserve_provider_segment(self.context, segment)
        alloc = self._get_allocation(self.context, observed)
        self.assertEqual(segment[api.PHYSICAL_NETWORK], alloc.physical_network)

    def test_release_segment(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'flat_net1'}
        self.driver.reserve_provider_segment(self.context, segment)
        self.driver.release_segment(self.context, segment)
        alloc = self._get_allocation(self.context, segment)
        self.assertIsNone(alloc)

    def test_reserve_provider_segment_already_reserved(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'flat_net1'}
        self.driver.reserve_provider_segment(self.context, segment)
        self.assertRaises(exc.FlatNetworkInUse,
                          self.driver.reserve_provider_segment,
                          self.context, segment)

    def test_allocate_tenant_segment(self):
        self.assertIsNone(self.driver.allocate_tenant_segment(self.context))

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
        cfg.CONF.set_override('path_mtu', 1425, group='ml2')
        self.driver.physnet_mtus = {'physnet1': 1450, 'physnet2': 1400}
        self.assertEqual(1400, self.driver.get_mtu('physnet2'))

        cfg.CONF.set_override('global_physnet_mtu', 0)
        cfg.CONF.set_override('path_mtu', 0, group='ml2')
        self.driver.physnet_mtus = {}
        self.assertEqual(0, self.driver.get_mtu('physnet1'))

    def test_parse_physical_network_mtus(self):
        cfg.CONF.set_override(
            'physical_network_mtus',
            ['physnet1:1500', 'physnet2:1500', 'physnet3:9000'],
            group='ml2')
        driver = type_flat.FlatTypeDriver()
        self.assertEqual('1500', driver.physnet_mtus['physnet1'])
        self.assertEqual('1500', driver.physnet_mtus['physnet2'])
        self.assertEqual('9000', driver.physnet_mtus['physnet3'])


class FlatTypeDefaultTest(base.BaseTestCase):

    def setUp(self):
        super(FlatTypeDefaultTest, self).setUp()
        self.driver = type_flat.FlatTypeDriver()
        self.driver.physnet_mtus = []

    def test_validate_provider_segment_default(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'other_flat_net'}
        self.driver.validate_provider_segment(segment)
