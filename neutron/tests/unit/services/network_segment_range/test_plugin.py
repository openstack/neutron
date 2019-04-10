# Copyright (c) 2019 Intel Corporation.
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

import mock

from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as exc
from neutron_lib.utils import helpers
from oslo_config import cfg

from neutron.db import segments_db
from neutron.services.network_segment_range import plugin as range_plugin
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit import testlib_api

SERVICE_PLUGIN_KLASS = ('neutron.services.network_segment_range.plugin.'
                        'NetworkSegmentRangePlugin')


class TestNetworkSegmentRange(testlib_api.SqlTestCase):

    _foo_range = {'name': 'foo-range',
                  'default': False,
                  'shared': False,
                  'project_id': test_plugin.TEST_TENANT_ID,
                  'network_type': 'foo_network_type',
                  'physical_network': 'foo_phys_net',
                  'minimum': 200,
                  'maximum': 300}

    _flat_range = {'name': 'foo-flat-range',
                   'default': False,
                   'shared': False,
                   'project_id': test_plugin.TEST_TENANT_ID,
                   'network_type': constants.TYPE_FLAT,
                   'physical_network': None,
                   'minimum': 0,
                   'maximum': 0}

    _vlan_range = {'name': 'foo-vlan-range',
                   'default': False,
                   'shared': False,
                   'project_id': test_plugin.TEST_TENANT_ID,
                   'network_type': constants.TYPE_VLAN,
                   'physical_network': 'phys_net',
                   'minimum': 200,
                   'maximum': 300}

    _vxlan_range = {'name': 'foo-vxlan-range',
                    'default': False,
                    'shared': False,
                    'project_id': test_plugin.TEST_TENANT_ID,
                    'network_type': constants.TYPE_VXLAN,
                    'physical_network': None,
                    'minimum': 400,
                    'maximum': 500}

    _gre_range = {'name': 'foo-vlan-range',
                  'default': False,
                  'shared': False,
                  'project_id': test_plugin.TEST_TENANT_ID,
                  'network_type': constants.TYPE_GRE,
                  'physical_network': None,
                  'minimum': 600,
                  'maximum': 700}

    _geneve_range = {'name': 'foo-geneve-range',
                     'default': False,
                     'shared': False,
                     'project_id': test_plugin.TEST_TENANT_ID,
                     'network_type': constants.TYPE_GENEVE,
                     'physical_network': None,
                     'minimum': 800,
                     'maximum': 900}

    def setUp(self):
        super(TestNetworkSegmentRange, self).setUp()
        with mock.patch("neutron_lib.plugins.directory.get_plugin"):
            self.plugin = range_plugin.NetworkSegmentRangePlugin()
        self.context = context.get_admin_context()
        cfg.CONF.set_override('service_plugins', [SERVICE_PLUGIN_KLASS])

    def _validate_resource(self, resource, keys, res_name):
        for k in keys:
            self.assertIn(k, resource[res_name])
            if isinstance(keys[k], list):
                self.assertEqual(
                     sorted(keys[k], key=helpers.safe_sort_key),
                     sorted(resource[res_name][k], key=helpers.safe_sort_key))
            else:
                self.assertEqual(keys[k], resource[res_name][k])

    def test__is_network_segment_range_referenced(self):
        with mock.patch.object(segments_db,
                               'network_segments_exist_in_range',
                               return_value=True):
            self.assertTrue(self.plugin._is_network_segment_range_referenced(
                self.context, self._vlan_range))

    def test__is_network_segment_range_unreferenced(self):
        with mock.patch.object(segments_db,
                               'network_segments_exist_in_range',
                               return_value=False):
            self.assertFalse(self.plugin._is_network_segment_range_referenced(
                self.context, self._vlan_range))

    def test__is_network_segment_range_type_supported(self):
        for foo_range in [self._vlan_range, self._vxlan_range,
                          self._gre_range, self._geneve_range]:
            self.assertTrue(
                self.plugin.
                _is_network_segment_range_type_supported(
                    foo_range['network_type']))

    def test__is_network_segment_range_type_unsupported(self):
        self.assertRaises(
            exc.NeutronException,
            self.plugin._is_network_segment_range_type_supported,
            self._foo_range['network_type'])
        self.assertRaises(
            exc.NeutronException,
            self.plugin._is_network_segment_range_type_supported,
            self._flat_range['network_type'])

    def test__are_allocated_segments_in_range_impacted(self):
        existing_range = self._foo_range
        updated_range = self._vlan_range
        impacted_existing_ranges = [(150, 250), (250, 320),
                                    (200, 300), (180, 330)]
        for ret in impacted_existing_ranges:
            with mock.patch.object(segments_db,
                                   'min_max_actual_segments_in_range',
                                   return_value=ret):
                self.assertTrue(
                    self.plugin._are_allocated_segments_in_range_impacted(
                        self.context, existing_range, updated_range))

    def test__are_allocated_segments_in_range_unimpacted(self):
        existing_range = self._foo_range
        updated_range = self._vlan_range
        with mock.patch.object(segments_db,
                               'min_max_actual_segments_in_range',
                               return_value=(220, 270)):
            self.assertFalse(
                self.plugin._are_allocated_segments_in_range_impacted(
                    self.context, existing_range, updated_range))

    def test_create_network_segment_range(self):
        test_range = self._vlan_range
        network_segment_range = {'network_segment_range': test_range}
        ret = self.plugin.create_network_segment_range(self.context,
                                                       network_segment_range)
        res = {'network_segment_range': ret}
        self._validate_resource(res, test_range, 'network_segment_range')

    def test_create_network_segment_range_failed_with_unsupported_network_type(
            self):
        test_range = self._flat_range
        network_segment_range = {'network_segment_range': test_range}
        self.assertRaises(
            exc.NeutronException,
            self.plugin.create_network_segment_range,
            self.context,
            network_segment_range)

    def test_create_network_segment_range_missing_physical_network_for_vlan(
            self):
        test_range = self._vlan_range.copy()
        test_range.pop("physical_network")
        network_segment_range = {'network_segment_range': test_range}
        self.assertRaises(
            exc.NeutronException,
            self.plugin.create_network_segment_range,
            self.context,
            network_segment_range)

    def test_update_network_segment_range(self):
        test_range = self._vlan_range
        network_segment_range = {'network_segment_range': test_range}
        ret = self.plugin.create_network_segment_range(self.context,
                                                       network_segment_range)
        updated_network_segment_range = {
            'network_segment_range': {'minimum': 700, 'maximum': 800}}
        with mock.patch.object(self.plugin,
                               '_are_allocated_segments_in_range_impacted',
                               return_value=False):
            updated_ret = self.plugin.update_network_segment_range(
                self.context, ret['id'], updated_network_segment_range)
        res = {'network_segment_range': updated_ret}
        test_range['minimum'] = 700
        test_range['maximum'] = 800
        self._validate_resource(res, test_range, 'network_segment_range')

    def test_update_network_segment_range_failed_with_impacted_existing_range(
            self):
        test_range = self._vlan_range
        network_segment_range = {'network_segment_range': test_range}
        ret = self.plugin.create_network_segment_range(self.context,
                                                       network_segment_range)
        updated_network_segment_range = {
            'network_segment_range': {'minimum': 150, 'maximum': 250}}
        with mock.patch.object(self.plugin,
                               '_are_allocated_segments_in_range_impacted',
                               return_value=True):
            self.assertRaises(
                exc.NeutronException,
                self.plugin.update_network_segment_range,
                self.context,
                ret['id'],
                updated_network_segment_range)

    def test_delete_network_segment_range(self):
        test_range = self._vlan_range
        network_segment_range = {'network_segment_range': test_range}
        ret = self.plugin.create_network_segment_range(self.context,
                                                       network_segment_range)
        with mock.patch.object(self.plugin,
                               '_is_network_segment_range_referenced',
                               return_value=False):
            try:
                self.plugin.delete_network_segment_range(
                    self.context, ret['id'])
            except exc.NeutronException:
                self.fail("delete_network_segment_range raised "
                          "NeutronException unexpectedly!")

    def test_delete_network_segment_range_failed_with_segment_referenced(self):
        test_range = self._vlan_range
        network_segment_range = {'network_segment_range': test_range}
        ret = self.plugin.create_network_segment_range(self.context,
                                                       network_segment_range)
        with mock.patch.object(self.plugin,
                               '_is_network_segment_range_referenced',
                               return_value=True):
            self.assertRaises(
                exc.NeutronException,
                self.plugin.delete_network_segment_range,
                self.context,
                ret['id'])
