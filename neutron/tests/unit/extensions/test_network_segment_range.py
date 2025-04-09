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

from unittest import mock

from neutron_lib import constants
from neutron_lib import context
from oslo_config import cfg
import webob.exc

from neutron.common import config
from neutron.db import db_base_plugin_v2
from neutron.db import segments_db
from neutron.extensions import network_segment_range as ext_range
from neutron.services.network_segment_range import plugin as plugin_range
from neutron.tests.common import test_db_base_plugin_v2

SERVICE_PLUGIN_KLASS = ('neutron.services.network_segment_range.plugin.'
                        'NetworkSegmentRangePlugin')
TEST_PLUGIN_KLASS = (
    'neutron.tests.unit.extensions.test_network_segment_range.'
    'NetworkSegmentRangeTestPlugin')
TARGET_PLUGIN = 'neutron.plugins.ml2.plugin.Ml2Plugin'


class NetworkSegmentRangeExtensionManager:

    def get_resources(self):
        return ext_range.Network_segment_range.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class NetworkSegmentRangeTestBase(test_db_base_plugin_v2.
                                  NeutronDbPluginV2TestCase):

    def _create_network_segment_range(self, fmt, expected_res_status=None,
                                      **kwargs):
        network_segment_range = {'network_segment_range': {}}
        for k, v in kwargs.items():
            network_segment_range['network_segment_range'][k] = str(v)

        network_segment_range_req = self.new_create_request(
            'network-segment-ranges', network_segment_range, fmt,
            as_admin=True)

        network_segment_range_res = network_segment_range_req.get_response(
            self.ext_api)

        if expected_res_status:
            self.assertEqual(expected_res_status,
                             network_segment_range_res.status_int)
        return network_segment_range_res

    def network_segment_range(self, **kwargs):
        res = self._create_network_segment_range(self.fmt, **kwargs)
        self._check_http_response(res)
        return self.deserialize(self.fmt, res)

    def _test_create_network_segment_range(self, expected=None, **kwargs):
        network_segment_range = self.network_segment_range(**kwargs)
        self._validate_resource(network_segment_range, kwargs,
                                'network_segment_range')
        if expected:
            self._compare_resource(network_segment_range, expected,
                                   'network_segment_range')
        return network_segment_range

    def _test_update_network_segment_range(self, range_id,
                                           data, expected=None):
        update_req = self.new_update_request(
            'network-segment-ranges', data, range_id, as_admin=True)

        update_res = update_req.get_response(self.ext_api)
        if expected:
            network_segment_range = self.deserialize(self.fmt, update_res)
            self._compare_resource(network_segment_range, expected,
                                   'network_segment_range')
            return network_segment_range

        return update_res


class NetworkSegmentRangeTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                                    plugin_range.NetworkSegmentRangePlugin):
    """Test plugin to mixin the network segment range extension."""
    __native_pagination_support = True
    __native_sorting_support = True
    __filter_validation_support = True

    supported_extension_aliases = ["provider", "network-segment-range"]

    def __init__(self):
        super().__init__()
        self.type_manager = mock.Mock()


class TestNetworkSegmentRange(NetworkSegmentRangeTestBase):

    def setUp(self, plugin=None):
        config.register_common_config_options()
        if not plugin:
            plugin = TEST_PLUGIN_KLASS
        service_plugins = {'network_segment_range_plugin_name':
                           SERVICE_PLUGIN_KLASS}
        cfg.CONF.set_override('service_plugins', [SERVICE_PLUGIN_KLASS])
        ext_mgr = NetworkSegmentRangeExtensionManager()
        super().setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)

    def _test_create_network_segment_range(self, expected=None, **kwargs):
        for d in (kwargs, expected):
            if d is None:
                continue
            d.setdefault('name', '')
            d.setdefault('shared', True)
            d.setdefault('project_id', None)
            d.setdefault('network_type', constants.TYPE_VLAN)
            d.setdefault('physical_network', 'phys_net')
            d.setdefault('minimum', 200)
            d.setdefault('maximum', 300)
        return (super().
                _test_create_network_segment_range(expected, **kwargs))

    def test_create_network_segment_range_empty_name(self):
        expected_range = {'name': '',
                          'shared': True,
                          'project_id': None,
                          'network_type': constants.TYPE_VLAN,
                          'physical_network': 'phys_net',
                          'minimum': 200,
                          'maximum': 300}
        self._test_create_network_segment_range(expected=expected_range)

    def test_create_network_segment_range_with_name(self):
        expected_range = {'name': 'foo-range-name',
                          'shared': True,
                          'project_id': None,
                          'network_type': constants.TYPE_VLAN,
                          'physical_network': 'phys_net',
                          'minimum': 200,
                          'maximum': 300}
        self._test_create_network_segment_range(
            name='foo-range-name',
            expected=expected_range)

    def test_create_network_segment_range_unsupported_network_type(self):
        exc = self.assertRaises(webob.exc.HTTPClientError,
                                self._test_create_network_segment_range,
                                network_type='foo-network-type')
        self.assertEqual(webob.exc.HTTPClientError.code, exc.code)
        self.assertIn('foo-network-type is not in valid_values',
                      exc.explanation)

    def test_create_network_segment_range_no_physical_network(self):
        expected_range = {'shared': True,
                          'project_id': None,
                          'network_type': constants.TYPE_VXLAN,
                          'physical_network': ''}
        self._test_create_network_segment_range(
            network_type=constants.TYPE_VXLAN,
            physical_network='',
            expected=expected_range)

    def test_create_network_segment_range_tenant_specific(self):
        expected_range = {'shared': False,
                          'project_id': test_db_base_plugin_v2.TEST_TENANT_ID,
                          'network_type': constants.TYPE_VLAN,
                          'physical_network': 'phys_net',
                          'minimum': 200,
                          'maximum': 300}
        self._test_create_network_segment_range(
            shared=False,
            project_id=test_db_base_plugin_v2.TEST_TENANT_ID,
            network_type=constants.TYPE_VLAN,
            physical_network='phys_net',
            expected=expected_range)

    def test_create_network_segment_ranges_in_certain_order(self):
        ctx = context.get_admin_context()
        range1 = self._test_create_network_segment_range(
            name='foo-range1', physical_network='phys_net1')
        range2 = self._test_create_network_segment_range(
            name='foo-range2', physical_network='phys_net2')
        range3 = self._test_create_network_segment_range(
            name='foo-range3', physical_network='phys_net3')
        network_segment_ranges = (
            NetworkSegmentRangeTestPlugin.get_network_segment_ranges(
                NetworkSegmentRangeTestPlugin(), ctx))
        self.assertEqual(range1['network_segment_range']['id'],
                         network_segment_ranges[0]['id'])
        self.assertEqual(range2['network_segment_range']['id'],
                         network_segment_ranges[1]['id'])
        self.assertEqual(range3['network_segment_range']['id'],
                         network_segment_ranges[2]['id'])

    def test_create_network_segment_range_failed_with_vlan_minimum_id(self):
        exc = self.assertRaises(webob.exc.HTTPClientError,
                                self._test_create_network_segment_range,
                                minimum=0)
        self.assertEqual(webob.exc.HTTPClientError.code, exc.code)
        self.assertIn('Invalid input for minimum', exc.explanation)

    def test_create_network_segment_range_failed_with_vlan_maximum_id(self):
        exc = self.assertRaises(webob.exc.HTTPClientError,
                                self._test_create_network_segment_range,
                                minimum=4095)
        self.assertEqual(webob.exc.HTTPServerError.code, exc.code)
        self.assertIn('Invalid network VLAN range', exc.explanation)

    def test_create_network_segment_range_failed_with_tunnel_minimum_id(self):
        tunnel_type = [constants.TYPE_VXLAN,
                       constants.TYPE_GRE,
                       constants.TYPE_GENEVE]
        for network_type in tunnel_type:
            exc = self.assertRaises(webob.exc.HTTPClientError,
                                    self._test_create_network_segment_range,
                                    network_type=network_type,
                                    physical_network=None,
                                    minimum=0)
            self.assertEqual(webob.exc.HTTPClientError.code, exc.code)
            self.assertIn('Invalid input for minimum', exc.explanation)

    def test_create_network_segment_range_failed_with_tunnel_maximum_id(self):
        expected_res = [(constants.TYPE_VXLAN, 2 ** 24),
                        (constants.TYPE_GRE, 2 ** 32),
                        (constants.TYPE_GENEVE, 2 ** 24)]
        for network_type, max_id in expected_res:
            exc = self.assertRaises(webob.exc.HTTPClientError,
                                    self._test_create_network_segment_range,
                                    network_type=network_type,
                                    physical_network=None,
                                    maximum=max_id)
            if network_type == constants.TYPE_GRE:
                self.assertEqual(webob.exc.HTTPClientError.code, exc.code)
                self.assertIn('Invalid input for maximum', exc.explanation)
            else:
                self.assertEqual(webob.exc.HTTPServerError.code, exc.code)
                self.assertIn('Invalid network tunnel range', exc.explanation)

    def test_update_network_segment_range_set_name(self):
        network_segment_range = self._test_create_network_segment_range()
        with mock.patch.object(segments_db, 'min_max_actual_segments_in_range',
                               return_value=(None, None)):
            result = self._update(
                'network-segment-ranges',
                network_segment_range['network_segment_range']['id'],
                {'network_segment_range': {'name': 'foo-name'}},
                expected_code=webob.exc.HTTPOk.code,
                as_admin=True)
            self.assertEqual('foo-name',
                             result['network_segment_range']['name'])

    def test_update_network_segment_range_set_name_to_empty(self):
        network_segment_range = self._test_create_network_segment_range(
            name='foo-range-name')
        with mock.patch.object(segments_db, 'min_max_actual_segments_in_range',
                               return_value=(None, None)):
            result = self._update(
                'network-segment-ranges',
                network_segment_range['network_segment_range']['id'],
                {'network_segment_range': {'name': ''}},
                expected_code=webob.exc.HTTPOk.code,
                as_admin=True)
            self.assertEqual('', result['network_segment_range']['name'])

    def test_update_network_segment_range_min_max(self):
        network_segment_range = self._test_create_network_segment_range()
        with mock.patch.object(segments_db, 'min_max_actual_segments_in_range',
                               return_value=(None, None)):
            result = self._update(
                'network-segment-ranges',
                network_segment_range['network_segment_range']['id'],
                {'network_segment_range': {'minimum': 1200, 'maximum': 1300}},
                expected_code=webob.exc.HTTPOk.code,
                as_admin=True)
            self.assertEqual(1200, result['network_segment_range']['minimum'])
            self.assertEqual(1300, result['network_segment_range']['maximum'])

    def test_get_network_segment_range(self):
        network_segment_range = self._test_create_network_segment_range()
        req = self.new_show_request(
            'network-segment-ranges',
            network_segment_range['network_segment_range']['id'],
            as_admin=True)
        res = self.deserialize(self.fmt, req.get_response(self.ext_api))
        self.assertEqual(
            network_segment_range['network_segment_range']['id'],
            res['network_segment_range']['id'])

    def test_list_network_segment_ranges(self):
        self._test_create_network_segment_range(name='foo-range1')
        self._test_create_network_segment_range(
            name='foo-range2', minimum=400, maximum=500)
        res = self._list('network-segment-ranges', as_admin=True)
        self.assertEqual(2, len(res['network_segment_ranges']))

    def test_list_network_segment_ranges_with_sort(self):
        range1 = self._test_create_network_segment_range(
            name='foo-range1', physical_network='phys_net1')
        range2 = self._test_create_network_segment_range(
            name='foo-range2', physical_network='phys_net2')
        self._test_list_with_sort('network-segment-range',
                                  (range2, range1),
                                  [('name', 'desc')],
                                  as_admin=True)

    def test_list_network_segment_ranges_with_pagination(self):
        range1 = self._test_create_network_segment_range(
            name='foo-range1', physical_network='phys_net1')
        range2 = self._test_create_network_segment_range(
            name='foo-range2', physical_network='phys_net2')
        range3 = self._test_create_network_segment_range(
            name='foo-range3', physical_network='phys_net3')
        self._test_list_with_pagination(
            'network-segment-range',
            (range1, range2, range3),
            ('name', 'asc'), 2, 2,
            as_admin=True)

    def test_list_network_segment_ranges_with_pagination_reverse(self):
        range1 = self._test_create_network_segment_range(
            name='foo-range1', physical_network='phys_net1')
        range2 = self._test_create_network_segment_range(
            name='foo-range2', physical_network='phys_net2')
        range3 = self._test_create_network_segment_range(
            name='foo-range3', physical_network='phys_net3')
        self._test_list_with_pagination_reverse(
            'network-segment-range',
            (range1, range2, range3),
            ('name', 'asc'), 2, 2,
            as_admin=True)

    def test_delete_network_segment_range(self):
        network_segment_range = self._test_create_network_segment_range()
        with mock.patch.object(segments_db, 'network_segments_exist_in_range',
                               return_value=False):
            self._delete('network-segment-ranges',
                         network_segment_range['network_segment_range']['id'],
                         as_admin=True)
            self._show('network-segment-ranges',
                       network_segment_range['network_segment_range']['id'],
                       expected_code=webob.exc.HTTPNotFound.code,
                       as_admin=True)
