# Copyright (c) 2014 OpenStack Foundation
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

import mock
from oslo.config import cfg

#NOTE this import loads tests required options
from neutron.plugins.mlnx.common import config  # noqa
from neutron.plugins.mlnx.common import constants
from neutron.plugins.mlnx import mlnx_plugin
from neutron.tests.unit import testlib_api


class TestMlnxPluginConfig(testlib_api.SqlTestCase):
    expected_vlan_mappings = {'physnet1': [(1, 1000)],
                              'physnet2': [(1, 1000)]}
    expected_network_types = {'physnet1': constants.TYPE_ETH,
                              'physnet2': constants.TYPE_IB}
    config_vlan_ranges = ['physnet1:1:1000', 'physnet2:1:1000']
    config_network_types = ['physnet1:eth', 'physnet2:ib']

    def setUp(self):
        super(TestMlnxPluginConfig, self).setUp()
        cfg.CONF.set_override(group='MLNX',
                              name='network_vlan_ranges',
                              override=self.config_vlan_ranges)

    def _create_mlnx_plugin(self):
        with mock.patch('neutron.plugins.mlnx.db.mlnx_db_v2'):
            return mlnx_plugin.MellanoxEswitchPlugin()

    def _assert_expected_config(self):
        plugin = self._create_mlnx_plugin()
        self.assertEqual(plugin.network_vlan_ranges,
                         self.expected_vlan_mappings)
        self.assertEqual(plugin.phys_network_type_maps,
                         self.expected_network_types)

    def test_vlan_ranges_with_network_type(self):
        cfg.CONF.set_override(group='MLNX',
                              name='physical_network_type_mappings',
                              override=self.config_network_types)
        self._assert_expected_config()

    def test_vlan_ranges_partial_network_type(self):
        cfg.CONF.set_override(group='MLNX',
                              name='physical_network_type_mappings',
                              override=self.config_network_types[:1])
        cfg.CONF.set_override(group='MLNX',
                              name='physical_network_type',
                              override=constants.TYPE_IB)
        self._assert_expected_config()

    def test_vlan_ranges_no_network_type(self):
        cfg.CONF.set_override(group='MLNX',
                              name='physical_network_type',
                              override=constants.TYPE_IB)
        cfg.CONF.set_override(group='MLNX',
                              name='physical_network_type_mappings',
                              override=[])
        self.expected_network_types.update({'physnet1': constants.TYPE_IB})
        self._assert_expected_config()
        self.expected_network_types.update({'physnet1': constants.TYPE_ETH})

    def test_parse_physical_network_mappings_invalid_type(self):
        cfg.CONF.set_override(group='MLNX',
                              name='physical_network_type_mappings',
                              override=['physnet:invalid-type'])
        self.assertRaises(SystemExit, self._create_mlnx_plugin)

    def test_invalid_network_type(self):
        cfg.CONF.set_override(group='MLNX',
                              name='physical_network_type',
                              override='invalid-type')
        self.assertRaises(SystemExit, self._create_mlnx_plugin)
