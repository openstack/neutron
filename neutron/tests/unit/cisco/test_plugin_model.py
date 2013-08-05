# Copyright 2014 Cisco Systems, Inc.
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

import sys

import mock

from neutron import context
from neutron.plugins.cisco.common import cisco_constants as const
from neutron.plugins.cisco.common import config as cisco_config
from neutron.plugins.cisco.models import virt_phy_sw_v2
from neutron.plugins.cisco.nexus import cisco_nexus_plugin_v2
from neutron.tests.unit import testlib_api


class TestCiscoPluginModel(testlib_api.SqlTestCase):

    def setUp(self):
        # Point config file to: neutron/tests/etc/neutron.conf.test
        self.config_parse()

        super(TestCiscoPluginModel, self).setUp()

    def test_non_nexus_device_driver(self):
        """Tests handling of an non-Nexus device driver being configured."""
        with mock.patch.dict(sys.modules, {'mock_driver': mock.Mock()}):
            cisco_config.CONF.set_override('nexus_driver',
                                           'mock_driver.Non_Nexus_Driver',
                                           'CISCO')
            # Plugin model instance should have is_nexus_plugin set to False
            model = virt_phy_sw_v2.VirtualPhysicalSwitchModelV2()
            self.assertFalse(model.is_nexus_plugin)

            # Model's _invoke_nexus_for_net_create should just return False
            user_id = 'user_id'
            tenant_id = 'tenant_id'
            ctx = context.Context(user_id, tenant_id)
            self.assertFalse(model._invoke_nexus_for_net_create(
                ctx, tenant_id, net_id='net_id',
                instance_id='instance_id', host_id='host_id'))

    def test_nexus_plugin_calls_ignored_if_plugin_not_loaded(self):
        """Verifies Nexus plugin calls are ignored if plugin is not loaded."""
        cisco_config.CONF.set_override(const.NEXUS_PLUGIN,
                                       None, 'CISCO_PLUGINS')
        with mock.patch.object(cisco_nexus_plugin_v2.NexusPlugin,
                               'create_network') as mock_create_network:
            model = virt_phy_sw_v2.VirtualPhysicalSwitchModelV2()
            model._invoke_plugin_per_device(model, const.NEXUS_PLUGIN,
                                            'create_network')
            self.assertFalse(mock_create_network.called)
