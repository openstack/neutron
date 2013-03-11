# Copyright (c) 2013 OpenStack, LLC.
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

from quantum import context
from quantum.manager import QuantumManager
from quantum.plugins.mlnx.common import constants
from quantum.tests.unit import test_db_plugin as test_plugin

PLUGIN_NAME = ('quantum.plugins.mlnx.mlnx_plugin.MellanoxEswitchPlugin')


class MlnxPluginV2TestCase(test_plugin.QuantumDbPluginV2TestCase):
    _plugin_name = PLUGIN_NAME

    def setUp(self):
        super(MlnxPluginV2TestCase, self).setUp(self._plugin_name)


class TestMlnxBasicGet(test_plugin.TestBasicGet, MlnxPluginV2TestCase):
    pass


class TestMlnxV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                             MlnxPluginV2TestCase):
    pass


class TestMlnxPortsV2(test_plugin.TestPortsV2,
                      MlnxPluginV2TestCase):
    VIF_TYPE = constants.VIF_TYPE_DIRECT
    HAS_PORT_FILTER = False

    def test_port_vif_details(self):
        plugin = QuantumManager.get_plugin()
        with self.port(name='name') as port:
            port_id = port['port']['id']
            self.assertEqual(port['port']['binding:vif_type'],
                             self.VIF_TYPE)
            # By default user is admin - now test non admin user
            ctx = context.Context(user_id=None,
                                  tenant_id=self._tenant_id,
                                  is_admin=False,
                                  read_deleted="no")
            non_admin_port = plugin.get_port(ctx, port_id)
            self.assertIn('status', non_admin_port)
            self.assertNotIn('binding:vif_type', non_admin_port)


class TestMlnxNetworksV2(test_plugin.TestNetworksV2, MlnxPluginV2TestCase):
    pass
