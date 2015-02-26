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

from neutron.api import extensions
from neutron.plugins.ml2 import config
from neutron.plugins.ml2 import driver_api as api
from neutron.tests.unit.ml2 import extensions as test_extensions
from neutron.tests.unit.ml2 import test_ml2_plugin


class ExtensionDriverTestCase(test_ml2_plugin.Ml2PluginV2TestCase):

    _extension_drivers = ['test']

    def setUp(self):
        config.cfg.CONF.set_override('extension_drivers',
                                     self._extension_drivers,
                                     group='ml2')
        super(ExtensionDriverTestCase, self).setUp()

    def test_network_attr(self):
        with self.network() as network:
            # Test create network
            ent = network['network'].get('network_extension')
            self.assertIsNotNone(ent)

            # Test list networks
            res = self._list('networks')
            val = res['networks'][0].get('network_extension')
            self.assertEqual('Test_Network_Extension', val)

            # Test network update
            data = {'network':
                    {'network_extension': 'Test_Network_Extension_Update'}}
            res = self._update('networks', network['network']['id'], data)
            val = res['network'].get('network_extension')
            self.assertEqual('Test_Network_Extension_Update', val)

    def test_subnet_attr(self):
        with self.subnet() as subnet:
            # Test create subnet
            ent = subnet['subnet'].get('subnet_extension')
            self.assertIsNotNone(ent)

            # Test list subnets
            res = self._list('subnets')
            val = res['subnets'][0].get('subnet_extension')
            self.assertEqual('Test_Subnet_Extension', val)

            # Test subnet update
            data = {'subnet':
                    {'subnet_extension': 'Test_Subnet_Extension_Update'}}
            res = self._update('subnets', subnet['subnet']['id'], data)
            val = res['subnet'].get('subnet_extension')
            self.assertEqual('Test_Subnet_Extension_Update', val)

    def test_port_attr(self):
        with self.port() as port:
            # Test create port
            ent = port['port'].get('port_extension')
            self.assertIsNotNone(ent)

            # Test list ports
            res = self._list('ports')
            val = res['ports'][0].get('port_extension')
            self.assertEqual('Test_Port_Extension', val)

            # Test port update
            data = {'port': {'port_extension': 'Test_Port_Extension_Update'}}
            res = self._update('ports', port['port']['id'], data)
            val = res['port'].get('port_extension')
            self.assertEqual('Test_Port_Extension_Update', val)


class TestExtensionDriver(api.ExtensionDriver):
    _supported_extension_alias = 'test_extension'

    def initialize(self):
        self.network_extension = 'Test_Network_Extension'
        self.subnet_extension = 'Test_Subnet_Extension'
        self.port_extension = 'Test_Port_Extension'
        extensions.append_api_extensions_path(test_extensions.__path__)

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_create_network(self, plugin_context, data, result):
        result['network_extension'] = self.network_extension

    def process_create_subnet(self, plugin_context, data, result):
        result['subnet_extension'] = self.subnet_extension

    def process_create_port(self, plugin_context, data, result):
        result['port_extension'] = self.port_extension

    def process_update_network(self, plugin_context, data, result):
        self.network_extension = data['network']['network_extension']
        result['network_extension'] = self.network_extension

    def process_update_subnet(self, plugin_context, data, result):
        self.subnet_extension = data['subnet']['subnet_extension']
        result['subnet_extension'] = self.subnet_extension

    def process_update_port(self, plugin_context, data, result):
        self.port_extension = data['port_extension']
        result['port_extension'] = self.port_extension

    def extend_network_dict(self, session, base_model, result):
        if self._supported_extension_alias is 'test_extension':
            result['network_extension'] = self.network_extension

    def extend_subnet_dict(self, session, base_model, result):
        if self._supported_extension_alias is 'test_extension':
            result['subnet_extension'] = self.subnet_extension

    def extend_port_dict(self, session, base_model, result):
        if self._supported_extension_alias is 'test_extension':
            result['port_extension'] = self.port_extension
