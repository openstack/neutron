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
            ent = network['network'].get('network_extension')
            self.assertIsNotNone(ent)

    def test_subnet_attr(self):
        with self.subnet() as subnet:
            ent = subnet['subnet'].get('subnet_extension')
            self.assertIsNotNone(ent)

    def test_port_attr(self):
        with self.port() as port:
            ent = port['port'].get('port_extension')
            self.assertIsNotNone(ent)


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

    def process_create_network(self, session, data, result):
        result['network_extension'] = self.network_extension

    def process_create_subnet(self, session, data, result):
        result['subnet_extension'] = self.subnet_extension

    def process_create_port(self, session, data, result):
        result['port_extension'] = self.port_extension
