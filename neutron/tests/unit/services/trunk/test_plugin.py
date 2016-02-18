# Copyright 2016 Hewlett Packard Enterprise Development Company, LP
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

from neutron import manager
from neutron.services.trunk import exceptions as trunk_exc
from neutron.services.trunk import plugin as trunk_plugin
from neutron.tests.unit.plugins.ml2 import test_plugin


class TrunkPluginTestCase(test_plugin.Ml2PluginV2TestCase):

    def setUp(self):
        super(TrunkPluginTestCase, self).setUp()
        self.trunk_plugin = trunk_plugin.TrunkPlugin()

    def test_delete_trunk_raise_in_use(self):
        with self.port() as port:
            trunk = {'port_id': port['port']['id'],
                     'tenant_id': 'test_tenant',
                     'sub_ports': []}
            response = (
                self.trunk_plugin.create_trunk(self.context, {'trunk': trunk}))
            core_plugin = manager.NeutronManager.get_plugin()
            port['port']['binding:host_id'] = 'host'
            core_plugin.update_port(self.context, port['port']['id'], port)
            self.assertRaises(trunk_exc.TrunkInUse,
                              self.trunk_plugin.delete_trunk,
                              self.context, response['id'])
