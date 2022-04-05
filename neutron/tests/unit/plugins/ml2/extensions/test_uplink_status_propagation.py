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

from neutron_lib.api.definitions import port as port_def
from neutron_lib.plugins import directory
from oslo_config import cfg

from neutron.plugins.ml2.extensions import uplink_status_propagation as usp
from neutron.tests.unit.plugins.ml2 import test_plugin


class UplinkStatusPropagationML2ExtDriverTestCase(
        test_plugin.Ml2PluginV2TestCase):

    _extension_drivers = ['uplink_status_propagation']

    def setUp(self):
        cfg.CONF.set_override('extension_drivers',
                              self._extension_drivers,
                              group='ml2')
        super(UplinkStatusPropagationML2ExtDriverTestCase, self).setUp()
        self.plugin = directory.get_plugin()

    def test_extend_port_dict_no_project_default(self):
        for db_data in ({'propagate_uplink_status': None}, {}):
            response_data = {}
            session = mock.Mock()

            driver = usp.UplinkStatusPropagationExtensionDriver()
            driver.extend_port_dict(session, db_data, response_data)
            self.assertTrue(response_data['propagate_uplink_status'])

    def test_show_port_has_propagate_uplink_status(self):
        with self.port(propagate_uplink_status=True) as port:
            req = self.new_show_request(port_def.COLLECTION_NAME,
                                        port['port']['id'],
                                        self.fmt)
            n = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertTrue(n['port']['propagate_uplink_status'])

    def test_port_create_propagate_uplink_status(self):
        with self.network() as n:
            args = {'port':
                    {'name': 'test',
                     'network_id': n['network']['id'],
                     'tenant_id': n['network']['id'],
                     'device_id': '',
                     'device_owner': '',
                     'fixed_ips': '',
                     'propagate_uplink_status': True,
                     'admin_state_up': True,
                     'status': 'ACTIVE'}}
            port = None
            try:
                port = self.plugin.create_port(self.context, args)
            finally:
                if port:
                    self.plugin.delete_port(self.context, port['id'])
            self.assertTrue(port['propagate_uplink_status'])
