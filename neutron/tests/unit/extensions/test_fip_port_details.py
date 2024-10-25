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
#

from neutron_lib.api.definitions import external_net as enet_apidef
from neutron_lib.api.definitions import fip_port_details as apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from oslo_config import cfg

from neutron.db import l3_fip_port_details
from neutron.extensions import l3
from neutron.tests.unit.extensions import test_l3


class FloatingIPPortDetailsTestExtensionManager:

    def get_resources(self):
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestFloatingIPPortDetailsIntPlugin(
        test_l3.TestL3NatIntPlugin,
        l3_fip_port_details.Fip_port_details_db_mixin):
    supported_extension_aliases = [enet_apidef.ALIAS, l3_apidef.ALIAS,
                                   apidef.ALIAS]


class TestFloatingIPPortDetailsL3NatServicePlugin(
        test_l3.TestL3NatServicePlugin,
        l3_fip_port_details.Fip_port_details_db_mixin):
    supported_extension_aliases = [l3_apidef.ALIAS, apidef.ALIAS]


class FloatingIPPortDetailsDBTestCaseBase(test_l3.L3NatTestCaseMixin):

    def _assert_port_details(self, port, port_details):
        port['name'] = port_details['name']
        port['network_id'] = port_details['network_id']
        port['mac_address'] = port_details['mac_address']
        port['admin_state_up'] = port_details['admin_state_up']
        port['status'] = port_details['status']
        port['device_id'] = port_details['device_id']
        port['device_owner'] = port_details['device_owner']

    def test_floatingip_create_with_port_details(self):
        with self.port() as p:
            with self.floatingip_with_assoc(port_id=p['port']['id']) as fip:
                body = self._show('floatingips', fip['floatingip']['id'])
                self.assertEqual(body['floatingip']['id'],
                                 fip['floatingip']['id'])
                self.assertEqual(body['floatingip']['port_id'],
                                 fip['floatingip']['port_id'])
                self._assert_port_details(
                    p['port'], body['floatingip']['port_details'])

    def test_floatingip_update_with_port_details(self):
        with self.port() as p:
            private_sub = {'subnet': {'id':
                                      p['port']['fixed_ips'][0]['subnet_id']}}
            with self.floatingip_no_assoc(private_sub) as fip:
                body = self._show('floatingips', fip['floatingip']['id'])
                self.assertIsNone(body['floatingip']['port_id'])
                self.assertIsNone(body['floatingip']['port_details'])

                port_id = p['port']['id']
                body = self._update('floatingips', fip['floatingip']['id'],
                                    {'floatingip': {'port_id': port_id}})
                self.assertEqual(port_id, body['floatingip']['port_id'])
                self._assert_port_details(
                    p['port'], body['floatingip']['port_details'])

    def test_floatingip_list_with_port_details(self):
        with self.port() as p:
            with self.floatingip_with_assoc(port_id=p['port']['id']) as fip:
                body = self._list('floatingips')
                self.assertEqual(body['floatingips'][0]['id'],
                                 fip['floatingip']['id'])
                self.assertEqual(body['floatingips'][0]['port_id'],
                                 fip['floatingip']['port_id'])
                self._assert_port_details(
                    p['port'], body['floatingips'][0]['port_details'])


class FloatingIPPortDetailsDBIntTestCase(test_l3.L3BaseForIntTests,
                                         FloatingIPPortDetailsDBTestCaseBase):

    def setUp(self, plugin=None):
        if not plugin:
            plugin = ('neutron.tests.unit.extensions.test_fip_port_details.'
                      'TestFloatingIPPortDetailsIntPlugin')
        cfg.CONF.set_default('max_routes', 3)
        ext_mgr = FloatingIPPortDetailsTestExtensionManager()
        super(test_l3.L3BaseForIntTests, self).setUp(
            plugin=plugin,
            ext_mgr=ext_mgr)

        self.setup_notification_driver()


class FloatingIPPortDetailsDBSepTestCase(test_l3.L3BaseForSepTests,
                                         FloatingIPPortDetailsDBTestCaseBase):

    def setUp(self):
        # the plugin without L3 support
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        # the L3 service plugin
        l3_plugin = ('neutron.tests.unit.extensions.test_fip_port_details.'
                     'TestFloatingIPPortDetailsL3NatServicePlugin')
        service_plugins = {'l3_plugin_name': l3_plugin}

        cfg.CONF.set_default('max_routes', 3)
        ext_mgr = FloatingIPPortDetailsTestExtensionManager()
        super(test_l3.L3BaseForSepTests, self).setUp(
            plugin=plugin,
            ext_mgr=ext_mgr,
            service_plugins=service_plugins)

        self.setup_notification_driver()
