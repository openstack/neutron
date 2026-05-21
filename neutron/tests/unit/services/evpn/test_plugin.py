# Copyright 2026 Red Hat, LLC
# All Rights Reserved.
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

from neutron_lib.api.definitions import evpn as evpn_apidef
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

from neutron.services.evpn import plugin as evpn_plugin
from neutron.tests.common import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_l3


class TestEVPNPlugin(test_db_base_plugin_v2.NeutronDbPluginV2TestCase,
                     test_l3.L3NatTestCaseMixin):

    def setUp(self):
        plugin = (
            'neutron.tests.unit.extensions.test_l3.TestL3NatIntPlugin')
        service_plugins = {
            'evpn': 'neutron.services.evpn.plugin.EVPNPlugin',
        }
        ext_mgr = test_l3.L3TestExtensionManager()
        super().setUp(plugin=plugin, service_plugins=service_plugins,
                      ext_mgr=ext_mgr)
        self.evpn_plugin = directory.get_plugin(plugin_constants.EVPN)
        self.mock_db_call = mock.patch.object(
            evpn_plugin, '_fake_db_call').start()

    def test_get_plugin_type(self):
        self.assertEqual(
            plugin_constants.EVPN,
            evpn_plugin.EVPNPlugin.get_plugin_type())

    def test_get_plugin_description(self):
        self.assertIsNotNone(self.evpn_plugin.get_plugin_description())

    def test_plugin_loaded(self):
        self.assertIsInstance(self.evpn_plugin, evpn_plugin.EVPNPlugin)

    def test_extend_router_dict_no_allocation(self):
        with self.router(as_admin=True) as router:
            self.assertIn(evpn_apidef.EVPN_VNI, router['router'])
            self.assertIsNone(router['router'][evpn_apidef.EVPN_VNI])

    def test_extend_router_dict_with_allocation(self):
        mock_alloc = mock.Mock()
        mock_alloc.evpn_vni = 5000
        router_res = {}
        router_db = {'evpn_vni_allocation': mock_alloc}
        evpn_plugin.EVPNPlugin._extend_router_dict(router_res, router_db)
        self.assertEqual(5000, router_res[evpn_apidef.EVPN_VNI])

    def test_extend_router_dict_no_allocation_key(self):
        router_res = {}
        router_db = {}
        evpn_plugin.EVPNPlugin._extend_router_dict(router_res, router_db)
        self.assertIsNone(router_res[evpn_apidef.EVPN_VNI])

    def test_router_create_calls_db(self):
        with self.router(as_admin=True):
            self.mock_db_call.assert_called_once_with('create evpn')

    def test_router_delete_calls_db(self):
        with self.router(as_admin=True) as router:
            self.mock_db_call.reset_mock()
            self._delete('routers', router['router']['id'])
            self.mock_db_call.assert_called_once_with('delete evpn')

    def test_router_interface_create_without_advertise_host(self):
        with self.router(as_admin=True) as router, \
                self.network() as net, \
                self.subnet(network=net) as subnet:
            self.mock_db_call.reset_mock()
            self._router_interface_action(
                'add', router['router']['id'],
                subnet['subnet']['id'], None,
                as_admin=True)
            self.mock_db_call.assert_not_called()

    def test_router_interface_create_with_advertise_host(self):
        with self.router(as_admin=True) as router, \
                self.network() as net, \
                self.subnet(network=net) as subnet:
            self.mock_db_call.reset_mock()
            self._router_interface_action(
                'add', router['router']['id'],
                subnet['subnet']['id'], None,
                as_admin=True,
                advertise_host=True)
            self.mock_db_call.assert_called_once_with('advertise port')

    def test_router_interface_delete_calls_db(self):
        with self.router(as_admin=True) as router, \
                self.network() as net, \
                self.subnet(network=net) as subnet:
            self._router_interface_action(
                'add', router['router']['id'],
                subnet['subnet']['id'], None,
                as_admin=True)
            self.mock_db_call.reset_mock()
            self._router_interface_action(
                'remove', router['router']['id'],
                subnet['subnet']['id'], None,
                as_admin=True)
            self.mock_db_call.assert_called_once_with('remove port')
