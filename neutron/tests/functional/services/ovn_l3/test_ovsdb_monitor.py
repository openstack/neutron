# Copyright 2025 Red Hat, Inc.
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

from neutron_lib.api.definitions import external_net
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

from neutron.common.ovn import utils as ovn_utils
from neutron.common import utils as n_utils
from neutron.tests.functional import base
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_l3


class TestLogicalRouterPortEvent(
    base.TestOVNFunctionalBase,
    test_l3.L3NatTestCaseMixin):

    def setUp(self, **kwargs):
        super().setUp(**kwargs)
        self.chassis = self.add_fake_chassis('ovs-host1')
        self.l3_plugin = directory.get_plugin(plugin_constants.L3)
        self.l3_plugin._post_fork_initialize(mock.ANY, mock.ANY, mock.ANY)
        self.ext_api = test_extensions.setup_extensions_middleware(
            test_l3.L3TestExtensionManager())
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: True}
        self.net_ext = self._make_network(
            self.fmt, 'net_ext', True, as_admin=True, **kwargs)
        self.subnet = self._make_subnet(self.fmt, self.net_ext, '20.0.10.1',
                                        '20.0.10.0/24')
        self.router = self._make_router(self.fmt, self._project_id)
        self.router_id = self.router['router']['id']
        self.net_ext_id = self.net_ext['network']['id']
        self.subnet_id = self.subnet['subnet']['id']

    def test_add_and_delete_gw_network(self):
        def is_called():
            try:
                mock_update_router.assert_called_once_with(
                    mock.ANY, self.router_id)
                return True
            except AssertionError:
                return False

        with mock.patch.object(
                self.l3_plugin._ovn_client,
                'update_router_ha_chassis_group') as mock_update_router:
            self._add_external_gateway_to_router(self.router_id,
                                                 self.net_ext_id)
            n_utils.wait_until_true(is_called, timeout=10)
            mock_update_router.reset_mock()
            self._remove_external_gateway_from_router(
                self.router_id, self.net_ext_id, external_gw_info={})
            n_utils.wait_until_true(is_called, timeout=10)

    def test_add_private_network(self):
        def is_called():
            try:
                mock_link.assert_called_once_with(
                    mock.ANY, self.net_ext_id, self.router_id)
                return True
            except AssertionError:
                return False

        with mock.patch.object(
                self.l3_plugin._ovn_client,
                'link_network_ha_chassis_group') as mock_link:
            self._router_interface_action(
                'add', self.router_id, self.subnet_id, None)
            n_utils.wait_until_true(is_called, timeout=10)

    def test_delete_private_network(self):
        def is_called():
            try:
                mock_unlink.assert_called_once_with(self.net_ext_id)
                return True
            except AssertionError:
                return False

        with mock.patch.object(
                self.l3_plugin._ovn_client,
                'link_network_ha_chassis_group'), \
                mock.patch.object(
                    self.l3_plugin._ovn_client,
                    'unlink_network_ha_chassis_group') as mock_unlink:
            self._router_interface_action(
                'add', self.router_id, self.subnet_id, None)
            self._router_interface_action(
                'remove', self.router_id, self.subnet_id, None)
            n_utils.wait_until_true(is_called, timeout=10)

    def test_delete_router(self):
        # The ``Logical_Router`` deletion triggers the
        # ``LogicalRouterPortEvent`` event, but nothing is executed/called.
        def is_called():
            try:
                mock_update_router.assert_called_once_with(
                    mock.ANY, self.router_id)
                return True
            except AssertionError:
                return False

        with mock.patch.object(
                self.l3_plugin._ovn_client,
                'update_router_ha_chassis_group') as mock_update_router:
            self._add_external_gateway_to_router(self.router_id,
                                                 self.net_ext_id)
            n_utils.wait_until_true(is_called, timeout=10)
            mock_update_router.reset_mock()
            req = self.new_delete_request('routers', self.router_id)
            req.get_response(self.api)
            self.assertRaises(n_utils.WaitTimeout, n_utils.wait_until_true,
                              is_called, timeout=5)


class TestLogicalRouterPortGatewayChassisEvent(
    base.TestOVNFunctionalBase,
    test_l3.L3NatTestCaseMixin):

    def setUp(self, **kwargs):
        super().setUp(**kwargs)
        self.chassis = self.add_fake_chassis('ovs-host1')
        self.l3_plugin = directory.get_plugin(plugin_constants.L3)
        self.l3_plugin._post_fork_initialize(mock.ANY, mock.ANY, mock.ANY)
        self.ext_api = test_extensions.setup_extensions_middleware(
            test_l3.L3TestExtensionManager())
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: True}
        self.net_ext = self._make_network(
            self.fmt, 'net_ext', True, as_admin=True, **kwargs)
        self.subnet = self._make_subnet(self.fmt, self.net_ext, '20.0.10.1',
                                        '20.0.10.0/24')
        self.router = self._make_router(self.fmt, self._project_id)
        self.router_id = self.router['router']['id']
        self.net_ext_id = self.net_ext['network']['id']
        self.subnet_id = self.subnet['subnet']['id']

    def test_add_and_remove_gateway_chassis(self):
        def is_called():
            try:
                mock_update_router.assert_called_once_with(
                    mock.ANY, self.router_id)
                return True
            except AssertionError:
                return False

        ch_list = []
        for idx in range(5):
            ch_list.append(self.add_fake_chassis(f'host-{idx}'))
        self._add_external_gateway_to_router(self.router_id, self.net_ext_id)
        lr = self.l3_plugin._nb_ovn.lookup('Logical_Router',
                                           ovn_utils.ovn_name(self.router_id))
        lrp_gw = lr.ports[0]
        with mock.patch.object(
                self.l3_plugin._ovn_client,
                'update_router_ha_chassis_group') as mock_update_router:
            for ch_name in ch_list:
                self.l3_plugin._nb_ovn.lrp_set_gateway_chassis(
                    lrp_gw.uuid, ch_name).execute(check_error=True)
                n_utils.wait_until_true(is_called, timeout=10)
                mock_update_router.reset_mock()

            for ch_name in ch_list:
                self.l3_plugin._nb_ovn.lrp_del_gateway_chassis(
                    lrp_gw.uuid, ch_name).execute(check_error=True)
                n_utils.wait_until_true(is_called, timeout=10)
                mock_update_router.reset_mock()
