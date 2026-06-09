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
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

from neutron.db.models import evpn as evpn_models
from neutron.services.evpn import commands as evpn_ovn
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
        self.mock_nb_idl = mock.patch.object(
            evpn_plugin.EVPNPlugin, '_nb_idl',
            new_callable=mock.PropertyMock).start()
        super().setUp(plugin=plugin, service_plugins=service_plugins,
                      ext_mgr=ext_mgr)
        self.evpn_plugin = directory.get_plugin(plugin_constants.EVPN)
        self.ctx = context.get_admin_context()
        self.nb_idl = self.mock_nb_idl.return_value
        self.txn = self.nb_idl.transaction.return_value.__enter__.return_value

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
        mock_instance = mock.Mock()
        mock_instance.mapping.vni_allocation.vni = 5000
        router_res = {}
        router_db = {'evpn_instance': mock_instance}
        evpn_plugin.EVPNPlugin._extend_router_dict(router_res, router_db)
        self.assertEqual(5000, router_res[evpn_apidef.EVPN_VNI])

    def test_extend_router_dict_no_allocation_key(self):
        router_res = {}
        router_db = {}
        evpn_plugin.EVPNPlugin._extend_router_dict(router_res, router_db)
        self.assertIsNone(router_res[evpn_apidef.EVPN_VNI])

    def test_router_create_no_vni(self):
        with self.router(as_admin=True) as router:
            self.assertIsNone(router['router'][evpn_apidef.EVPN_VNI])
            self.txn.add.assert_not_called()

    def test_router_create_with_vni(self):
        with self.router(as_admin=True,
                         arg_list=('evpn_vni',), evpn_vni=5000) as router:
            self.assertEqual(5000, router['router'][evpn_apidef.EVPN_VNI])
            self.txn.add.assert_called_once()
            cmd = self.txn.add.call_args[0][0]
            self.assertIsInstance(cmd, evpn_ovn.CreateEVPNRouterCommand)
            self.assertEqual(5000, cmd.vni)
            self.assertIsNotNone(cmd.vlan)

    def test_router_delete_deallocates_vni(self):
        with self.router(as_admin=True,
                         arg_list=('evpn_vni',), evpn_vni=5000) as router:
            router_id = router['router']['id']
            self.txn.reset_mock()
            self._delete('routers', router_id)

            with db_api.CONTEXT_READER.using(self.ctx):
                instance = self.ctx.session.query(
                    evpn_models.EVPNL3Instance
                ).filter_by(router_id=router_id).one_or_none()
            self.assertIsNone(instance)

            self.txn.add.assert_called_once()
            cmd = self.txn.add.call_args[0][0]
            self.assertIsInstance(cmd, evpn_ovn.DeleteEVPNRouterCommand)
            self.assertEqual(5000, cmd.vni)

    def test_router_delete_without_vni(self):
        with self.router(as_admin=True) as router:
            self.txn.reset_mock()
            self._delete('routers', router['router']['id'])
            self.txn.add.assert_not_called()

    def test_router_interface_create_without_advertise_host(self):
        with self.router(as_admin=True,
                         arg_list=('evpn_vni',), evpn_vni=5000) as router, \
                self.network() as net, \
                self.subnet(network=net) as subnet:
            self.txn.reset_mock()
            self._router_interface_action(
                'add', router['router']['id'],
                subnet['subnet']['id'], None,
                as_admin=True)

            # TODO(jlibosva): The API does not expose advertise_host yet,
            # so we validate the DB directly.
            with db_api.CONTEXT_READER.using(self.ctx):
                evpn_net = self.ctx.session.query(
                    evpn_models.EVPNNetwork
                ).filter_by(
                    network_id=net['network']['id']
                ).one_or_none()
            self.assertIsNone(evpn_net)
            self.txn.add.assert_not_called()

    def test_router_interface_create_with_advertise_host(self):
        with self.router(as_admin=True,
                         arg_list=('evpn_vni',), evpn_vni=5000) as router, \
                self.network() as net, \
                self.subnet(network=net) as subnet:
            self.txn.reset_mock()
            self._router_interface_action(
                'add', router['router']['id'],
                subnet['subnet']['id'], None,
                as_admin=True,
                advertise_host=True)

            # TODO(jlibosva): The API does not expose advertise_host yet,
            # so we validate the DB directly.
            with db_api.CONTEXT_READER.using(self.ctx):
                evpn_net = self.ctx.session.query(
                    evpn_models.EVPNNetwork
                ).filter_by(
                    network_id=net['network']['id']
                ).one_or_none()
            self.assertIsNotNone(evpn_net)
            self.assertEqual(
                router['router']['id'], evpn_net.router_id)

            self.txn.add.assert_called_once()
            cmd = self.txn.add.call_args[0][0]
            self.assertIsInstance(cmd, evpn_ovn.AdvertiseHostCommand)

    def test_router_interface_delete_cleans_evpn_network(self):
        with self.router(as_admin=True,
                         arg_list=('evpn_vni',), evpn_vni=5000) as router, \
                self.network() as net, \
                self.subnet(network=net) as subnet:
            self._router_interface_action(
                'add', router['router']['id'],
                subnet['subnet']['id'], None,
                as_admin=True,
                advertise_host=True)
            self._router_interface_action(
                'remove', router['router']['id'],
                subnet['subnet']['id'], None,
                as_admin=True)

            # TODO(jlibosva): The API does not expose advertise_host yet,
            # so we validate the DB directly.
            with db_api.CONTEXT_READER.using(self.ctx):
                evpn_net = self.ctx.session.query(
                    evpn_models.EVPNNetwork
                ).filter_by(
                    network_id=net['network']['id']
                ).one_or_none()
            self.assertIsNone(evpn_net)
