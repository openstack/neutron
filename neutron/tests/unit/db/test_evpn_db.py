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

from neutron_lib.api.definitions import evpn as evpn_apidef
from neutron_lib import context
from neutron_lib.db import api as db_api
from webob import exc

from neutron.db.models import evpn as evpn_models
from neutron.tests.common import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_l3


class TestEVPNDb(test_db_base_plugin_v2.NeutronDbPluginV2TestCase,
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
        self.ctx = context.get_admin_context()

    def test_router_create_no_vni(self):
        with self.router(as_admin=True) as router:
            self.assertIsNone(router['router'][evpn_apidef.EVPN_VNI])

    def test_router_create_with_vni(self):
        with self.router(as_admin=True,
                         arg_list=(evpn_apidef.EVPN_VNI,),
                         evpn_vni=5000) as router:
            self.assertEqual(5000, router['router'][evpn_apidef.EVPN_VNI])

    def test_router_create_duplicate_vni(self):
        with self.router(as_admin=True,
                         arg_list=(evpn_apidef.EVPN_VNI,),
                         evpn_vni=5000):
            res = self._create_router(
                self.fmt, as_admin=True,
                arg_list=(evpn_apidef.EVPN_VNI,),
                evpn_vni=5000)
            self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_router_create_different_vnis(self):
        with self.router(as_admin=True,
                         arg_list=(evpn_apidef.EVPN_VNI,),
                         evpn_vni=5000) as r1, \
                self.router(as_admin=True,
                            arg_list=(evpn_apidef.EVPN_VNI,),
                            evpn_vni=5001) as r2:
            self.assertEqual(5000, r1['router'][evpn_apidef.EVPN_VNI])
            self.assertEqual(5001, r2['router'][evpn_apidef.EVPN_VNI])

    def test_router_show_vni(self):
        with self.router(as_admin=True,
                         arg_list=(evpn_apidef.EVPN_VNI,),
                         evpn_vni=5000) as router:
            body = self._show('routers', router['router']['id'])
            self.assertEqual(5000, body['router'][evpn_apidef.EVPN_VNI])

    def test_router_show_no_vni(self):
        with self.router(as_admin=True) as router:
            body = self._show('routers', router['router']['id'])
            self.assertIsNone(body['router'][evpn_apidef.EVPN_VNI])

    def test_router_delete_with_vni(self):
        with self.router(as_admin=True,
                         arg_list=(evpn_apidef.EVPN_VNI,),
                         evpn_vni=5000) as router:
            router_id = router['router']['id']
            self._delete('routers', router_id)
            body = self._list('routers')
            router_ids = [r['id'] for r in body['routers']]
            self.assertNotIn(router_id, router_ids)

    def test_router_delete_frees_vni(self):
        with self.router(as_admin=True,
                         arg_list=(evpn_apidef.EVPN_VNI,),
                         evpn_vni=5000) as router:
            self._delete('routers', router['router']['id'])

        with self.router(as_admin=True,
                         arg_list=(evpn_apidef.EVPN_VNI,),
                         evpn_vni=5000) as router:
            self.assertEqual(5000, router['router'][evpn_apidef.EVPN_VNI])

    def test_router_interface_add_with_advertise_host(self):
        with self.router(as_admin=True,
                         arg_list=(evpn_apidef.EVPN_VNI,),
                         evpn_vni=5000) as router, \
                self.network() as net, \
                self.subnet(network=net) as subnet:
            self._router_interface_action(
                'add', router['router']['id'],
                subnet['subnet']['id'], None,
                as_admin=True,
                advertise_host=True)

            # TODO(jlibosva): Currently the API does not expose the
            # advertise_host flag, so we need to check the database directly.
            with db_api.CONTEXT_READER.using(self.ctx):
                evpn_net = self.ctx.session.query(
                    evpn_models.EVPNNetwork
                ).filter_by(
                    network_id=net['network']['id']
                ).one_or_none()
            self.assertIsNotNone(evpn_net)
            self.assertEqual(
                router['router']['id'], evpn_net.router_id)

    def test_router_interface_add_without_advertise_host(self):
        with self.router(as_admin=True,
                         arg_list=(evpn_apidef.EVPN_VNI,),
                         evpn_vni=5000) as router, \
                self.network() as net, \
                self.subnet(network=net) as subnet:
            self._router_interface_action(
                'add', router['router']['id'],
                subnet['subnet']['id'], None,
                as_admin=True)

            # TODO(jlibosva): Currently the API does not expose the
            # advertise_host flag, so we need to check the database directly.
            with db_api.CONTEXT_READER.using(self.ctx):
                evpn_net = self.ctx.session.query(
                    evpn_models.EVPNNetwork
                ).filter_by(
                    network_id=net['network']['id']
                ).one_or_none()
            self.assertIsNone(evpn_net)

    def test_router_interface_remove_cleans_evpn_network(self):
        with self.router(as_admin=True,
                         arg_list=(evpn_apidef.EVPN_VNI,),
                         evpn_vni=5000) as router, \
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

            # TODO(jlibosva): Currently the API does not expose the
            # advertise_host flag, so we need to check the database directly.
            with db_api.CONTEXT_READER.using(self.ctx):
                evpn_net = self.ctx.session.query(
                    evpn_models.EVPNNetwork
                ).filter_by(
                    network_id=net['network']['id']
                ).one_or_none()
            self.assertIsNone(evpn_net)
