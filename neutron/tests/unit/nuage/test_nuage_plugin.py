# Copyright 2014 Alcatel-Lucent USA Inc.
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
# @author: Ronak Shah, Aniket Dandekar, Nuage Networks, Alcatel-Lucent USA Inc.

import contextlib
import os

import mock
from oslo.config import cfg
from webob import exc

from neutron.extensions import external_net
from neutron.extensions import portbindings
from neutron.plugins.nuage import extensions
from neutron.plugins.nuage import plugin as nuage_plugin
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.nuage import fake_nuageclient
from neutron.tests.unit import test_db_plugin
from neutron.tests.unit import test_extension_extraroute as extraroute_test
from neutron.tests.unit import test_l3_plugin

API_EXT_PATH = os.path.dirname(extensions.__file__)
FAKE_DEFAULT_ENT = 'default'
NUAGE_PLUGIN_PATH = 'neutron.plugins.nuage.plugin'
FAKE_SERVER = '1.1.1.1'
FAKE_SERVER_AUTH = 'user:pass'
FAKE_SERVER_SSL = False
FAKE_BASE_URI = '/base/'
FAKE_AUTH_RESOURCE = '/auth'
FAKE_ORGANIZATION = 'fake_org'

_plugin_name = ('%s.NuagePlugin' % NUAGE_PLUGIN_PATH)


class NuagePluginV2TestCase(test_db_plugin.NeutronDbPluginV2TestCase):
    def setUp(self, plugin=_plugin_name,
              ext_mgr=None, service_plugins=None):
        def mock_nuageClient_init(self):
            server = FAKE_SERVER
            serverauth = FAKE_SERVER_AUTH
            serverssl = FAKE_SERVER_SSL
            base_uri = FAKE_BASE_URI
            auth_resource = FAKE_AUTH_RESOURCE
            organization = FAKE_ORGANIZATION
            self.nuageclient = None
            self.nuageclient = fake_nuageclient.FakeNuageClient(server,
                                                                base_uri,
                                                                serverssl,
                                                                serverauth,
                                                                auth_resource,
                                                                organization)

        with mock.patch.object(nuage_plugin.NuagePlugin,
                               'nuageclient_init', new=mock_nuageClient_init):
            cfg.CONF.set_override('api_extensions_path',
                                  API_EXT_PATH)
            super(NuagePluginV2TestCase, self).setUp(plugin=plugin,
                                                     ext_mgr=ext_mgr)

    def _assert_no_assoc_fip(self, fip):
        body = self._show('floatingips',
                          fip['floatingip']['id'])
        self.assertIsNone(body['floatingip']['port_id'])
        self.assertIsNone(
            body['floatingip']['fixed_ip_address'])

    def _associate_and_assert_fip(self, fip, port, allow=True):
        port_id = port['port']['id']
        ip_address = (port['port']['fixed_ips']
                      [0]['ip_address'])
        if allow:
            body = self._update(
                'floatingips', fip['floatingip']['id'],
                {'floatingip': {'port_id': port_id}})
            self.assertEqual(
                body['floatingip']['port_id'], port_id)
            self.assertEqual(
                body['floatingip']['fixed_ip_address'],
                ip_address)
            return body['floatingip']['router_id']
        else:
            code = exc.HTTPInternalServerError.code
            self._update(
                'floatingips', fip['floatingip']['id'],
                {'floatingip': {'port_id': port_id}},
                expected_code=code)

    def _test_floatingip_update_different_router(self):
        with contextlib.nested(self.subnet(cidr='10.0.0.0/24'),
                               self.subnet(cidr='10.0.1.0/24')) as (
                                   s1, s2):
            with contextlib.nested(self.port(subnet=s1),
                                   self.port(subnet=s2)) as (p1, p2):
                private_sub1 = {'subnet':
                                {'id':
                                 p1['port']['fixed_ips'][0]['subnet_id']}}
                private_sub2 = {'subnet':
                                {'id':
                                 p2['port']['fixed_ips'][0]['subnet_id']}}
                with self.subnet(cidr='12.0.0.0/24') as public_sub:
                    with contextlib.nested(
                            self.floatingip_no_assoc_with_public_sub(
                                private_sub1, public_sub=public_sub),
                            self.floatingip_no_assoc_with_public_sub(
                                private_sub2, public_sub=public_sub)) as (
                                    (fip1, r1), (fip2, r2)):

                        self._assert_no_assoc_fip(fip1)
                        self._assert_no_assoc_fip(fip2)

                        fip1_r1_res = self._associate_and_assert_fip(fip1, p1)
                        self.assertEqual(fip1_r1_res, r1['router']['id'])
                        # The following operation will associate the floating
                        # ip to a different router and should fail
                        self._associate_and_assert_fip(fip1, p2, allow=False)
                        # disassociate fip1
                        self._update(
                            'floatingips', fip1['floatingip']['id'],
                            {'floatingip': {'port_id': None}})
                        fip2_r2_res = self._associate_and_assert_fip(fip2, p2)
                        self.assertEqual(fip2_r2_res, r2['router']['id'])

    def _test_network_update_external_failure(self):
        with self.router() as r:
            with self.subnet() as s1:
                self._set_net_external(s1['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s1['subnet']['network_id'])
                self._update('networks', s1['subnet']['network_id'],
                             {'network': {external_net.EXTERNAL: False}},
                             expected_code=exc.HTTPInternalServerError.code)
                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s1['subnet']['network_id'])


class TestNuageBasicGet(NuagePluginV2TestCase,
                        test_db_plugin.TestBasicGet):
    pass


class TestNuageV2HTTPResponse(NuagePluginV2TestCase,
                              test_db_plugin.TestV2HTTPResponse):
    pass


class TestNuageNetworksV2(NuagePluginV2TestCase,
                          test_db_plugin.TestNetworksV2):
    pass


class TestNuageSubnetsV2(NuagePluginV2TestCase,
                         test_db_plugin.TestSubnetsV2):
    def test_create_subnet_bad_hostroutes(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_create_subnet_inconsistent_ipv4_hostroute_dst_v6(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_create_subnet_inconsistent_ipv4_hostroute_np_v6(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_update_subnet_adding_additional_host_routes_and_dns(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_update_subnet_inconsistent_ipv6_hostroute_dst_v4(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_update_subnet_inconsistent_ipv6_hostroute_np_v4(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_create_subnet_with_one_host_route(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_create_subnet_with_two_host_routes(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_create_subnet_with_too_many_routes(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_update_subnet_route(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_update_subnet_route_to_None(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_update_subnet_route_with_too_many_entries(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_delete_subnet_with_route(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_delete_subnet_with_dns_and_route(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_validate_subnet_host_routes_exhausted(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_validate_subnet_dns_nameservers_exhausted(self):
        self.skipTest("Plugin does not support Neutron Subnet host-routes")

    def test_create_subnet_with_none_gateway(self):
        self.skipTest("Plugin does not support "
                      "Neutron Subnet no-gateway option")

    def test_create_subnet_with_none_gateway_fully_allocated(self):
        self.skipTest("Plugin does not support Neutron "
                      "Subnet no-gateway option")

    def test_create_subnet_with_none_gateway_allocation_pool(self):
        self.skipTest("Plugin does not support Neutron "
                      "Subnet no-gateway option")


class TestNuagePluginPortBinding(NuagePluginV2TestCase,
                                 test_bindings.PortBindingsTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS

    def setUp(self):
        super(TestNuagePluginPortBinding, self).setUp()


class TestNuagePortsV2(NuagePluginV2TestCase,
                       test_db_plugin.TestPortsV2):
    pass


class TestNuageL3NatTestCase(NuagePluginV2TestCase,
                             test_l3_plugin.L3NatDBIntTestCase):

    def test_floatingip_update_different_router(self):
        self._test_floatingip_update_different_router()

    def test_network_update_external_failure(self):
        self._test_network_update_external_failure()


class TestNuageExtrarouteTestCase(NuagePluginV2TestCase,
                                  extraroute_test.ExtraRouteDBIntTestCase):

    def test_router_update_with_dup_destination_address(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                with self.port(subnet=s, do_delete=False) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

                    routes = [{'destination': '135.207.0.0/16',
                               'nexthop': '10.0.1.3'},
                              {'destination': '135.207.0.0/16',
                               'nexthop': '10.0.1.5'}]

                    self._update('routers', r['router']['id'],
                                 {'router': {'routes':
                                             routes}},
                                 expected_code=exc.HTTPBadRequest.code)

                    # clean-up
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_floatingip_update_different_router(self):
        self._test_floatingip_update_different_router()

    def test_network_update_external_failure(self):
        self._test_network_update_external_failure()
