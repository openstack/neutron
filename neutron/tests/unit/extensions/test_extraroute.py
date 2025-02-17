# Copyright 2013, Nachi Ueno, NTT MCL, Inc.
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

from neutron_lib.api.definitions import external_net as enet_apidef
from neutron_lib.api.definitions import extraroute as xroute_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib import constants
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_utils import uuidutils
from webob import exc

from neutron.db import extraroute_db
from neutron.extensions import l3
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.extensions import test_l3


_uuid = uuidutils.generate_uuid
_get_path = test_base._get_path


class ExtraRouteTestExtensionManager:

    def get_resources(self):
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


# This plugin class is for tests with plugin that integrates L3.
class TestExtraRouteIntPlugin(test_l3.TestL3NatIntPlugin,
                              extraroute_db.ExtraRoute_db_mixin):
    supported_extension_aliases = [enet_apidef.ALIAS, l3_apidef.ALIAS,
                                   xroute_apidef.ALIAS]


# A fake l3 service plugin class with extra route capability for
# plugins that delegate away L3 routing functionality
class TestExtraRouteL3NatServicePlugin(test_l3.TestL3NatServicePlugin,
                                       extraroute_db.ExtraRoute_db_mixin):
    supported_extension_aliases = [l3_apidef.ALIAS, xroute_apidef.ALIAS]


class ExtraRouteDBTestCaseBase:
    def _routes_update_prepare(
            self, router_id, subnet_id,
            port_id, routes, skip_add=False, tenant_id=None, as_admin=False):
        if not skip_add:
            self._router_interface_action(
                'add', router_id, subnet_id, port_id, tenant_id=tenant_id,
                as_admin=as_admin)
        tenant_id = tenant_id or self._tenant_id
        self._update('routers', router_id, {'router': {'routes': routes}},
                     request_tenant_id=tenant_id, as_admin=as_admin)
        return self._show('routers', router_id, tenant_id=tenant_id)

    def _routes_update_cleanup(self, port_id, subnet_id, router_id, routes):
        self._update('routers', router_id, {'router': {'routes': routes}})
        self._router_interface_action('remove', router_id, subnet_id, port_id)

    def test_route_update_with_one_route(self):
        routes = [{'destination': '135.207.0.0/16', 'nexthop': '10.0.1.3'}]
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                fixed_ip_data = [{'ip_address': '10.0.1.2'}]
                with self.port(subnet=s, fixed_ips=fixed_ip_data) as p:
                    body = self._routes_update_prepare(r['router']['id'],
                                                       None, p['port']['id'],
                                                       routes)
                    self.assertEqual(routes, body['router']['routes'])
                    self._routes_update_cleanup(p['port']['id'],
                                                None, r['router']['id'], [])

    def test_route_update_with_external_route(self):
        my_tenant = 'tenant1'
        with self.subnet(cidr='10.0.1.0/24', tenant_id='notme') as ext_subnet,\
                self.port(subnet=ext_subnet,
                          tenant_id='notme') as nexthop_port:
            nexthop_ip = nexthop_port['port']['fixed_ips'][0]['ip_address']
            routes = [{'destination': '135.207.0.0/16',
                       'nexthop': nexthop_ip}]
            self._set_net_external(ext_subnet['subnet']['network_id'])
            ext_info = {'network_id': ext_subnet['subnet']['network_id']}
            with self.router(
                    external_gateway_info=ext_info, tenant_id=my_tenant) as r:
                body = self._routes_update_prepare(
                    r['router']['id'], None, None, routes, skip_add=True,
                    tenant_id=my_tenant)
                self.assertEqual(routes, body['router']['routes'])

    def test_route_update_with_route_via_another_tenant_subnet(self):
        my_tenant = 'tenant1'
        with self.subnet(cidr='10.0.1.0/24', tenant_id='notme') as subnet,\
                self.port(subnet=subnet, tenant_id='notme') as nexthop_port:
            nexthop_ip = nexthop_port['port']['fixed_ips'][0]['ip_address']
            routes = [{'destination': '135.207.0.0/16',
                       'nexthop': nexthop_ip}]
            with self.router(tenant_id=my_tenant) as r:
                body = self._routes_update_prepare(
                    r['router']['id'], subnet['subnet']['id'], None, routes,
                    tenant_id=my_tenant, as_admin=True)
                self.assertEqual(routes, body['router']['routes'])

    def test_route_clear_routes_with_None(self):
        routes = [{'destination': '135.207.0.0/16',
                   'nexthop': '10.0.1.3'},
                  {'destination': '12.0.0.0/8',
                   'nexthop': '10.0.1.4'},
                  {'destination': '141.212.0.0/16',
                   'nexthop': '10.0.1.5'}]
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                fixed_ip_data = [{'ip_address': '10.0.1.2'}]
                with self.port(subnet=s, fixed_ips=fixed_ip_data) as p:
                    self._routes_update_prepare(r['router']['id'],
                                                None, p['port']['id'], routes)
                    body = self._update('routers', r['router']['id'],
                                        {'router': {'routes': None}})
                    self.assertEqual([], body['router']['routes'])
                    self._routes_update_cleanup(p['port']['id'],
                                                None, r['router']['id'], [])

    def test_router_interface_in_use_by_route(self):
        routes = [{'destination': '135.207.0.0/16',
                   'nexthop': '10.0.1.3'}]
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                fixed_ip_data = [{'ip_address': '10.0.1.2'}]
                with self.port(subnet=s, fixed_ips=fixed_ip_data) as p:
                    body = self._routes_update_prepare(r['router']['id'],
                                                       None, p['port']['id'],
                                                       routes)
                    self.assertEqual(routes, body['router']['routes'])
                    self._router_interface_action(
                        'remove',
                        r['router']['id'],
                        None,
                        p['port']['id'],
                        expected_code=exc.HTTPConflict.code)

                    self._routes_update_cleanup(p['port']['id'],
                                                None, r['router']['id'], [])

    def test_route_update_with_multi_routes(self):
        routes = [{'destination': '135.207.0.0/16',
                   'nexthop': '10.0.1.3'},
                  {'destination': '12.0.0.0/8',
                   'nexthop': '10.0.1.4'},
                  {'destination': '141.212.0.0/16',
                   'nexthop': '10.0.1.5'}]
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                fixed_ip_data = [{'ip_address': '10.0.1.2'}]
                with self.port(subnet=s, fixed_ips=fixed_ip_data) as p:
                    body = self._routes_update_prepare(r['router']['id'],
                                                       None, p['port']['id'],
                                                       routes)
                    self.assertEqual(
                        sorted(body['router']['routes'],
                               key=helpers.safe_sort_key),
                        sorted(routes, key=helpers.safe_sort_key))
                    self._routes_update_cleanup(p['port']['id'],
                                                None, r['router']['id'], [])

    def test_routes_update_for_multiple_routers(self):
        with self.router() as r1,\
                self.router() as r2,\
                self.subnet(cidr='10.0.0.0/24') as s:
            with self.port(subnet=s) as p1,\
                    self.port(subnet=s) as p2:
                p1_ip = p1['port']['fixed_ips'][0]['ip_address']
                p2_ip = p2['port']['fixed_ips'][0]['ip_address']
                routes1 = [{'destination': '135.207.0.0/16',
                            'nexthop': p2_ip}]
                routes2 = [{'destination': '12.0.0.0/8',
                            'nexthop': p1_ip}]
                body = self._routes_update_prepare(r1['router']['id'],
                                                   None, p1['port']['id'],
                                                   routes1)
                self.assertEqual(routes1, body['router']['routes'])

                body = self._routes_update_prepare(r2['router']['id'],
                                                   None, p2['port']['id'],
                                                   routes2)
                self.assertEqual(routes2, body['router']['routes'])

                self._routes_update_cleanup(p1['port']['id'],
                                            None, r1['router']['id'], [])
                self._routes_update_cleanup(p2['port']['id'],
                                            None, r2['router']['id'], [])

    def test_router_update_delete_routes(self):
        routes_orig = [{'destination': '135.207.0.0/16',
                        'nexthop': '10.0.1.3'},
                       {'destination': '12.0.0.0/8',
                        'nexthop': '10.0.1.4'},
                       {'destination': '141.212.0.0/16',
                        'nexthop': '10.0.1.5'}]
        routes_left = [{'destination': '135.207.0.0/16',
                        'nexthop': '10.0.1.3'},
                       {'destination': '141.212.0.0/16',
                        'nexthop': '10.0.1.5'}]
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                fixed_ip_data = [{'ip_address': '10.0.1.2'}]
                with self.port(subnet=s, fixed_ips=fixed_ip_data) as p:
                    body = self._routes_update_prepare(r['router']['id'],
                                                       None, p['port']['id'],
                                                       routes_orig)
                    self.assertEqual(
                        sorted(body['router']['routes'],
                               key=helpers.safe_sort_key),
                        sorted(routes_orig, key=helpers.safe_sort_key))
                    body = self._routes_update_prepare(r['router']['id'],
                                                       None, p['port']['id'],
                                                       routes_left,
                                                       skip_add=True)
                    self.assertEqual(
                        sorted(body['router']['routes'],
                               key=helpers.safe_sort_key),
                        sorted(routes_left, key=helpers.safe_sort_key))
                    self._routes_update_cleanup(p['port']['id'],
                                                None, r['router']['id'], [])

    def _test_malformed_route(self, routes):
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                with self.port(subnet=s) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

                    self._update('routers', r['router']['id'],
                                 {'router': {'routes': routes}},
                                 expected_code=exc.HTTPBadRequest.code)
                    # clean-up
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_no_destination_route(self):
        self._test_malformed_route([{'nexthop': '10.0.1.6'}])

    def test_no_nexthop_route(self):
        self._test_malformed_route({'destination': '135.207.0.0/16'})

    def test_none_destination(self):
        self._test_malformed_route([{'destination': None,
                                     'nexthop': '10.0.1.3'}])

    def test_none_nexthop(self):
        self._test_malformed_route([{'destination': '135.207.0.0/16',
                                     'nexthop': None}])

    def test_nexthop_is_port_ip(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                with self.port(subnet=s) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])
                    port_ip = p['port']['fixed_ips'][0]['ip_address']
                    routes = [{'destination': '135.207.0.0/16',
                               'nexthop': port_ip}]

                    self._update('routers', r['router']['id'],
                                 {'router': {'routes':
                                             routes}},
                                 expected_code=exc.HTTPBadRequest.code)
                    # clean-up
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_router_update_with_too_many_routes(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                with self.port(subnet=s) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

                    routes = [{'destination': '135.207.0.0/16',
                               'nexthop': '10.0.1.3'},
                              {'destination': '12.0.0.0/8',
                               'nexthop': '10.0.1.4'},
                              {'destination': '141.212.0.0/16',
                               'nexthop': '10.0.1.5'},
                              {'destination': '192.168.0.0/16',
                               'nexthop': '10.0.1.6'}]

                    self._update('routers', r['router']['id'],
                                 {'router': {'routes':
                                             routes}},
                                 expected_code=exc.HTTPBadRequest.code)

                    # clean-up
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_router_update_with_dup_address(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                with self.port(subnet=s) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

                    routes = [{'destination': '135.207.0.0/16',
                               'nexthop': '10.0.1.3'},
                              {'destination': '135.207.0.0/16',
                               'nexthop': '10.0.1.3'}]

                    self._update('routers', r['router']['id'],
                                 {'router': {'routes':
                                             routes}},
                                 expected_code=exc.HTTPBadRequest.code)

                    # clean-up
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_router_update_with_invalid_ip_address(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                with self.port(subnet=s) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

                    routes = [{'destination': '512.207.0.0/16',
                               'nexthop': '10.0.1.3'}]

                    self._update('routers', r['router']['id'],
                                 {'router': {'routes':
                                             routes}},
                                 expected_code=exc.HTTPBadRequest.code)

                    routes = [{'destination': '127.207.0.0/48',
                               'nexthop': '10.0.1.3'}]

                    self._update('routers', r['router']['id'],
                                 {'router': {'routes':
                                             routes}},
                                 expected_code=exc.HTTPBadRequest.code)

                    routes = [{'destination': 'invalid_ip_address',
                               'nexthop': '10.0.1.3'}]

                    self._update('routers', r['router']['id'],
                                 {'router': {'routes':
                                             routes}},
                                 expected_code=exc.HTTPBadRequest.code)

                    routes = [{'destination': '1.1.1.1/24',
                               'nexthop': '10.0.1.3'}]

                    self._update('routers', r['router']['id'],
                                 {'router': {'routes':
                                             routes}},
                                 expected_code=exc.HTTPBadRequest.code)

                    # clean-up
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_router_update_with_invalid_nexthop_ip(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                with self.port(subnet=s) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

                    routes = [{'destination': '127.207.0.0/16',
                               'nexthop': ' 300.10.10.4'}]

                    self._update('routers', r['router']['id'],
                                 {'router': {'routes':
                                             routes}},
                                 expected_code=exc.HTTPBadRequest.code)

                    # clean-up
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_router_update_with_nexthop_is_outside_port_subnet(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                with self.port(subnet=s) as p:
                    self._router_interface_action('add',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

                    routes = [{'destination': '127.207.0.0/16',
                               'nexthop': ' 20.10.10.4'}]

                    self._update('routers', r['router']['id'],
                                 {'router': {'routes':
                                             routes}},
                                 expected_code=exc.HTTPBadRequest.code)

                    # clean-up
                    self._router_interface_action('remove',
                                                  r['router']['id'],
                                                  None,
                                                  p['port']['id'])

    def test_router_update_on_external_port(self):
        with self.router() as r:
            with self.subnet(cidr='10.0.1.0/24') as s:
                self._set_net_external(s['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                body = self._show('routers', r['router']['id'])
                net_id = body['router']['external_gateway_info']['network_id']
                self.assertEqual(net_id, s['subnet']['network_id'])
                port_res = self._list_ports(
                    'json',
                    200,
                    s['subnet']['network_id'],
                    tenant_id=r['router']['tenant_id'],
                    device_owner=constants.DEVICE_OWNER_ROUTER_GW)
                port_list = self.deserialize('json', port_res)
                self.assertEqual(1, len(port_list['ports']))

                with self.port(subnet=s) as p:
                    next_hop = p['port']['fixed_ips'][0]['ip_address']
                    routes = [{'destination': '135.207.0.0/16',
                               'nexthop': next_hop}]
                    body = self._update('routers', r['router']['id'],
                                        {'router': {'routes':
                                                    routes}})

                    body = self._show('routers', r['router']['id'])
                    self.assertEqual(routes, body['router']['routes'])

                    self._remove_external_gateway_from_router(
                        r['router']['id'],
                        s['subnet']['network_id'])
                    body = self._show('routers', r['router']['id'])
                    gw_info = body['router']['external_gateway_info']
                    self.assertIsNone(gw_info)

    def test_router_list_with_sort(self):
        with self.router(name='router1') as router1,\
                self.router(name='router2') as router2,\
                self.router(name='router3') as router3:
            self._test_list_with_sort('router', (router3, router2, router1),
                                      [('name', 'desc')])

    def test_router_list_with_pagination(self):
        with self.router(name='router1') as router1,\
                self.router(name='router2') as router2,\
                self.router(name='router3') as router3:
            self._test_list_with_pagination('router',
                                            (router1, router2, router3),
                                            ('name', 'asc'), 2, 2)

    def test_router_list_with_pagination_reverse(self):
        with self.router(name='router1') as router1,\
                self.router(name='router2') as router2,\
                self.router(name='router3') as router3:
            self._test_list_with_pagination_reverse('router',
                                                    (router1, router2,
                                                     router3),
                                                    ('name', 'asc'), 2, 2)


class ExtraRouteDBIntTestCase(test_l3.L3NatDBIntTestCase,
                              ExtraRouteDBTestCaseBase):

    def setUp(self, plugin=None, ext_mgr=None):
        if not plugin:
            plugin = ('neutron.tests.unit.extensions.test_extraroute.'
                      'TestExtraRouteIntPlugin')
        cfg.CONF.set_default('max_routes', 3)
        ext_mgr = ExtraRouteTestExtensionManager()
        super(test_l3.L3BaseForIntTests, self).setUp(plugin=plugin,
                                                     ext_mgr=ext_mgr)
        self.setup_notification_driver()


class ExtraRouteDBSepTestCase(test_l3.L3NatDBSepTestCase,
                              ExtraRouteDBTestCaseBase):
    def setUp(self):
        # the plugin without L3 support
        plugin = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'
        # the L3 service plugin
        l3_plugin = ('neutron.tests.unit.extensions.test_extraroute.'
                     'TestExtraRouteL3NatServicePlugin')
        service_plugins = {'l3_plugin_name': l3_plugin}

        cfg.CONF.set_default('max_routes', 3)
        ext_mgr = ExtraRouteTestExtensionManager()
        super(test_l3.L3BaseForSepTests, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr,
            service_plugins=service_plugins)

        self.setup_notification_driver()
