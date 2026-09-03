# Copyright 2026 Red Hat, Inc.
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

from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import ovn_bgp as ovn_bgp_apidef
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import constants as n_const
from neutron_lib.plugins import directory
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.common.ovn import utils as ovn_utils
from neutron.services.bgp import constants as bgp_const
from neutron.services.bgp import helpers as bgp_helpers
from neutron.tests.functional import base

BGP_PLUGIN = 'neutron.services.bgp.plugin.BGPServicePlugin'


class TestBGPLeakRoutes(base.TestOVNFunctionalBase):

    def setUp(self):
        super().setUp(
            service_plugins={'bgp': BGP_PLUGIN})
        self.bgp_plugin = directory.get_plugin('bgp-service')

    def _create_ext_network(self):
        net_arg = {pnet.NETWORK_TYPE: 'flat',
                   pnet.PHYSICAL_NETWORK: 'physnet1',
                   external_net.EXTERNAL: True}
        network = self._make_network(
            self.fmt, 'ext-net', True, as_admin=True,
            arg_list=(pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                      external_net.EXTERNAL),
            **net_arg)
        self._make_subnet(
            self.fmt, network, '192.168.1.1', '192.168.1.0/24',
            ip_version=n_const.IP_VERSION_4)
        return network

    def _create_tenant_network_and_subnet(self, cidr='10.0.0.0/24',
                                          gateway='10.0.0.1'):
        network = self._make_network(self.fmt, 'tenant-net', True)
        subnet = self._make_subnet(
            self.fmt, network, gateway, cidr,
            ip_version=n_const.IP_VERSION_4)
        return network, subnet

    def _create_router_with_gw(self, ext_network):
        router = self.l3_plugin.create_router(self.context, {'router': {
            'name': 'test-router',
            'admin_state_up': True,
            'project_id': self._project_id,
            'external_gateway_info': {
                'network_id': ext_network['network']['id']}}})
        return router

    def _attach_subnet_to_router(self, router_id, subnet_id):
        return self.l3_plugin.add_router_interface(
            self.context, router_id, {'subnet_id': subnet_id})

    def _set_leak_routes(self, subnet_id, leak_routes):
        plugin = directory.get_plugin()
        data = {'subnet': {ovn_bgp_apidef.LEAK_ROUTES: leak_routes}}
        return plugin.update_subnet(
            self.context, subnet_id, data)

    def _get_bgp_lr_main(self):
        return self.nb_api.lookup(
            'Logical_Router', bgp_const.MAIN_ROUTER_NAME)

    def _get_static_routes(self):
        lr = self._get_bgp_lr_main()
        return list(lr.static_routes)

    def _get_router_gw_ip(self, router):
        gw_port = directory.get_plugin().get_port(
            self.context, router['gw_port_id'])
        return gw_port['fixed_ips'][0]['ip_address']

    def _assert_route(self, route, prefix, nexthop):
        self.assertEqual(prefix, route.ip_prefix)
        self.assertEqual(nexthop, route.nexthop)
        self.assertTrue(
            route.output_port,
            "output_port not set on route %s" % prefix)

    @staticmethod
    def _get_lrp_name(network_id):
        tenant_ls_name = ovn_utils.ovn_name(network_id)
        return bgp_helpers.get_lrp_name(
            bgp_const.MAIN_ROUTER_NAME, tenant_ls_name)

    @staticmethod
    def _get_lsp_name(network_id):
        tenant_ls_name = ovn_utils.ovn_name(network_id)
        return bgp_helpers.get_lsp_name(
            tenant_ls_name, bgp_const.MAIN_ROUTER_NAME)

    def _setup_topology(self, cidr='10.0.0.0/24', gateway='10.0.0.1'):
        ext_net = self._create_ext_network()
        tenant_net, tenant_subnet = (
            self._create_tenant_network_and_subnet(cidr, gateway))
        router = self._create_router_with_gw(ext_net)
        subnet_id = tenant_subnet['subnet']['id']
        self._attach_subnet_to_router(router['id'], subnet_id)

        # Create bgp-lr-main so commands can operate on it
        self.nb_api.lr_add(
            bgp_const.MAIN_ROUTER_NAME, may_exist=True
        ).execute(check_error=True)

        return router, tenant_net, tenant_subnet

    def test_leak_routes_creates_lrp_lsp_and_static_route(self):
        router, tenant_net, tenant_subnet = self._setup_topology()
        network_id = tenant_net['network']['id']
        subnet_id = tenant_subnet['subnet']['id']

        self._set_leak_routes(subnet_id, True)

        lrp_name = self._get_lrp_name(network_id)
        lsp_name = self._get_lsp_name(network_id)

        lrp = self.nb_api.lookup('Logical_Router_Port', lrp_name)
        self.assertIsNotNone(lrp)

        lsp = self.nb_api.lookup('Logical_Switch_Port', lsp_name)
        self.assertIsNotNone(lsp)

        routes = self._get_static_routes()
        self.assertEqual(1, len(routes))
        nexthop = self._get_router_gw_ip(router)
        self._assert_route(routes[0], '10.0.0.0/24', nexthop)

    def test_unleak_routes_removes_static_route_and_lrp_lsp(self):
        router, tenant_net, tenant_subnet = self._setup_topology()
        network_id = tenant_net['network']['id']
        subnet_id = tenant_subnet['subnet']['id']

        self._set_leak_routes(subnet_id, True)
        self._set_leak_routes(subnet_id, False)

        lrp_name = self._get_lrp_name(network_id)
        lsp_name = self._get_lsp_name(network_id)

        self.assertRaises(
            idlutils.RowNotFound,
            self.nb_api.lookup, 'Logical_Router_Port', lrp_name)
        self.assertRaises(
            idlutils.RowNotFound,
            self.nb_api.lookup, 'Logical_Switch_Port', lsp_name)

        routes = self._get_static_routes()
        self.assertEqual(0, len(routes))

    def test_leak_two_subnets_same_network_shares_lrp(self):
        ext_net = self._create_ext_network()
        tenant_net = self._make_network(self.fmt, 'tenant-net', True)
        subnet1 = self._make_subnet(
            self.fmt, tenant_net, '10.0.1.1', '10.0.1.0/24',
            ip_version=n_const.IP_VERSION_4)
        subnet2 = self._make_subnet(
            self.fmt, tenant_net, '10.0.2.1', '10.0.2.0/24',
            ip_version=n_const.IP_VERSION_4)
        router = self._create_router_with_gw(ext_net)
        self._attach_subnet_to_router(
            router['id'], subnet1['subnet']['id'])
        self._attach_subnet_to_router(
            router['id'], subnet2['subnet']['id'])

        self.nb_api.lr_add(
            bgp_const.MAIN_ROUTER_NAME, may_exist=True
        ).execute(check_error=True)

        network_id = tenant_net['network']['id']

        self._set_leak_routes(subnet1['subnet']['id'], True)
        self._set_leak_routes(subnet2['subnet']['id'], True)

        routes = self._get_static_routes()
        self.assertEqual(2, len(routes))
        prefixes = {r.ip_prefix for r in routes}
        self.assertEqual({'10.0.1.0/24', '10.0.2.0/24'}, prefixes)

        # Unleak first subnet — LRP/LSP should remain
        self._set_leak_routes(subnet1['subnet']['id'], False)

        lrp_name = self._get_lrp_name(network_id)
        lrp = self.nb_api.lookup('Logical_Router_Port', lrp_name)
        self.assertIsNotNone(lrp)

        routes = self._get_static_routes()
        self.assertEqual(1, len(routes))
        self.assertEqual('10.0.2.0/24', routes[0].ip_prefix)

        # Unleak second subnet — LRP/LSP should be removed
        self._set_leak_routes(subnet2['subnet']['id'], False)

        self.assertRaises(
            idlutils.RowNotFound,
            self.nb_api.lookup, 'Logical_Router_Port', lrp_name)
        self.assertEqual(0, len(self._get_static_routes()))

    def test_router_interface_removal_tears_down_ovn_state(self):
        router, tenant_net, tenant_subnet = self._setup_topology()
        network_id = tenant_net['network']['id']
        subnet_id = tenant_subnet['subnet']['id']

        self._set_leak_routes(subnet_id, True)

        # Verify OVN state exists
        lrp_name = self._get_lrp_name(network_id)
        self.nb_api.lookup('Logical_Router_Port', lrp_name)
        self.assertEqual(1, len(self._get_static_routes()))

        # Remove router interface
        self.l3_plugin.remove_router_interface(
            self.context, router['id'], {'subnet_id': subnet_id})

        # OVN state should be cleaned up
        self.assertRaises(
            idlutils.RowNotFound,
            self.nb_api.lookup, 'Logical_Router_Port', lrp_name)
        self.assertEqual(0, len(self._get_static_routes()))

    def test_router_interface_removal_keeps_lrp_if_other_leaked_subnet(self):
        """Two leaked subnets on same network; removing one keeps LRP."""
        ext_net = self._create_ext_network()
        tenant_net = self._make_network(self.fmt, 'tenant-net', True)
        subnet1 = self._make_subnet(
            self.fmt, tenant_net, '10.0.1.1', '10.0.1.0/24',
            ip_version=n_const.IP_VERSION_4)
        subnet2 = self._make_subnet(
            self.fmt, tenant_net, '10.0.2.1', '10.0.2.0/24',
            ip_version=n_const.IP_VERSION_4)
        router = self._create_router_with_gw(ext_net)
        self._attach_subnet_to_router(
            router['id'], subnet1['subnet']['id'])
        self._attach_subnet_to_router(
            router['id'], subnet2['subnet']['id'])

        self.nb_api.lr_add(
            bgp_const.MAIN_ROUTER_NAME, may_exist=True
        ).execute(check_error=True)

        network_id = tenant_net['network']['id']
        self._set_leak_routes(subnet1['subnet']['id'], True)
        self._set_leak_routes(subnet2['subnet']['id'], True)

        # Remove router interface for subnet1
        self.l3_plugin.remove_router_interface(
            self.context, router['id'],
            {'subnet_id': subnet1['subnet']['id']})

        # Propagating LRP should still exist (subnet2 is still leaked)
        lrp_name = self._get_lrp_name(network_id)
        lrp = self.nb_api.lookup('Logical_Router_Port', lrp_name)
        self.assertIsNotNone(lrp)

        # Only subnet2's route should remain
        routes = self._get_static_routes()
        self.assertEqual(1, len(routes))
        self.assertEqual('10.0.2.0/24', routes[0].ip_prefix)

        # Remove router interface for subnet2 — now LRP should be gone
        self.l3_plugin.remove_router_interface(
            self.context, router['id'],
            {'subnet_id': subnet2['subnet']['id']})

        self.assertRaises(
            idlutils.RowNotFound,
            self.nb_api.lookup, 'Logical_Router_Port', lrp_name)
        self.assertEqual(0, len(self._get_static_routes()))

    def test_router_interface_removal_removes_lrp_if_only_leaked_subnet(self):
        """Two subnets on same network, one leaked; removing it tears down."""
        ext_net = self._create_ext_network()
        tenant_net = self._make_network(self.fmt, 'tenant-net', True)
        subnet1 = self._make_subnet(
            self.fmt, tenant_net, '10.0.1.1', '10.0.1.0/24',
            ip_version=n_const.IP_VERSION_4)
        subnet2 = self._make_subnet(
            self.fmt, tenant_net, '10.0.2.1', '10.0.2.0/24',
            ip_version=n_const.IP_VERSION_4)
        router = self._create_router_with_gw(ext_net)
        self._attach_subnet_to_router(
            router['id'], subnet1['subnet']['id'])
        self._attach_subnet_to_router(
            router['id'], subnet2['subnet']['id'])

        self.nb_api.lr_add(
            bgp_const.MAIN_ROUTER_NAME, may_exist=True
        ).execute(check_error=True)

        network_id = tenant_net['network']['id']
        # Only leak subnet1, subnet2 is not leaked
        self._set_leak_routes(subnet1['subnet']['id'], True)

        # Remove router interface for the leaked subnet
        self.l3_plugin.remove_router_interface(
            self.context, router['id'],
            {'subnet_id': subnet1['subnet']['id']})

        # Propagating LRP should be removed (no more leaked subnets)
        lrp_name = self._get_lrp_name(network_id)
        self.assertRaises(
            idlutils.RowNotFound,
            self.nb_api.lookup, 'Logical_Router_Port', lrp_name)
        self.assertEqual(0, len(self._get_static_routes()))

    def test_leak_idempotent_on_repeated_enable(self):
        router, tenant_net, tenant_subnet = self._setup_topology()
        subnet_id = tenant_subnet['subnet']['id']

        self._set_leak_routes(subnet_id, True)
        # Setting again should be a no-op (idempotent)
        self._set_leak_routes(subnet_id, True)

        routes = self._get_static_routes()
        self.assertEqual(1, len(routes))

    def test_static_route_nexthop_is_router_gw_port_ip(self):
        router, tenant_net, tenant_subnet = self._setup_topology()
        subnet_id = tenant_subnet['subnet']['id']

        self._set_leak_routes(subnet_id, True)

        routes = self._get_static_routes()
        self.assertEqual(1, len(routes))
        nexthop = self._get_router_gw_ip(router)
        self._assert_route(routes[0], '10.0.0.0/24', nexthop)
        self.assertNotEqual('192.168.1.1', nexthop)
