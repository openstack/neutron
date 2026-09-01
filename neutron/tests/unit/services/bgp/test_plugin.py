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

from neutron_lib.api.definitions import ovn_bgp as ovn_bgp_apidef
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import context as n_context
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
import webob

from neutron.services.bgp import plugin as bgp_plugin
from neutron.tests import base
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit.plugins.ml2 import test_plugin as ml2_test

BGP_PLUGIN = 'neutron.services.bgp.plugin.BGPServicePlugin'


class BGPServicePluginAPITestCase(test_l3.L3NatTestCaseMixin,
                                  ml2_test.Ml2PluginV2TestCase):

    def get_additional_service_plugins(self):
        return {'bgp_plugin': BGP_PLUGIN}

    def setUp(self):
        cfg.CONF.set_override('type_drivers', 'geneve,flat,local',
                              group='ml2')
        cfg.CONF.set_override('vni_ranges', ['1:1000'],
                              group='ml2_type_geneve')
        super().setUp()
        l3_ext_mgr = test_l3.L3TestExtensionManager()
        self.ext_api = test_extensions.setup_extensions_middleware(l3_ext_mgr)

    def _create_geneve_network(self, project_id=None):
        project_id = project_id or self._project_id
        data = {'network': {'name': 'net-geneve',
                            'project_id': project_id,
                            pnet.NETWORK_TYPE: 'geneve',
                            'admin_state_up': True}}
        req = self.new_create_request('networks', data, as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)
        return self.deserialize(self.fmt, res)

    def _create_ext_network(self):
        data = {'network': {'name': 'ext-net',
                            'project_id': self._project_id,
                            pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            'router:external': True,
                            'admin_state_up': True}}
        req = self.new_create_request('networks', data, as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)
        return self.deserialize(self.fmt, res)

    def _get_or_create_ext_network(self):
        if not hasattr(self, '_ext_net_id'):
            ext_net = self._create_ext_network()
            self._ext_net_id = ext_net['network']['id']
            self._make_subnet(
                self.fmt, ext_net, '172.16.0.1', '172.16.0.0/24')
        return self._ext_net_id

    def _create_leakable_topology(self, cidr='10.0.0.0/24', project_id=None):
        """Create a geneve network + subnet + router with ext GW.

        Returns (network, subnet, router).
        """
        project_id = project_id or self._project_id
        ext_net_id = self._get_or_create_ext_network()
        network = self._create_geneve_network(project_id=project_id)
        subnet = self._make_subnet(
            self.fmt, network, cidr.rsplit('.', 1)[0] + '.1', cidr,
            project_id=project_id)
        router = self._make_router(
            self.fmt, project_id, 'bgp-router',
            external_gateway_info={'network_id': ext_net_id})
        self._router_interface_action(
            'add', router['router']['id'],
            subnet['subnet']['id'], None,
            as_admin=True)
        return network, subnet, router

    def test_create_network_vlan_rejected(self):
        data = {'network': {'name': 'net-vlan',
                            'project_id': self._project_id,
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1}}
        req = self.new_create_request('networks', data, as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_network_flat_allowed(self):
        data = {'network': {'name': 'net-flat',
                            'project_id': self._project_id,
                            pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'physnet1'}}
        req = self.new_create_request('networks', data, as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

    def test_create_network_geneve_allowed(self):
        self._create_geneve_network()

    def test_create_second_flat_network_rejected(self):
        data = {'network': {'name': 'net-flat-1',
                            'project_id': self._project_id,
                            pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'physnet1'}}
        req = self.new_create_request('networks', data, as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

        data = {'network': {'name': 'net-flat-2',
                            'project_id': self._project_id,
                            pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'physnet2'}}
        req = self.new_create_request('networks', data, as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_subnet_show_has_leak_routes(self):
        with self.subnet() as subnet:
            req = self.new_show_request('subnets', subnet['subnet']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertIn(ovn_bgp_apidef.LEAK_ROUTES, res['subnet'])
            self.assertFalse(res['subnet'][ovn_bgp_apidef.LEAK_ROUTES])

    def test_update_subnet_leak_routes_non_geneve_rejected(self):
        with self.subnet() as subnet:
            data = {'subnet': {ovn_bgp_apidef.LEAK_ROUTES: True}}
            req = self.new_update_request('subnets', data,
                                          subnet['subnet']['id'],
                                          as_admin=True)
            res = req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_update_subnet_leak_routes_geneve_no_router_rejected(self):
        network = self._create_geneve_network()
        with self.subnet(network=network) as subnet:
            data = {'subnet': {ovn_bgp_apidef.LEAK_ROUTES: True}}
            req = self.new_update_request('subnets', data,
                                          subnet['subnet']['id'],
                                          as_admin=True)
            res = req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_update_subnet_leak_routes_no_ext_gw_rejected(self):
        network = self._create_geneve_network()
        with self.subnet(network=network) as subnet:
            subnet_id = subnet['subnet']['id']
            router = self._make_router(
                self.fmt, self._project_id, 'no-gw-router',
                as_admin=True)
            self._router_interface_action(
                'add', router['router']['id'], subnet_id, None,
                as_admin=True)
            data = {'subnet': {ovn_bgp_apidef.LEAK_ROUTES: True}}
            req = self.new_update_request('subnets', data, subnet_id,
                                          as_admin=True)
            res = req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def _test_update_subnet_leak_routes_enabled_helper(self):
        _network, subnet, _router = self._create_leakable_topology()
        subnet_id = subnet['subnet']['id']
        data = {'subnet': {ovn_bgp_apidef.LEAK_ROUTES: True}}
        req = self.new_update_request('subnets', data, subnet_id,
                                      as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPOk.code, res.status_int)

        req = self.new_show_request('subnets', subnet_id, as_admin=True)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertTrue(res['subnet'][ovn_bgp_apidef.LEAK_ROUTES])

        return subnet_id, data

    def test_update_subnet_leak_routes_enabled(self):
        self._test_update_subnet_leak_routes_enabled_helper()

    def test_update_subnet_leak_routes_enabled_already_enabled(self):
        subnet_id, data = self._test_update_subnet_leak_routes_enabled_helper()

        # Enable leak routes again
        req = self.new_update_request('subnets', data, subnet_id,
                                      as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPOk.code, res.status_int)

        req = self.new_show_request('subnets', subnet_id, as_admin=True)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertTrue(res['subnet'][ovn_bgp_apidef.LEAK_ROUTES])

    def _test_update_subnet_leak_routes_disabled_helper(self):
        _network, subnet, _router = self._create_leakable_topology()
        subnet_id = subnet['subnet']['id']
        data = {'subnet': {ovn_bgp_apidef.LEAK_ROUTES: True}}
        req = self.new_update_request('subnets', data, subnet_id,
                                      as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPOk.code, res.status_int)

        data = {'subnet': {ovn_bgp_apidef.LEAK_ROUTES: False}}
        req = self.new_update_request('subnets', data, subnet_id,
                                      as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPOk.code, res.status_int)

        req = self.new_show_request('subnets', subnet_id, as_admin=True)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertFalse(res['subnet'][ovn_bgp_apidef.LEAK_ROUTES])

        return subnet_id, data

    def test_update_subnet_leak_routes_disabled(self):
        self._test_update_subnet_leak_routes_disabled_helper()

    def test_update_subnet_leak_routes_disabled_already_disabled(self):
        subnet_id, data = (
            self._test_update_subnet_leak_routes_disabled_helper())
        req = self.new_update_request('subnets', data, subnet_id,
                                      as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPOk.code, res.status_int)

        req = self.new_show_request('subnets', subnet_id, as_admin=True)
        res = self.deserialize(self.fmt, req.get_response(self.api))
        self.assertFalse(res['subnet'][ovn_bgp_apidef.LEAK_ROUTES])

    def test_update_subnet_noop_does_not_change_leak_routes(self):
        """Updating unrelated attribute does not affect leak_routes."""
        network = self._create_geneve_network()
        with self.subnet(network=network) as subnet:
            subnet_id = subnet['subnet']['id']
            data = {'subnet': {'name': 'renamed'}}
            req = self.new_update_request('subnets', data, subnet_id,
                                          as_admin=True)
            res = req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPOk.code, res.status_int)

            req = self.new_show_request('subnets', subnet_id,
                                        as_admin=True)
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertFalse(res['subnet'][ovn_bgp_apidef.LEAK_ROUTES])

    def test_update_subnet_leak_routes_overlap_rejected(self):
        _net1, _sub1, _router1 = self._create_leakable_topology(
            cidr='10.0.0.0/24')
        _net2, subnet2, _router2 = self._create_leakable_topology(
            cidr='10.0.0.0/16')

        data = {'subnet': {ovn_bgp_apidef.LEAK_ROUTES: True}}
        req = self.new_update_request('subnets', data,
                                      _sub1['subnet']['id'],
                                      as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPOk.code, res.status_int)

        data = {'subnet': {ovn_bgp_apidef.LEAK_ROUTES: True}}
        req = self.new_update_request('subnets', data,
                                      subnet2['subnet']['id'],
                                      as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_update_subnet_leak_routes_no_overlap_allowed(self):
        _net1, _sub1, _router1 = self._create_leakable_topology(
            cidr='10.0.0.0/24')
        _net2, subnet2, _router2 = self._create_leakable_topology(
            cidr='10.0.1.0/24')

        data = {'subnet': {ovn_bgp_apidef.LEAK_ROUTES: True}}
        req = self.new_update_request('subnets', data,
                                      _sub1['subnet']['id'],
                                      as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPOk.code, res.status_int)

        data = {'subnet': {ovn_bgp_apidef.LEAK_ROUTES: True}}
        req = self.new_update_request('subnets', data,
                                      subnet2['subnet']['id'],
                                      as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPOk.code, res.status_int)

    def test_update_subnet_leak_routes_cross_project_overlap_rejected(self):
        """Overlap check is global, not scoped to a single project."""
        _net1, _sub1, _router1 = self._create_leakable_topology(
            cidr='10.0.0.0/24', project_id='project-a')
        _net2, subnet2, _router2 = self._create_leakable_topology(
            cidr='10.0.0.0/16', project_id='project-b')

        data = {'subnet': {ovn_bgp_apidef.LEAK_ROUTES: True}}
        req = self.new_update_request('subnets', data,
                                      _sub1['subnet']['id'],
                                      as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPOk.code, res.status_int)

        data = {'subnet': {ovn_bgp_apidef.LEAK_ROUTES: True}}
        req = self.new_update_request('subnets', data,
                                      subnet2['subnet']['id'],
                                      as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)


class BGPCidrOverlapValidationTestCase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.plugin = bgp_plugin.BGPServicePlugin()
        self.context = n_context.Context(user_id='user', project_id='project')
        self.mock_leaked_cidrs = mock.patch.object(
            bgp_plugin.bgp_objects.SubnetBGPLeakRoutes,
            'get_leaked_subnet_cidrs').start()

    def test_no_existing_leaked_subnets(self):
        self.mock_leaked_cidrs.return_value = []
        self.plugin._validate_no_cidr_overlap(self.context, '10.0.0.0/24')

    def test_exact_same_cidr_rejected(self):
        self.mock_leaked_cidrs.return_value = [
            ('existing-subnet', '10.0.0.0/24')]
        self.assertRaises(
            n_exc.BadRequest,
            self.plugin._validate_no_cidr_overlap,
            self.context, '10.0.0.0/24')

    def test_new_subnet_inside_existing_rejected(self):
        self.mock_leaked_cidrs.return_value = [
            ('existing-subnet', '10.0.0.0/16')]
        self.assertRaises(
            n_exc.BadRequest,
            self.plugin._validate_no_cidr_overlap,
            self.context, '10.0.0.0/24')

    def test_new_supernet_of_existing_rejected(self):
        self.mock_leaked_cidrs.return_value = [
            ('existing-subnet', '10.0.0.0/24')]
        self.assertRaises(
            n_exc.BadRequest,
            self.plugin._validate_no_cidr_overlap,
            self.context, '10.0.0.0/16')

    def test_non_overlapping_cidrs_allowed(self):
        self.mock_leaked_cidrs.return_value = [
            ('existing-subnet', '10.0.0.0/24')]
        self.plugin._validate_no_cidr_overlap(self.context, '10.0.1.0/24')

    def test_different_address_family_allowed(self):
        """IPv4 and IPv6 subnets never overlap."""
        self.mock_leaked_cidrs.return_value = [
            ('existing-subnet', '10.0.0.0/24')]
        self.plugin._validate_no_cidr_overlap(self.context, 'fd00::/64')

    def test_ipv6_overlap_rejected(self):
        self.mock_leaked_cidrs.return_value = [
            ('existing-subnet', 'fd00::/48')]
        self.assertRaises(
            n_exc.BadRequest,
            self.plugin._validate_no_cidr_overlap,
            self.context, 'fd00::/64')

    def test_multiple_leaked_one_overlaps_rejected(self):
        self.mock_leaked_cidrs.return_value = [
            ('subnet-a', '192.168.0.0/24'),
            ('subnet-b', '10.0.0.0/16')]
        self.assertRaises(
            n_exc.BadRequest,
            self.plugin._validate_no_cidr_overlap,
            self.context, '10.0.1.0/24')

    def test_multiple_leaked_none_overlaps_allowed(self):
        self.mock_leaked_cidrs.return_value = [
            ('subnet-a', '192.168.0.0/24'),
            ('subnet-b', '172.16.0.0/16')]
        self.plugin._validate_no_cidr_overlap(self.context, '10.0.0.0/24')
