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


import contextlib
import copy
import os

import mock
import netaddr
from oslo_config import cfg
from webob import exc

from neutron.common import constants
from neutron import context
from neutron.extensions import external_net
from neutron.extensions import l3
from neutron.extensions import portbindings
from neutron.extensions import providernet as pnet
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.openstack.common import uuidutils
from neutron.plugins.nuage import extensions
from neutron.plugins.nuage.extensions import nuage_router
from neutron.plugins.nuage import plugin as nuage_plugin
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.nuage import fake_nuageclient
from neutron.tests.unit import test_db_plugin
from neutron.tests.unit import test_extension_extraroute as extraroute_test
from neutron.tests.unit import test_extension_security_group as test_sg
from neutron.tests.unit import test_extensions


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


def getNuageClient():
    server = FAKE_SERVER
    serverauth = FAKE_SERVER_AUTH
    serverssl = FAKE_SERVER_SSL
    base_uri = FAKE_BASE_URI
    auth_resource = FAKE_AUTH_RESOURCE
    organization = FAKE_ORGANIZATION
    nuageclient = fake_nuageclient.FakeNuageClient(server,
                                                   base_uri,
                                                   serverssl,
                                                   serverauth,
                                                   auth_resource,
                                                   organization)
    return nuageclient


class NuagePluginV2TestCase(test_db_plugin.NeutronDbPluginV2TestCase):
    def setUp(self, plugin=_plugin_name,
              ext_mgr=None, service_plugins=None):

        if 'v6' in self._testMethodName:
            self.skipTest("Nuage Plugin does not support IPV6.")

        def mock_nuageClient_init(self):
            self.nuageclient = getNuageClient()

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

    def _test_floatingip_update_different_fixed_ip_same_port(self):
        with self.subnet() as s:
            # The plugin use the last IP as a gateway
            ip_range = list(netaddr.IPNetwork(s['subnet']['cidr']))[:-1]
            fixed_ips = [{'ip_address': str(ip_range[-3])},
                         {'ip_address': str(ip_range[-2])}]
            with self.port(subnet=s, fixed_ips=fixed_ips) as p:
                with self.floatingip_with_assoc(
                    port_id=p['port']['id'],
                    fixed_ip=str(ip_range[-3])) as fip:
                    body = self._show('floatingips', fip['floatingip']['id'])
                    self.assertEqual(fip['floatingip']['id'],
                                     body['floatingip']['id'])
                    self.assertEqual(fip['floatingip']['port_id'],
                                     body['floatingip']['port_id'])
                    self.assertEqual(str(ip_range[-3]),
                                     body['floatingip']['fixed_ip_address'])
                    self.assertIsNotNone(body['floatingip']['router_id'])
                    body_2 = self._update(
                        'floatingips', fip['floatingip']['id'],
                        {'floatingip': {'port_id': p['port']['id'],
                                        'fixed_ip_address': str(ip_range[-2])}
                         })
                    self.assertEqual(fip['floatingip']['port_id'],
                                     body_2['floatingip']['port_id'])
                    self.assertEqual(str(ip_range[-2]),
                                     body_2['floatingip']['fixed_ip_address'])

    def _test_floatingip_create_different_fixed_ip_same_port(self):
        """Test to create fixed IPs using the same port.

        This tests that it is possible to delete a port that has
        multiple floating ip addresses associated with it (each floating
        address associated with a unique fixed address).
        """

        with self.router() as r:
            with self.subnet(cidr='11.0.0.0/24') as public_sub:
                self._set_net_external(public_sub['subnet']['network_id'])
                self._add_external_gateway_to_router(
                    r['router']['id'],
                    public_sub['subnet']['network_id'])

                with self.subnet() as private_sub:
                    ip_range = list(netaddr.IPNetwork(
                        private_sub['subnet']['cidr']))[:-1]
                    fixed_ips = [{'ip_address': str(ip_range[-3])},
                                 {'ip_address': str(ip_range[-2])}]

                    self._router_interface_action(
                        'add', r['router']['id'],
                        private_sub['subnet']['id'], None)

                    with self.port(subnet=private_sub,
                                   fixed_ips=fixed_ips) as p:

                        fip1 = self._make_floatingip(
                            self.fmt,
                            public_sub['subnet']['network_id'],
                            p['port']['id'],
                            fixed_ip=str(ip_range[-2]))
                        fip2 = self._make_floatingip(
                            self.fmt,
                            public_sub['subnet']['network_id'],
                            p['port']['id'],
                            fixed_ip=str(ip_range[-3]))

                        # Test that floating ips are assigned successfully.
                        body = self._show('floatingips',
                                          fip1['floatingip']['id'])
                        self.assertEqual(
                            fip1['floatingip']['port_id'],
                            body['floatingip']['port_id'])

                        body = self._show('floatingips',
                                          fip2['floatingip']['id'])
                        self.assertEqual(
                            fip2['floatingip']['port_id'],
                            body['floatingip']['port_id'])
                        self._delete('ports', p['port']['id'])

                    # Test that port has been successfully deleted.
                    body = self._show('ports', p['port']['id'],
                                      expected_code=exc.HTTPNotFound.code)

                    for fip in [fip1, fip2]:
                        self._delete('floatingips',
                                     fip['floatingip']['id'])

                    self._router_interface_action(
                        'remove', r['router']['id'],
                        private_sub['subnet']['id'], None)

                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    public_sub['subnet']['network_id'])

    def test_router_update_gateway_with_different_external_subnet(self):
        self.skipTest("Plugin doesn't support multiple external networks")

    def test_router_create_with_gwinfo_ext_ip_subnet(self):
        self.skipTest("Plugin doesn't support multiple external networks")


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

    def test_create_subnet_nonzero_cidr(self):
        # The plugin requires 2 IP addresses available if gateway is set
        with contextlib.nested(
            self.subnet(cidr='10.129.122.5/8'),
            self.subnet(cidr='11.129.122.5/15'),
            self.subnet(cidr='12.129.122.5/16'),
            self.subnet(cidr='13.129.122.5/18'),
            self.subnet(cidr='14.129.122.5/22'),
            self.subnet(cidr='15.129.122.5/24'),
            self.subnet(cidr='16.129.122.5/28'),
        ) as subs:
            # the API should accept and correct these for users
            self.assertEqual('10.0.0.0/8', subs[0]['subnet']['cidr'])
            self.assertEqual('11.128.0.0/15', subs[1]['subnet']['cidr'])
            self.assertEqual('12.129.0.0/16', subs[2]['subnet']['cidr'])
            self.assertEqual('13.129.64.0/18', subs[3]['subnet']['cidr'])
            self.assertEqual('14.129.120.0/22', subs[4]['subnet']['cidr'])
            self.assertEqual('15.129.122.0/24', subs[5]['subnet']['cidr'])
            self.assertEqual('16.129.122.0/28', subs[6]['subnet']['cidr'])

    def test_create_subnet_gateway_outside_cidr(self):
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                    'cidr': '10.0.2.0/24',
                    'ip_version': '4',
                    'tenant_id': network['network']['tenant_id'],
                    'gateway_ip': '10.0.3.1'}}
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            self.assertEqual(exc.HTTPClientError.code, res.status_int)

    def test_create_subnet_with_dhcp_port(self):
        nuage_dhcp_port = '10.0.0.254'
        with self.network() as network:
            keys = {
                'cidr': '10.0.0.0/24',
                'gateway_ip': '10.0.0.1'
            }
            with self.subnet(network=network, **keys) as subnet:
                query_params = "fixed_ips=ip_address%%3D%s" % nuage_dhcp_port
                ports = self._list('ports', query_params=query_params)
                self.assertEqual(4, subnet['subnet']['ip_version'])
                self.assertIn('name', subnet['subnet'])
                self.assertEqual(1, len(ports['ports']))
                self.assertEqual(nuage_dhcp_port,
                                 ports['ports'][0]['fixed_ips']
                                 [0]['ip_address'])

    def test_create_subnet_with_nuage_subnet_template(self):
        with self.network() as network:
            nuage_subn_template = uuidutils.generate_uuid()
            data = {'subnet': {'tenant_id': network['network']['tenant_id']}}
            data['subnet']['cidr'] = '10.0.0.0/24'
            data['subnet']['ip_version'] = 4
            data['subnet']['network_id'] = network['network']['id']
            data['subnet']['nuage_subnet_template'] = nuage_subn_template
            subnet_req = self.new_create_request('subnets', data, 'json')
            subnet_res = subnet_req.get_response(self.api)
            self.assertEqual(exc.HTTPCreated.code, subnet_res.status_int)

    def test_delete_subnet_port_exists_returns_409(self):
        gateway_ip = '10.0.0.1'
        cidr = '10.0.0.0/24'
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        network = self.deserialize(self.fmt, res)
        subnet = self._make_subnet(self.fmt, network, gateway_ip,
                                   cidr, ip_version=4)
        self._create_port(self.fmt,
                          network['network']['id'])
        req = self.new_delete_request('subnets', subnet['subnet']['id'])
        res = req.get_response(self.api)
        self.assertEqual(409, res.status_int)


class TestNuagePluginPortBinding(NuagePluginV2TestCase,
                                 test_bindings.PortBindingsTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS

    def setUp(self):
        super(TestNuagePluginPortBinding, self).setUp()

    def test_ports_vif_details(self):
        # The Plugin will create 2 extra ports
        plugin = manager.NeutronManager.get_plugin()
        cfg.CONF.set_default('allow_overlapping_ips', True)
        with contextlib.nested(self.port(), self.port()):
            ctx = context.get_admin_context()
            ports = plugin.get_ports(ctx)
            self.assertEqual(4, len(ports))
            for port in ports:
                self._check_response_portbindings(port)
            # By default user is admin - now test non admin user
            ctx = self._get_non_admin_context()
            ports = self._list('ports', neutron_context=ctx)['ports']
            self.assertEqual(4, len(ports))
            for non_admin_port in ports:
                self._check_response_no_portbindings(non_admin_port)


class TestNuageExtrarouteTestCase(NuagePluginV2TestCase,
                                  extraroute_test.ExtraRouteDBIntTestCase):

    def test_router_create_with_gwinfo_ext_ip_subnet(self):
        self.skipTest("Nuage plugin does not support multiple subnets per "
                      "external network.")

    def test_router_update_gateway_with_different_external_subnet(self):
        self.skipTest("Nuage plugin does not support multiple subnets per "
                      "external networks.")

    def test_router_update_with_dup_destination_address(self):
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
                    device_own=constants.DEVICE_OWNER_ROUTER_GW)
                port_list = self.deserialize('json', port_res)
                # The plugin will create 1 port
                self.assertEqual(2, len(port_list['ports']))

                routes = [{'destination': '135.207.0.0/16',
                           'nexthop': '10.0.1.3'}]

                body = self._update('routers', r['router']['id'],
                                    {'router': {'routes':
                                                routes}})

                body = self._show('routers', r['router']['id'])
                self.assertEqual(routes,
                                 body['router']['routes'])

                self._remove_external_gateway_from_router(
                    r['router']['id'],
                    s['subnet']['network_id'])
                body = self._show('routers', r['router']['id'])
                gw_info = body['router']['external_gateway_info']
                self.assertIsNone(gw_info)

    def test_floatingip_create_different_fixed_ip_same_port(self):
        self._test_floatingip_create_different_fixed_ip_same_port()

    def test_floatingip_update_different_router(self):
        self._test_floatingip_update_different_router()

    def test_floatingip_update_different_fixed_ip_same_port(self):
        self._test_floatingip_update_different_fixed_ip_same_port()

    def test_network_update_external_failure(self):
        self._test_network_update_external_failure()

    def test_update_port_with_assoc_floatingip(self):
        with self.subnet(cidr='200.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.port() as port:
                p_id = port['port']['id']
                with self.floatingip_with_assoc(port_id=p_id):
                    # Update the port with dummy vm info
                    port_dict = {
                        'device_id': uuidutils.generate_uuid(),
                        'device_owner': 'compute:Nova'
                    }
                    port = self._update('ports', port['port']['id'],
                                        {'port': port_dict})
                    self.assertEqual(port_dict['device_id'],
                                     port['port']['device_id'])

    def test_disassociated_floatingip_delete(self):
        with self.subnet(cidr='200.0.0.0/24') as public_sub:
            self._set_net_external(public_sub['subnet']['network_id'])
            with self.port() as port:
                p_id = port['port']['id']
                with self.floatingip_with_assoc(port_id=p_id) as fip:

                    # Disassociate fip from the port
                    fip = self._update('floatingips', fip['floatingip']['id'],
                                       {'floatingip': {'port_id': None}})
                    self.assertIsNone(fip['floatingip']['router_id'])


class NuageRouterTestExtensionManager(object):

    def get_resources(self):
        l3.RESOURCE_ATTRIBUTE_MAP['routers'].update(
            nuage_router.EXTENDED_ATTRIBUTES_2_0['routers'])
        return l3.L3.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestNuageRouterExtTestCase(NuagePluginV2TestCase):

    def setUp(self):
        self._l3_attribute_map_bk = copy.deepcopy(l3.RESOURCE_ATTRIBUTE_MAP)
        ext_mgr = NuageRouterTestExtensionManager()
        super(TestNuageRouterExtTestCase, self).setUp(plugin=_plugin_name,
                                                      ext_mgr=ext_mgr)
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.addCleanup(self.restore_l3_attribute_map)

    def restore_l3_attribute_map(self):
        l3.RESOURCE_ATTRIBUTE_MAP = self._l3_attribute_map_bk

    def test_router_create_with_nuage_rtr_template(self):
        nuage_rtr_template = uuidutils.generate_uuid()
        data = {'router': {'tenant_id': uuidutils.generate_uuid()}}
        data['router']['name'] = 'router1'
        data['router']['admin_state_up'] = True
        data['router']['nuage_router_template'] = nuage_rtr_template
        router_req = self.new_create_request('routers', data, 'json')
        router_res = router_req.get_response(self.ext_api)
        self.assertEqual(exc.HTTPCreated.code, router_res.status_int)


class TestNuageProviderNetTestCase(NuagePluginV2TestCase):

    def test_create_provider_network(self):
        phys_net = uuidutils.generate_uuid()
        data = {'network': {'name': 'pnet1',
                            'tenant_id': 'admin',
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: phys_net,
                            pnet.SEGMENTATION_ID: 123}}
        network_req = self.new_create_request('networks', data, self.fmt)
        net = self.deserialize(self.fmt, network_req.get_response(self.api))
        self.assertEqual('vlan', net['network'][pnet.NETWORK_TYPE])
        self.assertEqual(phys_net, net['network'][pnet.PHYSICAL_NETWORK])
        self.assertEqual(123, net['network'][pnet.SEGMENTATION_ID])

    def test_create_provider_network_no_admin(self):
        phys_net = uuidutils.generate_uuid()
        data = {'network': {'name': 'pnet1',
                            'tenant_id': 'no_admin',
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: phys_net,
                            pnet.SEGMENTATION_ID: 123}}
        network_req = self.new_create_request('networks', data, self.fmt)
        network_req.environ['neutron.context'] = context.Context(
                                    '', 'no_admin', is_admin=False)
        res = network_req.get_response(self.api)
        self.assertEqual(exc.HTTPForbidden.code, res.status_int)

    def test_get_network_for_provider_network(self):
        phys_net = uuidutils.generate_uuid()
        data = {'network': {'name': 'pnet1',
                            'tenant_id': 'admin',
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: phys_net,
                            pnet.SEGMENTATION_ID: 123}}
        network_req = self.new_create_request('networks', data, self.fmt)
        res = self.deserialize(self.fmt, network_req.get_response(self.api))

        get_req = self.new_show_request('networks', res['network']['id'])
        net = self.deserialize(self.fmt, get_req.get_response(self.api))
        self.assertEqual('vlan', net['network'][pnet.NETWORK_TYPE])
        self.assertEqual(phys_net, net['network'][pnet.PHYSICAL_NETWORK])
        self.assertEqual(123, net['network'][pnet.SEGMENTATION_ID])

    def test_list_networks_for_provider_network(self):
        phys_net = uuidutils.generate_uuid()
        data1 = {'network': {'name': 'pnet1',
                            'tenant_id': 'admin',
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: phys_net,
                            pnet.SEGMENTATION_ID: 123}}
        network_req_1 = self.new_create_request('networks', data1, self.fmt)
        network_req_1.get_response(self.api)
        data2 = {'network': {'name': 'pnet2',
                            'tenant_id': 'admin',
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: phys_net,
                            pnet.SEGMENTATION_ID: 234}}
        network_req_2 = self.new_create_request('networks', data2, self.fmt)
        network_req_2.get_response(self.api)

        list_req = self.new_list_request('networks')
        pnets = self.deserialize(self.fmt, list_req.get_response(self.api))
        self.assertEqual(2, len(pnets['networks']))
        self.assertEqual('vlan', pnets['networks'][0][pnet.NETWORK_TYPE])
        self.assertEqual(phys_net, pnets['networks'][0][pnet.PHYSICAL_NETWORK])
        self.assertEqual(123, pnets['networks'][0][pnet.SEGMENTATION_ID])
        self.assertEqual('vlan', pnets['networks'][1][pnet.NETWORK_TYPE])
        self.assertEqual(phys_net, pnets['networks'][1][pnet.PHYSICAL_NETWORK])
        self.assertEqual(234, pnets['networks'][1][pnet.SEGMENTATION_ID])


class TestNuageSecurityGroupTestCase(NuagePluginV2TestCase,
                                     test_sg.TestSecurityGroups):

    def test_list_ports_security_group(self):
        with self.network() as n:
            with self.subnet(n):
                self._create_port(self.fmt, n['network']['id'])
                req = self.new_list_request('ports')
                res = req.get_response(self.api)
                ports = self.deserialize(self.fmt, res)
                # The Nuage plugin reserve the first port
                port = ports['ports'][1]
                self.assertEqual(1, len(port[ext_sg.SECURITYGROUPS]))
                self._delete('ports', port['id'])
