# Copyright 2022 Troila
# All rights reserved.
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

from neutron_lib.api.definitions import address_scope as scope_apidef
from neutron_lib.api.definitions import dns as dns_apidef
from neutron_lib.api.definitions import dvr as dvr_apidef
from neutron_lib.api.definitions import external_net as enet_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import l3_ext_gw_mode
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import fixture
from oslo_config import cfg
from oslo_utils import uuidutils
from webob import exc

from neutron.db import address_scope_db
from neutron.extensions import address_scope as ext_address_scope
from neutron.extensions import l3
from neutron.extensions import l3_ndp_proxy
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_address_scope
from neutron.tests.unit.extensions import test_l3

_uuid = uuidutils.generate_uuid


class TestL3NDPProxyIntPlugin(address_scope_db.AddressScopeDbMixin,
                              test_l3.TestL3NatServicePlugin,
                              test_l3.TestL3NatIntPlugin):

    supported_extension_aliases = [enet_apidef.ALIAS, l3_apidef.ALIAS,
                                   dns_apidef.ALIAS, scope_apidef.ALIAS,
                                   l3_ext_gw_mode.ALIAS, dvr_apidef.ALIAS]


class ExtendL3NDPPRroxyExtensionManager(object):

    def get_resources(self):
        return (l3.L3.get_resources() +
                l3_ndp_proxy.L3_ndp_proxy.get_resources() +
                ext_address_scope.Address_scope.get_resources())

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class L3NDPProxyTestCase(test_address_scope.AddressScopeTestCase,
                         test_l3.L3BaseForIntTests,
                         test_l3.L3NatTestCaseMixin):
    fmt = 'json'
    tenant_id = _uuid()

    def setUp(self):
        mock.patch('neutron.api.rpc.handlers.resources_rpc.'
                   'ResourcesPushRpcApi').start()
        svc_plugins = ('neutron.services.ndp_proxy.plugin.NDPProxyPlugin',)
        plugin = ('neutron.tests.unit.extensions.'
                  'test_l3_ndp_proxy.TestL3NDPProxyIntPlugin')
        ext_mgr = ExtendL3NDPPRroxyExtensionManager()
        super(L3NDPProxyTestCase, self).setUp(
              ext_mgr=ext_mgr, service_plugins=svc_plugins, plugin=plugin)
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

        self.address_scope_id = self._make_address_scope(
            self.fmt, constants.IP_VERSION_6,
            **{'tenant_id': self.tenant_id})['address_scope']['id']
        self.subnetpool_id = self._make_subnetpool(
            self.fmt, ['2001::0/96'],
            **{'address_scope_id': self.address_scope_id,
               'default_prefixlen': 112, 'tenant_id': self.tenant_id,
               'name': "test-ipv6-pool"})['subnetpool']['id']
        self.ext_net = self._make_network(
            self.fmt, 'ext-net', True)
        self.ext_net_id = self.ext_net['network']['id']
        self._set_net_external(self.ext_net_id)
        self._ext_subnet_v4 = self._make_subnet(
            self.fmt, self.ext_net, gateway="10.0.0.1",
            cidr="10.0.0.0/24")
        self._ext_subnet_v4_id = self._ext_subnet_v4['subnet']['id']
        self._ext_subnet_v6 = self._make_subnet(
            self.fmt, self.ext_net, gateway="2001::1:1",
            subnetpool_id=self.subnetpool_id,
            cidr="2001::1:0/112",
            ip_version=constants.IP_VERSION_6,
            ipv6_ra_mode=constants.DHCPV6_STATEFUL,
            ipv6_address_mode=constants.DHCPV6_STATEFUL)
        self._ext_subnet_v6_id = self._ext_subnet_v6['subnet']['id']
        self.router1 = self._make_router(self.fmt, self.tenant_id)
        self.router1_id = self.router1['router']['id']
        self.private_net = self._make_network(self.fmt, 'private-net', True)
        self.private_subnet = self._make_subnet(
            self.fmt, self.private_net, gateway="2001::2:1",
            subnetpool_id=self.subnetpool_id,
            cidr="2001::2:0/112",
            ip_version=constants.IP_VERSION_6,
            ipv6_ra_mode=constants.DHCPV6_STATEFUL,
            ipv6_address_mode=constants.DHCPV6_STATEFUL)
        self._update_router(
            self.router1_id,
            {'external_gateway_info': {'network_id': self.ext_net_id},
             'enable_ndp_proxy': True})
        self._router_interface_action(
            'add', self.router1_id,
            self.private_subnet['subnet']['id'], None)

    def _create_ndp_proxy(self, router_id, port_id, ip_address=None,
                          description=None, fmt=None, tenant_id=None,
                          expected_code=exc.HTTPCreated.code,
                          expected_message=None):
        tenant_id = tenant_id or self.tenant_id
        data = {'ndp_proxy': {
            "port_id": port_id,
            "router_id": router_id}
        }
        if ip_address:
            data['ndp_proxy']['ip_address'] = ip_address
        if description:
            data['ndp_proxy']['description'] = description

        req_res = self._req(
            'POST', 'ndp-proxies', data,
            fmt or self.fmt)
        req_res.environ['neutron.context'] = context.Context(
            '', tenant_id, is_admin=True)

        res = req_res.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int)
        if expected_message:
            self.assertEqual(expected_message,
                             res.json_body['NeutronError']['message'])
        return self.deserialize(self.fmt, res)

    def _update_ndp_proxy(self, ndp_proxy_id,
                          tenant_id=None, fmt=None,
                          expected_code=exc.HTTPOk.code,
                          expected_message=None, **kwargs):
        tenant_id = tenant_id or self.tenant_id
        data = {}
        for k, v in kwargs.items():
            data[k] = v
        req_res = self._req(
            'PUT', 'ndp-proxies', {'ndp_proxy': data},
            fmt or self.fmt, id=ndp_proxy_id)
        req_res.environ['neutron.context'] = context.Context(
            '', tenant_id, is_admin=True)
        res = req_res.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int)
        if expected_message:
            self.assertEqual(expected_message,
                             res.json_body['NeutronError']['message'])
        return self.deserialize(self.fmt, res)

    def _get_ndp_proxy(self, ndp_proxy_id, tenant_id=None,
                       fmt=None, expected_code=exc.HTTPOk.code,
                       expected_message=None):
        req_res = self._req('GET', 'ndp-proxies', id=ndp_proxy_id,
                            fmt=(fmt or self.fmt))
        res = req_res.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int)
        if expected_message:
            self.assertEqual(expected_message,
                             res.json_body['NeutronError']['message'])
        return self.deserialize(self.fmt, res)

    def _list_ndp_proxy(self, tenant_id=None, fmt=None,
                        expected_code=exc.HTTPOk.code,
                        expected_message=None, **kwargs):
        req_res = self._req('GET', 'ndp-proxies', params=kwargs,
                            fmt=(fmt or self.fmt))
        res = req_res.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int)
        if expected_message:
            self.assertEqual(expected_message,
                             res.json_body['NeutronError']['message'])
        return self.deserialize(self.fmt, res)

    def _delete_ndp_proxy(self, ndp_proxy_id, tenant_id=None,
                          fmt=None, expected_code=exc.HTTPNoContent.code,
                          expected_message=None):
        req_res = self._req('DELETE', 'ndp-proxies', id=ndp_proxy_id,
                            fmt=(fmt or self.fmt))
        res = req_res.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int)
        if expected_message:
            self.assertEqual(expected_message,
                             res.json_body['NeutronError']['message'])
        if res.status_int != exc.HTTPNoContent.code:
            return self.deserialize(self.fmt, res)

    def _update_router(self, router_id, update_date, tenant_id=None,
                       fmt=None, expected_code=exc.HTTPOk.code,
                       expected_message=None):
        tenant_id = tenant_id or self.tenant_id
        data = {'router': update_date}
        router_req = self.new_update_request(
            'routers', id=router_id, data=data,
            fmt=(fmt or self.fmt))
        router_req.environ['neutron.context'] = context.Context(
            '', tenant_id, is_admin=True)
        res = router_req.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int)
        if expected_message:
            self.assertEqual(expected_message,
                             res.json_body['NeutronError']['message'])

    def _get_router(self, router_id, tenant_id=None, fmt=None,
                    expected_code=exc.HTTPOk.code,
                    expected_message=None):
        req_res = self._req('GET', 'routers', id=router_id,
                            fmt=(fmt or self.fmt))
        res = req_res.get_response(self.ext_api)
        self.assertEqual(expected_code, res.status_int)
        if expected_message:
            self.assertEqual(expected_message,
                             res.json_body['NeutronError']['message'])
        return self.deserialize(self.fmt, res)

    def test_create_and_update_ndp_proxy_without_exception(self):
        with self.port(self.private_subnet) as port1, \
                self.port(self.private_subnet) as port2:
            ipv6_address = port1['port']['fixed_ips'][0]['ip_address']
            ndp_proxy = self._create_ndp_proxy(self.router1_id,
                                               port1['port']['id'])
            ndp_proxy_id = ndp_proxy['ndp_proxy']['id']
            desc_str = "Test update description"
            self._update_ndp_proxy(
                ndp_proxy_id, **{'description': desc_str})
            new_ndp_proxy = self._get_ndp_proxy(ndp_proxy_id)
            self.assertEqual(
                desc_str, new_ndp_proxy['ndp_proxy']['description'])

            ipv6_address = port2['port']['fixed_ips'][0]['ip_address']
            self._create_ndp_proxy(self.router1_id, port2['port']['id'],
                                   ipv6_address)
            list_res = self._list_ndp_proxy()
            self.assertEqual(len(list_res['ndp_proxies']), 2)
            self._delete_ndp_proxy(ndp_proxy_id)
            list_res = self._list_ndp_proxy()
            self.assertEqual(len(list_res['ndp_proxies']), 1)

    def test_enable_ndp_proxy_without_external_gateway(self):
        with self.router() as router:
            router_id = router['router']['id']
            err_msg = ("Can not enable ndp proxy on router %s, The router has "
                       "no external gateway or the external gateway port has "
                       "no IPv6 address or IPv6 address scope.") % router_id
            self._update_router(router_id, {'enable_ndp_proxy': True},
                expected_code=exc.HTTPConflict.code,
                expected_message=err_msg)

    def test_enable_ndp_proxy_without_address_scope(self):
        with self.network() as ext_net, \
            self.subnet(
                cidr='2001::12:0/112',
                ip_version=constants.IP_VERSION_6,
                ipv6_ra_mode=constants.DHCPV6_STATEFUL,
                ipv6_address_mode=constants.DHCPV6_STATEFUL):
            self._set_net_external(ext_net['network']['id'])
            res = self._make_router(
                self.fmt, self.tenant_id,
                external_gateway_info={'network_id': ext_net['network']['id']},
                **{'enable_ndp_proxy': True})
            expected_msg = (
                "The external network %s don't support IPv6 ndp proxy, the "
                "network has no IPv6 subnets or has no IPv6 address "
                "scope.") % ext_net['network']['id']
            self.assertTrue(expected_msg in res['NeutronError']['message'])
            router = self._make_router(
                self.fmt, self.tenant_id,
                external_gateway_info={'network_id': ext_net['network']['id']})
            expected_msg = (
                "Can not enable ndp proxy on router %s, The router has no "
                "external gateway or the external gateway port has no IPv6 "
                "address or IPv6 address scope.") % router['router']['id']
            self._update_router(
                router['router']['id'], {'enable_ndp_proxy': True},
                expected_code=exc.HTTPConflict.code,
                expected_message=expected_msg)

    def test_delete_router_gateway_with_enable_ndp_proxy(self):
        with self.router() as router:
            router_id = router['router']['id']
            self._update_router(
                router_id,
                {'external_gateway_info': {'network_id': self.ext_net_id}})
            err_msg = ("Can not enable ndp proxy on router %s, The router's "
                       "external gateway will be unset.") % router_id
            self._update_router(
                router_id,
                {'external_gateway_info': {}, 'enable_ndp_proxy': True},
                expected_code=exc.HTTPConflict.code,
                expected_message=err_msg)

    def test_unset_router_gateway_with_ndp_proxy(self):
        with self.port(self.private_subnet) as port1:
            self._create_ndp_proxy(self.router1_id, port1['port']['id'])
            err_msg = ("Unable to unset external gateway of router %s, "
                       "There are one or more ndp proxies still in use "
                       "on the router.") % self.router1_id
            self._update_router(
                self.router1_id, {'external_gateway_info': {}},
                expected_code=exc.HTTPConflict.code,
                expected_message=err_msg)

    def test_create_ndp_proxy_with_invalid_port(self):
        with self.subnet(
            subnetpool_id=self.subnetpool_id,
            cidr='2001::8:0/112',
            ip_version=constants.IP_VERSION_6,
            ipv6_ra_mode=constants.DHCPV6_STATEFUL,
            ipv6_address_mode=constants.DHCPV6_STATEFUL) as sub1, \
                self.subnet(
                    self.private_net,
                    ip_version=constants.IP_VERSION_6,
                    ipv6_ra_mode=constants.DHCPV6_STATEFUL,
                    ipv6_address_mode=constants.DHCPV6_STATEFUL,
                    subnetpool_id=self.subnetpool_id,
                    cidr='2001::9:0/112') as sub2, \
                self.subnet(self.private_net) as sub3, \
                self.port(sub1) as port1, \
                self.port(
                    sub3,
                    **{'fixed_ips': [
                       {'subnet_id': sub3['subnet']['id']}]}) as port2, \
                self.port(
                    sub2,
                    **{'fixed_ips': [
                       {'subnet_id': sub2['subnet']['id'],
                        'ip_address': '2001::9:12'},
                       {'subnet_id': self.private_subnet['subnet']['id'],
                        'ip_address': '2001::2:12'},
                       {'subnet_id': sub3['subnet']['id']}]}) as port3:
            err_msg = ("The port %s cannot reach the router %s by IPv6 "
                       "subnet.") % (port1['port']['id'], self.router1_id)
            # Subnet not add to the router
            self._create_ndp_proxy(
                self.router1_id, port1['port']['id'],
                expected_code=exc.HTTPConflict.code,
                expected_message=err_msg)
            self._router_interface_action(
                'add', self.router1_id,
                sub1['subnet']['id'], None)
            # Invalid address: the adress not belong to the port
            err_msg = ("The address 2001::10:22 is invalid, reason: "
                       "This address not belong to the "
                       "port %s.") % port1['port']['id']
            self._create_ndp_proxy(
                self.router1_id, port1['port']['id'],
                ip_address="2001::10:22",
                expected_code=exc.HTTPBadRequest.code,
                expected_message=err_msg)
            # The subnet of specified address don't connect to router
            err_msg = ("The address 2001::9:12 is invalid, reason: "
                       "This address cannot reach the "
                       "router %s.") % self.router1_id
            self._create_ndp_proxy(
                self.router1_id, port3['port']['id'],
                ip_address='2001::9:12',
                expected_code=exc.HTTPBadRequest.code,
                expected_message=err_msg)
            # Port only has IPv4 address
            err_msg = ("Bad ndp_proxy request: Requested port %s must "
                       "allocate one IPv6 address at "
                       "least.") % port2['port']['id']
            self._create_ndp_proxy(
                self.router1_id, port2['port']['id'],
                expected_code=exc.HTTPBadRequest.code,
                expected_message=err_msg)
            # Auto select valid address
            ndp_proxy = self._create_ndp_proxy(
                self.router1_id, port3['port']['id'])
            self.assertEqual('2001::2:12',
                             ndp_proxy['ndp_proxy']['ip_address'])

    def test_create_ndp_proxy_with_invalid_router(self):
        with self.subnet(
            subnetpool_id=self.subnetpool_id,
            cidr='2001::8:0/112',
            ipv6_ra_mode=constants.DHCPV6_STATEFUL,
            ipv6_address_mode=constants.DHCPV6_STATEFUL,
            ip_version=constants.IP_VERSION_6) as subnet, \
                self.router() as router, \
                self.port(subnet) as port:
            router_id = router['router']['id']
            subnet_id = subnet['subnet']['id']
            port_id = port['port']['id']
            err_msg = ("The port %s cannot reach the router %s by "
                       "IPv6 subnet.") % (port_id, router_id)
            self._create_ndp_proxy(
                router_id, port_id,
                expected_code=exc.HTTPConflict.code,
                expected_message=err_msg)
            self._router_interface_action(
                'add', router_id, subnet_id, None)
            err_msg = ("The enable_ndp_proxy parameter of router %s must be "
                       "set as True while create ndp proxy entry on "
                       "it.") % router_id
            self._create_ndp_proxy(
                router_id, port_id,
                expected_code=exc.HTTPConflict.code,
                expected_message=err_msg)

    def test_update_gateway_without_ipv6_fixed_ip(self):
        with self.router() as router:
            router_id = router['router']['id']
            self._update_router(
                router_id,
                {'external_gateway_info': {
                    'network_id': self.ext_net_id},
                    'enable_ndp_proxy': True})
            err_msg = ("Can't remove the IPv6 subnet from external gateway of "
                       "router %s, the IPv6 subnet in use by the router's "
                       "ndp proxy.") % router_id
            ext_gw_data = {
                'external_gateway_info': {
                    'network_id': self.ext_net_id,
                    'external_fixed_ips': [
                        {'subnet_id': self._ext_subnet_v4_id}]}}
            self._update_router(
                router_id, ext_gw_data,
                expected_code=exc.HTTPConflict.code,
                expected_message=err_msg)
            ext_gw_data = {
                'external_gateway_info': {
                    'network_id': self.ext_net_id,
                    'external_fixed_ips': [
                        {'subnet_id': self._ext_subnet_v6_id}]}}
            self._update_router(router_id, ext_gw_data)

    def test_remove_subnet(self):
        with self.subnet(ip_version=constants.IP_VERSION_6,
                    ipv6_ra_mode=constants.DHCPV6_STATEFUL,
                    ipv6_address_mode=constants.DHCPV6_STATEFUL,
                    subnetpool_id=self.subnetpool_id,
                    cidr='2001::50:0/112') as subnet, \
                self.port(subnet) as port:
            subnet_id = subnet['subnet']['id']
            port_id = port['port']['id']
            self._router_interface_action(
                'add', self.router1_id, subnet_id, None)
            self._create_ndp_proxy(
                self.router1_id, port_id)
            err_msg = ("Unable to remove subnet %s from router %s, There "
                       "are one or more ndp proxies still in use on the "
                       "subnet.") % (subnet_id, self.router1_id)
            expected_body = {
                "NeutronError": {
                    "type": "RouterInterfaceInUseByNDPProxy",
                    "message": err_msg, "detail": ""}}
            self._router_interface_action(
                'remove', self.router1_id, subnet_id, None,
                expected_code=exc.HTTPConflict.code,
                expected_body=expected_body)

    def test_create_ndp_proxy_with_different_address_scope(self):
        with self.address_scope(
            ip_version=constants.IP_VERSION_6,
            tenant_id=self.tenant_id) as addr_scope, \
                self.subnetpool(['2001::100:0:0/100'],
                **{'address_scope_id': addr_scope['address_scope']['id'],
                   'default_prefixlen': 112, 'name': 'test1',
                   'tenant_id': self.tenant_id}) as subnetpool, \
                self.subnet(
                    cidr='2001::100:1:0/112',
                    ip_version=constants.IP_VERSION_6,
                    ipv6_ra_mode=constants.DHCPV6_STATEFUL,
                    ipv6_address_mode=constants.DHCPV6_STATEFUL,
                    subnetpool_id=subnetpool['subnetpool']['id'],
                    tenant_id=self.tenant_id) as subnet, \
                self.port(subnet) as port:
            subnet_id = subnet['subnet']['id']
            port_id = port['port']['id']
            self._router_interface_action(
                'add', self.router1_id, subnet_id, None)
            err_msg = ("The IPv6 address scope %s of external network "
                       "conflict with internal network's IPv6 address "
                       "scope %s.") % (self.address_scope_id,
                                       addr_scope['address_scope']['id'])
            self._create_ndp_proxy(
                self.router1_id, port_id,
                expected_code=exc.HTTPConflict.code,
                expected_message=err_msg)

    def test_create_router_with_external_gateway(self):
        def _create_router(self, data, expected_code=exc.HTTPCreated.code,
                          expected_message=None):
            router_req = self.new_create_request(
                'routers', data, self.fmt)
            router_req.environ['neutron.context'] = context.Context(
                '', self.tenant_id, is_admin=True)
            res = router_req.get_response(self.ext_api)
            self.assertEqual(expected_code, res.status_int)
            if expected_message:
                self.assertIn(expected_message,
                              res.json_body['NeutronError']['message'])
            return self.deserialize(self.fmt, res)

        # Create router with enable_ndp_proxy is True but not external gateway
        err_msg = ("The request body not contain external gateway "
                   "information.")
        data = {'router': {'external_gateway_info': {},
                           'enable_ndp_proxy': True}}
        _create_router(self, data, expected_code=exc.HTTPConflict.code,
                       expected_message=err_msg)

        data = {'router': {
            'external_gateway_info': {'network_id': self.ext_net_id}}}
        res = _create_router(self, data)
        self.assertFalse(res['router']['enable_ndp_proxy'])

        data = {'router': {
            'external_gateway_info': {'network_id': self.ext_net_id},
            'enable_ndp_proxy': True}}
        res = _create_router(self, data)
        self.assertTrue(res['router']['enable_ndp_proxy'])

        # Set default enable_ndp_proxy as True
        cfg.CONF.set_override("enable_ndp_proxy_by_default", True)
        data = {'router': {
            'external_gateway_info': {'network_id': self.ext_net_id}}}
        res = _create_router(self, data)
        self.assertTrue(res['router']['enable_ndp_proxy'])

    def test_enable_ndp_proxy_by_default_conf_option(self):
        cfg.CONF.set_override("enable_ndp_proxy_by_default", True)
        with self.subnet(
            subnetpool_id=self.subnetpool_id,
            cidr='2001::8:0/112',
            ipv6_ra_mode=constants.DHCPV6_STATEFUL,
            ipv6_address_mode=constants.DHCPV6_STATEFUL,
            ip_version=constants.IP_VERSION_6) as subnet, \
                self.port(subnet) as port, \
                self.router() as router:
            router_id = router['router']['id']
            subnet_id = subnet['subnet']['id']
            port_id = port['port']['id']
            self._router_interface_action(
                'add', router_id, subnet_id, None)
            router_dict = self._get_router(router_id)
            self.assertFalse(router_dict['router']['enable_ndp_proxy'])
            self._update_router(
                router_id,
                {'external_gateway_info': {'network_id': self.ext_net_id}})
            router_dict = self._get_router(router_id)
            self.assertTrue(router_dict['router']['enable_ndp_proxy'])
            self._create_ndp_proxy(
                router_id, port_id)

    def test_create_ndp_proxy_with_duplicated(self):
        with self.port(self.private_subnet) as port1:
            self._create_ndp_proxy(self.router1_id, port1['port']['id'])
            retry_fixture = fixture.DBRetryErrorsFixture(max_retries=1)
            retry_fixture.setUp()
            self._create_ndp_proxy(
                self.router1_id, port1['port']['id'],
                expected_code=exc.HTTPConflict.code)
            retry_fixture.cleanUp()
