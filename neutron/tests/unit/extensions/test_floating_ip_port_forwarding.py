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

from unittest import mock

from oslo_utils import uuidutils
from webob import exc

from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import \
    test_expose_port_forwarding_in_fip as test_fip_pf
from neutron.tests.unit.extensions import test_l3

_uuid = uuidutils.generate_uuid


class FloatingIPPorForwardingTestCase(test_l3.L3BaseForIntTests,
                                      test_l3.L3NatTestCaseMixin):
    fmt = 'json'

    def setUp(self):
        mock.patch('neutron.api.rpc.handlers.resources_rpc.'
                   'ResourcesPushRpcApi').start()
        svc_plugins = (test_fip_pf.PF_PLUGIN_NAME, test_fip_pf.L3_PLUGIN,
                       'neutron.services.qos.qos_plugin.QoSPlugin')
        ext_mgr = test_fip_pf.ExtendFipPortForwardingExtensionManager()
        super(FloatingIPPorForwardingTestCase, self).setUp(
            ext_mgr=ext_mgr, service_plugins=svc_plugins)
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def _create_fip_port_forwarding(self, fmt,
                                    floating_ip_id,
                                    external_port,
                                    internal_port,
                                    protocol,
                                    internal_ip_address,
                                    internal_port_id,
                                    tenant_id=None,
                                    description=None,
                                    external_port_range=None,
                                    internal_port_range=None,
                                    as_admin=False):
        tenant_id = tenant_id or self._tenant_id
        data = {'port_forwarding': {
            "protocol": protocol,
            "internal_ip_address": internal_ip_address,
            "internal_port_id": internal_port_id}
        }
        if external_port_range and internal_port_range:
            data['port_forwarding'][
                'internal_port_range'] = internal_port_range
            data['port_forwarding'][
                'external_port_range'] = external_port_range
        else:
            data['port_forwarding']['internal_port'] = internal_port
            data['port_forwarding']['external_port'] = external_port

        if description:
            data['port_forwarding']['description'] = description

        fip_pf_req = self.new_create_request(
            'floatingips', data, fmt or self.fmt, floating_ip_id,
            subresource='port_forwardings',
            tenant_id=tenant_id, as_admin=as_admin)

        return fip_pf_req.get_response(self.ext_api)

    def _update_fip_port_forwarding(self, fmt, floating_ip_id,
                                    port_forwarding_id,
                                    req_tenant_id=None, as_admin=False,
                                    **kwargs):
        req_tenant_id = req_tenant_id or self._tenant_id
        port_forwarding = {}
        for k, v in kwargs.items():
            port_forwarding[k] = v
        data = {'port_forwarding': port_forwarding}

        fip_pf_req = self.new_update_request(
            'floatingips', data, floating_ip_id, fmt or self.fmt,
            sub_id=port_forwarding_id,
            subresource='port_forwardings',
            tenant_id=req_tenant_id,
            as_admin=as_admin)

        return fip_pf_req.get_response(self.ext_api)

    def test_create_floatingip_port_forwarding_with_port_number_0(self):
        with self.network() as ext_net:
            network_id = ext_net['network']['id']
            self._set_net_external(network_id)
            with self.subnet(ext_net, cidr='10.10.10.0/24'), \
                    self.router() as router, \
                    self.subnet(cidr='11.0.0.0/24') as private_subnet, \
                    self.port(private_subnet) as port:
                self._add_external_gateway_to_router(
                    router['router']['id'],
                    network_id)
                self._router_interface_action(
                    'add', router['router']['id'],
                    private_subnet['subnet']['id'],
                    None)
                fip = self._make_floatingip(
                    self.fmt,
                    network_id)
                self.assertIsNone(fip['floatingip'].get('port_id'))
                res = self._create_fip_port_forwarding(
                    self.fmt, fip['floatingip']['id'],
                    2222, 0,
                    'tcp',
                    port['port']['fixed_ips'][0]['ip_address'],
                    port['port']['id'])
                self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

                res = self._create_fip_port_forwarding(
                    self.fmt, fip['floatingip']['id'],
                    0, 22,
                    'tcp',
                    port['port']['fixed_ips'][0]['ip_address'],
                    port['port']['id'])
                self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_create_floatingip_port_forwarding_with_description(self):
        with self.network() as ext_net:
            network_id = ext_net['network']['id']
            self._set_net_external(network_id)
            with self.subnet(ext_net, cidr='10.10.10.0/24'), \
                    self.router() as router, \
                    self.subnet(cidr='11.0.0.0/24') as private_subnet, \
                    self.port(private_subnet) as port:
                self._add_external_gateway_to_router(
                    router['router']['id'],
                    network_id)
                self._router_interface_action(
                    'add', router['router']['id'],
                    private_subnet['subnet']['id'],
                    None)
                fip = self._make_floatingip(
                    self.fmt,
                    network_id)
                self.assertIsNone(fip['floatingip'].get('port_id'))
                res = self._create_fip_port_forwarding(
                    self.fmt, fip['floatingip']['id'],
                    2222, 22,
                    'tcp',
                    port['port']['fixed_ips'][0]['ip_address'],
                    port['port']['id'],
                    description="blablablabla")
                self.assertEqual(exc.HTTPCreated.code, res.status_int)
                pf_body = self.deserialize(self.fmt, res)
                self.assertEqual(
                    "blablablabla", pf_body['port_forwarding']['description'])

    def test_create_floatingip_port_forwarding_with_ranges(self):
        internal_port_range = '22:24'
        external_port_range = '2222:2224'
        with self.network() as ext_net:
            network_id = ext_net['network']['id']
            self._set_net_external(network_id)
            with self.subnet(ext_net, cidr='10.10.10.0/24'), \
                    self.router() as router, \
                    self.subnet(cidr='11.0.0.0/24') as private_subnet, \
                    self.port(private_subnet) as port:
                self._add_external_gateway_to_router(
                    router['router']['id'],
                    network_id)
                self._router_interface_action(
                    'add', router['router']['id'],
                    private_subnet['subnet']['id'],
                    None)
                fip = self._make_floatingip(
                    self.fmt,
                    network_id)
                self.assertIsNone(fip['floatingip'].get('port_id'))
                res = self._create_fip_port_forwarding(
                    self.fmt, fip['floatingip']['id'],
                    None, None,
                    'tcp',
                    port['port']['fixed_ips'][0]['ip_address'],
                    port['port']['id'],
                    internal_port_range=internal_port_range,
                    external_port_range=external_port_range)
                self.assertEqual(exc.HTTPCreated.code, res.status_int)
                pf_body = self.deserialize(self.fmt, res)
                self.assertEqual(
                    internal_port_range,
                    pf_body['port_forwarding']['internal_port_range'])
                self.assertEqual(
                    external_port_range,
                    pf_body['port_forwarding']['external_port_range'])

    def test_create_floatingip_port_forwarding_with_ranges_port_collisions(
            self):
        internal_port_range1 = '22:24'
        internal_port_range2 = '23:25'
        external_port_range1 = '2222:2224'
        external_port_range2 = '2223:2225'
        with self.network() as ext_net:
            network_id = ext_net['network']['id']
            self._set_net_external(network_id)
            with self.subnet(ext_net, cidr='10.10.10.0/24'), \
                    self.router() as router, \
                    self.subnet(cidr='11.0.0.0/24') as private_subnet, \
                    self.port(private_subnet) as port:
                self._add_external_gateway_to_router(
                    router['router']['id'],
                    network_id)
                self._router_interface_action(
                    'add', router['router']['id'],
                    private_subnet['subnet']['id'],
                    None)
                fip = self._make_floatingip(
                    self.fmt,
                    network_id)
                self.assertIsNone(fip['floatingip'].get('port_id'))
                self._create_fip_port_forwarding(
                    self.fmt, fip['floatingip']['id'],
                    None, None,
                    'tcp',
                    port['port']['fixed_ips'][0]['ip_address'],
                    port['port']['id'],
                    internal_port_range=internal_port_range1,
                    external_port_range=external_port_range1)
                response = self._create_fip_port_forwarding(
                    self.fmt, fip['floatingip']['id'],
                    None, None,
                    'tcp',
                    port['port']['fixed_ips'][0]['ip_address'],
                    port['port']['id'],
                    internal_port_range=internal_port_range2,
                    external_port_range=external_port_range2)
                self.assertEqual(exc.HTTPBadRequest.code,
                                 response.status_int)

    def test_update_floatingip_port_forwarding_with_dup_internal_port(self):
        with self.network() as ext_net:
            network_id = ext_net['network']['id']
            self._set_net_external(network_id)
            with self.subnet(ext_net, cidr='10.10.10.0/24'), \
                    self.router() as router, \
                    self.subnet(cidr='11.0.0.0/24') as private_subnet, \
                    self.port(private_subnet) as port:
                self._add_external_gateway_to_router(
                    router['router']['id'],
                    network_id)
                self._router_interface_action(
                    'add', router['router']['id'],
                    private_subnet['subnet']['id'],
                    None)
                fip1 = self._make_floatingip(
                    self.fmt,
                    network_id)
                self.assertIsNone(fip1['floatingip'].get('port_id'))
                self._create_fip_port_forwarding(
                    self.fmt, fip1['floatingip']['id'],
                    2222, 22,
                    'tcp',
                    port['port']['fixed_ips'][0]['ip_address'],
                    port['port']['id'],
                    description="blablablabla")
                fip2 = self._make_floatingip(
                    self.fmt,
                    network_id)
                fip_pf_response = self._create_fip_port_forwarding(
                    self.fmt, fip2['floatingip']['id'],
                    2222, 23,
                    'tcp',
                    port['port']['fixed_ips'][0]['ip_address'],
                    port['port']['id'],
                    description="blablablabla")
                update_res = self._update_fip_port_forwarding(
                    self.fmt, fip2['floatingip']['id'],
                    fip_pf_response.json['port_forwarding']['id'],
                    **{'internal_port': 22})
                self.assertEqual(exc.HTTPBadRequest.code,
                                 update_res.status_int)
