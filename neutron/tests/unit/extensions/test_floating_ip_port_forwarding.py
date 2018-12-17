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

import mock
from neutron_lib import context
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
                                    tenant_id=None):
        tenant_id = tenant_id or _uuid()
        data = {'port_forwarding': {
            "external_port": external_port,
            "internal_port": internal_port,
            "protocol": protocol,
            "internal_ip_address": internal_ip_address,
            "internal_port_id": internal_port_id}
        }

        fip_pf_req = self._req(
            'POST', 'floatingips', data,
            fmt or self.fmt, id=floating_ip_id,
            subresource='port_forwardings')

        fip_pf_req.environ['neutron.context'] = context.Context(
            '', tenant_id, is_admin=True)

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
