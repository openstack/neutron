#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import mock
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import floating_ip_port_forwarding as apidef
from neutron_lib import context

from neutron.extensions import floating_ip_port_forwarding as pf_ext
from neutron.extensions import l3
from neutron.services.portforwarding import pf_plugin
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_l3


PLUGIN_NAME = 'port_forwarding'
L3_PLUGIN = 'neutron.tests.unit.extensions.test_l3.TestL3NatServicePlugin'
CORE_PLUGIN = 'neutron.tests.unit.extensions.test_l3.TestNoL3NatPlugin'


class ExtendFipPortForwardingExtensionManager(object):

    def get_resources(self):
        return (l3.L3.get_resources() +
                pf_ext.Floating_ip_port_forwarding.get_resources())

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestExtendFipPortForwardingExtension(
        test_db_base_plugin_v2.NeutronDbPluginV2TestCase,
        test_l3.L3NatTestCaseMixin):

    def setUp(self):
        mock.patch('neutron.api.rpc.handlers.resources_rpc.'
                   'ResourcesPushRpcApi').start()
        svc_plugins = {'l3_plugin_name': L3_PLUGIN,
                       'port_forwarding_plugin_name': PLUGIN_NAME}
        ext_mgr = ExtendFipPortForwardingExtensionManager()
        super(TestExtendFipPortForwardingExtension, self).setUp(
            plugin=CORE_PLUGIN, ext_mgr=ext_mgr, service_plugins=svc_plugins)
        self.pf_plugin = pf_plugin.PortForwardingPlugin()

    def test_get_fip_after_port_forwarding_create(self):
        port_forwarding = {
            apidef.RESOURCE_NAME:
                {apidef.EXTERNAL_PORT: 2225,
                 apidef.INTERNAL_PORT: 25,
                 apidef.INTERNAL_PORT_ID: None,
                 apidef.PROTOCOL: "tcp",
                 apidef.INTERNAL_IP_ADDRESS: None}}
        ctx = context.get_admin_context()
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        with self.network(**kwargs) as extnet, self.network() as innet:
            with self.subnet(network=extnet, cidr='200.0.0.0/22'),\
                    self.subnet(network=innet, cidr='10.0.0.0/24') as insub,\
                    self.router() as router:
                fip = self._make_floatingip(self.fmt, extnet['network']['id'])
                # check the floatingip response contains port_forwarding field
                self.assertIn(apidef.COLLECTION_NAME, fip['floatingip'])
                self._add_external_gateway_to_router(router['router']['id'],
                                                     extnet['network']['id'])
                self._router_interface_action('add', router['router']['id'],
                                              insub['subnet']['id'], None)

                def _get_expected(ref):
                    want_fields = [apidef.INTERNAL_IP_ADDRESS, apidef.PROTOCOL,
                                   apidef.INTERNAL_PORT, apidef.EXTERNAL_PORT]
                    expect = {
                        key: value
                        for key, value in ref[apidef.RESOURCE_NAME].items()
                        if key in want_fields}
                    return expect

                with self.port(subnet=insub) as port1,\
                        self.port(subnet=insub) as port2:
                    update_dict1 = {
                        apidef.INTERNAL_PORT_ID: port1['port']['id'],
                        apidef.INTERNAL_IP_ADDRESS:
                            port1['port']['fixed_ips'][0]['ip_address']}
                    port_forwarding[apidef.RESOURCE_NAME].update(update_dict1)
                    self.pf_plugin.create_floatingip_port_forwarding(
                        ctx, fip['floatingip']['id'], port_forwarding)

                    body = self._show('floatingips', fip['floatingip']['id'])
                    self.assertEqual(
                        1, len(body['floatingip'][apidef.COLLECTION_NAME]))

                    expect_result1 = _get_expected(port_forwarding)
                    self.assertEqual(
                        expect_result1,
                        body['floatingip'][apidef.COLLECTION_NAME][0])

                    update_dict2 = {
                        apidef.EXTERNAL_PORT: 2226,
                        apidef.INTERNAL_PORT_ID: port2['port']['id'],
                        apidef.INTERNAL_IP_ADDRESS:
                            port2['port']['fixed_ips'][0]['ip_address']}
                    port_forwarding[apidef.RESOURCE_NAME].update(update_dict2)
                    self.pf_plugin.create_floatingip_port_forwarding(
                        ctx, fip['floatingip']['id'], port_forwarding)

                    body = self._show('floatingips', fip['floatingip']['id'])
                    self.assertEqual(
                        2, len(body['floatingip'][apidef.COLLECTION_NAME]))
                    expect_result2 = _get_expected(port_forwarding)
                    expect = [expect_result1, expect_result2]
                    self.assertEqual(
                        expect, body['floatingip'][apidef.COLLECTION_NAME])
