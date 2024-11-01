# Copyright (c) 2021 China Unicom Cloud Data Co.,Ltd.
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

from neutron_lib import context
from oslo_config import cfg

from neutron.agent.common import ovs_lib
from neutron.agent.l2.extensions.dhcp import extension as ovs_dhcp
from neutron.plugins.ml2.drivers.openvswitch.agent \
    import ovs_agent_extension_api as ovs_ext_api
from neutron.tests import base


class DHCPAgentExtensionTestCase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        cfg.CONF.set_override('enable_ipv6', True, group='DHCP')
        self.context = context.get_admin_context()
        self.int_br = mock.Mock()
        self.tun_br = mock.Mock()
        self.plugin_rpc = mock.Mock()
        self.remote_resource_cache = mock.Mock()
        self.plugin_rpc.remote_resource_cache = self.remote_resource_cache
        self.ovs_dhcp = ovs_dhcp.DHCPAgentExtension()
        self.agent_api = ovs_ext_api.OVSAgentExtensionAPI(
            self.int_br,
            self.tun_br,
            phys_brs=None,
            plugin_rpc=self.plugin_rpc)
        self.ovs_dhcp.consume_api(self.agent_api)
        self.ovs_dhcp.initialize(None, None)

    def tearDown(self):
        self.ovs_dhcp.app_mgr.uninstantiate(self.ovs_dhcp.dhcp4_app.name)
        self.ovs_dhcp.app_mgr.uninstantiate(self.ovs_dhcp.dhcp6_app.name)
        super().tearDown()

    def test_handle_port(self):
        port = {"port_id": "p1",
                "fixed_ips": [{"ip_address": "1.1.1.1"}],
                "vif_port": ovs_lib.VifPort("tap-p1", "1", "p1",
                                            "aa:aa:aa:aa:aa:aa", "br-int"),
                "device_owner": "compute:test"}
        self.ovs_dhcp.handle_port(self.context, port)
        self.ovs_dhcp.int_br.add_dhcp_ipv4_flow.assert_called_once_with(
            port['port_id'],
            port["vif_port"].ofport,
            port["vif_port"].vif_mac)
        self.ovs_dhcp.int_br.add_dhcp_ipv6_flow.assert_called_once_with(
            port['port_id'],
            port["vif_port"].ofport,
            port["vif_port"].vif_mac)
        self.assertIsNotNone(self.ovs_dhcp.VIF_PORT_CACHE.get(port['port_id']))

    def _test_delete_port(self, with_vif_port=False):
        vif_port = ovs_lib.VifPort("tap-p1", 1, "p1",
                                   "aa:aa:aa:aa:aa:aa", "br-int")
        port1 = {"port_id": "p1",
                 "fixed_ips": [{"ip_address": "1.1.1.1"}],
                 "vif_port": vif_port,
                 "device_owner": "compute:test"}
        self.ovs_dhcp.handle_port(self.context, port1)
        with mock.patch.object(self.ovs_dhcp.int_br, "get_vif_ports",
                               return_value=[]):
            if with_vif_port:
                port2 = {"port_id": "p1",
                         "vif_port": vif_port}
            else:
                port2 = {"port_id": "p1"}
            self.ovs_dhcp.delete_port(self.context, port2)
            self.ovs_dhcp.int_br.del_dhcp_flow.assert_called_once_with(
                port1["vif_port"].ofport,
                port1["vif_port"].vif_mac)
            # verify the cache
            self.assertNotIn("p1", self.ovs_dhcp.VIF_PORT_CACHE.keys())

    def test_delete_port_without_vif_port(self):
        self._test_delete_port()

    def test_delete_port_with_vif_port(self):
        self._test_delete_port(with_vif_port=True)
