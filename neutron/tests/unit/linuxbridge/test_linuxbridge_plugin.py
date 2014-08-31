# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
from oslo.config import cfg

from neutron.common import constants as q_const
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.linuxbridge import lb_neutron_plugin
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import test_security_groups_rpc as test_sg_rpc

PLUGIN_NAME = ('neutron.plugins.linuxbridge.'
               'lb_neutron_plugin.LinuxBridgePluginV2')


class LinuxBridgePluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):
    _plugin_name = PLUGIN_NAME

    def setUp(self):
        super(LinuxBridgePluginV2TestCase, self).setUp(PLUGIN_NAME)
        self.port_create_status = 'DOWN'


class TestLinuxBridgeBasicGet(test_plugin.TestBasicGet,
                              LinuxBridgePluginV2TestCase):
    pass


class TestLinuxBridgeV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                                    LinuxBridgePluginV2TestCase):
    pass


class TestLinuxBridgeNetworksV2(test_plugin.TestNetworksV2,
                                LinuxBridgePluginV2TestCase):
    pass


class TestLinuxBridgePortsV2(test_plugin.TestPortsV2,
                             LinuxBridgePluginV2TestCase):

    def test_update_port_status_build(self):
        with self.port() as port:
            self.assertEqual(port['port']['status'], 'DOWN')
            self.assertEqual(self.port_create_status, 'DOWN')


class TestLinuxBridgePortBinding(LinuxBridgePluginV2TestCase,
                                 test_bindings.PortBindingsTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_BRIDGE
    HAS_PORT_FILTER = True
    ENABLE_SG = True
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_IPTABLES_DRIVER

    def setUp(self):
        test_sg_rpc.set_firewall_driver(self.FIREWALL_DRIVER)
        cfg.CONF.set_override(
            'enable_security_group', self.ENABLE_SG,
            group='SECURITYGROUP')
        super(TestLinuxBridgePortBinding, self).setUp()


class TestLinuxBridgePortBindingNoSG(TestLinuxBridgePortBinding):
    HAS_PORT_FILTER = False
    ENABLE_SG = False
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_NOOP_DRIVER


class TestLinuxBridgePortBindingHost(
    LinuxBridgePluginV2TestCase,
    test_bindings.PortBindingsHostTestCaseMixin):
    pass


class TestLinuxBridgePluginRpcCallbacks(test_plugin.NeutronDbPluginV2TestCase):
    def setUp(self):
        super(TestLinuxBridgePluginRpcCallbacks, self).setUp(PLUGIN_NAME)
        self.callbacks = lb_neutron_plugin.LinuxBridgeRpcCallbacks()

    def test_update_device_down(self):
        with mock.patch.object(manager.NeutronManager, "get_plugin") as gp:
            plugin = gp.return_value
            plugin.get_port_from_device.return_value = None
            self.assertEqual(
                self.callbacks.update_device_down("fake_context",
                                                  agent_id="123",
                                                  device="device",
                                                  host="host"),
                {'device': 'device', 'exists': False}
            )
            plugin.get_port_from_device.return_value = {
                'id': 'fakeid',
                'status': q_const.PORT_STATUS_ACTIVE}
            self.assertEqual(
                self.callbacks.update_device_down("fake_context",
                                                  agent_id="123",
                                                  device="device",
                                                  host="host"),
                {'device': 'device', 'exists': True}
            )

    def test_update_device_up(self):
        with mock.patch.object(manager.NeutronManager, "get_plugin") as gp:
            plugin = gp.return_value
            plugin.get_port_from_device.return_value = {
                'id': 'fakeid',
                'status': q_const.PORT_STATUS_ACTIVE}
            self.callbacks.update_device_up("fake_context",
                                            agent_id="123",
                                            device="device",
                                            host="host")
            plugin.get_port_from_device.assert_called_once_with('device')
