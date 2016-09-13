# Copyright (c) 2015 Thales Services SAS
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

from oslo_utils import uuidutils

from neutron.agent.linux import bridge_lib
from neutron.tests.common import net_helpers
from neutron.tests.functional import base


class BridgeLibTestCase(base.BaseSudoTestCase):

    def setUp(self):
        super(BridgeLibTestCase, self).setUp()
        self.bridge, self.port_fixture = self.create_bridge_port_fixture()

    def create_bridge_port_fixture(self):
        bridge = self.useFixture(
            net_helpers.LinuxBridgeFixture(namespace=None)).bridge
        port_fixture = self.useFixture(
            net_helpers.LinuxBridgePortFixture(
                bridge, port_id=uuidutils.generate_uuid()))
        return bridge, port_fixture

    def test_is_bridged_interface(self):
        self.assertTrue(
            bridge_lib.is_bridged_interface(self.port_fixture.br_port.name))

    def test_is_not_bridged_interface(self):
        self.assertFalse(
            bridge_lib.is_bridged_interface(self.port_fixture.port.name))

    def test_get_bridge_names(self):
        self.assertIn(self.bridge.name, bridge_lib.get_bridge_names())

    def test_get_interface_ifindex(self):
        port = self.port_fixture.br_port
        t1 = bridge_lib.get_interface_ifindex(str(port))
        self.port_fixture.veth_fixture.destroy()
        self.port_fixture.veth_fixture._setUp()
        t2 = bridge_lib.get_interface_ifindex(str(port))
        self.assertIsNotNone(t1)
        self.assertIsNotNone(t2)
        self.assertGreaterEqual(t2, t1)

    def test_get_interface_bridge(self):
        bridge = bridge_lib.BridgeDevice.get_interface_bridge(
            self.port_fixture.br_port.name)
        self.assertEqual(self.bridge.name, bridge.name)

    def test_get_interface_no_bridge(self):
        bridge = bridge_lib.BridgeDevice.get_interface_bridge(
            self.port_fixture.port.name)
        self.assertIsNone(bridge)

    def test_get_interfaces(self):
        self.assertEqual(
            [self.port_fixture.br_port.name], self.bridge.get_interfaces())

    def test_get_interfaces_no_bridge(self):
        bridge = bridge_lib.BridgeDevice('--fake--')
        self.assertEqual([], bridge.get_interfaces())

    def test_disable_ipv6(self):
        sysfs_path = ("/proc/sys/net/ipv6/conf/%s/disable_ipv6" %
                      self.bridge.name)

        # first, make sure it's enabled
        with open(sysfs_path, 'r') as sysfs_disable_ipv6_file:
            sysfs_disable_ipv6 = sysfs_disable_ipv6_file.read()
            self.assertEqual("0\n", sysfs_disable_ipv6)

        self.assertEqual(0, self.bridge.disable_ipv6())
        with open(sysfs_path, 'r') as sysfs_disable_ipv6_file:
            sysfs_disable_ipv6 = sysfs_disable_ipv6_file.read()
            self.assertEqual("1\n", sysfs_disable_ipv6)
