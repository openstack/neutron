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


from neutron.agent.linux import bridge_lib
from neutron.tests.common import net_helpers
from neutron.tests.functional import base


class BridgeLibTestCase(base.BaseSudoTestCase):

    def setUp(self):
        super(BridgeLibTestCase, self).setUp()
        self.bridge, self.port_fixture = self.create_bridge_port_fixture()

    def create_bridge_port_fixture(self):
        bridge = self.useFixture(
            net_helpers.LinuxBridgeFixture(use_namespace=False)).bridge
        port_fixture = self.useFixture(
            net_helpers.LinuxBridgePortFixture(bridge))
        return bridge, port_fixture

    def test_get_interface_bridged_time(self):
        port = self.port_fixture.br_port
        t1 = bridge_lib.get_interface_bridged_time(port)
        self.bridge.delif(port)
        self.bridge.addif(port)
        t2 = bridge_lib.get_interface_bridged_time(port)
        self.assertIsNotNone(t1)
        self.assertIsNotNone(t2)
        self.assertGreater(t2, t1)
