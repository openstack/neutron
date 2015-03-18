# Copyright 2015 Intel Corporation.
# Copyright 2015 Isaku Yamahata <isaku.yamahata at intel com>
#                               <isaku.yamahata at gmail com>
# All Rights Reserved.
#
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

from neutron.agent.linux import iptables_firewall
from neutron.tests.functional.agent.linux import base


class IptablesFirewallTestCase(base.BaseBridgeTestCase):
    def setUp(self):
        super(IptablesFirewallTestCase, self).setUp()
        self.bridge = self.create_bridge()

        self.src_veth, self.src_br_veth = self.create_veth_pairs(
            self.bridge.namespace)
        self.bridge.addif(self.src_br_veth.name)
        self._set_ip_up(self.src_veth, '%s/24' % self.SRC_ADDRESS)
        self.src_br_veth.link.set_up()

        self.dst_veth, self.dst_br_veth = self.create_veth_pairs(
            self.bridge.namespace)
        self.bridge.addif(self.dst_br_veth.name)
        self._set_ip_up(self.dst_veth, '%s/24' % self.DST_ADDRESS)
        self.dst_br_veth.link.set_up()

        self.firewall = iptables_firewall.IptablesFirewallDriver(
            namespace=self.bridge.namespace)

    # TODO(yamahata): add tests...
    # setup firewall on bridge and send packet from src_veth and observe
    # if sent packet can be observed on dst_veth
    def test_firewall(self):
        pass
