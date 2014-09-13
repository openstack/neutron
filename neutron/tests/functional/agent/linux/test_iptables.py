# Copyright (c) 2014 Red Hat, Inc.
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

from neutron.agent.linux import iptables_manager
from neutron.tests.functional.agent.linux import base


class IptablesManagerTestCase(base.BaseIPVethTestCase):

    def setUp(self):
        super(IptablesManagerTestCase, self).setUp()
        self.src_ns, self.dst_ns = self.prepare_veth_pairs()
        self.iptables = iptables_manager.IptablesManager(
            root_helper=self.root_helper,
            namespace=self.dst_ns.namespace)

    def test_icmp(self):
        self.pinger.assert_ping_from_ns(self.src_ns, self.DST_ADDRESS)
        self.iptables.ipv4['filter'].add_rule('INPUT', base.ICMP_BLOCK_RULE)
        self.iptables.apply()
        self.pinger.assert_no_ping_from_ns(self.src_ns, self.DST_ADDRESS)
        self.iptables.ipv4['filter'].remove_rule('INPUT',
                                                 base.ICMP_BLOCK_RULE)
        self.iptables.apply()
        self.pinger.assert_ping_from_ns(self.src_ns, self.DST_ADDRESS)
