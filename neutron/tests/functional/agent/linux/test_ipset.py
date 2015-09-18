# Copyright (c) 2015 Red Hat, Inc.
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

from neutron.agent.linux import ipset_manager
from neutron.agent.linux import iptables_manager
from neutron.tests.functional.agent.linux import base
from neutron.tests.functional.agent.linux import helpers

MAX_IPSET_NAME_LENGTH = 28
IPSET_ETHERTYPE = 'IPv4'
UNRELATED_IP = '1.1.1.1'


class IpsetBase(base.BaseIPVethTestCase):

    def setUp(self):
        super(IpsetBase, self).setUp()

        self.src_ns, self.dst_ns = self.prepare_veth_pairs()
        self.ipset_name = base.get_rand_name(MAX_IPSET_NAME_LENGTH, 'set-')
        self.icmp_accept_rule = ('-p icmp -m set --match-set %s src -j ACCEPT'
                                 % self.ipset_name)
        self.ipset = self._create_ipset_manager_and_set(self.dst_ns,
                                                        self.ipset_name)
        self.addCleanup(self.ipset._destroy, self.ipset_name)
        self.dst_iptables = iptables_manager.IptablesManager(
            namespace=self.dst_ns.namespace)

        self._add_iptables_ipset_rules()
        self.addCleanup(self._remove_iptables_ipset_rules)
        self.pinger = helpers.Pinger(self.src_ns)

    def _create_ipset_manager_and_set(self, dst_ns, set_name):
        ipset = ipset_manager.IpsetManager(
            namespace=dst_ns.namespace)

        ipset._create_set(set_name, IPSET_ETHERTYPE)
        return ipset

    def _remove_iptables_ipset_rules(self):
        self.dst_iptables.ipv4['filter'].remove_rule(
            'INPUT', base.ICMP_BLOCK_RULE)
        self.dst_iptables.ipv4['filter'].remove_rule(
            'INPUT', self.icmp_accept_rule)
        self.dst_iptables.apply()

    def _add_iptables_ipset_rules(self):
        self.dst_iptables.ipv4['filter'].add_rule(
            'INPUT', self.icmp_accept_rule)
        self.dst_iptables.ipv4['filter'].add_rule(
            'INPUT', base.ICMP_BLOCK_RULE)
        self.dst_iptables.apply()


class IpsetManagerTestCase(IpsetBase):

    def test_add_member_allows_ping(self):
        self.pinger.assert_no_ping(self.DST_ADDRESS)
        self.ipset._add_member_to_set(self.ipset_name, self.SRC_ADDRESS)
        self.pinger.assert_ping(self.DST_ADDRESS)

    def test_del_member_denies_ping(self):
        self.ipset._add_member_to_set(self.ipset_name, self.SRC_ADDRESS)
        self.pinger.assert_ping(self.DST_ADDRESS)

        self.ipset._del_member_from_set(self.ipset_name, self.SRC_ADDRESS)
        self.pinger.assert_no_ping(self.DST_ADDRESS)

    def test_refresh_ipset_allows_ping(self):
        self.ipset._refresh_set(
            self.ipset_name, [UNRELATED_IP], IPSET_ETHERTYPE)
        self.pinger.assert_no_ping(self.DST_ADDRESS)

        self.ipset._refresh_set(
            self.ipset_name, [UNRELATED_IP, self.SRC_ADDRESS], IPSET_ETHERTYPE)
        self.pinger.assert_ping(self.DST_ADDRESS)

        self.ipset._refresh_set(
            self.ipset_name, [self.SRC_ADDRESS, UNRELATED_IP], IPSET_ETHERTYPE)
        self.pinger.assert_ping(self.DST_ADDRESS)

    def test_destroy_ipset_set(self):
        self._remove_iptables_ipset_rules()
        self.ipset._destroy(self.ipset_name)
