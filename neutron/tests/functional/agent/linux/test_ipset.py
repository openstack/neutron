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

from neutron.agent.linux import ipset_manager
from neutron.agent.linux import iptables_manager
from neutron.tests.functional.agent.linux import base

IPSET_CHAIN = 'test-chain'
IPSET_ETHERTYPE = 'IPv4'
ICMP_ACCEPT_RULE = '-p icmp -m set --match-set %s src -j ACCEPT' % IPSET_CHAIN
UNRELATED_IP = '1.1.1.1'


class IpsetBase(base.BaseIPVethTestCase):

    def setUp(self):
        super(IpsetBase, self).setUp()

        self.src_ns, self.dst_ns = self.prepare_veth_pairs()
        self.ipset = self._create_ipset_manager_and_chain(self.dst_ns,
                                                          IPSET_CHAIN)

        self.dst_iptables = iptables_manager.IptablesManager(
            root_helper=self.root_helper,
            namespace=self.dst_ns.namespace)

        self._add_iptables_ipset_rules(self.dst_iptables)

    def _create_ipset_manager_and_chain(self, dst_ns, chain_name):
        ipset = ipset_manager.IpsetManager(
            root_helper=self.root_helper,
            namespace=dst_ns.namespace)

        ipset.create_ipset_chain(chain_name, IPSET_ETHERTYPE)
        return ipset

    @staticmethod
    def _remove_iptables_ipset_rules(iptables_manager):
        iptables_manager.ipv4['filter'].remove_rule('INPUT', ICMP_ACCEPT_RULE)
        iptables_manager.apply()

    @staticmethod
    def _add_iptables_ipset_rules(iptables_manager):
        iptables_manager.ipv4['filter'].add_rule('INPUT', ICMP_ACCEPT_RULE)
        iptables_manager.ipv4['filter'].add_rule('INPUT', base.ICMP_BLOCK_RULE)
        iptables_manager.apply()


class IpsetManagerTestCase(IpsetBase):

    def test_add_member_allows_ping(self):
        self.pinger.assert_no_ping_from_ns(self.src_ns, self.DST_ADDRESS)
        self.ipset.add_member_to_ipset_chain(IPSET_CHAIN, self.SRC_ADDRESS)
        self.pinger.assert_ping_from_ns(self.src_ns, self.DST_ADDRESS)

    def test_del_member_denies_ping(self):
        self.ipset.add_member_to_ipset_chain(IPSET_CHAIN, self.SRC_ADDRESS)
        self.pinger.assert_ping_from_ns(self.src_ns, self.DST_ADDRESS)

        self.ipset.del_ipset_chain_member(IPSET_CHAIN, self.SRC_ADDRESS)
        self.pinger.assert_no_ping_from_ns(self.src_ns, self.DST_ADDRESS)

    def test_refresh_ipset_allows_ping(self):
        self.ipset.refresh_ipset_chain_by_name(IPSET_CHAIN, [UNRELATED_IP],
                                               IPSET_ETHERTYPE)
        self.pinger.assert_no_ping_from_ns(self.src_ns, self.DST_ADDRESS)

        self.ipset.refresh_ipset_chain_by_name(
            IPSET_CHAIN, [UNRELATED_IP, self.SRC_ADDRESS], IPSET_ETHERTYPE)
        self.pinger.assert_ping_from_ns(self.src_ns, self.DST_ADDRESS)

        self.ipset.refresh_ipset_chain_by_name(
            IPSET_CHAIN, [self.SRC_ADDRESS, UNRELATED_IP], IPSET_ETHERTYPE)
        self.pinger.assert_ping_from_ns(self.src_ns, self.DST_ADDRESS)

    def test_destroy_ipset_chain(self):
        self.assertRaises(RuntimeError,
                          self.ipset.destroy_ipset_chain_by_name, IPSET_CHAIN)
        self._remove_iptables_ipset_rules(self.dst_iptables)
        self.ipset.destroy_ipset_chain_by_name(IPSET_CHAIN)
