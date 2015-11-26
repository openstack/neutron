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
import copy

from neutron.agent.linux import iptables_firewall
from neutron.agent import securitygroups_rpc as sg_cfg
from neutron.common import constants
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers
from neutron.tests.functional import base
from oslo_config import cfg

DEVICE_OWNER_COMPUTE = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'fake'


class IptablesFirewallTestCase(base.BaseSudoTestCase):
    MAC_REAL = "fa:16:3e:9a:2f:49"
    MAC_SPOOFED = "fa:16:3e:9a:2f:48"
    FAKE_SECURITY_GROUP_ID = "fake_sg_id"

    def _set_src_mac(self, mac):
        self.client.port.link.set_down()
        self.client.port.link.set_address(mac)
        self.client.port.link.set_up()

    def setUp(self):
        cfg.CONF.register_opts(sg_cfg.security_group_opts, 'SECURITYGROUP')
        super(IptablesFirewallTestCase, self).setUp()

        bridge = self.useFixture(net_helpers.LinuxBridgeFixture()).bridge
        self.client, self.server = self.useFixture(
            machine_fixtures.PeerMachines(bridge)).machines

        self.firewall = iptables_firewall.IptablesFirewallDriver(
            namespace=bridge.namespace)

        self._set_src_mac(self.MAC_REAL)

        client_br_port_name = net_helpers.VethFixture.get_peer_name(
            self.client.port.name)
        self.src_port_desc = {'admin_state_up': True,
                              'device': client_br_port_name,
                              'device_owner': DEVICE_OWNER_COMPUTE,
                              'fixed_ips': [self.client.ip],
                              'mac_address': self.MAC_REAL,
                              'port_security_enabled': True,
                              'security_groups': [self.FAKE_SECURITY_GROUP_ID],
                              'status': 'ACTIVE'}

    # setup firewall on bridge and send packet from src_veth and observe
    # if sent packet can be observed on dst_veth
    def test_port_sec_within_firewall(self):

        # update the sg_group to make ping pass
        sg_rules = [{'ethertype': 'IPv4', 'direction': 'ingress',
                     'source_ip_prefix': '0.0.0.0/0', 'protocol': 'icmp'},
                    {'ethertype': 'IPv4', 'direction': 'egress'}]

        with self.firewall.defer_apply():
            self.firewall.update_security_group_rules(
                                                self.FAKE_SECURITY_GROUP_ID,
                                                sg_rules)
        self.firewall.prepare_port_filter(self.src_port_desc)
        self.client.assert_ping(self.server.ip)

        # modify the src_veth's MAC and test again
        self._set_src_mac(self.MAC_SPOOFED)
        self.client.assert_no_ping(self.server.ip)

        # update the port's port_security_enabled value and test again
        self.src_port_desc['port_security_enabled'] = False
        self.firewall.update_port_filter(self.src_port_desc)
        self.client.assert_ping(self.server.ip)

    def test_rule_application_converges(self):
        sg_rules = [{'ethertype': 'IPv4', 'direction': 'egress'},
                    {'ethertype': 'IPv6', 'direction': 'egress'},
                    {'ethertype': 'IPv4', 'direction': 'ingress',
                     'source_ip_prefix': '0.0.0.0/0', 'protocol': 'icmp'},
                    {'ethertype': 'IPv6', 'direction': 'ingress',
                     'source_ip_prefix': '0::0/0', 'protocol': 'ipv6-icmp'}]
        # make sure port ranges converge on all protocols with and without
        # port ranges (prevents regression of bug 1502924)
        for proto in ('tcp', 'udp', 'icmp'):
            for version in ('IPv4', 'IPv6'):
                if proto == 'icmp' and version == 'IPv6':
                    proto = 'ipv6-icmp'
                base = {'ethertype': version, 'direction': 'ingress',
                        'protocol': proto}
                sg_rules.append(copy.copy(base))
                base['port_range_min'] = 50
                base['port_range_max'] = 50
                sg_rules.append(copy.copy(base))
                base['port_range_max'] = 55
                sg_rules.append(copy.copy(base))
                base['source_port_range_min'] = 60
                base['source_port_range_max'] = 60
                sg_rules.append(copy.copy(base))
                base['source_port_range_max'] = 65
                sg_rules.append(copy.copy(base))

        # add some single-host rules to prevent regression of bug 1502917
        sg_rules.append({'ethertype': 'IPv4', 'direction': 'ingress',
                         'source_ip_prefix': '77.77.77.77/32'})
        sg_rules.append({'ethertype': 'IPv6', 'direction': 'ingress',
                         'source_ip_prefix': 'fe80::1/128'})
        self.firewall.update_security_group_rules(
            self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self.firewall.prepare_port_filter(self.src_port_desc)
        # after one prepare call, another apply should be a NOOP
        self.assertEqual([], self.firewall.iptables._apply())

        orig_sg_rules = copy.copy(sg_rules)
        for proto in ('tcp', 'udp', 'icmp'):
            for version in ('IPv4', 'IPv6'):
                if proto == 'icmp' and version == 'IPv6':
                    proto = 'ipv6-icmp'
                # make sure firewall is in converged state
                self.firewall.update_security_group_rules(
                    self.FAKE_SECURITY_GROUP_ID, orig_sg_rules)
                self.firewall.update_port_filter(self.src_port_desc)
                sg_rules = copy.copy(orig_sg_rules)

                # remove one rule and add another to make sure it results in
                # exactly one delete and insert
                sg_rules.pop(0 if version == 'IPv4' else 1)
                sg_rules.append({'ethertype': version, 'direction': 'egress',
                                 'protocol': proto})
                self.firewall.update_security_group_rules(
                    self.FAKE_SECURITY_GROUP_ID, sg_rules)
                result = self.firewall.update_port_filter(self.src_port_desc)
                deletes = [r for r in result if r.startswith('-D ')]
                creates = [r for r in result if r.startswith('-I ')]
                self.assertEqual(1, len(deletes))
                self.assertEqual(1, len(creates))
                # quick sanity check to make sure the insert was for the
                # correct proto
                self.assertIn('-p %s' % proto, creates[0])
                # another apply should be a NOOP if the right rule was removed
                # and the new one was inserted in the correct position
                self.assertEqual([], self.firewall.iptables._apply())

    def test_rule_ordering_correct(self):
        sg_rules = [
            {'ethertype': 'IPv4', 'direction': 'egress', 'protocol': 'tcp',
             'port_range_min': i, 'port_range_max': i}
            for i in range(50, 61)
        ]
        self.firewall.update_security_group_rules(
            self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self.firewall.prepare_port_filter(self.src_port_desc)
        self._assert_sg_out_tcp_rules_appear_in_order(sg_rules)
        # remove a rule and add a new one
        sg_rules.pop(5)
        sg_rules.insert(8, {'ethertype': 'IPv4', 'direction': 'egress',
                            'protocol': 'tcp', 'port_range_min': 400,
                            'port_range_max': 400})
        self.firewall.update_security_group_rules(
            self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self.firewall.prepare_port_filter(self.src_port_desc)
        self._assert_sg_out_tcp_rules_appear_in_order(sg_rules)

        # reverse all of the rules (requires lots of deletes and inserts)
        sg_rules = list(reversed(sg_rules))
        self.firewall.update_security_group_rules(
            self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self.firewall.prepare_port_filter(self.src_port_desc)
        self._assert_sg_out_tcp_rules_appear_in_order(sg_rules)

    def _assert_sg_out_tcp_rules_appear_in_order(self, sg_rules):
        outgoing_rule_pref = '-A %s-o%s' % (self.firewall.iptables.wrap_name,
                                            self.src_port_desc['device'][3:13])
        rules = [
            r for r in self.firewall.iptables.get_rules_for_table('filter')
            if r.startswith(outgoing_rule_pref)
        ]
        # we want to ensure the rules went in in the same order we sent
        indexes = [rules.index('%s -p tcp -m tcp --dport %s -j RETURN' %
                               (outgoing_rule_pref, i['port_range_min']))
                   for i in sg_rules]
        # all indexes should be in order with no unexpected rules in between
        self.assertEqual(range(indexes[0], indexes[-1] + 1), indexes)
