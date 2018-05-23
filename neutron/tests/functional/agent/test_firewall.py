# Copyright 2015 Intel Corporation.
# Copyright 2015 Isaku Yamahata <isaku.yamahata at intel com>
#                               <isaku.yamahata at gmail com>
# Copyright 2015 Red Hat, Inc.
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
import functools

import netaddr
from neutron_lib import constants
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils
import testscenarios

from neutron.agent.linux import iptables_firewall
from neutron.agent.linux import openvswitch_firewall
from neutron.agent.linux.openvswitch_firewall import constants as ovsfw_consts
from neutron.cmd.sanity import checks
from neutron.common import constants as n_const
from neutron.conf.agent import securitygroups_rpc as security_config
from neutron.tests.common import conn_testers
from neutron.tests.common import helpers
from neutron.tests.functional.agent.linux import base as linux_base
from neutron.tests.functional import constants as test_constants

LOG = logging.getLogger(__name__)

load_tests = testscenarios.load_tests_apply_scenarios

reverse_direction = {
    conn_testers.ConnectionTester.INGRESS:
        conn_testers.ConnectionTester.EGRESS,
    conn_testers.ConnectionTester.EGRESS:
        conn_testers.ConnectionTester.INGRESS}
reverse_transport_protocol = {
    conn_testers.ConnectionTester.TCP: conn_testers.ConnectionTester.UDP,
    conn_testers.ConnectionTester.UDP: conn_testers.ConnectionTester.TCP}

DEVICE_OWNER_COMPUTE = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'fake'


def skip_if_firewall(firewall_name):
    def outter(f):
        @functools.wraps(f)
        def wrap(self, *args, **kwargs):
            if self.firewall_name == firewall_name:
                self.skipTest("This test doesn't use %s firewall" %
                              firewall_name)
            return f(self, *args, **kwargs)
        return wrap
    return outter


def _add_rule(sg_rules, base, port_range_min=None, port_range_max=None):
    rule = copy.copy(base)
    if port_range_min:
        rule['port_range_min'] = port_range_min
    if port_range_max:
        rule['port_range_max'] = port_range_max
    sg_rules.append(rule)


class BaseFirewallTestCase(linux_base.BaseOVSLinuxTestCase):
    FAKE_SECURITY_GROUP_ID = uuidutils.generate_uuid()
    MAC_SPOOFED = "fa:16:3e:9a:2f:48"
    scenarios_iptables = testscenarios.multiply_scenarios(
        [('IptablesFirewallDriver', {'initialize': 'initialize_iptables',
                                     'firewall_name': 'iptables'})],
        [('with ipset', {'enable_ipset': True}),
         ('without ipset', {'enable_ipset': False})])

    scenarios_ovs_fw_interfaces = testscenarios.multiply_scenarios(
        [('OVS Firewall Driver', {'initialize': 'initialize_ovs',
                                  'firewall_name': 'openvswitch'})])

    scenarios = scenarios_iptables + scenarios_ovs_fw_interfaces

    ip_cidr = None
    vlan_range = set(range(1, test_constants.VLAN_COUNT - 1))

    def setUp(self):
        security_config.register_securitygroups_opts()
        self.net_id = uuidutils.generate_uuid()
        super(BaseFirewallTestCase, self).setUp()
        self.tester, self.firewall = getattr(self, self.initialize)()
        if self.firewall_name == "openvswitch":
            self.assign_vlan_to_peers()
        self.src_port_desc = self._create_port_description(
            self.tester.vm_port_id,
            [self.tester.vm_ip_address],
            self.tester.vm_mac_address,
            [self.FAKE_SECURITY_GROUP_ID],
            self.net_id)
        # FIXME(jlibosva): We should consider to call prepare_port_filter with
        # deferred bridge depending on its performance
        self.firewall.prepare_port_filter(self.src_port_desc)
        # Traffic coming from patch-port is always VLAN tagged
        self.tester.set_peer_port_as_patch_port()

    def initialize_iptables(self):
        cfg.CONF.set_override('enable_ipset', self.enable_ipset,
                              'SECURITYGROUP')
        br_name = ('brq' + self.net_id)[:n_const.LINUX_DEV_LEN]
        tester = self.useFixture(
            conn_testers.LinuxBridgeConnectionTester(self.ip_cidr,
                                                     bridge_name=br_name))
        firewall_drv = iptables_firewall.IptablesFirewallDriver(
            namespace=tester.bridge_namespace)
        return tester, firewall_drv

    def initialize_ovs(self):
        # Tests for ovs requires kernel >= 4.3 and OVS >= 2.5
        if not checks.ovs_conntrack_supported():
            self.skipTest("Open vSwitch with conntrack is not installed "
                          "on this machine. To run tests for OVS/CT firewall,"
                          " please meet the requirements (kernel>=4.3, "
                          "OVS>=2.5). More info at "
                          "https://github.com/openvswitch/ovs/blob/master/"
                          "FAQ.md")
        tester = self.useFixture(
            conn_testers.OVSConnectionTester(self.ip_cidr))
        firewall_drv = openvswitch_firewall.OVSFirewallDriver(tester.bridge)
        return tester, firewall_drv

    def assign_vlan_to_peers(self):
        vlan = helpers.get_not_used_vlan(self.firewall.int_br.br,
                                         self.vlan_range)
        LOG.debug("Using %d vlan tag for this test", vlan)
        self.tester.set_vm_tag(vlan)
        self.tester.set_peer_tag(vlan)

    @staticmethod
    def _create_port_description(port_id, ip_addresses, mac_address, sg_ids,
                                 net_id):
        return {'admin_state_up': True,
                'device': port_id,
                'device_owner': DEVICE_OWNER_COMPUTE,
                'fixed_ips': ip_addresses,
                'mac_address': mac_address,
                'port_security_enabled': True,
                'security_groups': sg_ids,
                'status': 'ACTIVE',
                'network_id': net_id}

    def _apply_security_group_rules(self, sg_id, sg_rules):
        with self.firewall.defer_apply():
            self.firewall.update_security_group_rules(sg_id, sg_rules)
            self.firewall.update_port_filter(self.src_port_desc)

    def _apply_security_group_members(self, sg_id, members):
        with self.firewall.defer_apply():
            self.firewall.update_security_group_members(sg_id, members)
            self.firewall.update_port_filter(self.src_port_desc)


class FirewallTestCase(BaseFirewallTestCase):
    ip_cidr = '192.168.0.1/24'

    @skip_if_firewall('openvswitch')
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
                _add_rule(sg_rules, base, port_range_min=50,
                          port_range_max=50)
                _add_rule(sg_rules, base, port_range_max=55)
                _add_rule(sg_rules, base, port_range_min=60,
                          port_range_max=60)
                _add_rule(sg_rules, base, port_range_max=65)

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

    @skip_if_firewall('openvswitch')
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
        self.assertEqual(list(range(indexes[0], indexes[-1] + 1)), indexes)

    def test_ingress_icmp_secgroup(self):
        # update the sg_group to make ping pass
        sg_rules = [{'ethertype': constants.IPv4,
                     'direction': constants.INGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_ICMP},
                    {'ethertype': constants.IPv4,
                     'direction': constants.EGRESS_DIRECTION}]

        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.INGRESS)
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.INGRESS)

    def test_mac_spoofing(self):
        sg_rules = [{'ethertype': constants.IPv4,
                     'direction': constants.INGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_ICMP},
                    {'ethertype': constants.IPv4,
                     'direction': constants.EGRESS_DIRECTION}]
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)

        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.INGRESS)
        self.tester.vm_mac_address = self.MAC_SPOOFED
        self.tester.flush_arp_tables()
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.INGRESS)
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.EGRESS)

    @skip_if_firewall('openvswitch')
    def test_mac_spoofing_works_without_port_security_enabled(self):
        self.src_port_desc['port_security_enabled'] = False
        self.firewall.update_port_filter(self.src_port_desc)

        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.INGRESS)
        self.tester.vm_mac_address = self.MAC_SPOOFED
        self.tester.flush_arp_tables()
        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.INGRESS)
        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.EGRESS)

    def test_port_security_enabled_set_to_false(self):
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.INGRESS)
        self.src_port_desc['port_security_enabled'] = False
        self.firewall.update_port_filter(self.src_port_desc)
        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.INGRESS)

    def test_dhcp_requests_from_vm(self):
        # DHCPv4 uses source port 67, destination port 68
        self.tester.assert_connection(direction=self.tester.EGRESS,
                                      protocol=self.tester.UDP,
                                      src_port=68, dst_port=67)

    def test_dhcp_server_forbidden_on_vm(self):
        self.tester.assert_no_connection(direction=self.tester.EGRESS,
                                         protocol=self.tester.UDP,
                                         src_port=67, dst_port=68)
        self.tester.assert_no_connection(direction=self.tester.INGRESS,
                                         protocol=self.tester.UDP,
                                         src_port=68, dst_port=67)

    def test_ip_spoofing(self):
        sg_rules = [{'ethertype': constants.IPv4,
                     'direction': constants.INGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_ICMP}]
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)
        not_allowed_ip = "%s/24" % (
            netaddr.IPAddress(self.tester.vm_ip_address) + 1)

        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.INGRESS)
        self.tester.vm_ip_cidr = not_allowed_ip
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.INGRESS)
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.EGRESS)
        self.tester.assert_no_connection(protocol=self.tester.UDP,
                                         src_port=68, dst_port=67,
                                         direction=self.tester.EGRESS)

    @skip_if_firewall('openvswitch')
    def test_ip_spoofing_works_without_port_security_enabled(self):
        self.src_port_desc['port_security_enabled'] = False
        self.firewall.update_port_filter(self.src_port_desc)

        sg_rules = [{'ethertype': constants.IPv4,
                     'direction': constants.INGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_ICMP}]
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)
        not_allowed_ip = "%s/24" % (
            netaddr.IPAddress(self.tester.vm_ip_address) + 1)

        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.INGRESS)
        self.tester.vm_ip_cidr = not_allowed_ip
        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.INGRESS)
        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.EGRESS)

    def test_allowed_address_pairs(self):
        sg_rules = [{'ethertype': constants.IPv4,
                     'direction': constants.INGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_ICMP},
                    {'ethertype': constants.IPv4,
                     'direction': constants.EGRESS_DIRECTION}]
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)

        port_mac = self.tester.vm_mac_address
        allowed_ip = netaddr.IPAddress(self.tester.vm_ip_address) + 1
        not_allowed_ip = "%s/24" % (allowed_ip + 1)
        allowed_mac = 'fa:16:3e:8c:84:13'
        not_allowed_mac = 'fa:16:3e:8c:84:14'
        self.src_port_desc['allowed_address_pairs'] = [
            {'mac_address': port_mac,
             'ip_address': "%s/32" % allowed_ip},
            {'mac_address': allowed_mac,
             'ip_address': "%s/32" % allowed_ip}]
        allowed_ip = "%s/24" % allowed_ip

        self.firewall.update_port_filter(self.src_port_desc)
        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.INGRESS)
        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.EGRESS)
        self.tester.vm_ip_cidr = allowed_ip
        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.INGRESS)
        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.EGRESS)
        self.tester.vm_ip_cidr = not_allowed_ip
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.INGRESS)
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.EGRESS)
        self.tester.vm_mac_address = allowed_mac
        self.tester.vm_ip_cidr = allowed_ip
        self.tester.flush_arp_tables()
        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.INGRESS)
        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.EGRESS)
        self.tester.vm_mac_address = allowed_mac
        self.tester.vm_ip_cidr = not_allowed_ip
        self.tester.flush_arp_tables()
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.INGRESS)
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.EGRESS)
        self.tester.vm_mac_address = not_allowed_mac
        self.tester.vm_ip_cidr = allowed_ip
        self.tester.flush_arp_tables()
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.INGRESS)
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.EGRESS)

    def test_arp_is_allowed(self):
        self.tester.assert_connection(protocol=self.tester.ARP,
                                      direction=self.tester.EGRESS)
        self.tester.assert_connection(protocol=self.tester.ARP,
                                      direction=self.tester.INGRESS)

    def _test_rule(self, direction, protocol):
        sg_rules = [{'ethertype': constants.IPv4, 'direction': direction,
                     'protocol': protocol}]
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)
        not_allowed_direction = reverse_direction[direction]
        not_allowed_protocol = reverse_transport_protocol[protocol]

        self.tester.assert_connection(protocol=protocol,
                                      direction=direction)
        self.tester.assert_no_connection(protocol=not_allowed_protocol,
                                         direction=direction)
        self.tester.assert_no_connection(protocol=protocol,
                                         direction=not_allowed_direction)

    def test_ingress_tcp_rule(self):
        self._test_rule(self.tester.INGRESS, self.tester.TCP)

    def test_next_port_closed(self):
        # https://bugs.launchpad.net/neutron/+bug/1611991 was caused by wrong
        # masking in rules which allow traffic to a port with even port number
        port = 42
        for direction in (self.tester.EGRESS, self.tester.INGRESS):
            sg_rules = [{'ethertype': constants.IPv4,
                         'direction': direction,
                         'protocol': constants.PROTO_NAME_TCP,
                         'source_port_range_min': port,
                         'source_port_range_max': port}]
            self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID,
                                             sg_rules)

            self.tester.assert_connection(protocol=self.tester.TCP,
                                          direction=direction,
                                          src_port=port)
            self.tester.assert_no_connection(protocol=self.tester.TCP,
                                             direction=direction,
                                             src_port=port + 1)

    def test_ingress_udp_rule(self):
        self._test_rule(self.tester.INGRESS, self.tester.UDP)

    def test_egress_tcp_rule(self):
        self._test_rule(self.tester.EGRESS, self.tester.TCP)

    def test_egress_udp_rule(self):
        self._test_rule(self.tester.EGRESS, self.tester.UDP)

    def test_connection_with_destination_port_range(self):
        port_min = 12345
        port_max = 12346
        sg_rules = [{'ethertype': constants.IPv4,
                     'direction': constants.INGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_TCP,
                     'port_range_min': port_min,
                     'port_range_max': port_max}]
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)

        self.tester.assert_connection(protocol=self.tester.TCP,
                                      direction=self.tester.INGRESS,
                                      dst_port=port_min)
        self.tester.assert_connection(protocol=self.tester.TCP,
                                      direction=self.tester.INGRESS,
                                      dst_port=port_max)
        self.tester.assert_no_connection(protocol=self.tester.TCP,
                                         direction=self.tester.INGRESS,
                                         dst_port=port_min - 1)
        self.tester.assert_no_connection(protocol=self.tester.TCP,
                                         direction=self.tester.INGRESS,
                                         dst_port=port_max + 1)

    def test_connection_with_source_port_range(self):
        source_port_min = 12345
        source_port_max = 12346
        sg_rules = [{'ethertype': constants.IPv4,
                     'direction': constants.EGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_TCP,
                     'source_port_range_min': source_port_min,
                     'source_port_range_max': source_port_max}]
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)

        self.tester.assert_connection(protocol=self.tester.TCP,
                                      direction=self.tester.EGRESS,
                                      src_port=source_port_min)
        self.tester.assert_connection(protocol=self.tester.TCP,
                                      direction=self.tester.EGRESS,
                                      src_port=source_port_max)
        self.tester.assert_no_connection(protocol=self.tester.TCP,
                                         direction=self.tester.EGRESS,
                                         src_port=source_port_min - 1)
        self.tester.assert_no_connection(protocol=self.tester.TCP,
                                         direction=self.tester.EGRESS,
                                         src_port=source_port_max + 1)

    @skip_if_firewall('iptables')
    def test_established_connection_is_cut(self):
        port = 12345
        sg_rules = [{'ethertype': constants.IPv4,
                     'direction': constants.INGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_TCP,
                     'port_range_min': port,
                     'port_range_max': port}]
        connection = {'protocol': self.tester.TCP,
                      'direction': self.tester.INGRESS,
                      'dst_port': port}
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self.tester.establish_connection(**connection)

        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, list())
        self.tester.assert_no_established_connection(**connection)

    def test_preventing_firewall_blink(self):
        direction = self.tester.INGRESS
        sg_rules = [{'ethertype': 'IPv4', 'direction': 'ingress',
                     'protocol': 'tcp'}]
        self.tester.start_sending_icmp(direction)
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, {})
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self.tester.stop_sending_icmp(direction)
        packets_sent = self.tester.get_sent_icmp_packets(direction)
        packets_received = self.tester.get_received_icmp_packets(direction)
        self.assertGreater(packets_sent, 0)
        self.assertEqual(packets_received, 0)

    def test_remote_security_groups(self):
        self.tester.set_peer_port_as_vm_port()

        remote_sg_id = 'remote_sg_id'
        peer_port_desc = self._create_port_description(
            self.tester.peer_port_id,
            [self.tester.peer_ip_address],
            self.tester.peer_mac_address,
            [remote_sg_id],
            self.net_id)

        vm_sg_members = {'IPv4': [self.tester.peer_ip_address]}
        peer_sg_rules = [{'ethertype': 'IPv4', 'direction': 'egress',
                          'protocol': 'icmp'}]
        self.firewall.update_security_group_rules(remote_sg_id, peer_sg_rules)
        self.firewall.update_security_group_members(remote_sg_id,
                                                    vm_sg_members)
        self.firewall.prepare_port_filter(peer_port_desc)

        vm_sg_rules = [{'ethertype': 'IPv4', 'direction': 'ingress',
                        'protocol': 'icmp', 'remote_group_id': remote_sg_id}]
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID,
                                         vm_sg_rules)

        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.INGRESS)
        self.tester.assert_no_connection(protocol=self.tester.TCP,
                                         direction=self.tester.INGRESS)
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.EGRESS)

    def test_related_connection(self):
        """Test ICMP net unreachable packets get back

        When destination address of ip traffic is not reachable, ICMP packets
        are returned. This packets are marked as RELATED traffic by conntrack
        and this test case validates such packets are not dropped by the
        firewall as ingress ICMP packets are not allowed in this test case. The
        used address below 1.2.3.4 is outside of subnet that is used in tester
        object.

        """
        # Enable ip forwarding on the interface in order to reply with
        # destination net unreachable
        self.tester._peer.execute([
            'sysctl', '-w', 'net.ipv4.conf.%s.forwarding=1' %
            self.tester._peer.port.name])
        self.tester.set_vm_default_gateway(self.tester.peer_ip_address)
        vm_sg_rules = [{'ethertype': 'IPv4', 'direction': 'egress',
                        'protocol': 'icmp'}]
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID,
                                         vm_sg_rules)

        self.tester.assert_net_unreachable(self.tester.EGRESS, '1.2.3.4')

    @skip_if_firewall('iptables')
    def test_tracked_connection(self):
        # put an openflow rule to perform a CT lookup and hence packet will
        # carry conntrack information
        self.tester.bridge.add_flow(
            table=0,
            priority=200,
            dl_type="0x0800",
            ct_state=ovsfw_consts.OF_STATE_NOT_TRACKED,
            actions="ct(table=0)"
        )

        # update the sg_group to make ping pass
        sg_rules = [{'ethertype': constants.IPv4,
                     'direction': constants.INGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_ICMP},
                    {'ethertype': constants.IPv4,
                     'direction': constants.EGRESS_DIRECTION}]

        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.INGRESS)
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.INGRESS)


class FirewallTestCaseIPv6(BaseFirewallTestCase):
    scenarios = BaseFirewallTestCase.scenarios_ovs_fw_interfaces
    ip_cidr = '2001:db8:aaaa::1/64'

    def test_icmp_from_specific_address(self):
        sg_rules = [{'ethertype': constants.IPv6,
                     'direction': constants.INGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_ICMP,
                     'source_ip_prefix': self.tester.peer_ip_address}]

        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.INGRESS)
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.INGRESS)

    def test_icmp_to_specific_address(self):
        sg_rules = [{'ethertype': constants.IPv6,
                     'direction': constants.EGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_ICMP,
                     'destination_ip_prefix': self.tester.peer_ip_address}]

        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.EGRESS)
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.EGRESS)

    def test_tcp_from_specific_address(self):
        sg_rules = [{'ethertype': constants.IPv6,
                     'direction': constants.INGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_TCP,
                     'source_ip_prefix': self.tester.peer_ip_address}]

        self.tester.assert_no_connection(protocol=self.tester.TCP,
                                         direction=self.tester.INGRESS)
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self.tester.assert_connection(protocol=self.tester.TCP,
                                      direction=self.tester.INGRESS)
        self.tester.assert_no_connection(protocol=self.tester.UDP,
                                         direction=self.tester.INGRESS)
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.INGRESS)

    def test_tcp_to_specific_address(self):
        sg_rules = [{'ethertype': constants.IPv6,
                     'direction': constants.EGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_TCP,
                     'destination_ip_prefix': self.tester.peer_ip_address}]

        self.tester.assert_no_connection(protocol=self.tester.TCP,
                                         direction=self.tester.EGRESS)
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self.tester.assert_connection(protocol=self.tester.TCP,
                                      direction=self.tester.EGRESS)
        self.tester.assert_no_connection(protocol=self.tester.UDP,
                                         direction=self.tester.EGRESS)
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.EGRESS)

    def test_udp_from_specific_address(self):
        sg_rules = [{'ethertype': constants.IPv6,
                     'direction': constants.INGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_UDP,
                     'source_ip_prefix': self.tester.peer_ip_address}]

        self.tester.assert_no_connection(protocol=self.tester.UDP,
                                         direction=self.tester.INGRESS)
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self.tester.assert_connection(protocol=self.tester.UDP,
                                      direction=self.tester.INGRESS)
        self.tester.assert_no_connection(protocol=self.tester.TCP,
                                         direction=self.tester.INGRESS)
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.INGRESS)

    def test_udp_to_specific_address(self):
        sg_rules = [{'ethertype': constants.IPv6,
                     'direction': constants.EGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_UDP,
                     'destination_ip_prefix': self.tester.peer_ip_address}]

        self.tester.assert_no_connection(protocol=self.tester.UDP,
                                         direction=self.tester.EGRESS)
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)
        self.tester.assert_connection(protocol=self.tester.UDP,
                                      direction=self.tester.EGRESS)
        self.tester.assert_no_connection(protocol=self.tester.TCP,
                                         direction=self.tester.EGRESS)
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.EGRESS)

    @skip_if_firewall('openvswitch')
    def test_ip_spoofing(self):
        sg_rules = [{'ethertype': constants.IPv6,
                     'direction': constants.INGRESS_DIRECTION,
                     'protocol': constants.PROTO_NAME_ICMP}]
        self._apply_security_group_rules(self.FAKE_SECURITY_GROUP_ID, sg_rules)
        not_allowed_ip = "%s/64" % (
            netaddr.IPAddress(self.tester.vm_ip_address) + 1)

        self.tester.assert_connection(protocol=self.tester.ICMP,
                                      direction=self.tester.INGRESS)
        self.tester.vm_ip_cidr = not_allowed_ip
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.INGRESS)
        self.tester.assert_no_connection(protocol=self.tester.ICMP,
                                         direction=self.tester.EGRESS)
        self.tester.assert_no_connection(protocol=self.tester.UDP,
                                         src_port=546, dst_port=547,
                                         direction=self.tester.EGRESS)
