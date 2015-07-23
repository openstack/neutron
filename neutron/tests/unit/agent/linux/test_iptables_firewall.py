# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
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

import copy

import mock
from oslo_config import cfg
import six

from neutron.agent.common import config as a_cfg
from neutron.agent.linux import ipset_manager
from neutron.agent.linux import iptables_comments as ic
from neutron.agent.linux import iptables_firewall
from neutron.agent import securitygroups_rpc as sg_cfg
from neutron.common import constants
from neutron.tests import base
from neutron.tests.unit.api.v2 import test_base


_uuid = test_base._uuid
#TODO(mangelajo): replace all 'IPv4', 'IPv6' to constants
FAKE_PREFIX = {'IPv4': '10.0.0.0/24',
               'IPv6': 'fe80::/48'}
FAKE_IP = {'IPv4': '10.0.0.1',
           'IPv6': 'fe80::1'}
#TODO(mangelajo): replace all '*_sgid' strings for the constants
FAKE_SGID = 'fake_sgid'
OTHER_SGID = 'other_sgid'
_IPv6 = constants.IPv6
_IPv4 = constants.IPv4


class BaseIptablesFirewallTestCase(base.BaseTestCase):
    def setUp(self):
        super(BaseIptablesFirewallTestCase, self).setUp()
        cfg.CONF.register_opts(a_cfg.ROOT_HELPER_OPTS, 'AGENT')
        cfg.CONF.register_opts(sg_cfg.security_group_opts, 'SECURITYGROUP')
        cfg.CONF.set_override('comment_iptables_rules', False, 'AGENT')
        self.utils_exec_p = mock.patch(
            'neutron.agent.linux.utils.execute')
        self.utils_exec = self.utils_exec_p.start()
        self.iptables_cls_p = mock.patch(
            'neutron.agent.linux.iptables_manager.IptablesManager')
        iptables_cls = self.iptables_cls_p.start()
        self.iptables_inst = mock.Mock()
        self.v4filter_inst = mock.Mock()
        self.v6filter_inst = mock.Mock()
        self.iptables_inst.ipv4 = {'filter': self.v4filter_inst,
                                   'raw': self.v4filter_inst
                                   }
        self.iptables_inst.ipv6 = {'filter': self.v6filter_inst,
                                   'raw': self.v6filter_inst
                                   }
        iptables_cls.return_value = self.iptables_inst

        self.firewall = iptables_firewall.IptablesFirewallDriver()
        self.firewall.iptables = self.iptables_inst


class IptablesFirewallTestCase(BaseIptablesFirewallTestCase):

    def _fake_port(self):
        return {'device': 'tapfake_dev',
                'mac_address': 'ff:ff:ff:ff:ff:ff',
                'network_id': 'fake_net',
                'fixed_ips': [FAKE_IP['IPv4'],
                              FAKE_IP['IPv6']]}

    def test_prepare_port_filter_with_no_sg(self):
        port = self._fake_port()
        self.firewall.prepare_port_filter(port)
        calls = [mock.call.add_chain('sg-fallback'),
                 mock.call.add_rule(
                     'sg-fallback', '-j DROP',
                     comment=ic.UNMATCH_DROP),
                 mock.call.remove_chain('sg-chain'),
                 mock.call.add_chain('sg-chain'),
                 mock.call.add_chain('ifake_dev'),
                 mock.call.add_rule('FORWARD',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $sg-chain', comment=ic.VM_INT_SG),
                 mock.call.add_rule('sg-chain',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $ifake_dev',
                                    comment=ic.SG_TO_VM_SG),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state INVALID -j DROP',
                     comment=None),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN',
                     comment=None),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-j $sg-fallback', comment=None),
                 mock.call.add_chain('ofake_dev'),
                 mock.call.add_rule('FORWARD',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $sg-chain', comment=ic.VM_INT_SG),
                 mock.call.add_rule('sg-chain',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged -j $ofake_dev',
                                    comment=ic.SG_TO_VM_SG),
                 mock.call.add_rule('INPUT',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged -j $ofake_dev',
                                    comment=ic.INPUT_TO_SG),
                 mock.call.add_chain('sfake_dev'),
                 mock.call.add_rule(
                     'sfake_dev',
                     '-s 10.0.0.1 -m mac --mac-source FF:FF:FF:FF:FF:FF '
                     '-j RETURN',
                     comment=ic.PAIR_ALLOW),
                 mock.call.add_rule(
                     'sfake_dev', '-j DROP',
                     comment=ic.PAIR_DROP),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 68 --dport 67 -j RETURN',
                     comment=None),
                 mock.call.add_rule('ofake_dev', '-j $sfake_dev',
                                    comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 67 --dport 68 -j DROP',
                     comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-m state --state INVALID -j DROP', comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN',
                     comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-j $sg-fallback',
                     comment=None),
                 mock.call.add_rule('sg-chain', '-j ACCEPT')]

        self.v4filter_inst.assert_has_calls(calls)

    def test_filter_ipv4_ingress(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress'}
        ingress = mock.call.add_rule('ifake_dev', '-j RETURN',
                                     comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule(
            'ifake_dev', '-s %s -j RETURN' % prefix, comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_tcp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'tcp'}
        ingress = mock.call.add_rule(
            'ifake_dev', '-p tcp -m tcp -j RETURN', comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_tcp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'tcp',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-s %s -p tcp -m tcp -j RETURN' % prefix,
                                     comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_icmp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'icmp'}
        ingress = mock.call.add_rule('ifake_dev', '-p icmp -j RETURN',
                                     comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_icmp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'icmp',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule(
            'ifake_dev', '-s %s -p icmp -j RETURN' % prefix,
            comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_tcp_port(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 10}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-p tcp -m tcp --dport 10 -j RETURN',
                                     comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_tcp_mport(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100}
        ingress = mock.call.add_rule(
            'ifake_dev',
            '-p tcp -m tcp -m multiport --dports 10:100 -j RETURN',
            comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_tcp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule(
            'ifake_dev',
            '-s %s -p tcp -m tcp -m multiport --dports 10:100 '
            '-j RETURN' % prefix, comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_udp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'udp'}
        ingress = mock.call.add_rule(
            'ifake_dev', '-p udp -m udp -j RETURN', comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_udp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'udp',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-s %s -p udp -m udp -j RETURN' % prefix,
                                     comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_udp_port(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 10}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-p udp -m udp --dport 10 -j RETURN',
                                     comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_udp_mport(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100}
        ingress = mock.call.add_rule(
            'ifake_dev',
            '-p udp -m udp -m multiport --dports 10:100 -j RETURN',
            comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_udp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule(
            'ifake_dev',
            '-s %s -p udp -m udp -m multiport --dports 10:100 '
            '-j RETURN' % prefix, comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress'}
        egress = mock.call.add_rule('ofake_dev', '-j RETURN', comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev', '-s %s -j RETURN' % prefix, comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_tcp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'tcp'}
        egress = mock.call.add_rule(
            'ofake_dev', '-p tcp -m tcp -j RETURN', comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_tcp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'tcp',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule('ofake_dev',
                                    '-s %s -p tcp -m tcp -j RETURN' % prefix,
                                    comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_icmp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'icmp'}
        egress = mock.call.add_rule('ofake_dev', '-p icmp -j RETURN',
                                    comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_icmp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'icmp',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev', '-s %s -p icmp -j RETURN' % prefix,
            comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_icmp_type(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'icmp',
                'source_port_range_min': 8,
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev',
            '-s %s -p icmp --icmp-type 8 -j RETURN' % prefix,
            comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_icmp_type_name(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'icmp',
                'source_port_range_min': 'echo-request',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev',
            '-s %s -p icmp --icmp-type echo-request -j RETURN' % prefix,
            comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_icmp_type_code(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'icmp',
                'source_port_range_min': 8,
                'source_port_range_max': 0,
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev',
            '-s %s -p icmp --icmp-type 8/0 -j RETURN' % prefix,
            comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_tcp_port(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 10}
        egress = mock.call.add_rule('ofake_dev',
                                    '-p tcp -m tcp --dport 10 -j RETURN',
                                    comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_tcp_mport(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100}
        egress = mock.call.add_rule(
            'ofake_dev',
            '-p tcp -m tcp -m multiport --dports 10:100 -j RETURN',
            comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_tcp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev',
            '-s %s -p tcp -m tcp -m multiport --dports 10:100 '
            '-j RETURN' % prefix, comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_udp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'udp'}
        egress = mock.call.add_rule(
            'ofake_dev', '-p udp -m udp -j RETURN', comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_udp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'udp',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule('ofake_dev',
                                    '-s %s -p udp -m udp -j RETURN' % prefix,
                                    comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_udp_port(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 10}
        egress = mock.call.add_rule('ofake_dev',
                                    '-p udp -m udp --dport 10 -j RETURN',
                                    comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_udp_mport(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100}
        egress = mock.call.add_rule(
            'ofake_dev',
            '-p udp -m udp -m multiport --dports 10:100 -j RETURN',
            comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_udp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev',
            '-s %s -p udp -m udp -m multiport --dports 10:100 '
            '-j RETURN' % prefix, comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress'}
        ingress = mock.call.add_rule('ifake_dev', '-j RETURN',
                                     comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule(
            'ifake_dev', '-s %s -j RETURN' % prefix, comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_tcp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'tcp'}
        ingress = mock.call.add_rule(
            'ifake_dev', '-p tcp -m tcp -j RETURN', comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_tcp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'tcp',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-s %s -p tcp -m tcp -j RETURN' % prefix,
                                     comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_tcp_port(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 10}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-p tcp -m tcp --dport 10 -j RETURN',
                                     comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_icmp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'icmp'}
        ingress = mock.call.add_rule(
            'ifake_dev', '-p icmpv6 -j RETURN', comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_icmp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'icmp',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule(
            'ifake_dev', '-s %s -p icmpv6 -j RETURN' % prefix,
            comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_tcp_mport(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100}
        ingress = mock.call.add_rule(
            'ifake_dev',
            '-p tcp -m tcp -m multiport --dports 10:100 -j RETURN',
            comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def _test_filter_ingress_tcp_min_port_0(self, ethertype):
        rule = {'ethertype': ethertype,
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 0,
                'port_range_max': 100}
        ingress = mock.call.add_rule(
            'ifake_dev',
            '-p tcp -m tcp -m multiport --dports 0:100 -j RETURN',
            comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ingress_tcp_min_port_0_for_ipv4(self):
        self._test_filter_ingress_tcp_min_port_0('IPv4')

    def test_filter_ingress_tcp_min_port_0_for_ipv6(self):
        self._test_filter_ingress_tcp_min_port_0('IPv6')

    def test_filter_ipv6_ingress_tcp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule(
            'ifake_dev',
            '-s %s -p tcp -m tcp -m multiport --dports 10:100 '
            '-j RETURN' % prefix, comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_udp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'udp'}
        ingress = mock.call.add_rule(
            'ifake_dev', '-p udp -m udp -j RETURN', comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_udp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'udp',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-s %s -p udp -m udp -j RETURN' % prefix,
                                     comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_udp_port(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 10}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-p udp -m udp --dport 10 -j RETURN',
                                     comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_udp_mport(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100}
        ingress = mock.call.add_rule(
            'ifake_dev',
            '-p udp -m udp -m multiport --dports 10:100 -j RETURN',
            comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_udp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule(
            'ifake_dev',
            '-s %s -p udp -m udp -m multiport --dports 10:100 '
            '-j RETURN' % prefix, comment=None)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress'}
        egress = mock.call.add_rule('ofake_dev', '-j RETURN', comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev', '-s %s -j RETURN' % prefix, comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_tcp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'tcp'}
        egress = mock.call.add_rule(
            'ofake_dev', '-p tcp -m tcp -j RETURN', comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_tcp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'tcp',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule('ofake_dev',
                                    '-s %s -p tcp -m tcp -j RETURN' % prefix,
                                    comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_icmp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'icmp'}
        egress = mock.call.add_rule(
            'ofake_dev', '-p icmpv6 -j RETURN', comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_icmp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'icmp',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev', '-s %s -p icmpv6 -j RETURN' % prefix,
            comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_icmp_type(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'icmp',
                'source_port_range_min': 8,
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev',
            '-s %s -p icmpv6 --icmpv6-type 8 -j RETURN' % prefix,
            comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_icmp_type_name(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'icmp',
                'source_port_range_min': 'echo-request',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev',
            '-s %s -p icmpv6 --icmpv6-type echo-request -j RETURN' % prefix,
            comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_icmp_type_code(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'icmp',
                'source_port_range_min': 8,
                'source_port_range_max': 0,
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev',
            '-s %s -p icmpv6 --icmpv6-type 8/0 -j RETURN' % prefix,
            comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_tcp_port(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 10}
        egress = mock.call.add_rule('ofake_dev',
                                    '-p tcp -m tcp --dport 10 -j RETURN',
                                    comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_tcp_mport(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100}
        egress = mock.call.add_rule(
            'ofake_dev',
            '-p tcp -m tcp -m multiport --dports 10:100 -j RETURN',
            comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_tcp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev',
            '-s %s -p tcp -m tcp -m multiport --dports 10:100 '
            '-j RETURN' % prefix, comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_udp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'udp'}
        egress = mock.call.add_rule(
            'ofake_dev', '-p udp -m udp -j RETURN', comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_udp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'udp',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule('ofake_dev',
                                    '-s %s -p udp -m udp -j RETURN' % prefix,
                                    comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_udp_port(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 10}
        egress = mock.call.add_rule('ofake_dev',
                                    '-p udp -m udp --dport 10 -j RETURN',
                                    comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_udp_mport(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100}
        egress = mock.call.add_rule(
            'ofake_dev',
            '-p udp -m udp -m multiport --dports 10:100 -j RETURN',
            comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_udp_mport_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 100,
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev',
            '-s %s -p udp -m udp -m multiport --dports 10:100 '
            '-j RETURN' % prefix, comment=None)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def _test_prepare_port_filter(self,
                                  rule,
                                  ingress_expected_call=None,
                                  egress_expected_call=None):
        port = self._fake_port()
        ethertype = rule['ethertype']
        prefix = FAKE_IP[ethertype]
        filter_inst = self.v4filter_inst
        dhcp_rule = [mock.call.add_rule(
            'ofake_dev',
            '-p udp -m udp --sport 68 --dport 67 -j RETURN',
            comment=None)]

        if ethertype == 'IPv6':
            filter_inst = self.v6filter_inst

            dhcp_rule = [mock.call.add_rule('ofake_dev', '-p icmpv6 '
                                            '--icmpv6-type %s -j DROP'
                                            % constants.ICMPV6_TYPE_RA,
                                            comment=None),
                         mock.call.add_rule('ofake_dev',
                                            '-p icmpv6 -j RETURN',
                                            comment=None),
                         mock.call.add_rule('ofake_dev', '-p udp -m udp '
                                            '--sport 546 --dport 547 '
                                            '-j RETURN', comment=None)]
        sg = [rule]
        port['security_group_rules'] = sg
        self.firewall.prepare_port_filter(port)
        calls = [mock.call.add_chain('sg-fallback'),
                 mock.call.add_rule(
                     'sg-fallback',
                     '-j DROP',
                     comment=ic.UNMATCH_DROP),
                 mock.call.remove_chain('sg-chain'),
                 mock.call.add_chain('sg-chain'),
                 mock.call.add_chain('ifake_dev'),
                 mock.call.add_rule('FORWARD',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $sg-chain', comment=ic.VM_INT_SG),
                 mock.call.add_rule('sg-chain',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $ifake_dev',
                                    comment=ic.SG_TO_VM_SG)
                 ]
        if ethertype == 'IPv6':
            for icmp6_type in constants.ICMPV6_ALLOWED_TYPES:
                calls.append(
                    mock.call.add_rule('ifake_dev',
                                       '-p icmpv6 --icmpv6-type %s -j RETURN' %
                                       icmp6_type, comment=None))
        calls += [
            mock.call.add_rule(
                'ifake_dev',
                '-m state --state INVALID -j DROP', comment=None
            ),
            mock.call.add_rule(
                'ifake_dev',
                '-m state --state RELATED,ESTABLISHED -j RETURN',
                comment=None
            )
        ]

        if ingress_expected_call:
            calls.append(ingress_expected_call)

        calls += [mock.call.add_rule('ifake_dev',
                                     '-j $sg-fallback', comment=None),
                  mock.call.add_chain('ofake_dev'),
                  mock.call.add_rule('FORWARD',
                                     '-m physdev --physdev-in tapfake_dev '
                                     '--physdev-is-bridged '
                                     '-j $sg-chain', comment=ic.VM_INT_SG),
                  mock.call.add_rule('sg-chain',
                                     '-m physdev --physdev-in tapfake_dev '
                                     '--physdev-is-bridged -j $ofake_dev',
                                     comment=ic.SG_TO_VM_SG),
                  mock.call.add_rule('INPUT',
                                     '-m physdev --physdev-in tapfake_dev '
                                     '--physdev-is-bridged -j $ofake_dev',
                                     comment=ic.INPUT_TO_SG),
                  mock.call.add_chain('sfake_dev'),
                  mock.call.add_rule(
                      'sfake_dev',
                      '-s %s -m mac --mac-source FF:FF:FF:FF:FF:FF -j RETURN'
                      % prefix,
                      comment=ic.PAIR_ALLOW),
                  mock.call.add_rule(
                      'sfake_dev', '-j DROP',
                      comment=ic.PAIR_DROP)]
        calls += dhcp_rule
        calls.append(mock.call.add_rule('ofake_dev', '-j $sfake_dev',
                                        comment=None))
        if ethertype == 'IPv4':
            calls.append(mock.call.add_rule(
                'ofake_dev',
                '-p udp -m udp --sport 67 --dport 68 -j DROP',
                comment=None))
        if ethertype == 'IPv6':
            calls.append(mock.call.add_rule(
                'ofake_dev',
                '-p udp -m udp --sport 547 --dport 546 -j DROP',
                comment=None))

        calls += [
            mock.call.add_rule(
                'ofake_dev',
                '-m state --state INVALID -j DROP', comment=None),
            mock.call.add_rule(
                'ofake_dev',
                '-m state --state RELATED,ESTABLISHED -j RETURN',
                comment=None),
        ]

        if egress_expected_call:
            calls.append(egress_expected_call)

        calls += [mock.call.add_rule('ofake_dev',
                                     '-j $sg-fallback', comment=None),
                  mock.call.add_rule('sg-chain', '-j ACCEPT')]

        filter_inst.assert_has_calls(calls)

    def test_update_delete_port_filter(self):
        port = self._fake_port()
        port['security_group_rules'] = [{'ethertype': 'IPv4',
                                         'direction': 'ingress'}]
        self.firewall.prepare_port_filter(port)
        port['security_group_rules'] = [{'ethertype': 'IPv4',
                                         'direction': 'egress'}]
        self.firewall.update_port_filter(port)
        self.firewall.update_port_filter({'device': 'no-exist-device'})
        self.firewall.remove_port_filter(port)
        self.firewall.remove_port_filter({'device': 'no-exist-device'})
        calls = [mock.call.add_chain('sg-fallback'),
                 mock.call.add_rule(
                     'sg-fallback',
                     '-j DROP',
                     comment=ic.UNMATCH_DROP),
                 mock.call.remove_chain('sg-chain'),
                 mock.call.add_chain('sg-chain'),
                 mock.call.add_chain('ifake_dev'),
                 mock.call.add_rule(
                     'FORWARD',
                     '-m physdev --physdev-out tapfake_dev '
                     '--physdev-is-bridged -j $sg-chain',
                     comment=ic.VM_INT_SG),
                 mock.call.add_rule(
                     'sg-chain',
                     '-m physdev --physdev-out tapfake_dev '
                     '--physdev-is-bridged -j $ifake_dev',
                     comment=ic.SG_TO_VM_SG),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state INVALID -j DROP', comment=None),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN',
                     comment=None),
                 mock.call.add_rule('ifake_dev', '-j RETURN',
                                    comment=None),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-j $sg-fallback', comment=None),
                 mock.call.add_chain('ofake_dev'),
                 mock.call.add_rule(
                     'FORWARD',
                     '-m physdev --physdev-in tapfake_dev '
                     '--physdev-is-bridged -j $sg-chain',
                     comment=ic.VM_INT_SG),
                 mock.call.add_rule(
                     'sg-chain',
                     '-m physdev --physdev-in tapfake_dev '
                     '--physdev-is-bridged -j $ofake_dev',
                     comment=ic.SG_TO_VM_SG),
                 mock.call.add_rule(
                     'INPUT',
                     '-m physdev --physdev-in tapfake_dev '
                     '--physdev-is-bridged -j $ofake_dev',
                     comment=ic.INPUT_TO_SG),
                 mock.call.add_chain('sfake_dev'),
                 mock.call.add_rule(
                     'sfake_dev',
                     '-s 10.0.0.1 -m mac --mac-source FF:FF:FF:FF:FF:FF '
                     '-j RETURN',
                     comment=ic.PAIR_ALLOW),
                 mock.call.add_rule(
                     'sfake_dev', '-j DROP',
                     comment=ic.PAIR_DROP),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 68 --dport 67 -j RETURN',
                     comment=None),
                 mock.call.add_rule('ofake_dev', '-j $sfake_dev',
                                    comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 67 --dport 68 -j DROP',
                     comment=None),
                 mock.call.add_rule(
                     'ofake_dev', '-m state --state INVALID -j DROP',
                     comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN',
                     comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-j $sg-fallback', comment=None),
                 mock.call.add_rule('sg-chain', '-j ACCEPT'),
                 mock.call.remove_chain('ifake_dev'),
                 mock.call.remove_chain('ofake_dev'),
                 mock.call.remove_chain('sfake_dev'),
                 mock.call.remove_chain('sg-chain'),
                 mock.call.add_chain('sg-chain'),
                 mock.call.add_chain('ifake_dev'),
                 mock.call.add_rule(
                     'FORWARD',
                     '-m physdev --physdev-out tapfake_dev '
                     '--physdev-is-bridged -j $sg-chain',
                     comment=ic.VM_INT_SG),
                 mock.call.add_rule(
                     'sg-chain',
                     '-m physdev --physdev-out tapfake_dev '
                     '--physdev-is-bridged -j $ifake_dev',
                     comment=ic.SG_TO_VM_SG),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state INVALID -j DROP', comment=None),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN',
                     comment=None),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-j $sg-fallback', comment=None),
                 mock.call.add_chain('ofake_dev'),
                 mock.call.add_rule(
                     'FORWARD',
                     '-m physdev --physdev-in tapfake_dev '
                     '--physdev-is-bridged -j $sg-chain',
                     comment=ic.VM_INT_SG),
                 mock.call.add_rule(
                     'sg-chain',
                     '-m physdev --physdev-in tapfake_dev '
                     '--physdev-is-bridged -j $ofake_dev',
                     comment=ic.SG_TO_VM_SG),
                 mock.call.add_rule(
                     'INPUT',
                     '-m physdev --physdev-in tapfake_dev '
                     '--physdev-is-bridged -j $ofake_dev',
                     comment=ic.INPUT_TO_SG),
                 mock.call.add_chain('sfake_dev'),
                 mock.call.add_rule(
                     'sfake_dev',
                     '-s 10.0.0.1 -m mac --mac-source FF:FF:FF:FF:FF:FF '
                     '-j RETURN',
                     comment=ic.PAIR_ALLOW),
                 mock.call.add_rule(
                     'sfake_dev', '-j DROP',
                     comment=ic.PAIR_DROP),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 68 --dport 67 -j RETURN',
                     comment=None),
                 mock.call.add_rule('ofake_dev', '-j $sfake_dev',
                                    comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 67 --dport 68 -j DROP',
                     comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-m state --state INVALID -j DROP', comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN',
                     comment=None),
                 mock.call.add_rule('ofake_dev', '-j RETURN',
                                    comment=None),
                 mock.call.add_rule('ofake_dev',
                                    '-j $sg-fallback',
                                    comment=None),
                 mock.call.add_rule('sg-chain', '-j ACCEPT'),
                 mock.call.remove_chain('ifake_dev'),
                 mock.call.remove_chain('ofake_dev'),
                 mock.call.remove_chain('sfake_dev'),
                 mock.call.remove_chain('sg-chain'),
                 mock.call.add_chain('sg-chain')]

        self.v4filter_inst.assert_has_calls(calls)

    def test_remove_unknown_port(self):
        port = self._fake_port()
        self.firewall.remove_port_filter(port)
        # checking no exception occures
        self.assertFalse(self.v4filter_inst.called)

    def test_defer_apply(self):
        with self.firewall.defer_apply():
            pass
        self.iptables_inst.assert_has_calls([mock.call.defer_apply_on(),
                                             mock.call.defer_apply_off()])

    def test_filter_defer_with_exception(self):
        try:
            with self.firewall.defer_apply():
                raise Exception("same exception")
        except Exception:
            pass
        self.iptables_inst.assert_has_calls([mock.call.defer_apply_on(),
                                             mock.call.defer_apply_off()])

    def _mock_chain_applies(self):
        class CopyingMock(mock.MagicMock):
            """Copies arguments so mutable arguments can be asserted on.

            Copied verbatim from unittest.mock documentation.
            """
            def __call__(self, *args, **kwargs):
                args = copy.deepcopy(args)
                kwargs = copy.deepcopy(kwargs)
                return super(CopyingMock, self).__call__(*args, **kwargs)
        # Need to use CopyingMock because _{setup,remove}_chains_apply are
        # usually called with that's modified between calls (i.e.,
        # self.firewall.filtered_ports).
        chain_applies = CopyingMock()
        self.firewall._setup_chains_apply = chain_applies.setup
        self.firewall._remove_chains_apply = chain_applies.remove
        return chain_applies

    def test_mock_chain_applies(self):
        chain_applies = self._mock_chain_applies()
        port_prepare = {'device': 'd1', 'mac_address': 'prepare'}
        port_update = {'device': 'd1', 'mac_address': 'update'}
        self.firewall.prepare_port_filter(port_prepare)
        self.firewall.update_port_filter(port_update)
        self.firewall.remove_port_filter(port_update)
        chain_applies.assert_has_calls([mock.call.remove({}, {}),
                                mock.call.setup({'d1': port_prepare}, {}),
                                mock.call.remove({'d1': port_prepare}, {}),
                                mock.call.setup({'d1': port_update}, {}),
                                mock.call.remove({'d1': port_update}, {}),
                                mock.call.setup({}, {})])

    def test_defer_chain_apply_need_pre_defer_copy(self):
        chain_applies = self._mock_chain_applies()
        port = self._fake_port()
        device2port = {port['device']: port}
        self.firewall.prepare_port_filter(port)
        with self.firewall.defer_apply():
            self.firewall.remove_port_filter(port)
        chain_applies.assert_has_calls([mock.call.remove({}, {}),
                                        mock.call.setup(device2port, {}),
                                        mock.call.remove(device2port, {}),
                                        mock.call.setup({}, {})])

    def test_defer_chain_apply_coalesce_simple(self):
        chain_applies = self._mock_chain_applies()
        port = self._fake_port()
        with self.firewall.defer_apply():
            self.firewall.prepare_port_filter(port)
            self.firewall.update_port_filter(port)
            self.firewall.remove_port_filter(port)
        chain_applies.assert_has_calls([mock.call.remove({}, {}),
                                        mock.call.setup({}, {})])

    def test_defer_chain_apply_coalesce_multiple_ports(self):
        chain_applies = self._mock_chain_applies()
        port1 = {'device': 'd1', 'mac_address': 'mac1', 'network_id': 'net1'}
        port2 = {'device': 'd2', 'mac_address': 'mac2', 'network_id': 'net1'}
        device2port = {'d1': port1, 'd2': port2}
        with self.firewall.defer_apply():
            self.firewall.prepare_port_filter(port1)
            self.firewall.prepare_port_filter(port2)
        chain_applies.assert_has_calls([mock.call.remove({}, {}),
                                        mock.call.setup(device2port, {})])

    def test_ip_spoofing_filter_with_multiple_ips(self):
        port = {'device': 'tapfake_dev',
                'mac_address': 'ff:ff:ff:ff:ff:ff',
                'network_id': 'fake_net',
                'fixed_ips': ['10.0.0.1', 'fe80::1', '10.0.0.2']}
        self.firewall.prepare_port_filter(port)
        calls = [mock.call.add_chain('sg-fallback'),
                 mock.call.add_rule(
                     'sg-fallback', '-j DROP',
                     comment=ic.UNMATCH_DROP),
                 mock.call.remove_chain('sg-chain'),
                 mock.call.add_chain('sg-chain'),
                 mock.call.add_chain('ifake_dev'),
                 mock.call.add_rule('FORWARD',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $sg-chain', comment=ic.VM_INT_SG),
                 mock.call.add_rule('sg-chain',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $ifake_dev',
                                    comment=ic.SG_TO_VM_SG),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state INVALID -j DROP', comment=None),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN',
                     comment=None),
                 mock.call.add_rule('ifake_dev',
                                    '-j $sg-fallback', comment=None),
                 mock.call.add_chain('ofake_dev'),
                 mock.call.add_rule('FORWARD',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $sg-chain', comment=ic.VM_INT_SG),
                 mock.call.add_rule('sg-chain',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged -j $ofake_dev',
                                    comment=ic.SG_TO_VM_SG),
                 mock.call.add_rule('INPUT',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged -j $ofake_dev',
                                    comment=ic.INPUT_TO_SG),
                 mock.call.add_chain('sfake_dev'),
                 mock.call.add_rule(
                     'sfake_dev',
                     '-s 10.0.0.1 -m mac --mac-source FF:FF:FF:FF:FF:FF '
                     '-j RETURN',
                     comment=ic.PAIR_ALLOW),
                 mock.call.add_rule(
                     'sfake_dev',
                     '-s 10.0.0.2 -m mac --mac-source FF:FF:FF:FF:FF:FF '
                     '-j RETURN',
                     comment=ic.PAIR_ALLOW),
                 mock.call.add_rule(
                     'sfake_dev', '-j DROP',
                     comment=ic.PAIR_DROP),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 68 --dport 67 -j RETURN',
                     comment=None),
                 mock.call.add_rule('ofake_dev', '-j $sfake_dev',
                                    comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 67 --dport 68 -j DROP',
                     comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-m state --state INVALID -j DROP', comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN',
                     comment=None),
                 mock.call.add_rule('ofake_dev',
                                    '-j $sg-fallback', comment=None),
                 mock.call.add_rule('sg-chain', '-j ACCEPT')]
        self.v4filter_inst.assert_has_calls(calls)

    def test_ip_spoofing_no_fixed_ips(self):
        port = {'device': 'tapfake_dev',
                'mac_address': 'ff:ff:ff:ff:ff:ff',
                'network_id': 'fake_net',
                'fixed_ips': []}
        self.firewall.prepare_port_filter(port)
        calls = [mock.call.add_chain('sg-fallback'),
                 mock.call.add_rule(
                     'sg-fallback', '-j DROP',
                     comment=ic.UNMATCH_DROP),
                 mock.call.remove_chain('sg-chain'),
                 mock.call.add_chain('sg-chain'),
                 mock.call.add_chain('ifake_dev'),
                 mock.call.add_rule('FORWARD',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $sg-chain', comment=ic.VM_INT_SG),
                 mock.call.add_rule('sg-chain',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $ifake_dev',
                                    comment=ic.SG_TO_VM_SG),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state INVALID -j DROP', comment=None),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN',
                     comment=None),
                 mock.call.add_rule('ifake_dev', '-j $sg-fallback',
                                    comment=None),
                 mock.call.add_chain('ofake_dev'),
                 mock.call.add_rule('FORWARD',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $sg-chain', comment=ic.VM_INT_SG),
                 mock.call.add_rule('sg-chain',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged -j $ofake_dev',
                                    comment=ic.SG_TO_VM_SG),
                 mock.call.add_rule('INPUT',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged -j $ofake_dev',
                                    comment=ic.INPUT_TO_SG),
                 mock.call.add_chain('sfake_dev'),
                 mock.call.add_rule(
                     'sfake_dev',
                     '-m mac --mac-source FF:FF:FF:FF:FF:FF -j RETURN',
                     comment=ic.PAIR_ALLOW),
                 mock.call.add_rule(
                     'sfake_dev', '-j DROP',
                     comment=ic.PAIR_DROP),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 68 --dport 67 -j RETURN',
                     comment=None),
                 mock.call.add_rule('ofake_dev', '-j $sfake_dev',
                                    comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 67 --dport 68 -j DROP',
                     comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-m state --state INVALID -j DROP',
                     comment=None),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN',
                     comment=None),
                 mock.call.add_rule('ofake_dev', '-j $sg-fallback',
                                    comment=None),
                 mock.call.add_rule('sg-chain', '-j ACCEPT')]
        self.v4filter_inst.assert_has_calls(calls)


class IptablesFirewallEnhancedIpsetTestCase(BaseIptablesFirewallTestCase):
    def setUp(self):
        super(IptablesFirewallEnhancedIpsetTestCase, self).setUp()
        self.firewall.ipset = mock.Mock()
        self.firewall.ipset.get_name.side_effect = (
            ipset_manager.IpsetManager.get_name)
        self.firewall.ipset.set_exists.return_value = True

    def _fake_port(self, sg_id=FAKE_SGID):
        return {'device': 'tapfake_dev',
                'mac_address': 'ff:ff:ff:ff:ff:ff',
                'network_id': 'fake_net',
                'fixed_ips': [FAKE_IP['IPv4'],
                              FAKE_IP['IPv6']],
                'security_groups': [sg_id],
                'security_group_source_groups': [sg_id]}

    def _fake_sg_rule_for_ethertype(self, ethertype, remote_group):
        return {'direction': 'ingress', 'remote_group_id': remote_group,
                'ethertype': ethertype}

    def _fake_sg_rules(self, sg_id=FAKE_SGID, remote_groups=None):
        remote_groups = remote_groups or {_IPv4: [FAKE_SGID],
                                          _IPv6: [FAKE_SGID]}
        rules = []
        for ip_version, remote_group_list in six.iteritems(remote_groups):
            for remote_group in remote_group_list:
                rules.append(self._fake_sg_rule_for_ethertype(ip_version,
                                                              remote_group))
        return {sg_id: rules}

    def _fake_sg_members(self, sg_ids=None):
        return {sg_id: copy.copy(FAKE_IP) for sg_id in (sg_ids or [FAKE_SGID])}

    def test_prepare_port_filter_with_new_members(self):
        self.firewall.sg_rules = self._fake_sg_rules()
        self.firewall.sg_members = {'fake_sgid': {
            'IPv4': ['10.0.0.1', '10.0.0.2'], 'IPv6': ['fe80::1']}}
        self.firewall.pre_sg_members = {}
        port = self._fake_port()
        self.firewall.prepare_port_filter(port)
        calls = [
            mock.call.set_members('fake_sgid', 'IPv4',
                                  ['10.0.0.1', '10.0.0.2']),
            mock.call.set_members('fake_sgid', 'IPv6',
                                  ['fe80::1'])
        ]
        self.firewall.ipset.assert_has_calls(calls, any_order=True)

    def _setup_fake_firewall_members_and_rules(self, firewall):
        firewall.sg_rules = self._fake_sg_rules()
        firewall.pre_sg_rules = self._fake_sg_rules()
        firewall.sg_members = self._fake_sg_members()
        firewall.pre_sg_members = firewall.sg_members

    def _prepare_rules_and_members_for_removal(self):
        self._setup_fake_firewall_members_and_rules(self.firewall)
        self.firewall.pre_sg_members[OTHER_SGID] = (
            self.firewall.pre_sg_members[FAKE_SGID])

    def test_determine_remote_sgs_to_remove(self):
        self._prepare_rules_and_members_for_removal()
        ports = [self._fake_port()]

        self.assertEqual(
            {_IPv4: set([OTHER_SGID]), _IPv6: set([OTHER_SGID])},
            self.firewall._determine_remote_sgs_to_remove(ports))

    def test_determine_remote_sgs_to_remove_ipv6_unreferenced(self):
        self._prepare_rules_and_members_for_removal()
        ports = [self._fake_port()]
        self.firewall.sg_rules = self._fake_sg_rules(
            remote_groups={_IPv4: [OTHER_SGID, FAKE_SGID],
                           _IPv6: [FAKE_SGID]})
        self.assertEqual(
            {_IPv4: set(), _IPv6: set([OTHER_SGID])},
            self.firewall._determine_remote_sgs_to_remove(ports))

    def test_get_remote_sg_ids_by_ipversion(self):
        self.firewall.sg_rules = self._fake_sg_rules(
            remote_groups={_IPv4: [FAKE_SGID], _IPv6: [OTHER_SGID]})

        ports = [self._fake_port()]

        self.assertEqual(
            {_IPv4: set([FAKE_SGID]), _IPv6: set([OTHER_SGID])},
            self.firewall._get_remote_sg_ids_sets_by_ipversion(ports))

    def test_get_remote_sg_ids(self):
        self.firewall.sg_rules = self._fake_sg_rules(
            remote_groups={_IPv4: [FAKE_SGID, FAKE_SGID, FAKE_SGID],
                           _IPv6: [OTHER_SGID, OTHER_SGID, OTHER_SGID]})

        port = self._fake_port()

        self.assertEqual(
            {_IPv4: set([FAKE_SGID]), _IPv6: set([OTHER_SGID])},
            self.firewall._get_remote_sg_ids(port))

    def test_determine_sg_rules_to_remove(self):
        self.firewall.pre_sg_rules = self._fake_sg_rules(sg_id=OTHER_SGID)
        ports = [self._fake_port()]

        self.assertEqual(set([OTHER_SGID]),
                         self.firewall._determine_sg_rules_to_remove(ports))

    def test_get_sg_ids_set_for_ports(self):
        sg_ids = set([FAKE_SGID, OTHER_SGID])
        ports = [self._fake_port(sg_id) for sg_id in sg_ids]

        self.assertEqual(sg_ids,
                         self.firewall._get_sg_ids_set_for_ports(ports))

    def test_clear_sg_members(self):
        self.firewall.sg_members = self._fake_sg_members(
            sg_ids=[FAKE_SGID, OTHER_SGID])
        self.firewall._clear_sg_members(_IPv4, [OTHER_SGID])

        self.assertEqual(0, len(self.firewall.sg_members[OTHER_SGID][_IPv4]))

    def test_remove_unused_sg_members(self):
        self.firewall.sg_members = self._fake_sg_members([FAKE_SGID,
                                                          OTHER_SGID])
        self.firewall.sg_members[FAKE_SGID][_IPv4] = []
        self.firewall.sg_members[FAKE_SGID][_IPv6] = []
        self.firewall.sg_members[OTHER_SGID][_IPv6] = []
        self.firewall._remove_unused_sg_members()

        self.assertIn(OTHER_SGID, self.firewall.sg_members)
        self.assertNotIn(FAKE_SGID, self.firewall.sg_members)

    def test_remove_unused_security_group_info_clears_unused_rules(self):
        self._setup_fake_firewall_members_and_rules(self.firewall)
        self.firewall.prepare_port_filter(self._fake_port())

        # create another SG which won't be referenced by any filtered port
        fake_sg_rules = self.firewall.sg_rules['fake_sgid']
        self.firewall.pre_sg_rules[OTHER_SGID] = fake_sg_rules
        self.firewall.sg_rules[OTHER_SGID] = fake_sg_rules

        # call the cleanup function, and check the unused sg_rules are out
        self.firewall._remove_unused_security_group_info()
        self.assertNotIn(OTHER_SGID, self.firewall.sg_rules)

    def test_remove_unused_security_group_info(self):
        self._setup_fake_firewall_members_and_rules(self.firewall)
        # no filtered ports in 'fake_sgid', so all rules and members
        # are not needed and we expect them to be cleaned up
        self.firewall.prepare_port_filter(self._fake_port(OTHER_SGID))
        self.firewall._remove_unused_security_group_info()

        self.assertNotIn(FAKE_SGID, self.firewall.sg_members)

    def test_remove_all_unused_info(self):
        self._setup_fake_firewall_members_and_rules(self.firewall)
        self.firewall.filtered_ports = {}
        self.firewall._remove_unused_security_group_info()
        self.assertFalse(self.firewall.sg_members)
        self.assertFalse(self.firewall.sg_rules)

    def test_prepare_port_filter_with_deleted_member(self):
        self.firewall.sg_rules = self._fake_sg_rules()
        self.firewall.pre_sg_rules = self._fake_sg_rules()
        self.firewall.sg_members = {'fake_sgid': {
            'IPv4': [
                '10.0.0.1', '10.0.0.3', '10.0.0.4', '10.0.0.5'],
            'IPv6': ['fe80::1']}}
        self.firewall.pre_sg_members = {'fake_sgid': {
            'IPv4': ['10.0.0.2'],
            'IPv6': ['fe80::1']}}
        self.firewall.prepare_port_filter(self._fake_port())
        calls = [
            mock.call.set_members('fake_sgid', 'IPv4',
                                  ['10.0.0.1', '10.0.0.3', '10.0.0.4',
                                   '10.0.0.5']),
            mock.call.set_members('fake_sgid', 'IPv6', ['fe80::1'])]

        self.firewall.ipset.assert_has_calls(calls, True)

    def test_remove_port_filter_with_destroy_ipset_chain(self):
        self.firewall.sg_rules = self._fake_sg_rules()
        port = self._fake_port()
        self.firewall.sg_members = {'fake_sgid': {
            'IPv4': ['10.0.0.1'],
            'IPv6': ['fe80::1']}}
        self.firewall.pre_sg_members = {'fake_sgid': {
            'IPv4': [],
            'IPv6': []}}
        self.firewall.prepare_port_filter(port)
        self.firewall.filter_defer_apply_on()
        self.firewall.sg_members = {'fake_sgid': {
            'IPv4': [],
            'IPv6': []}}
        self.firewall.pre_sg_members = {'fake_sgid': {
            'IPv4': ['10.0.0.1'],
            'IPv6': ['fe80::1']}}
        self.firewall.remove_port_filter(port)
        self.firewall.filter_defer_apply_off()
        calls = [
            mock.call.set_members('fake_sgid', 'IPv4', ['10.0.0.1']),
            mock.call.set_members('fake_sgid', 'IPv6', ['fe80::1']),
            mock.call.get_name('fake_sgid', 'IPv4'),
            mock.call.set_exists('fake_sgid', 'IPv4'),
            mock.call.get_name('fake_sgid', 'IPv6'),
            mock.call.set_exists('fake_sgid', 'IPv6'),
            mock.call.destroy('fake_sgid', 'IPv4'),
            mock.call.destroy('fake_sgid', 'IPv6')]

        self.firewall.ipset.assert_has_calls(calls, any_order=True)

    def test_prepare_port_filter_with_sg_no_member(self):
        self.firewall.sg_rules = self._fake_sg_rules()
        self.firewall.sg_rules[FAKE_SGID].append(
            {'direction': 'ingress', 'remote_group_id': 'fake_sgid2',
             'ethertype': 'IPv4'})
        self.firewall.sg_rules.update()
        self.firewall.sg_members['fake_sgid'] = {
            'IPv4': ['10.0.0.1', '10.0.0.2'], 'IPv6': ['fe80::1']}
        self.firewall.pre_sg_members = {}
        port = self._fake_port()
        port['security_group_source_groups'].append('fake_sgid2')
        self.firewall.prepare_port_filter(port)
        calls = [mock.call.set_members('fake_sgid', 'IPv4',
                                       ['10.0.0.1', '10.0.0.2']),
                 mock.call.set_members('fake_sgid', 'IPv6', ['fe80::1'])]

        self.firewall.ipset.assert_has_calls(calls, any_order=True)

    def test_filter_defer_apply_off_with_sg_only_ipv6_rule(self):
        self.firewall.sg_rules = self._fake_sg_rules()
        self.firewall.pre_sg_rules = self._fake_sg_rules()
        self.firewall.ipset_chains = {'IPv4fake_sgid': ['10.0.0.2'],
                                      'IPv6fake_sgid': ['fe80::1']}
        self.firewall.sg_members = {'fake_sgid': {
            'IPv4': ['10.0.0.2'],
            'IPv6': ['fe80::1']}}
        self.firewall.pre_sg_members = {'fake_sgid': {
            'IPv4': ['10.0.0.2'],
            'IPv6': ['fe80::1']}}
        self.firewall.sg_rules['fake_sgid'].remove(
            {'direction': 'ingress', 'remote_group_id': 'fake_sgid',
             'ethertype': 'IPv4'})
        self.firewall.sg_rules.update()
        self.firewall._defer_apply = True
        port = self._fake_port()
        self.firewall.filtered_ports['tapfake_dev'] = port
        self.firewall._pre_defer_filtered_ports = {}
        self.firewall._pre_defer_unfiltered_ports = {}
        self.firewall.filter_defer_apply_off()
        calls = [mock.call.destroy('fake_sgid', 'IPv4')]

        self.firewall.ipset.assert_has_calls(calls, True)

    def test_sg_rule_expansion_with_remote_ips(self):
        other_ips = ['10.0.0.2', '10.0.0.3', '10.0.0.4']
        self.firewall.sg_members = {'fake_sgid': {
            'IPv4': [FAKE_IP['IPv4']] + other_ips,
            'IPv6': [FAKE_IP['IPv6']]}}

        port = self._fake_port()
        rule = self._fake_sg_rule_for_ethertype(_IPv4, FAKE_SGID)
        rules = self.firewall._expand_sg_rule_with_remote_ips(
            rule, port, 'ingress')
        self.assertEqual(list(rules),
                         [dict(list(rule.items()) +
                               [('source_ip_prefix', '%s/32' % ip)])
                          for ip in other_ips])

    def test_build_ipv4v6_mac_ip_list(self):
        mac_oth = 'ffff-ffff-ffff'
        mac_unix = 'ff:ff:ff:ff:ff:ff'
        ipv4 = FAKE_IP['IPv4']
        ipv6 = FAKE_IP['IPv6']
        fake_ipv4_pair = []
        fake_ipv4_pair.append((mac_unix, ipv4))
        fake_ipv6_pair = []
        fake_ipv6_pair.append((mac_unix, ipv6))

        mac_ipv4_pairs = []
        mac_ipv6_pairs = []

        self.firewall._build_ipv4v6_mac_ip_list(mac_oth, ipv4,
                                                mac_ipv4_pairs, mac_ipv6_pairs)
        self.assertEqual(fake_ipv4_pair, mac_ipv4_pairs)
        self.firewall._build_ipv4v6_mac_ip_list(mac_oth, ipv6,
                                                mac_ipv4_pairs, mac_ipv6_pairs)
        self.assertEqual(fake_ipv6_pair, mac_ipv6_pairs)

    def test_update_ipset_members(self):
        self.firewall.sg_members[FAKE_SGID][_IPv4] = []
        self.firewall.sg_members[FAKE_SGID][_IPv6] = []
        sg_info = {constants.IPv4: [FAKE_SGID]}
        self.firewall._update_ipset_members(sg_info)
        calls = [mock.call.set_members(FAKE_SGID, constants.IPv4, [])]
        self.firewall.ipset.assert_has_calls(calls)
