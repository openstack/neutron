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
from oslo.config import cfg

from neutron.agent.common import config as a_cfg
from neutron.agent.linux import iptables_firewall
from neutron.agent import securitygroups_rpc as sg_cfg
from neutron.common import constants
from neutron.tests import base
from neutron.tests.unit import test_api_v2


_uuid = test_api_v2._uuid
FAKE_PREFIX = {'IPv4': '10.0.0.0/24',
               'IPv6': 'fe80::/48'}
FAKE_IP = {'IPv4': '10.0.0.1',
           'IPv6': 'fe80::1'}

TEST_IP_RANGE = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4',
                 '10.0.0.5', '10.0.0.6', '10.0.0.7', '10.0.0.8',
                 '10.0.0.9', '10.0.0.10']


class BaseIptablesFirewallTestCase(base.BaseTestCase):
    def setUp(self):
        super(BaseIptablesFirewallTestCase, self).setUp()
        cfg.CONF.register_opts(a_cfg.ROOT_HELPER_OPTS, 'AGENT')
        cfg.CONF.register_opts(sg_cfg.security_group_opts, 'SECURITYGROUP')
        self.utils_exec_p = mock.patch(
            'neutron.agent.linux.utils.execute')
        self.utils_exec = self.utils_exec_p.start()
        self.iptables_cls_p = mock.patch(
            'neutron.agent.linux.iptables_manager.IptablesManager')
        iptables_cls = self.iptables_cls_p.start()
        self.iptables_inst = mock.Mock()
        self.v4filter_inst = mock.Mock()
        self.v6filter_inst = mock.Mock()
        self.iptables_inst.ipv4 = {'filter': self.v4filter_inst}
        self.iptables_inst.ipv6 = {'filter': self.v6filter_inst}
        iptables_cls.return_value = self.iptables_inst

        self.firewall = iptables_firewall.IptablesFirewallDriver()
        self.firewall.iptables = self.iptables_inst


class IptablesFirewallTestCase(BaseIptablesFirewallTestCase):

    def _fake_port(self):
        return {'device': 'tapfake_dev',
                'mac_address': 'ff:ff:ff:ff:ff:ff',
                'fixed_ips': [FAKE_IP['IPv4'],
                              FAKE_IP['IPv6']]}

    def test_prepare_port_filter_with_no_sg(self):
        port = self._fake_port()
        self.firewall.prepare_port_filter(port)
        calls = [mock.call.add_chain('sg-fallback'),
                 mock.call.add_rule('sg-fallback', '-j DROP'),
                 mock.call.ensure_remove_chain('sg-chain'),
                 mock.call.add_chain('sg-chain'),
                 mock.call.add_chain('ifake_dev'),
                 mock.call.add_rule('FORWARD',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $sg-chain'),
                 mock.call.add_rule('sg-chain',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $ifake_dev'),
                 mock.call.add_rule(
                     'ifake_dev', '-m state --state INVALID -j DROP'),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN'),
                 mock.call.add_rule('ifake_dev', '-j $sg-fallback'),
                 mock.call.add_chain('ofake_dev'),
                 mock.call.add_rule('FORWARD',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $sg-chain'),
                 mock.call.add_rule('sg-chain',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $ofake_dev'),
                 mock.call.add_rule('INPUT',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $ofake_dev'),
                 mock.call.add_chain('sfake_dev'),
                 mock.call.add_rule(
                     'sfake_dev', '-m mac --mac-source ff:ff:ff:ff:ff:ff '
                     '-s 10.0.0.1 -j RETURN'),
                 mock.call.add_rule('sfake_dev', '-j DROP'),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 68 --dport 67 -j RETURN'),
                 mock.call.add_rule('ofake_dev', '-j $sfake_dev'),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 67 --dport 68 -j DROP'),
                 mock.call.add_rule(
                     'ofake_dev', '-m state --state INVALID -j DROP'),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN'),
                 mock.call.add_rule('ofake_dev', '-j $sg-fallback'),
                 mock.call.add_rule('sg-chain', '-j ACCEPT')]

        self.v4filter_inst.assert_has_calls(calls)

    def test_filter_ipv4_ingress(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress'}
        ingress = mock.call.add_rule('ifake_dev', '-j RETURN')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule('ifake_dev', '-s %s -j RETURN' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_tcp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'tcp'}
        ingress = mock.call.add_rule('ifake_dev', '-p tcp -m tcp -j RETURN')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_tcp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'tcp',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-s %s -p tcp -m tcp -j RETURN' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_icmp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'icmp'}
        ingress = mock.call.add_rule('ifake_dev', '-p icmp -j RETURN')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_icmp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'icmp',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule(
            'ifake_dev', '-s %s -p icmp -j RETURN' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_tcp_port(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 10}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-p tcp -m tcp --dport 10 -j RETURN')
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
            '-p tcp -m tcp -m multiport --dports 10:100 -j RETURN')
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
            '-j RETURN' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_udp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'udp'}
        ingress = mock.call.add_rule('ifake_dev', '-p udp -m udp -j RETURN')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_udp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'udp',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-s %s -p udp -m udp -j RETURN' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_ingress_udp_port(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'ingress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 10}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-p udp -m udp --dport 10 -j RETURN')
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
            '-p udp -m udp -m multiport --dports 10:100 -j RETURN')
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
            '-j RETURN' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress'}
        egress = mock.call.add_rule('ofake_dev', '-j RETURN')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule('ofake_dev', '-s %s -j RETURN' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_tcp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'tcp'}
        egress = mock.call.add_rule('ofake_dev', '-p tcp -m tcp -j RETURN')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_tcp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'tcp',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule('ofake_dev',
                                    '-s %s -p tcp -m tcp -j RETURN' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_icmp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'icmp'}
        egress = mock.call.add_rule('ofake_dev', '-p icmp -j RETURN')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_icmp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'icmp',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev', '-s %s -p icmp -j RETURN' % prefix)
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
            '-s %s -p icmp --icmp-type 8 -j RETURN' % prefix)
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
            '-s %s -p icmp --icmp-type echo-request -j RETURN' % prefix)
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
            '-s %s -p icmp --icmp-type 8/0 -j RETURN' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_tcp_port(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 10}
        egress = mock.call.add_rule('ofake_dev',
                                    '-p tcp -m tcp --dport 10 -j RETURN')
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
            '-p tcp -m tcp -m multiport --dports 10:100 -j RETURN')
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
            '-j RETURN' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_udp(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'udp'}
        egress = mock.call.add_rule('ofake_dev', '-p udp -m udp -j RETURN')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_udp_prefix(self):
        prefix = FAKE_PREFIX['IPv4']
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'udp',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule('ofake_dev',
                                    '-s %s -p udp -m udp -j RETURN' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv4_egress_udp_port(self):
        rule = {'ethertype': 'IPv4',
                'direction': 'egress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 10}
        egress = mock.call.add_rule('ofake_dev',
                                    '-p udp -m udp --dport 10 -j RETURN')
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
            '-p udp -m udp -m multiport --dports 10:100 -j RETURN')
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
            '-j RETURN' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress'}
        ingress = mock.call.add_rule('ifake_dev', '-j RETURN')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule('ifake_dev', '-s %s -j RETURN' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_tcp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'tcp'}
        ingress = mock.call.add_rule('ifake_dev', '-p tcp -m tcp -j RETURN')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_tcp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'tcp',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-s %s -p tcp -m tcp -j RETURN' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_tcp_port(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 10}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-p tcp -m tcp --dport 10 -j RETURN')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_icmp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'icmp'}
        ingress = mock.call.add_rule('ifake_dev', '-p icmpv6 -j RETURN')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_icmp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'icmp',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule(
            'ifake_dev', '-s %s -p icmpv6 -j RETURN' % prefix)
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
            '-p tcp -m tcp -m multiport --dports 10:100 -j RETURN')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

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
            '-j RETURN' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_udp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'udp'}
        ingress = mock.call.add_rule('ifake_dev', '-p udp -m udp -j RETURN')
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_udp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'udp',
                'source_ip_prefix': prefix}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-s %s -p udp -m udp -j RETURN' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_ingress_udp_port(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'ingress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 10}
        ingress = mock.call.add_rule('ifake_dev',
                                     '-p udp -m udp --dport 10 -j RETURN')
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
            '-p udp -m udp -m multiport --dports 10:100 -j RETURN')
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
            '-j RETURN' % prefix)
        egress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress'}
        egress = mock.call.add_rule('ofake_dev', '-j RETURN')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule('ofake_dev', '-s %s -j RETURN' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_tcp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'tcp'}
        egress = mock.call.add_rule('ofake_dev', '-p tcp -m tcp -j RETURN')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_tcp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'tcp',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule('ofake_dev',
                                    '-s %s -p tcp -m tcp -j RETURN' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_icmp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'icmp'}
        egress = mock.call.add_rule('ofake_dev', '-p icmpv6 -j RETURN')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_icmp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'icmp',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule(
            'ofake_dev', '-s %s -p icmpv6 -j RETURN' % prefix)
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
            '-s %s -p icmpv6 --icmpv6-type 8 -j RETURN' % prefix)
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
            '-s %s -p icmpv6 --icmpv6-type echo-request -j RETURN' % prefix)
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
            '-s %s -p icmpv6 --icmpv6-type 8/0 -j RETURN' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_tcp_port(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'tcp',
                'port_range_min': 10,
                'port_range_max': 10}
        egress = mock.call.add_rule('ofake_dev',
                                    '-p tcp -m tcp --dport 10 -j RETURN')
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
            '-p tcp -m tcp -m multiport --dports 10:100 -j RETURN')
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
            '-j RETURN' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_udp(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'udp'}
        egress = mock.call.add_rule('ofake_dev', '-p udp -m udp -j RETURN')
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_udp_prefix(self):
        prefix = FAKE_PREFIX['IPv6']
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'udp',
                'source_ip_prefix': prefix}
        egress = mock.call.add_rule('ofake_dev',
                                    '-s %s -p udp -m udp -j RETURN' % prefix)
        ingress = None
        self._test_prepare_port_filter(rule, ingress, egress)

    def test_filter_ipv6_egress_udp_port(self):
        rule = {'ethertype': 'IPv6',
                'direction': 'egress',
                'protocol': 'udp',
                'port_range_min': 10,
                'port_range_max': 10}
        egress = mock.call.add_rule('ofake_dev',
                                    '-p udp -m udp --dport 10 -j RETURN')
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
            '-p udp -m udp -m multiport --dports 10:100 -j RETURN')
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
            '-j RETURN' % prefix)
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
            '-p udp -m udp --sport 68 --dport 67 -j RETURN')]

        if ethertype == 'IPv6':
            filter_inst = self.v6filter_inst

            dhcp_rule = [mock.call.add_rule('ofake_dev',
                                            '-p icmpv6 -j RETURN'),
                         mock.call.add_rule('ofake_dev', '-p udp -m udp '
                                            '--sport 546 --dport 547 '
                                            '-j RETURN')]
        sg = [rule]
        port['security_group_rules'] = sg
        self.firewall.prepare_port_filter(port)
        calls = [mock.call.add_chain('sg-fallback'),
                 mock.call.add_rule('sg-fallback', '-j DROP'),
                 mock.call.ensure_remove_chain('sg-chain'),
                 mock.call.add_chain('sg-chain'),
                 mock.call.add_chain('ifake_dev'),
                 mock.call.add_rule('FORWARD',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $sg-chain'),
                 mock.call.add_rule('sg-chain',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $ifake_dev'),
                 ]
        if ethertype == 'IPv6':
            for icmp6_type in constants.ICMPV6_ALLOWED_TYPES:
                calls.append(
                    mock.call.add_rule('ifake_dev',
                                       '-p icmpv6 --icmpv6-type %s -j RETURN' %
                                       icmp6_type))
        calls += [mock.call.add_rule('ifake_dev',
                                     '-m state --state INVALID -j DROP'),
                  mock.call.add_rule(
                      'ifake_dev',
                      '-m state --state RELATED,ESTABLISHED -j RETURN')]

        if ingress_expected_call:
            calls.append(ingress_expected_call)

        calls += [mock.call.add_rule('ifake_dev', '-j $sg-fallback'),
                  mock.call.add_chain('ofake_dev'),
                  mock.call.add_rule('FORWARD',
                                     '-m physdev --physdev-in tapfake_dev '
                                     '--physdev-is-bridged '
                                     '-j $sg-chain'),
                  mock.call.add_rule('sg-chain',
                                     '-m physdev --physdev-in tapfake_dev '
                                     '--physdev-is-bridged '
                                     '-j $ofake_dev'),
                  mock.call.add_rule('INPUT',
                                     '-m physdev --physdev-in tapfake_dev '
                                     '--physdev-is-bridged '
                                     '-j $ofake_dev'),
                  mock.call.add_chain('sfake_dev'),
                  mock.call.add_rule(
                      'sfake_dev',
                      '-m mac --mac-source ff:ff:ff:ff:ff:ff -s %s -j RETURN'
                      % prefix),
                  mock.call.add_rule('sfake_dev', '-j DROP')]
        calls += dhcp_rule
        calls.append(mock.call.add_rule('ofake_dev', '-j $sfake_dev'))
        if ethertype == 'IPv4':
            calls.append(mock.call.add_rule(
                'ofake_dev',
                '-p udp -m udp --sport 67 --dport 68 -j DROP'))
        if ethertype == 'IPv6':
            calls.append(mock.call.add_rule(
                'ofake_dev',
                '-p udp -m udp --sport 547 --dport 546 -j DROP'))

        calls += [mock.call.add_rule(
                  'ofake_dev', '-m state --state INVALID -j DROP'),
                  mock.call.add_rule(
                      'ofake_dev',
                      '-m state --state RELATED,ESTABLISHED -j RETURN')]

        if egress_expected_call:
            calls.append(egress_expected_call)

        calls += [mock.call.add_rule('ofake_dev', '-j $sg-fallback'),
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
                 mock.call.add_rule('sg-fallback', '-j DROP'),
                 mock.call.ensure_remove_chain('sg-chain'),
                 mock.call.add_chain('sg-chain'),
                 mock.call.add_chain('ifake_dev'),
                 mock.call.add_rule(
                     'FORWARD',
                     '-m physdev --physdev-out tapfake_dev '
                     '--physdev-is-bridged -j $sg-chain'),
                 mock.call.add_rule(
                     'sg-chain',
                     '-m physdev --physdev-out tapfake_dev '
                     '--physdev-is-bridged -j $ifake_dev'),
                 mock.call.add_rule(
                     'ifake_dev', '-m state --state INVALID -j DROP'),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN'),
                 mock.call.add_rule('ifake_dev', '-j RETURN'),
                 mock.call.add_rule('ifake_dev', '-j $sg-fallback'),
                 mock.call.add_chain('ofake_dev'),
                 mock.call.add_rule(
                     'FORWARD',
                     '-m physdev --physdev-in tapfake_dev '
                     '--physdev-is-bridged -j $sg-chain'),
                 mock.call.add_rule(
                     'sg-chain',
                     '-m physdev --physdev-in tapfake_dev '
                     '--physdev-is-bridged -j $ofake_dev'),
                 mock.call.add_rule(
                     'INPUT',
                     '-m physdev --physdev-in tapfake_dev '
                     '--physdev-is-bridged -j $ofake_dev'),
                 mock.call.add_chain('sfake_dev'),
                 mock.call.add_rule(
                     'sfake_dev',
                     '-m mac --mac-source ff:ff:ff:ff:ff:ff -s 10.0.0.1 '
                     '-j RETURN'),
                 mock.call.add_rule('sfake_dev', '-j DROP'),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 68 --dport 67 -j RETURN'),
                 mock.call.add_rule('ofake_dev', '-j $sfake_dev'),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 67 --dport 68 -j DROP'),
                 mock.call.add_rule(
                     'ofake_dev', '-m state --state INVALID -j DROP'),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN'),
                 mock.call.add_rule('ofake_dev', '-j $sg-fallback'),
                 mock.call.add_rule('sg-chain', '-j ACCEPT'),
                 mock.call.ensure_remove_chain('ifake_dev'),
                 mock.call.ensure_remove_chain('ofake_dev'),
                 mock.call.ensure_remove_chain('sfake_dev'),
                 mock.call.ensure_remove_chain('sg-chain'),
                 mock.call.add_chain('sg-chain'),
                 mock.call.add_chain('ifake_dev'),
                 mock.call.add_rule(
                     'FORWARD',
                     '-m physdev --physdev-out tapfake_dev '
                     '--physdev-is-bridged -j $sg-chain'),
                 mock.call.add_rule(
                     'sg-chain',
                     '-m physdev --physdev-out tapfake_dev '
                     '--physdev-is-bridged -j $ifake_dev'),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state INVALID -j DROP'),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN'),
                 mock.call.add_rule('ifake_dev', '-j $sg-fallback'),
                 mock.call.add_chain('ofake_dev'),
                 mock.call.add_rule(
                     'FORWARD',
                     '-m physdev --physdev-in tapfake_dev '
                     '--physdev-is-bridged -j $sg-chain'),
                 mock.call.add_rule(
                     'sg-chain',
                     '-m physdev --physdev-in tapfake_dev '
                     '--physdev-is-bridged -j $ofake_dev'),
                 mock.call.add_rule(
                     'INPUT',
                     '-m physdev --physdev-in tapfake_dev '
                     '--physdev-is-bridged -j $ofake_dev'),
                 mock.call.add_chain('sfake_dev'),
                 mock.call.add_rule(
                     'sfake_dev',
                     '-m mac --mac-source ff:ff:ff:ff:ff:ff -s 10.0.0.1 '
                     '-j RETURN'),
                 mock.call.add_rule('sfake_dev', '-j DROP'),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 68 --dport 67 -j RETURN'),
                 mock.call.add_rule('ofake_dev', '-j $sfake_dev'),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 67 --dport 68 -j DROP'),
                 mock.call.add_rule(
                     'ofake_dev', '-m state --state INVALID -j DROP'),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN'),
                 mock.call.add_rule('ofake_dev', '-j RETURN'),
                 mock.call.add_rule('ofake_dev', '-j $sg-fallback'),
                 mock.call.add_rule('sg-chain', '-j ACCEPT'),
                 mock.call.ensure_remove_chain('ifake_dev'),
                 mock.call.ensure_remove_chain('ofake_dev'),
                 mock.call.ensure_remove_chain('sfake_dev'),
                 mock.call.ensure_remove_chain('sg-chain'),
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
        chain_applies.assert_has_calls([mock.call.remove({}),
                                        mock.call.setup({'d1': port_prepare}),
                                        mock.call.remove({'d1': port_prepare}),
                                        mock.call.setup({'d1': port_update}),
                                        mock.call.remove({'d1': port_update}),
                                        mock.call.setup({})])

    def test_defer_chain_apply_need_pre_defer_copy(self):
        chain_applies = self._mock_chain_applies()
        port = self._fake_port()
        device2port = {port['device']: port}
        self.firewall.prepare_port_filter(port)
        with self.firewall.defer_apply():
            self.firewall.remove_port_filter(port)
        chain_applies.assert_has_calls([mock.call.remove({}),
                                        mock.call.setup(device2port),
                                        mock.call.remove(device2port),
                                        mock.call.setup({})])

    def test_defer_chain_apply_coalesce_simple(self):
        chain_applies = self._mock_chain_applies()
        port = self._fake_port()
        with self.firewall.defer_apply():
            self.firewall.prepare_port_filter(port)
            self.firewall.update_port_filter(port)
            self.firewall.remove_port_filter(port)
        chain_applies.assert_has_calls([mock.call.remove({}),
                                        mock.call.setup({})])

    def test_defer_chain_apply_coalesce_multiple_ports(self):
        chain_applies = self._mock_chain_applies()
        port1 = {'device': 'd1', 'mac_address': 'mac1'}
        port2 = {'device': 'd2', 'mac_address': 'mac2'}
        device2port = {'d1': port1, 'd2': port2}
        with self.firewall.defer_apply():
            self.firewall.prepare_port_filter(port1)
            self.firewall.prepare_port_filter(port2)
        chain_applies.assert_has_calls([mock.call.remove({}),
                                        mock.call.setup(device2port)])

    def test_ip_spoofing_filter_with_multiple_ips(self):
        port = {'device': 'tapfake_dev',
                'mac_address': 'ff:ff:ff:ff:ff:ff',
                'fixed_ips': ['10.0.0.1', 'fe80::1', '10.0.0.2']}
        self.firewall.prepare_port_filter(port)
        calls = [mock.call.add_chain('sg-fallback'),
                 mock.call.add_rule('sg-fallback', '-j DROP'),
                 mock.call.ensure_remove_chain('sg-chain'),
                 mock.call.add_chain('sg-chain'),
                 mock.call.add_chain('ifake_dev'),
                 mock.call.add_rule('FORWARD',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $sg-chain'),
                 mock.call.add_rule('sg-chain',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $ifake_dev'),
                 mock.call.add_rule(
                     'ifake_dev', '-m state --state INVALID -j DROP'),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN'),
                 mock.call.add_rule('ifake_dev', '-j $sg-fallback'),
                 mock.call.add_chain('ofake_dev'),
                 mock.call.add_rule('FORWARD',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $sg-chain'),
                 mock.call.add_rule('sg-chain',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $ofake_dev'),
                 mock.call.add_rule('INPUT',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $ofake_dev'),
                 mock.call.add_chain('sfake_dev'),
                 mock.call.add_rule(
                     'sfake_dev',
                     '-m mac --mac-source ff:ff:ff:ff:ff:ff -s 10.0.0.1 '
                     '-j RETURN'),
                 mock.call.add_rule(
                     'sfake_dev',
                     '-m mac --mac-source ff:ff:ff:ff:ff:ff -s 10.0.0.2 '
                     '-j RETURN'),
                 mock.call.add_rule('sfake_dev', '-j DROP'),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 68 --dport 67 -j RETURN'),
                 mock.call.add_rule('ofake_dev', '-j $sfake_dev'),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 67 --dport 68 -j DROP'),
                 mock.call.add_rule(
                     'ofake_dev', '-m state --state INVALID -j DROP'),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN'),
                 mock.call.add_rule('ofake_dev', '-j $sg-fallback'),
                 mock.call.add_rule('sg-chain', '-j ACCEPT')]
        self.v4filter_inst.assert_has_calls(calls)

    def test_ip_spoofing_no_fixed_ips(self):
        port = {'device': 'tapfake_dev',
                'mac_address': 'ff:ff:ff:ff:ff:ff',
                'fixed_ips': []}
        self.firewall.prepare_port_filter(port)
        calls = [mock.call.add_chain('sg-fallback'),
                 mock.call.add_rule('sg-fallback', '-j DROP'),
                 mock.call.ensure_remove_chain('sg-chain'),
                 mock.call.add_chain('sg-chain'),
                 mock.call.add_chain('ifake_dev'),
                 mock.call.add_rule('FORWARD',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $sg-chain'),
                 mock.call.add_rule('sg-chain',
                                    '-m physdev --physdev-out tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $ifake_dev'),
                 mock.call.add_rule(
                     'ifake_dev', '-m state --state INVALID -j DROP'),
                 mock.call.add_rule(
                     'ifake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN'),
                 mock.call.add_rule('ifake_dev', '-j $sg-fallback'),
                 mock.call.add_chain('ofake_dev'),
                 mock.call.add_rule('FORWARD',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $sg-chain'),
                 mock.call.add_rule('sg-chain',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $ofake_dev'),
                 mock.call.add_rule('INPUT',
                                    '-m physdev --physdev-in tapfake_dev '
                                    '--physdev-is-bridged '
                                    '-j $ofake_dev'),
                 mock.call.add_chain('sfake_dev'),
                 mock.call.add_rule(
                     'sfake_dev',
                     '-m mac --mac-source ff:ff:ff:ff:ff:ff -j RETURN'),
                 mock.call.add_rule('sfake_dev', '-j DROP'),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 68 --dport 67 -j RETURN'),
                 mock.call.add_rule('ofake_dev', '-j $sfake_dev'),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-p udp -m udp --sport 67 --dport 68 -j DROP'),
                 mock.call.add_rule(
                     'ofake_dev', '-m state --state INVALID -j DROP'),
                 mock.call.add_rule(
                     'ofake_dev',
                     '-m state --state RELATED,ESTABLISHED -j RETURN'),
                 mock.call.add_rule('ofake_dev', '-j $sg-fallback'),
                 mock.call.add_rule('sg-chain', '-j ACCEPT')]
        self.v4filter_inst.assert_has_calls(calls)


class IptablesFirewallEnhancedIpsetTestCase(BaseIptablesFirewallTestCase):
    def setUp(self):
        super(IptablesFirewallEnhancedIpsetTestCase, self).setUp()
        self.firewall.ipset = mock.Mock()

    def _fake_port(self):
        return {'device': 'tapfake_dev',
                'mac_address': 'ff:ff:ff:ff:ff:ff',
                'fixed_ips': [FAKE_IP['IPv4'],
                              FAKE_IP['IPv6']],
                'security_groups': ['fake_sgid'],
                'security_group_source_groups': ['fake_sgid']}

    def _fake_sg_rule(self):
        return {'fake_sgid': [
            {'direction': 'ingress', 'remote_group_id': 'fake_sgid'}]}

    def test_prepare_port_filter_with_default_sg(self):
        self.firewall.sg_rules = self._fake_sg_rule()
        self.firewall.sg_members = {'fake_sgid': {
            'IPv4': ['10.0.0.1', '10.0.0.2'], 'IPv6': ['fe80::1']}}
        self.firewall.pre_sg_members = {}
        port = self._fake_port()
        self.firewall.prepare_port_filter(port)
        calls = [mock.call.create_ipset_chain('IPv4fake_sgid', 'IPv4'),
                 mock.call.refresh_ipset_chain_by_name(
                     'IPv4fake_sgid', ['10.0.0.1', '10.0.0.2'], 'IPv4'),
                 mock.call.create_ipset_chain('IPv6fake_sgid', 'IPv6'),
                 mock.call.refresh_ipset_chain_by_name(
                     'IPv6fake_sgid', ['fe80::1'], 'IPv6')]

        self.firewall.ipset.assert_has_calls(calls)

    def test_prepare_port_filter_with_add_members_beyond_4(self):
        self.firewall.sg_rules = self._fake_sg_rule()
        self.firewall.sg_members = {'fake_sgid': {
            'IPv4': TEST_IP_RANGE[:5],
            'IPv6': ['fe80::1']}}
        self.firewall.pre_sg_members = {}
        port = self._fake_port()
        self.firewall.prepare_port_filter(port)
        calls = [mock.call.create_ipset_chain('IPv4fake_sgid', 'IPv4'),
                 mock.call.refresh_ipset_chain_by_name(
                     'IPv4fake_sgid', TEST_IP_RANGE[:5], 'IPv4'),
                 mock.call.create_ipset_chain('IPv6fake_sgid', 'IPv6'),
                 mock.call.refresh_ipset_chain_by_name(
                     'IPv6fake_sgid', ['fe80::1'], 'IPv6')]

        self.firewall.ipset.assert_has_calls(calls)

    def test_prepare_port_filter_with_ipset_chain_exist(self):
        self.firewall.sg_rules = self._fake_sg_rule()
        self.firewall.ipset_chains = {'IPv4fake_sgid': ['10.0.0.2']}
        self.firewall.sg_members = {'fake_sgid': {
            'IPv4': TEST_IP_RANGE[:5],
            'IPv6': ['fe80::1']}}
        self.firewall.pre_sg_members = {'fake_sgid': {
            'IPv4': ['10.0.0.2'],
            'IPv6': ['fe80::1']}}
        port = self._fake_port()
        self.firewall.prepare_port_filter(port)
        calls = [
            mock.call.add_member_to_ipset_chain('IPv4fake_sgid', '10.0.0.1'),
            mock.call.add_member_to_ipset_chain('IPv4fake_sgid', '10.0.0.3'),
            mock.call.add_member_to_ipset_chain('IPv4fake_sgid', '10.0.0.4'),
            mock.call.add_member_to_ipset_chain('IPv4fake_sgid', '10.0.0.5'),
            mock.call.create_ipset_chain('IPv6fake_sgid', 'IPv6'),
            mock.call.refresh_ipset_chain_by_name(
                'IPv6fake_sgid', ['fe80::1'], 'IPv6')]

        self.firewall.ipset.assert_has_calls(calls, True)

    def test_prepare_port_filter_with_del_member(self):
        self.firewall.sg_rules = self._fake_sg_rule()
        self.firewall.ipset_chains = {'IPv4fake_sgid': ['10.0.0.2']}
        self.firewall.sg_members = {'fake_sgid': {
            'IPv4': [
                '10.0.0.1', '10.0.0.3', '10.0.0.4', '10.0.0.5'],
            'IPv6': ['fe80::1']}}
        self.firewall.pre_sg_members = {'fake_sgid': {
            'IPv4': ['10.0.0.2'],
            'IPv6': ['fe80::1']}}
        port = self._fake_port()
        self.firewall.prepare_port_filter(port)
        calls = [
            mock.call.add_member_to_ipset_chain('IPv4fake_sgid', '10.0.0.1'),
            mock.call.add_member_to_ipset_chain('IPv4fake_sgid', '10.0.0.3'),
            mock.call.add_member_to_ipset_chain('IPv4fake_sgid', '10.0.0.4'),
            mock.call.add_member_to_ipset_chain('IPv4fake_sgid', '10.0.0.5'),
            mock.call.del_ipset_chain_member('IPv4fake_sgid', '10.0.0.2'),
            mock.call.create_ipset_chain('IPv6fake_sgid', 'IPv6'),
            mock.call.refresh_ipset_chain_by_name(
                'IPv6fake_sgid', ['fe80::1'], 'IPv6')]

        self.firewall.ipset.assert_has_calls(calls, True)

    def test_prepare_port_filter_change_beyond_9(self):
        self.firewall.sg_rules = self._fake_sg_rule()
        self.firewall.ipset_chains = {'IPv4fake_sgid': TEST_IP_RANGE[5:]}
        self.firewall.sg_members = {'fake_sgid': {
            'IPv4': TEST_IP_RANGE[:5],
            'IPv6': ['fe80::1']}}
        self.firewall.pre_sg_members = {'fake_sgid': {
            'IPv4': TEST_IP_RANGE[5:],
            'IPv6': ['fe80::1']}}
        port = self._fake_port()
        self.firewall.prepare_port_filter(port)
        calls = [
            mock.call.refresh_ipset_chain_by_name('IPv4fake_sgid',
                                                  TEST_IP_RANGE[:5], 'IPv4'),
            mock.call.create_ipset_chain('IPv6fake_sgid', 'IPv6'),
            mock.call.refresh_ipset_chain_by_name(
                'IPv6fake_sgid', ['fe80::1'], 'IPv6')]

        self.firewall.ipset.assert_has_calls(calls)

    def test_prepare_port_filter_with_sg_no_member(self):
        self.firewall.sg_rules = self._fake_sg_rule()
        self.firewall.sg_rules['fake_sgid'].append(
            {'direction': 'ingress', 'remote_group_id': 'fake_sgid2'})
        self.firewall.sg_rules.update()
        self.firewall.sg_members = {'fake_sgid': {
            'IPv4': ['10.0.0.1', '10.0.0.2'], 'IPv6': ['fe80::1']}}
        self.firewall.pre_sg_members = {}
        port = self._fake_port()
        port['security_group_source_groups'].append('fake_sgid2')
        self.firewall.prepare_port_filter(port)
        calls = [mock.call.create_ipset_chain('IPv4fake_sgid', 'IPv4'),
                 mock.call.refresh_ipset_chain_by_name(
                     'IPv4fake_sgid', ['10.0.0.1', '10.0.0.2'], 'IPv4'),
                 mock.call.create_ipset_chain('IPv6fake_sgid', 'IPv6'),
                 mock.call.refresh_ipset_chain_by_name(
                     'IPv6fake_sgid', ['fe80::1'], 'IPv6')]

        self.firewall.ipset.assert_has_calls(calls)
