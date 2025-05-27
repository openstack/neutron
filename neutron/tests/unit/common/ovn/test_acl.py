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

from unittest import mock

from neutron_lib import constants as const
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.common.ovn import acl as ovn_acl
from neutron.common.ovn import utils as ovn_utils
from neutron.conf.agent import securitygroups_rpc
from neutron.tests import base
from neutron.tests.unit import fake_resources as fakes


class TestACLs(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.driver = mock.Mock()
        self.driver.nb_ovn = fakes.FakeOvsdbNbOvnIdl()
        self.plugin = fakes.FakePlugin()
        self.admin_context = mock.Mock()
        self.fake_port = fakes.FakePort.create_one_port({
            'id': 'fake_port_id1',
            'network_id': 'network_id1',
            'fixed_ips': [{'subnet_id': 'subnet_id1',
                           'ip_address': '1.1.1.1'}],
        }).info()
        self.fake_subnet = fakes.FakeSubnet.create_one_subnet({
            'id': 'subnet_id1',
            'ip_version': 4,
            'cidr': '1.1.1.0/24',
        }).info()
        mock_row_by_value = mock.patch.object(idlutils, 'row_by_value')
        mock_row_by_value.start()
        self.addCleanup(mock_row_by_value.stop)
        mock_acl_columns_severity = mock.patch.object(
            ovn_acl, '_acl_columns_name_severity_supported', return_value=True)
        mock_acl_columns_severity.start()
        self.addCleanup(mock_acl_columns_severity.stop)
        securitygroups_rpc.register_securitygroups_opts()

    def test_drop_all_ip_traffic_for_port(self):
        acls = ovn_acl.drop_all_ip_traffic_for_port(self.fake_port)
        acl_to_lport = {'action': 'drop', 'direction': 'to-lport',
                        'external_ids': {'neutron:lport':
                                         self.fake_port['id']},
                        'log': False, 'name': [], 'severity': [],
                        'lport': self.fake_port['id'],
                        'lswitch': 'neutron-network_id1',
                        'match': 'outport == "fake_port_id1" && ip',
                        'priority': 1001,
                        'meter': []}
        acl_from_lport = {'action': 'drop', 'direction': 'from-lport',
                          'external_ids': {'neutron:lport':
                                           self.fake_port['id']},
                          'log': False, 'name': [], 'severity': [],
                          'lport': self.fake_port['id'],
                          'lswitch': 'neutron-network_id1',
                          'match': 'inport == "fake_port_id1" && ip',
                          'priority': 1001,
                          'meter': []}
        for acl in acls:
            if 'to-lport' in acl.values():
                self.assertEqual(acl_to_lport, acl)
            if 'from-lport' in acl.values():
                self.assertEqual(acl_from_lport, acl)

    def test_acl_protocol_and_ports_for_tcp_udp_and_sctp_number(self):
        sg_rule = {'port_range_min': None,
                   'port_range_max': None}

        sg_rule['protocol'] = str(const.PROTO_NUM_TCP)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, None)
        self.assertEqual(' && tcp', match)

        sg_rule['protocol'] = str(const.PROTO_NUM_UDP)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, None)
        self.assertEqual(' && udp', match)

        sg_rule['protocol'] = str(const.PROTO_NUM_SCTP)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, None)
        self.assertEqual(' && sctp', match)

    def test_acl_protocol_and_ports_for_tcp_udp_and_sctp_number_one(self):
        sg_rule = {'port_range_min': 22,
                   'port_range_max': 22}

        sg_rule['protocol'] = str(const.PROTO_NUM_TCP)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, None)
        self.assertEqual(' && tcp && tcp.dst == 22', match)

        sg_rule['protocol'] = str(const.PROTO_NUM_UDP)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, None)
        self.assertEqual(' && udp && udp.dst == 22', match)

        sg_rule['protocol'] = str(const.PROTO_NUM_SCTP)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, None)
        self.assertEqual(' && sctp && sctp.dst == 22', match)

    def test_acl_protocol_and_ports_for_tcp_udp_and_sctp_number_range(self):
        sg_rule = {'port_range_min': 21,
                   'port_range_max': 23}

        sg_rule['protocol'] = str(const.PROTO_NUM_TCP)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, None)
        self.assertEqual(' && tcp && tcp.dst >= 21 && tcp.dst <= 23', match)

        sg_rule['protocol'] = str(const.PROTO_NUM_UDP)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, None)
        self.assertEqual(' && udp && udp.dst >= 21 && udp.dst <= 23', match)

        sg_rule['protocol'] = str(const.PROTO_NUM_SCTP)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, None)
        self.assertEqual(' && sctp && sctp.dst >= 21 && sctp.dst <= 23', match)

    def test_acl_protocol_and_ports_for_ipv6_icmp_protocol(self):
        sg_rule = {'port_range_min': None,
                   'port_range_max': None}
        icmp = 'icmp6'
        expected_match = ' && icmp6'

        sg_rule['protocol'] = const.PROTO_NAME_ICMP
        match = ovn_acl.acl_protocol_and_ports(sg_rule, icmp)
        self.assertEqual(expected_match, match)

        sg_rule['protocol'] = str(const.PROTO_NUM_ICMP)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, icmp)
        self.assertEqual(expected_match, match)

        sg_rule['protocol'] = const.PROTO_NAME_IPV6_ICMP
        match = ovn_acl.acl_protocol_and_ports(sg_rule, icmp)
        self.assertEqual(expected_match, match)

        sg_rule['protocol'] = const.PROTO_NAME_IPV6_ICMP_LEGACY
        match = ovn_acl.acl_protocol_and_ports(sg_rule, icmp)
        self.assertEqual(expected_match, match)

        sg_rule['protocol'] = str(const.PROTO_NUM_IPV6_ICMP)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, icmp)
        self.assertEqual(expected_match, match)

    def test_acl_protocol_and_ports_for_icmp4_and_icmp6_port_range(self):
        match_list = [
            (None, None, ' && icmp4'),
            (0, None, ' && icmp4 && icmp4.type == 0'),
            (0, 0, ' && icmp4 && icmp4.type == 0 && icmp4.code == 0'),
            (0, 5, ' && icmp4 && icmp4.type == 0 && icmp4.code == 5')]
        v6_match_list = [
            (None, None, ' && icmp6'),
            (133, None, ' && icmp6 && icmp6.type == 133'),
            (1, 1, ' && icmp6 && icmp6.type == 1 && icmp6.code == 1'),
            (138, 1, ' && icmp6 && icmp6.type == 138 && icmp6.code == 1')]

        sg_rule = {'protocol': const.PROTO_NAME_ICMP}
        icmp = 'icmp4'
        for pmin, pmax, expected_match in match_list:
            sg_rule['port_range_min'] = pmin
            sg_rule['port_range_max'] = pmax
            match = ovn_acl.acl_protocol_and_ports(sg_rule, icmp)
            self.assertEqual(expected_match, match)

        sg_rule = {'protocol': const.PROTO_NAME_IPV6_ICMP}
        icmp = 'icmp6'
        for pmin, pmax, expected_match in v6_match_list:
            sg_rule['port_range_min'] = pmin
            sg_rule['port_range_max'] = pmax
            match = ovn_acl.acl_protocol_and_ports(sg_rule, icmp)
            self.assertEqual(expected_match, match)

    def test_acl_protocol_and_ports_protocol_not_supported(self):
        sg_rule = {'port_range_min': None,
                   'port_range_max': None}
        sg_rule['protocol'] = '1234567'
        self.assertRaises(ovn_acl.ProtocolNotSupported,
                          ovn_acl.acl_protocol_and_ports, sg_rule, None)

    def test_acl_protocol_and_ports_protocol_range(self):
        sg_rule = {'port_range_min': None,
                   'port_range_max': None}

        # For more common protocols such as TCP, UDP and ICMP, we
        # prefer to use the protocol name in the match string instead of
        # the protocol number (e.g: the word "tcp" instead of "ip.proto
        # == 6"). This improves the readability/debbugability when
        # troubleshooting the ACLs
        skip_protos = (const.PROTO_NUM_TCP, const.PROTO_NUM_UDP,
                       const.PROTO_NUM_SCTP, const.PROTO_NUM_ICMP,
                       const.PROTO_NUM_IPV6_ICMP)

        for proto in range(256):
            if proto in skip_protos:
                continue
            sg_rule['protocol'] = str(proto)
            match = ovn_acl.acl_protocol_and_ports(sg_rule, None)
            self.assertEqual(' && ip.proto == %s' % proto, match)

    def test_acl_protocol_and_ports_name_to_number(self):
        sg_rule = {'port_range_min': None,
                   'port_range_max': None}

        sg_rule['protocol'] = str(const.PROTO_NAME_OSPF)
        match = ovn_acl.acl_protocol_and_ports(sg_rule, None)
        self.assertEqual(' && ip.proto == 89', match)

    def test_acl_direction(self):
        sg_rule = fakes.FakeSecurityGroupRule.create_one_security_group_rule({
            'direction': 'ingress'
        }).info()

        match = ovn_acl.acl_direction(sg_rule, self.fake_port)
        self.assertEqual('outport == "' + self.fake_port['id'] + '"', match)

        sg_rule['direction'] = 'egress'
        match = ovn_acl.acl_direction(sg_rule, self.fake_port)
        self.assertEqual('inport == "' + self.fake_port['id'] + '"', match)

    def test_acl_ethertype(self):
        sg_rule = fakes.FakeSecurityGroupRule.create_one_security_group_rule({
            'ethertype': 'IPv4'
        }).info()

        match, ip_version, icmp = ovn_acl.acl_ethertype(sg_rule)
        self.assertEqual(' && ip4', match)
        self.assertEqual('ip4', ip_version)
        self.assertEqual('icmp4', icmp)

        sg_rule['ethertype'] = 'IPv6'
        match, ip_version, icmp = ovn_acl.acl_ethertype(sg_rule)
        self.assertEqual(' && ip6', match)
        self.assertEqual('ip6', ip_version)
        self.assertEqual('icmp6', icmp)

        sg_rule['ethertype'] = 'IPv10'
        match, ip_version, icmp = ovn_acl.acl_ethertype(sg_rule)
        self.assertEqual('', match)
        self.assertIsNone(ip_version)
        self.assertIsNone(icmp)

    def test_acl_remote_ip_prefix(self):
        sg_rule = fakes.FakeSecurityGroupRule.create_one_security_group_rule({
            'direction': 'ingress',
            'remote_ip_prefix': None
        }).info()
        ip_version = 'ip4'
        remote_ip_prefix = '10.10.0.0/24'
        normalized_cidr = '10.10.0.0/24'

        match = ovn_acl.acl_remote_ip_prefix(sg_rule, ip_version)
        self.assertEqual('', match)

        sg_rule['remote_ip_prefix'] = remote_ip_prefix
        sg_rule['normalized_cidr'] = normalized_cidr
        match = ovn_acl.acl_remote_ip_prefix(sg_rule, ip_version)
        expected_match = ' && {}.src == {}'.format(
            ip_version, remote_ip_prefix)
        self.assertEqual(expected_match, match)

        sg_rule['direction'] = 'egress'
        match = ovn_acl.acl_remote_ip_prefix(sg_rule, ip_version)
        expected_match = ' && {}.dst == {}'.format(
            ip_version, remote_ip_prefix)
        self.assertEqual(expected_match, match)

    def test_acl_remote_ip_prefix_not_normalized(self):
        normalized_ip_prefix = '10.10.10.128/26'
        ip_version = 'ip4'
        sg_rule = fakes.FakeSecurityGroupRule.create_one_security_group_rule({
            'direction': 'ingress',
            'remote_ip_prefix': '10.10.10.175/26',
            'normalized_cidr': normalized_ip_prefix
        }).info()

        match = ovn_acl.acl_remote_ip_prefix(sg_rule, ip_version)
        expected_match = ' && {}.src == {}'.format(ip_version,
                                                   normalized_ip_prefix)
        self.assertEqual(expected_match, match)

    def test_acl_remote_group_id(self):
        sg_rule = fakes.FakeSecurityGroupRule.create_one_security_group_rule({
            'direction': 'ingress',
            'remote_group_id': None
        }).info()
        ip_version = 'ip4'
        sg_id = sg_rule['security_group_id']

        pg_name = ovn_utils.ovn_pg_addrset_name(sg_id, ip_version)

        match = ovn_acl.acl_remote_group_id(sg_rule, ip_version)
        self.assertEqual('', match)

        sg_rule['remote_group_id'] = sg_id
        match = ovn_acl.acl_remote_group_id(sg_rule, ip_version)
        self.assertEqual(' && ip4.src == $' + pg_name, match)

        sg_rule['direction'] = 'egress'
        match = ovn_acl.acl_remote_group_id(sg_rule, ip_version)
        self.assertEqual(' && ip4.dst == $' + pg_name, match)
