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
from neutron_lib import constants as const
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.common.ovn import acl as ovn_acl
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.conf.agent import securitygroups_rpc
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import commands as cmd
from neutron.tests import base
from neutron.tests.unit import fake_resources as fakes


class TestACLs(base.BaseTestCase):

    def setUp(self):
        super(TestACLs, self).setUp()
        self.driver = mock.Mock()
        self.driver._nb_ovn = fakes.FakeOvsdbNbOvnIdl()
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
                        'priority': 1001}
        acl_from_lport = {'action': 'drop', 'direction': 'from-lport',
                          'external_ids': {'neutron:lport':
                                           self.fake_port['id']},
                          'log': False, 'name': [], 'severity': [],
                          'lport': self.fake_port['id'],
                          'lswitch': 'neutron-network_id1',
                          'match': 'inport == "fake_port_id1" && ip',
                          'priority': 1001}
        for acl in acls:
            if 'to-lport' in acl.values():
                self.assertEqual(acl_to_lport, acl)
            if 'from-lport' in acl.values():
                self.assertEqual(acl_from_lport, acl)

    def test_add_acl_dhcp(self):
        ovn_dhcp_acls = ovn_acl.add_acl_dhcp(self.fake_port, self.fake_subnet)
        other_dhcp_acls = ovn_acl.add_acl_dhcp(self.fake_port,
                                               self.fake_subnet,
                                               ovn_dhcp=False)

        expected_match_to_lport = (
            'outport == "%s" && ip4 && ip4.src == %s && udp && udp.src == 67 '
            '&& udp.dst == 68') % (self.fake_port['id'],
                                   self.fake_subnet['cidr'])
        acl_to_lport = {'action': 'allow', 'direction': 'to-lport',
                        'external_ids': {'neutron:lport': 'fake_port_id1'},
                        'log': False, 'name': [], 'severity': [],
                        'lport': 'fake_port_id1',
                        'lswitch': 'neutron-network_id1',
                        'match': expected_match_to_lport, 'priority': 1002}
        expected_match_from_lport = (
            'inport == "%s" && ip4 && '
            'ip4.dst == {255.255.255.255, %s} && '
            'udp && udp.src == 68 && udp.dst == 67'
        ) % (self.fake_port['id'], self.fake_subnet['cidr'])
        acl_from_lport = {'action': 'allow', 'direction': 'from-lport',
                          'external_ids': {'neutron:lport': 'fake_port_id1'},
                          'log': False, 'name': [], 'severity': [],
                          'lport': 'fake_port_id1',
                          'lswitch': 'neutron-network_id1',
                          'match': expected_match_from_lport, 'priority': 1002}
        self.assertEqual(1, len(ovn_dhcp_acls))
        self.assertEqual(acl_from_lport, ovn_dhcp_acls[0])
        self.assertEqual(2, len(other_dhcp_acls))
        for acl in other_dhcp_acls:
            if 'to-lport' in acl.values():
                self.assertEqual(acl_to_lport, acl)
            if 'from-lport' in acl.values():
                self.assertEqual(acl_from_lport, acl)

    def _test_add_sg_rule_acl_for_port(self, sg_rule, direction, match):
        port = {'id': 'port-id',
                'network_id': 'network-id'}
        acl = ovn_acl.add_sg_rule_acl_for_port(port, sg_rule, match)
        self.assertEqual({'lswitch': 'neutron-network-id',
                          'lport': 'port-id',
                          'priority': ovn_const.ACL_PRIORITY_ALLOW,
                          'action': ovn_const.ACL_ACTION_ALLOW_RELATED,
                          'log': False, 'name': [], 'severity': [],
                          'direction': direction,
                          'match': match,
                          'external_ids': {
                              'neutron:lport': 'port-id',
                              'neutron:security_group_rule_id': 'sgr_id'}},
                         acl)

    def test_add_sg_rule_acl_for_port_remote_ip_prefix(self):
        sg_rule = {'id': 'sgr_id',
                   'direction': 'ingress',
                   'ethertype': 'IPv4',
                   'remote_group_id': None,
                   'remote_ip_prefix': '1.1.1.0/24',
                   'protocol': None}
        match = 'outport == "port-id" && ip4 && ip4.src == 1.1.1.0/24'
        self._test_add_sg_rule_acl_for_port(sg_rule,
                                            'to-lport',
                                            match)
        sg_rule['direction'] = 'egress'
        match = 'inport == "port-id" && ip4 && ip4.dst == 1.1.1.0/24'
        self._test_add_sg_rule_acl_for_port(sg_rule,
                                            'from-lport',
                                            match)

    def test_add_sg_rule_acl_for_port_remote_group(self):
        sg_rule = {'id': 'sgr_id',
                   'direction': 'ingress',
                   'ethertype': 'IPv4',
                   'remote_group_id': 'sg1',
                   'remote_ip_prefix': None,
                   'protocol': None}
        match = 'outport == "port-id" && ip4 && (ip4.src == 1.1.1.100' \
                ' || ip4.src == 1.1.1.101' \
                ' || ip4.src == 1.1.1.102)'

        self._test_add_sg_rule_acl_for_port(sg_rule,
                                            'to-lport',
                                            match)
        sg_rule['direction'] = 'egress'
        match = 'inport == "port-id" && ip4 && (ip4.dst == 1.1.1.100' \
                ' || ip4.dst == 1.1.1.101' \
                ' || ip4.dst == 1.1.1.102)'
        self._test_add_sg_rule_acl_for_port(sg_rule,
                                            'from-lport',
                                            match)

    def test__update_acls_compute_difference(self):
        lswitch_name = 'lswitch-1'
        port1 = {'id': 'port-id1',
                 'network_id': lswitch_name,
                 'fixed_ips': [{'subnet_id': 'subnet-id',
                                'ip_address': '1.1.1.101'},
                               {'subnet_id': 'subnet-id-v6',
                                'ip_address': '2001:0db8::1:0:0:1'}]}
        port2 = {'id': 'port-id2',
                 'network_id': lswitch_name,
                 'fixed_ips': [{'subnet_id': 'subnet-id',
                                'ip_address': '1.1.1.102'},
                               {'subnet_id': 'subnet-id-v6',
                                'ip_address': '2001:0db8::1:0:0:2'}]}
        ports = [port1, port2]
        # OLD ACLs, allow IPv4 communication
        aclport1_old1 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip4 && (ip.src == %s)' %
                         (port1['id'], port1['fixed_ips'][0]['ip_address'])}
        aclport1_old2 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip6 && (ip.src == %s)' %
                         (port1['id'], port1['fixed_ips'][1]['ip_address'])}
        aclport1_old3 = {'priority': 1002, 'direction': 'to-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'ip4 && (ip.src == %s)' %
                         (port2['fixed_ips'][0]['ip_address'])}
        port1_acls_old = [aclport1_old1, aclport1_old2, aclport1_old3]
        aclport2_old1 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip4 && (ip.src == %s)' %
                         (port2['id'], port2['fixed_ips'][0]['ip_address'])}
        aclport2_old2 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip6 && (ip.src == %s)' %
                         (port2['id'], port2['fixed_ips'][1]['ip_address'])}
        aclport2_old3 = {'priority': 1002, 'direction': 'to-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'ip4 && (ip.src == %s)' %
                         (port1['fixed_ips'][0]['ip_address'])}
        port2_acls_old = [aclport2_old1, aclport2_old2, aclport2_old3]
        acls_old_dict = {'%s' % (port1['id']): port1_acls_old,
                         '%s' % (port2['id']): port2_acls_old}
        acl_obj_dict = {str(aclport1_old1): 'row1',
                        str(aclport1_old2): 'row2',
                        str(aclport1_old3): 'row3',
                        str(aclport2_old1): 'row4',
                        str(aclport2_old2): 'row5',
                        str(aclport2_old3): 'row6'}
        # NEW ACLs, allow IPv6 communication
        aclport1_new1 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip4 && (ip.src == %s)' %
                         (port1['id'], port1['fixed_ips'][0]['ip_address'])}
        aclport1_new2 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip6 && (ip.src == %s)' %
                         (port1['id'], port1['fixed_ips'][1]['ip_address'])}
        aclport1_new3 = {'priority': 1002, 'direction': 'to-lport',
                         'lport': port1['id'], 'lswitch': lswitch_name,
                         'match': 'ip6 && (ip.src == %s)' %
                         (port2['fixed_ips'][1]['ip_address'])}
        port1_acls_new = [aclport1_new1, aclport1_new2, aclport1_new3]
        aclport2_new1 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip4 && (ip.src == %s)' %
                         (port2['id'], port2['fixed_ips'][0]['ip_address'])}
        aclport2_new2 = {'priority': 1002, 'direction': 'from-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'inport == %s && ip6 && (ip.src == %s)' %
                         (port2['id'], port2['fixed_ips'][1]['ip_address'])}
        aclport2_new3 = {'priority': 1002, 'direction': 'to-lport',
                         'lport': port2['id'], 'lswitch': lswitch_name,
                         'match': 'ip6 && (ip.src == %s)' %
                         (port1['fixed_ips'][1]['ip_address'])}
        port2_acls_new = [aclport2_new1, aclport2_new2, aclport2_new3]
        acls_new_dict = {'%s' % (port1['id']): port1_acls_new,
                         '%s' % (port2['id']): port2_acls_new}

        acls_new_dict_copy = copy.deepcopy(acls_new_dict)

        # Invoke _compute_acl_differences
        update_cmd = cmd.UpdateACLsCommand(self.driver._nb_ovn,
                                           [lswitch_name],
                                           iter(ports),
                                           acls_new_dict
                                           )
        acl_dels, acl_adds =\
            update_cmd._compute_acl_differences(iter(ports),
                                                acls_old_dict,
                                                acls_new_dict,
                                                acl_obj_dict)
        # Expected Difference (Sorted)
        acl_del_exp = {lswitch_name: ['row3', 'row6']}
        acl_adds_exp = {lswitch_name:
                        [{'priority': 1002, 'direction': 'to-lport',
                          'match': 'ip6 && (ip.src == %s)' %
                          (port2['fixed_ips'][1]['ip_address'])},
                         {'priority': 1002, 'direction': 'to-lport',
                          'match': 'ip6 && (ip.src == %s)' %
                          (port1['fixed_ips'][1]['ip_address'])}]}
        self.assertEqual(acl_del_exp, acl_dels)
        self.assertEqual(acl_adds_exp, acl_adds)

        # make sure argument add_acl=False will take no affect in
        # need_compare=True scenario
        update_cmd_with_acl = cmd.UpdateACLsCommand(self.driver._nb_ovn,
                                                    [lswitch_name],
                                                    iter(ports),
                                                    acls_new_dict_copy,
                                                    need_compare=True,
                                                    is_add_acl=False)
        new_acl_dels, new_acl_adds =\
            update_cmd_with_acl._compute_acl_differences(iter(ports),
                                                         acls_old_dict,
                                                         acls_new_dict_copy,
                                                         acl_obj_dict)
        self.assertEqual(acl_dels, new_acl_dels)
        self.assertEqual(acl_adds, new_acl_adds)

    def test__get_update_data_without_compare(self):
        lswitch_name = 'lswitch-1'
        port1 = {'id': 'port-id1',
                 'network_id': lswitch_name,
                 'fixed_ips': mock.Mock()}
        port2 = {'id': 'port-id2',
                 'network_id': lswitch_name,
                 'fixed_ips': mock.Mock()}
        ports = [port1, port2]
        aclport1_new = {'priority': 1002, 'direction': 'to-lport',
                        'match': 'outport == %s && ip4 && icmp4' %
                        (port1['id']), 'external_ids': {}}
        aclport2_new = {'priority': 1002, 'direction': 'to-lport',
                        'match': 'outport == %s && ip4 && icmp4' %
                        (port2['id']), 'external_ids': {}}
        acls_new_dict = {'%s' % (port1['id']): aclport1_new,
                         '%s' % (port2['id']): aclport2_new}

        # test for creating new acls
        update_cmd_add_acl = cmd.UpdateACLsCommand(self.driver._nb_ovn,
                                                   [lswitch_name],
                                                   iter(ports),
                                                   acls_new_dict,
                                                   need_compare=False,
                                                   is_add_acl=True)
        lswitch_dict, acl_del_dict, acl_add_dict = \
            update_cmd_add_acl._get_update_data_without_compare()
        self.assertIn('neutron-lswitch-1', lswitch_dict)
        self.assertEqual({}, acl_del_dict)
        expected_acls = {'neutron-lswitch-1': [aclport1_new, aclport2_new]}
        self.assertEqual(expected_acls, acl_add_dict)

        # test for deleting existing acls
        acl1 = mock.Mock(
            match='outport == port-id1 && ip4 && icmp4', external_ids={})
        acl2 = mock.Mock(
            match='outport == port-id2 && ip4 && icmp4', external_ids={})
        acl3 = mock.Mock(
            match='outport == port-id1 && ip4 && (ip4.src == fake_ip)',
            external_ids={})
        lswitch_obj = mock.Mock(
            name='neutron-lswitch-1', acls=[acl1, acl2, acl3])
        with mock.patch('ovsdbapp.backend.ovs_idl.idlutils.row_by_value',
                        return_value=lswitch_obj):
            update_cmd_del_acl = cmd.UpdateACLsCommand(self.driver._nb_ovn,
                                                       [lswitch_name],
                                                       iter(ports),
                                                       acls_new_dict,
                                                       need_compare=False,
                                                       is_add_acl=False)
            lswitch_dict, acl_del_dict, acl_add_dict = \
                update_cmd_del_acl._get_update_data_without_compare()
            self.assertIn('neutron-lswitch-1', lswitch_dict)
            expected_acls = {'neutron-lswitch-1': [acl1, acl2]}
            self.assertEqual(expected_acls, acl_del_dict)
            self.assertEqual({}, acl_add_dict)

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

        match = ovn_acl.acl_remote_ip_prefix(sg_rule, ip_version)
        self.assertEqual('', match)

        sg_rule['remote_ip_prefix'] = remote_ip_prefix
        match = ovn_acl.acl_remote_ip_prefix(sg_rule, ip_version)
        expected_match = ' && %s.src == %s' % (ip_version, remote_ip_prefix)
        self.assertEqual(expected_match, match)

        sg_rule['direction'] = 'egress'
        match = ovn_acl.acl_remote_ip_prefix(sg_rule, ip_version)
        expected_match = ' && %s.dst == %s' % (ip_version, remote_ip_prefix)
        self.assertEqual(expected_match, match)

    def test_acl_remote_ip_prefix_not_normalized(self):
        sg_rule = fakes.FakeSecurityGroupRule.create_one_security_group_rule({
            'direction': 'ingress',
            'remote_ip_prefix': '10.10.10.175/26'
        }).info()
        normalized_ip_prefix = '10.10.10.128/26'
        ip_version = 'ip4'

        match = ovn_acl.acl_remote_ip_prefix(sg_rule, ip_version)
        expected_match = ' && %s.src == %s' % (ip_version,
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
