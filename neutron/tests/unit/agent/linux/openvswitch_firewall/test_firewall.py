# Copyright 2015 Red Hat, Inc.
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

from neutron_lib.callbacks import events as callbacks_events
from neutron_lib.callbacks import registry as callbacks_registry
from neutron_lib.callbacks import resources as callbacks_resources
from neutron_lib import constants
from neutron_lib.plugins.ml2 import ovs_constants as ovs_consts
from neutron_lib.utils import helpers
from os_ken.ofproto import ofproto_v1_3_parser
from oslo_config import cfg
import testtools

from neutron.agent.common import ovs_lib
from neutron.agent.common import utils
from neutron.agent import firewall as agent_firewall
from neutron.agent.linux.openvswitch_firewall import constants as ovsfw_consts
from neutron.agent.linux.openvswitch_firewall import exceptions
from neutron.agent.linux.openvswitch_firewall import firewall as ovsfw
from neutron.conf.agent import securitygroups_rpc
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import ovs_bridge
from neutron.tests import base

TESTING_VLAN_TAG = 1
TESTING_SEGMENT = 1000
MATCH_1 = ofproto_v1_3_parser.OFPMatch(
    _ordered_fields=[('conj_id', 100), ('eth_type', 2048), ('reg5', 12),
                     ('ct_state', (2, 14))])
MATCH_2 = ofproto_v1_3_parser.OFPMatch(
    _ordered_fields=[('conj_id', 200), ('eth_type', 2048), ('reg5', 12),
                     ('ct_state', (2, 14))])
MATCH_3 = ofproto_v1_3_parser.OFPMatch(
    _ordered_fields=[('reg5', 13), ('ct_state', (10, 14)), ('ct_zone', 1),
                     ('ct_mark', 0)])
MATCH_4 = ofproto_v1_3_parser.OFPMatch(
    _ordered_fields=[('eth_type', 34525), ('ip_proto', 58),
                     ('icmpv6_type', 136), ('reg5', 11)])
INIT_OF_RULES = [
    mock.Mock(match=MATCH_1),
    mock.Mock(match=MATCH_2),
    mock.Mock(match=MATCH_3),
    mock.Mock(match=MATCH_4),
]
INIT_OF_RULES_VSCTL = [
    'priority=40,ct_state=+est,ip,reg5=0xd actions=ct(commit,zone=NXM_NX_REG6['
    '0..15],exec(load:0x1->NXM_NX_CT_MARK[]))',
    'priority=70,conj_id=100,ct_state=+est-rel-rpl,ip,reg5=0xc actions=load:0x'
    'f0->NXM_NX_REG7[],output:12',
    'priority=70,conj_id=200,ct_state=+est-rel-rpl,ipv6,reg5=0xc actions=load:'
    '0xf8->NXM_NX_REG7[],output:12',
    'priority=73,ct_state=+est-rel-rpl,ip,reg6=0x1,nw_src=10.10.0.42 actions=c'
    'onjunction(118,1/2)',
    'priority=70,ct_state=+est-rel-rpl,ip,reg6=0x1,nw_src=10.10.0.61 actions=c'
    'onjunction(120,1/2)'
]


def create_ofport(port_dict, network_type=None,
                  physical_network=None, segment_id=TESTING_SEGMENT):
    allowed_pairs_v4 = ovsfw.OFPort._get_allowed_pairs(
        port_dict, version=constants.IPv4)
    allowed_pairs_v6 = ovsfw.OFPort._get_allowed_pairs(
        port_dict, version=constants.IPv6)
    ovs_port = mock.Mock(vif_mac='00:00:00:00:00:00', ofport=1,
                         port_name="port-name",
                         allowed_pairs_v4=allowed_pairs_v4,
                         allowed_pairs_v6=allowed_pairs_v6)
    return ovsfw.OFPort(port_dict, ovs_port, vlan_tag=TESTING_VLAN_TAG,
                        segment_id=segment_id,
                        network_type=network_type,
                        physical_network=physical_network)


class TestCreateRegNumbers(base.BaseTestCase):
    def test_no_registers_defined(self):
        flow = {'foo': 'bar'}
        ovsfw.create_reg_numbers(flow)
        self.assertEqual({'foo': 'bar'}, flow)

    def test_all_registers_defined(self):
        flow = {'foo': 'bar', 'reg_port': 1, 'reg_net': 2,
                'reg_remote_group': 3}
        expected_flow = {'foo': 'bar',
                         'reg{:d}'.format(ovsfw_consts.REG_PORT): 1,
                         'reg{:d}'.format(ovsfw_consts.REG_NET): 2,
                         'reg{:d}'.format(ovsfw_consts.REG_REMOTE_GROUP): 3}
        ovsfw.create_reg_numbers(flow)
        self.assertEqual(expected_flow, flow)


class TestSecurityGroup(base.BaseTestCase):
    def setUp(self):
        super(TestSecurityGroup, self).setUp()
        self.sg = ovsfw.SecurityGroup('123')
        self.sg.members = {'type': [1, 2, 3, 4]}

    def test_update_rules_split(self):
        rules = [
            {'foo': 'bar', 'rule': 'all'}, {'bar': 'foo'},
            {'remote_group_id': '123456', 'foo': 'bar'},
            {'remote_address_group_id': 'fake_ag_id', 'bar': 'foo'}]
        expected_raw_rules = [{'foo': 'bar', 'rule': 'all'}, {'bar': 'foo'}]
        expected_remote_rules = [{'remote_group_id': '123456', 'foo': 'bar'},
                                 {'remote_address_group_id': 'fake_ag_id',
                                  'bar': 'foo'}]
        self.sg.update_rules(rules)

        self.assertEqual(expected_raw_rules, self.sg.raw_rules)
        self.assertEqual(expected_remote_rules, self.sg.remote_rules)

    def test_update_rules_protocols(self):
        rules = [
            {'foo': 'bar', 'protocol': constants.PROTO_NAME_ICMP,
             'ethertype': constants.IPv4},
            {'foo': 'bar', 'protocol': constants.PROTO_NAME_ICMP,
             'ethertype': constants.IPv6},
            {'foo': 'bar', 'protocol': constants.PROTO_NAME_IPV6_ICMP_LEGACY,
             'ethertype': constants.IPv6},
            {'foo': 'bar', 'protocol': constants.PROTO_NAME_TCP},
            {'foo': 'bar', 'protocol': '94'},
            {'foo': 'bar', 'protocol': 'baz'},
            {'foo': 'no_proto'}]
        self.sg.update_rules(rules)

        self.assertEqual({'foo': 'no_proto'}, self.sg.raw_rules.pop())
        protos = [rule['protocol'] for rule in self.sg.raw_rules]
        self.assertEqual([constants.PROTO_NUM_ICMP,
                          constants.PROTO_NUM_IPV6_ICMP,
                          constants.PROTO_NUM_IPV6_ICMP,
                          constants.PROTO_NUM_TCP,
                          94,
                          'baz'], protos)

    def test_get_ethertype_filtered_addresses(self):
        addresses = self.sg.get_ethertype_filtered_addresses('type')
        expected_addresses = [1, 2, 3, 4]
        self.assertEqual(expected_addresses, addresses)


class TestOFPort(base.BaseTestCase):
    def setUp(self):
        super(TestOFPort, self).setUp()
        self.ipv4_addresses = ['10.0.0.1', '192.168.0.1']
        self.ipv6_addresses = ['fe80::f816:3eff:fe2e:1']
        port_dict = {'device': 1,
                     'fixed_ips': self.ipv4_addresses + self.ipv6_addresses}
        self.port = create_ofport(port_dict)

    def test_ipv4_address(self):
        ipv4_addresses = self.port.ipv4_addresses
        self.assertEqual(self.ipv4_addresses, ipv4_addresses)

    def test_ipv6_address(self):
        ipv6_addresses = self.port.ipv6_addresses
        self.assertEqual(self.ipv6_addresses, ipv6_addresses)

    def test__get_allowed_pairs(self):
        port = {
            'allowed_address_pairs': [
                {'mac_address': 'foo', 'ip_address': '10.0.0.1'},
                {'mac_address': 'bar', 'ip_address': '192.168.0.1'},
                {'mac_address': 'qux', 'ip_address': '169.254.0.0/16'},
                {'mac_address': 'baz', 'ip_address': '2003::f'},
            ]}
        allowed_pairs_v4 = ovsfw.OFPort._get_allowed_pairs(port, version=4)
        allowed_pairs_v6 = ovsfw.OFPort._get_allowed_pairs(port, version=6)
        expected_aap_v4 = {('foo', '10.0.0.1'), ('bar', '192.168.0.1'),
                           ('qux', '169.254.0.0/16')}
        expected_aap_v6 = {('baz', '2003::f')}
        self.assertEqual(expected_aap_v4, allowed_pairs_v4)
        self.assertEqual(expected_aap_v6, allowed_pairs_v6)

    def test__get_allowed_pairs_empty(self):
        port = {}
        allowed_pairs = ovsfw.OFPort._get_allowed_pairs(port, version=4)
        self.assertFalse(allowed_pairs)

    def test_update(self):
        old_port_dict = self.port.neutron_port_dict
        new_port_dict = old_port_dict.copy()
        added_ips = [1, 2, 3]
        new_port_dict.update({
            'fixed_ips': added_ips,
            'allowed_address_pairs': [
                {'mac_address': '00:00:00:00:00:01',
                 'ip_address': '192.168.0.1'},
                {'mac_address': '00:00:00:00:00:01',
                 'ip_address': '2003::f'}],
        })
        self.port.update(new_port_dict)
        self.assertEqual(new_port_dict, self.port.neutron_port_dict)
        self.assertIsNot(new_port_dict, self.port.neutron_port_dict)
        self.assertEqual(added_ips, self.port.fixed_ips)
        self.assertEqual({('00:00:00:00:00:01', '192.168.0.1')},
                         self.port.allowed_pairs_v4)
        self.assertIn(('00:00:00:00:00:01', '2003::f'),
                      self.port.allowed_pairs_v6)


class TestSGPortMap(base.BaseTestCase):
    def setUp(self):
        super(TestSGPortMap, self).setUp()
        self.map = ovsfw.SGPortMap()

    def test_get_or_create_sg_existing_sg(self):
        self.map.sec_groups['id'] = mock.sentinel
        sg = self.map.get_or_create_sg('id')
        self.assertIs(mock.sentinel, sg)

    def test_get_or_create_sg_nonexisting_sg(self):
        with mock.patch.object(ovsfw, 'SecurityGroup') as sg_mock:
            sg = self.map.get_or_create_sg('id')
        self.assertEqual(sg_mock.return_value, sg)

    def _check_port(self, port_id, expected_sg_ids):
        port = self.map.ports[port_id]
        expected_sgs = [self.map.sec_groups[sg_id]
                        for sg_id in expected_sg_ids]
        self.assertEqual(port.sec_groups, expected_sgs)

    def _check_sg(self, sg_id, expected_port_ids):
        sg = self.map.sec_groups[sg_id]
        expected_ports = {self.map.ports[port_id]
                          for port_id in expected_port_ids}
        self.assertEqual(sg.ports, expected_ports)

    def _create_ports_and_sgroups(self):
        sg_1 = ovsfw.SecurityGroup(1)
        sg_2 = ovsfw.SecurityGroup(2)
        sg_3 = ovsfw.SecurityGroup(3)
        port_a = create_ofport({'device': 'a'})
        port_b = create_ofport({'device': 'b'})
        self.map.ports = {'a': port_a, 'b': port_b}
        self.map.sec_groups = {1: sg_1, 2: sg_2, 3: sg_3}
        port_a.sec_groups = [sg_1, sg_2]
        port_b.sec_groups = [sg_2, sg_3]
        sg_1.ports = {port_a}
        sg_2.ports = {port_a, port_b}
        sg_3.ports = {port_b}

    def test_create_port(self):
        port = create_ofport({'device': 'a'})
        sec_groups = ['1', '2']
        port_dict = {'security_groups': sec_groups}
        self.map.create_port(port, port_dict)
        self._check_port('a', sec_groups)
        self._check_sg('1', ['a'])
        self._check_sg('2', ['a'])

    def test_update_port_sg_added(self):
        self._create_ports_and_sgroups()
        port_dict = {'security_groups': [1, 2, 3]}
        self.map.update_port(self.map.ports['b'], port_dict)
        self._check_port('a', [1, 2])
        self._check_port('b', [1, 2, 3])
        self._check_sg(1, ['a', 'b'])
        self._check_sg(2, ['a', 'b'])
        self._check_sg(3, ['b'])

    def test_update_port_sg_removed(self):
        self._create_ports_and_sgroups()
        port_dict = {'security_groups': [1]}
        self.map.update_port(self.map.ports['b'], port_dict)
        self._check_port('a', [1, 2])
        self._check_port('b', [1])
        self._check_sg(1, ['a', 'b'])
        self._check_sg(2, ['a'])
        self._check_sg(3, [])

    def test_remove_port(self):
        self._create_ports_and_sgroups()
        self.map.remove_port(self.map.ports['a'])
        self._check_port('b', [2, 3])
        self._check_sg(1, [])
        self._check_sg(2, ['b'])
        self._check_sg(3, ['b'])
        self.assertNotIn('a', self.map.ports)

    def test_update_rules(self):
        """Just make sure it doesn't crash"""
        self.map.update_rules(1, [])

    def test_update_members(self):
        """Just make sure we doesn't crash"""
        self.map.update_members(1, [])


class TestConjIdMap(base.BaseTestCase):
    def setUp(self):
        super(TestConjIdMap, self).setUp()
        self.mock_int_br = mock.Mock()
        self.dump_flows_ret = [[]] * len(ovs_consts.OVS_FIREWALL_TABLES)
        self.dump_flows_ret[0] = INIT_OF_RULES
        self.mock_int_br.dump_flows.side_effect = self.dump_flows_ret
        self.conj_id_map = ovsfw.ConjIdMap(self.mock_int_br)

    def test_get_conj_id(self):
        allocated = []
        for direction in [constants.EGRESS_DIRECTION,
                          constants.INGRESS_DIRECTION]:
            id_ = self.conj_id_map.get_conj_id(
                'sg', 'remote', direction, constants.IPv4)
            allocated.append(id_)
        self.assertEqual(len(set(allocated)), 2)
        self.assertEqual(len(self.conj_id_map.id_map), 2)
        self.assertEqual(self.conj_id_map.get_conj_id(
            'sg', 'remote', constants.EGRESS_DIRECTION, constants.IPv4),
                         allocated[0])

    def test_get_conj_id_invalid(self):
        self.assertRaises(ValueError, self.conj_id_map.get_conj_id,
                          'sg', 'remote', 'invalid-direction',
                          constants.IPv6)

    def test_delete_sg(self):
        self.conj_id_map._max_id = 0
        test_data = [
            # conj_id: 8
            ('sg1', 'sg1', constants.INGRESS_DIRECTION, constants.IPv6, 0),
            # conj_id: 10
            ('sg1', 'sg1', constants.INGRESS_DIRECTION, constants.IPv6, 1),
            # conj_id: 12
            ('sg1', 'sg1', constants.INGRESS_DIRECTION, constants.IPv6, 2),
            # conj_id: 16
            ('sg2', 'sg1', constants.EGRESS_DIRECTION, constants.IPv6, 0),
            # conj_id: 24
            ('sg1', 'sg3', constants.INGRESS_DIRECTION, constants.IPv6, 0),
            # conj_id: 36 (and 32 without priority offset, stored in id_map)
            ('sg3', 'sg4', constants.INGRESS_DIRECTION, constants.IPv4, 2),
            # conj_id: 40
            ('sg5', 'sg4', constants.EGRESS_DIRECTION, constants.IPv4, 0),
        ]

        ids = []
        conj_id_segment = set([])  # see ConjIPFlowManager.get_conj_id
        # This is similar to ConjIPFlowManager.add method
        for sg_id, rsg_id, direction, ip_version, prio_offset in test_data:
            conj_id_tuple = (sg_id, rsg_id, direction, ip_version)
            conj_id = self.conj_id_map.get_conj_id(*conj_id_tuple)
            conj_id_segment.add(conj_id)
            conj_id_plus_prio = conj_id + prio_offset * 2
            self.conj_id_map.id_map_group[conj_id_tuple].add(conj_id_plus_prio)
            ids.append(conj_id_plus_prio)

        result = self.conj_id_map.delete_sg('sg1')
        self.assertEqual(
            {('sg3', 24), ('sg1', 12), ('sg1', 16), ('sg1', 8), ('sg1', 10)},
            result)
        result = self.conj_id_map.delete_sg('sg3')
        self.assertEqual({('sg4', 32), ('sg4', 36)}, result)
        result = self.conj_id_map.delete_sg('sg4')
        self.assertEqual({('sg4', 40)}, result)
        self.assertEqual({}, self.conj_id_map.id_map)
        self.assertEqual({}, self.conj_id_map.id_map_group)

        reallocated = set([])
        for sg_id, rsg_id, direction, ip_version, _ in test_data:
            conj_id_tuple = (sg_id, rsg_id, direction, ip_version)
            reallocated.add(self.conj_id_map.get_conj_id(*conj_id_tuple))
        self.assertEqual(reallocated, conj_id_segment)

    def test__init_max_id_os_ken(self):
        self.mock_int_br.dump_flows.side_effect = self.dump_flows_ret
        self.assertEqual(208, self.conj_id_map._init_max_id(self.mock_int_br))

        match = ofproto_v1_3_parser.OFPMatch(
            _ordered_fields=[('conj_id', 237), ('eth_type', 2048),
                             ('reg5', 12), ('ct_state', (2, 14))])
        new_rule = mock.Mock(match=match)
        self.dump_flows_ret[0] = INIT_OF_RULES + [new_rule]
        self.mock_int_br.dump_flows.side_effect = self.dump_flows_ret
        self.assertEqual(240, self.conj_id_map._init_max_id(self.mock_int_br))

    def test__init_max_id_vsctl(self):
        self.mock_int_br.dump_flows.side_effect = AttributeError()
        dump_flows_ret = [[]] * len(ovs_consts.OVS_FIREWALL_TABLES)
        dump_flows_ret[0] = INIT_OF_RULES_VSCTL
        self.mock_int_br.dump_flows_for_table.side_effect = dump_flows_ret

        self.assertEqual(208, self.conj_id_map._init_max_id(self.mock_int_br))

        new_rule = ('priority=70,conj_id=237,ct_state=+est-rel-rpl,ipv6,reg5=0'
                    'xc actions=load:0xf8->NXM_NX_REG7[],output:12')
        dump_flows_ret[0] = INIT_OF_RULES_VSCTL + [new_rule]
        self.mock_int_br.dump_flows_for_table.side_effect = dump_flows_ret
        self.assertEqual(240, self.conj_id_map._init_max_id(self.mock_int_br))

    def test__next_max_id(self):
        self.assertEqual(8, self.conj_id_map._next_max_id(0))
        self.assertEqual(0, self.conj_id_map._next_max_id(
            self.conj_id_map.MAX_CONJ_ID - 1))


class TestConjIPFlowManager(base.BaseTestCase):
    def setUp(self):
        super(TestConjIPFlowManager, self).setUp()
        self.driver = mock.Mock()
        self.driver.int_br.br.dump_flows.return_value = INIT_OF_RULES
        self.manager = ovsfw.ConjIPFlowManager(self.driver)
        self.vlan_tag = 100
        self.conj_id = 16

    def test_update_flows_for_vlan_no_members(self):
        remote_group = self.driver.sg_port_map.get_sg.return_value
        remote_group.members = {}
        with mock.patch.object(self.manager.conj_id_map,
                               'get_conj_id') as get_conj_id_mock:
            get_conj_id_mock.return_value = self.conj_id
            self.manager.add(self.vlan_tag, 'sg', 'remote_id',
                             constants.INGRESS_DIRECTION, constants.IPv4, 0)
            self.manager.update_flows_for_vlan(self.vlan_tag, mock.ANY)
        self.assertFalse(remote_group.get_ethertype_filtered_addresses.called)
        self.assertFalse(self.driver._add_flow.called)

    def test_update_flows_for_vlan_no_ports_but_members(self):
        remote_group = self.driver.sg_port_map.get_sg.return_value
        remote_group.ports = set()
        remote_group.members = {constants.IPv4: [
            ('10.22.3.4', 'fa:16:3e:aa:bb:cc'), ]}
        remote_group.get_ethertype_filtered_addresses.return_value = [
            ('10.22.3.4', 'fa:16:3e:aa:bb:cc'), ]
        with mock.patch.object(self.manager.conj_id_map,
                               'get_conj_id') as get_conj_id_mock:
            get_conj_id_mock.return_value = self.conj_id
            self.manager.add(self.vlan_tag, 'sg', 'remote_id',
                             constants.INGRESS_DIRECTION, constants.IPv4, 0)
            self.manager.update_flows_for_vlan(self.vlan_tag, mock.ANY)
        self.assertTrue(remote_group.get_ethertype_filtered_addresses.called)
        self.assertTrue(self.driver._add_flow.called)

    def test_update_flows_for_vlan_remote_group(self):
        remote_group = self.driver.sg_port_map.get_sg.return_value
        remote_group.get_ethertype_filtered_addresses.return_value = [
            ('10.22.3.4', 'fa:16:3e:aa:bb:cc'), ]
        with mock.patch.object(self.manager.conj_id_map,
                               'get_conj_id') as get_conj_id_mock:
            get_conj_id_mock.return_value = self.conj_id
            self.manager.add(self.vlan_tag, 'sg', 'remote_id',
                             constants.INGRESS_DIRECTION, constants.IPv4, 0)
            self.manager.add(self.vlan_tag, 'sg', 'remote_id',
                             constants.INGRESS_DIRECTION, constants.IPv4, 3)
            self.manager.update_flows_for_vlan(self.vlan_tag, 'ofport1')
        calls = [
            mock.call(actions='conjunction(16,1/2)', ct_state='+est-rel-rpl',
                      dl_type=2048, nw_src='10.22.3.4/32', priority=70,
                      reg_net=self.vlan_tag, table=82,
                      flow_group_id='ofport1'),
            mock.call(actions='conjunction(17,1/2)', ct_state='+new-est',
                      dl_type=2048, nw_src='10.22.3.4/32', priority=70,
                      reg_net=self.vlan_tag, table=82,
                      flow_group_id='ofport1'),
            mock.call(actions='conjunction(22,1/2)', ct_state='+est-rel-rpl',
                      dl_type=2048, nw_src='10.22.3.4/32', priority=73,
                      reg_net=self.vlan_tag, table=82,
                      flow_group_id='ofport1'),
            mock.call(actions='conjunction(23,1/2)', ct_state='+new-est',
                      dl_type=2048, nw_src='10.22.3.4/32', priority=73,
                      reg_net=self.vlan_tag, table=82,
                      flow_group_id='ofport1')]
        self.assertEqual(self.driver._add_flow.call_args_list, calls)

    def _sg_removed(self, sg_name):
        with mock.patch.object(self.manager.conj_id_map,
                               'get_conj_id') as get_id_mock, \
             mock.patch.object(self.manager.conj_id_map,
                               'delete_sg') as delete_sg_mock:
            get_id_mock.return_value = self.conj_id
            delete_sg_mock.return_value = [('remote_id', self.conj_id)]
            self.manager.add(self.vlan_tag, 'sg', 'remote_id',
                             constants.INGRESS_DIRECTION, constants.IPv4, 0)
            self.manager.flow_state[self.vlan_tag][(
                constants.INGRESS_DIRECTION, constants.IPv4)] = {
                    '10.22.3.4': [self.conj_id]}

            self.manager.sg_removed(sg_name)

    def test_sg_removed(self):
        self._sg_removed('sg')
        self.driver._add_flow.assert_not_called()
        self.driver.delete_flows_for_flow_state.assert_called_once_with(
            {'10.22.3.4': [self.conj_id]}, {},
            constants.INGRESS_DIRECTION, constants.IPv4, self.vlan_tag)
        self.driver.delete_flow_for_ip.assert_not_called()

    def test_remote_sg_removed(self):
        self._sg_removed('remote_id')
        self.driver._add_flow.assert_not_called()
        self.driver.delete_flows_for_flow_state.assert_called_once_with(
            {'10.22.3.4': [self.conj_id]}, {},
            constants.INGRESS_DIRECTION, constants.IPv4, self.vlan_tag)
        # "conj_id_to_remove" is populated with the remote_sg conj_id assigned,
        # "_update_flows_for_vlan_subr" will call "delete_flow_for_ip".
        self.driver.delete_flow_for_ip.assert_called_once_with(
            '10.22.3.4', 'ingress', 'IPv4', 100, {self.conj_id})


class FakeOVSPort(object):
    def __init__(self, name, port, mac):
        self.port_name = name
        self.ofport = port
        self.vif_mac = mac


class TestOVSFirewallDriver(base.BaseTestCase):
    def setUp(self):
        super(TestOVSFirewallDriver, self).setUp()
        mock_bridge = mock.patch.object(
            ovs_lib, 'OVSBridge', autospec=True).start()
        securitygroups_rpc.register_securitygroups_opts()
        self.firewall = ovsfw.OVSFirewallDriver(mock_bridge)
        self.delete_invalid_conntrack_entries_mock = mock.patch.object(
            self.firewall.ipconntrack,
            "delete_conntrack_state_by_remote_ips").start()
        self.mock_bridge = self.firewall.int_br
        self.mock_bridge.reset_mock()
        self.fake_ovs_port = FakeOVSPort('port', 1, '00:00:00:00:00:00')
        self.mock_bridge.br.get_vif_port_by_id.return_value = \
            self.fake_ovs_port

    def _prepare_security_group(self):
        security_group_rules = [
            {'ethertype': constants.IPv4,
             'protocol': constants.PROTO_NAME_TCP,
             'direction': constants.INGRESS_DIRECTION,
             'port_range_min': 123,
             'port_range_max': 123}]
        self.firewall.update_security_group_rules(1, security_group_rules)
        security_group_rules = [
            {'ethertype': constants.IPv4,
             'protocol': constants.PROTO_NAME_UDP,
             'direction': constants.EGRESS_DIRECTION},
            {'ethertype': constants.IPv6,
             'protocol': constants.PROTO_NAME_TCP,
             'remote_group_id': 2,
             'direction': constants.EGRESS_DIRECTION},
            {'ethertype': constants.IPv4,
             'protocol': constants.PROTO_NAME_TCP,
             'remote_address_group_id': 3,
             'direction': constants.EGRESS_DIRECTION}
        ]
        self.firewall.update_security_group_rules(2, security_group_rules)

    def _assert_invalid_conntrack_entries_deleted(self, port_dict):
        port_dict['of_port'] = mock.Mock(vlan_tag=10)
        self.delete_invalid_conntrack_entries_mock.assert_has_calls([
            mock.call(
                [port_dict], constants.IPv4, set(),
                mark=ovsfw_consts.CT_MARK_INVALID),
            mock.call(
                [port_dict], constants.IPv6, set(),
                mark=ovsfw_consts.CT_MARK_INVALID)])

    @property
    def port_ofport(self):
        return self.mock_bridge.br.get_vif_port_by_id.return_value.ofport

    @property
    def port_mac(self):
        return self.mock_bridge.br.get_vif_port_by_id.return_value.vif_mac

    def test_callbacks_registered(self):
        with mock.patch.object(callbacks_registry, "subscribe") as subscribe:
            firewall = ovsfw.OVSFirewallDriver(mock.MagicMock())
            subscribe.assert_called_once_with(
                firewall._init_firewall_callback,
                callbacks_resources.AGENT,
                callbacks_events.OVS_RESTARTED)

    def test_initialize_bridge(self):
        br = self.firewall.initialize_bridge(self.mock_bridge)
        self.assertEqual(br, self.mock_bridge.deferred.return_value)

    def test__add_flow_dl_type_formatted_to_string(self):
        dl_type = 0x0800
        self.firewall._add_flow(dl_type=dl_type)

    def test__add_flow_registers_are_replaced(self):
        self.firewall._add_flow(in_port=1, reg_port=1, reg_net=2)
        expected_calls = {'in_port': 1,
                          'reg{:d}'.format(ovsfw_consts.REG_PORT): 1,
                          'reg{:d}'.format(ovsfw_consts.REG_NET): 2}
        self.mock_bridge.br.add_flow.assert_called_once_with(
            **expected_calls)

    def test__drop_all_unmatched_flows(self):
        self.firewall._drop_all_unmatched_flows()
        expected_calls = [
            mock.call(actions='drop', priority=0,
                      table=ovs_consts.BASE_EGRESS_TABLE),
            mock.call(actions='drop', priority=0,
                      table=ovs_consts.RULES_EGRESS_TABLE),
            mock.call(actions='drop', priority=0,
                      table=ovs_consts.ACCEPT_OR_INGRESS_TABLE),
            mock.call(actions='drop', priority=0,
                      table=ovs_consts.BASE_INGRESS_TABLE),
            mock.call(actions='drop', priority=0,
                      table=ovs_consts.RULES_INGRESS_TABLE)]
        actual_calls = self.firewall.int_br.br.add_flow.call_args_list
        self.assertEqual(expected_calls, actual_calls)

    def test_get_or_create_ofport_non_existing(self):
        port_dict = {
            'device': 'port-id',
            'security_groups': [123, 456]}
        port = self.firewall.get_or_create_ofport(port_dict)
        sg1, sg2 = sorted(
            self.firewall.sg_port_map.sec_groups.values(),
            key=lambda x: x.id)
        self.assertIn(port, self.firewall.sg_port_map.ports.values())
        self.assertEqual(
            sorted(port.sec_groups, key=lambda x: x.id), [sg1, sg2])
        self.assertIn(port, sg1.ports)
        self.assertIn(port, sg2.ports)

    def test_get_or_create_ofport_existing(self):
        port_dict = {
            'device': 'port-id',
            'security_groups': [123, 456]}
        of_port = create_ofport(port_dict)
        self.firewall.sg_port_map.ports[of_port.id] = of_port
        port = self.firewall.get_or_create_ofport(port_dict)
        sg1, sg2 = sorted(
            self.firewall.sg_port_map.sec_groups.values(),
            key=lambda x: x.id)
        self.assertIs(of_port, port)
        self.assertIn(port, self.firewall.sg_port_map.ports.values())
        self.assertEqual(
            sorted(port.sec_groups, key=lambda x: x.id), [sg1, sg2])
        self.assertIn(port, sg1.ports)
        self.assertIn(port, sg2.ports)

    def test_get_or_create_ofport_changed(self):
        port_dict = {
            'device': 'port-id',
            'security_groups': [123, 456]}
        of_port = create_ofport(port_dict)
        self.firewall.sg_port_map.ports[of_port.id] = of_port
        fake_ovs_port = FakeOVSPort('port', 2, '00:00:00:00:00:00')
        self.mock_bridge.br.get_vif_port_by_id.return_value = \
            fake_ovs_port
        port = self.firewall.get_or_create_ofport(port_dict)
        self.assertIn(of_port.id, self.firewall.sg_port_map.ports.keys())
        self.assertEqual(port.ofport, 2)

    def test_get_or_create_ofport_missing(self):
        port_dict = {
            'device': 'port-id',
            'security_groups': [123, 456]}
        self.mock_bridge.br.get_vif_port_by_id.return_value = None
        with testtools.ExpectedException(exceptions.OVSFWPortNotFound):
            self.firewall.get_or_create_ofport(port_dict)

    def test_get_or_create_ofport_missing_nocreate(self):
        port_dict = {
            'device': 'port-id',
            'security_groups': [123, 456]}
        self.mock_bridge.br.get_vif_port_by_id.return_value = None
        self.assertIsNone(self.firewall.get_ofport(port_dict))
        self.assertFalse(self.mock_bridge.br.get_vif_port_by_id.called)

    def test_is_port_managed_managed_port(self):
        port_dict = {'device': 'port-id'}
        self.firewall.sg_port_map.ports[port_dict['device']] = object()
        is_managed = self.firewall.is_port_managed(port_dict)
        self.assertTrue(is_managed)

    def test_is_port_managed_not_managed_port(self):
        port_dict = {'device': 'port-id'}
        is_managed = self.firewall.is_port_managed(port_dict)
        self.assertFalse(is_managed)

    def test_prepare_port_filter(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1],
                     'fixed_ips': ["10.0.0.1"]}
        self._prepare_security_group()
        self.firewall.prepare_port_filter(port_dict)
        exp_egress_classifier = mock.call(
            actions='set_field:{:d}->reg5,set_field:{:d}->reg6,'
                    'resubmit(,{:d})'.format(
                        self.port_ofport, TESTING_VLAN_TAG,
                        ovs_consts.BASE_EGRESS_TABLE),
            in_port=self.port_ofport,
            priority=100,
            table=ovs_consts.TRANSIENT_TABLE)
        exp_ingress_classifier = mock.call(
            actions='set_field:{:d}->reg5,set_field:{:d}->reg6,'
                    'strip_vlan,resubmit(,{:d})'.format(
                        self.port_ofport, TESTING_VLAN_TAG,
                        ovs_consts.BASE_INGRESS_TABLE),
            dl_dst=self.port_mac,
            dl_vlan='0x%x' % TESTING_VLAN_TAG,
            priority=90,
            table=ovs_consts.TRANSIENT_TABLE)
        filter_rule = mock.call(
            actions='ct(commit,zone=NXM_NX_REG6[0..15]),'
            'output:{:d},resubmit(,{:d})'.format(
                self.port_ofport,
                ovs_consts.ACCEPTED_INGRESS_TRAFFIC_TABLE),
            dl_type="0x{:04x}".format(constants.ETHERTYPE_IP),
            nw_proto=constants.PROTO_NUM_TCP,
            priority=77,
            reg5=self.port_ofport,
            ct_state=ovsfw_consts.OF_STATE_NEW_NOT_ESTABLISHED,
            table=ovs_consts.RULES_INGRESS_TABLE,
            tcp_dst='0x007b')
        calls = self.mock_bridge.br.add_flow.call_args_list
        for call in exp_ingress_classifier, exp_egress_classifier, filter_rule:
            self.assertIn(call, calls)
        self._assert_invalid_conntrack_entries_deleted(port_dict)

    def test_prepare_port_filter_port_security_disabled(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1],
                     'port_security_enabled': False}
        self._prepare_security_group()
        with mock.patch.object(
                self.firewall, 'initialize_port_flows') as m_init_flows:
            self.firewall.prepare_port_filter(port_dict)
        self.assertFalse(m_init_flows.called)
        self.delete_invalid_conntrack_entries_mock.assert_not_called()

    def _test_initialize_port_flows_dvr_conntrack_direct(self, network_type):
        port_dict = {
            'device': 'port-id',
            'security_groups': [1]}
        segment_id = None
        if network_type == constants.TYPE_VLAN:
            segment_id = TESTING_SEGMENT
        of_port = create_ofport(port_dict,
                                network_type=network_type,
                                segment_id=segment_id)
        self.firewall.sg_port_map.ports[of_port.id] = of_port
        port = self.firewall.get_or_create_ofport(port_dict)

        fake_patch_port = 999
        self.mock_bridge.br.get_port_ofport.return_value = fake_patch_port

        expected_calls = []
        self.firewall.initialize_port_flows(port)

        call_args1 = {
            'table': ovs_consts.TRANSIENT_TABLE,
            'priority': 100,
            'in_port': port.ofport,
            'actions': 'set_field:{:d}->reg{:d},'
                       'set_field:{:d}->reg{:d},'
                       'resubmit(,{:d})'.format(
                           port.ofport,
                           ovsfw_consts.REG_PORT,
                           port.vlan_tag,
                           ovsfw_consts.REG_NET,
                           ovs_consts.BASE_EGRESS_TABLE)}
        expected_calls.append(mock.call(**call_args1))

        if network_type == constants.TYPE_VLAN:
            call_args2 = {
                'table': ovs_consts.TRANSIENT_TABLE,
                'priority': 90,
                'dl_dst': port.mac,
                'dl_vlan': '0x%x' % port.segment_id,
                'actions': 'set_field:{:d}->reg{:d},'
                           'set_field:{:d}->reg{:d},'
                           'strip_vlan,resubmit(,{:d})'.format(
                               port.ofport,
                               ovsfw_consts.REG_PORT,
                               port.vlan_tag,
                               ovsfw_consts.REG_NET,
                               ovs_consts.BASE_INGRESS_TABLE)}
            expected_calls.append(mock.call(**call_args2))

        if network_type == constants.TYPE_FLAT:
            call_args2 = {
                'table': ovs_consts.TRANSIENT_TABLE,
                'priority': 90,
                'dl_dst': port.mac,
                'vlan_tci': ovs_consts.FLAT_VLAN_TCI,
                'actions': 'set_field:{:d}->reg{:d},'
                           'set_field:{:d}->reg{:d},'
                           'resubmit(,{:d})'.format(
                               port.ofport,
                               ovsfw_consts.REG_PORT,
                               port.vlan_tag,
                               ovsfw_consts.REG_NET,
                               ovs_consts.BASE_INGRESS_TABLE)}
            expected_calls.append(mock.call(**call_args2))

        call_args3 = {
            'table': ovs_consts.TRANSIENT_TABLE,
            'priority': 90,
            'dl_dst': port.mac,
            'dl_vlan': '0x%x' % port.vlan_tag,
            'actions': 'set_field:{:d}->reg{:d},'
                       'set_field:{:d}->reg{:d},'
                       'strip_vlan,resubmit(,{:d})'.format(
                           port.ofport,
                           ovsfw_consts.REG_PORT,
                           port.vlan_tag,
                           ovsfw_consts.REG_NET,
                           ovs_consts.BASE_INGRESS_TABLE)}
        expected_calls.append(mock.call(**call_args3))
        self.mock_bridge.br.add_flow.assert_has_calls(expected_calls)

    def test_initialize_port_flows_dvr_conntrack_direct_vxlan(self):
        self._test_initialize_port_flows_dvr_conntrack_direct(
                network_type='vxlan')

    def test_initialize_port_flows_dvr_conntrack_direct_vlan(self):
        self._test_initialize_port_flows_dvr_conntrack_direct(
                network_type='vlan')

    def test_initialize_port_flows_dvr_conntrack_direct_flat(self):
        self._test_initialize_port_flows_dvr_conntrack_direct(
                network_type='flat')

    def test_initialize_port_flows_vlan_dvr_conntrack_direct_vlan(self):
        port_dict = {
            'device': 'port-id',
            'security_groups': [1]}
        of_port = create_ofport(port_dict,
                                network_type=constants.TYPE_VLAN,
                                physical_network='vlan1')
        self.firewall.sg_port_map.ports[of_port.id] = of_port
        port = self.firewall.get_or_create_ofport(port_dict)

        fake_patch_port = 999
        self.mock_bridge.br.get_port_ofport.return_value = fake_patch_port

        with mock.patch.object(helpers, "parse_mappings",
                               return_value={"vlan1": "br-vlan1"}):
            self.firewall.initialize_port_flows(port)

    def test_delete_all_port_flows(self):
        port_dict = {
            'device': 'port-id',
            'security_groups': [1]}
        of_port = create_ofport(port_dict,
                                network_type=constants.TYPE_VXLAN)
        self.firewall.sg_port_map.ports[of_port.id] = of_port
        port = self.firewall.get_or_create_ofport(port_dict)

        self.firewall.delete_all_port_flows(port)

        call_args1 = {"table": ovs_consts.TRANSIENT_TABLE,
                      "dl_dst": port.mac,
                      "dl_vlan": port.vlan_tag}
        flow1 = mock.call(**call_args1)

        call_args2 = {"table": ovs_consts.TRANSIENT_TABLE,
                      "dl_dst": port.mac,
                      "dl_vlan": port.segment_id}
        flow2 = mock.call(**call_args2)

        call_args3 = {"table": ovs_consts.ACCEPT_OR_INGRESS_TABLE,
                      "dl_dst": port.mac,
                      "reg6": port.vlan_tag}
        flow3 = mock.call(**call_args3)

        call_args4 = {"in_port": port.ofport,
                      "table": ovs_consts.TRANSIENT_TABLE}
        flow4 = mock.call(**call_args4)

        call_args5 = {"reg5": port.ofport}
        flow5 = mock.call(**call_args5)

        call_args6 = {"table": ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE,
                      "dl_dst": port.mac,
                      "reg6": port.vlan_tag}
        flow6 = mock.call(**call_args6)

        call_args7 = {"table": ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE,
                      "dl_src": port.mac,
                      "reg6": port.vlan_tag}
        flow7 = mock.call(**call_args7)

        self.mock_bridge.br.delete_flows.assert_has_calls(
            [flow1, flow2, flow3, flow6, flow7, flow4, flow5])

    def test_prepare_port_filter_initialized_port(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self._prepare_security_group()
        self.firewall.prepare_port_filter(port_dict)
        self.assertFalse(self.mock_bridge.br.delete_flows.called)
        self.firewall.prepare_port_filter(port_dict)
        self.assertTrue(self.mock_bridge.br.delete_flows.called)
        self._assert_invalid_conntrack_entries_deleted(port_dict)

    def test_update_port_filter(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self._prepare_security_group()
        self.firewall.prepare_port_filter(port_dict)
        port_dict['security_groups'] = [2]
        self.mock_bridge.reset_mock()

        self.firewall.update_port_filter(port_dict)
        self.assertTrue(self.mock_bridge.br.delete_flows.called)
        rsg_conj_id = self.firewall.conj_ip_manager.conj_id_map.get_conj_id(
            2, 2, constants.EGRESS_DIRECTION, constants.IPv6)
        rag_conj_id = self.firewall.conj_ip_manager.conj_id_map.get_conj_id(
            2, 3, constants.EGRESS_DIRECTION, constants.IPv4)
        filter_rules = [mock.call(
            actions='resubmit(,{:d})'.format(
                ovs_consts.ACCEPT_OR_INGRESS_TABLE),
            dl_type="0x{:04x}".format(constants.ETHERTYPE_IP),
            nw_proto=constants.PROTO_NUM_UDP,
            priority=77,
            ct_state=ovsfw_consts.OF_STATE_NEW_NOT_ESTABLISHED,
            reg5=self.port_ofport,
            table=ovs_consts.RULES_EGRESS_TABLE),
                        mock.call(
            actions='conjunction({:d},2/2)'.format(rsg_conj_id + 6),
            ct_state=ovsfw_consts.OF_STATE_ESTABLISHED_NOT_REPLY,
            dl_type=mock.ANY,
            nw_proto=6,
            priority=73, reg5=self.port_ofport,
            table=ovs_consts.RULES_EGRESS_TABLE),
                        mock.call(
            actions='conjunction({:d},2/2)'.format(rag_conj_id + 6),
            ct_state=ovsfw_consts.OF_STATE_ESTABLISHED_NOT_REPLY,
            dl_type=mock.ANY,
            nw_proto=6,
            priority=73, reg5=self.port_ofport,
            table=ovs_consts.RULES_EGRESS_TABLE)
        ]
        self.mock_bridge.br.add_flow.assert_has_calls(
            filter_rules, any_order=True)
        self._assert_invalid_conntrack_entries_deleted(port_dict)

    def test_update_port_filter_create_new_port_if_not_present(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self._prepare_security_group()

        with mock.patch.object(
            self.firewall, 'prepare_port_filter'
        ) as prepare_mock, mock.patch.object(
            self.firewall, 'initialize_port_flows'
        ) as initialize_port_flows_mock, mock.patch.object(
            self.firewall, 'add_flows_from_rules'
        ) as add_flows_from_rules_mock:
            self.firewall.update_port_filter(port_dict)

        self.assertFalse(prepare_mock.called)
        self.assertFalse(self.mock_bridge.br.delete_flows.called)
        self.assertTrue(initialize_port_flows_mock.called)
        self.assertTrue(add_flows_from_rules_mock.called)
        self._assert_invalid_conntrack_entries_deleted(port_dict)

    def test_update_port_filter_port_security_disabled(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self._prepare_security_group()
        self.firewall.prepare_port_filter(port_dict)
        self.delete_invalid_conntrack_entries_mock.reset_mock()
        port_dict['port_security_enabled'] = False
        self.firewall.update_port_filter(port_dict)
        self.assertTrue(self.mock_bridge.br.delete_flows.called)
        self.delete_invalid_conntrack_entries_mock.assert_not_called()

    def test_update_port_filter_applies_added_flows(self):
        """Check flows are applied right after _set_flows is called."""
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self._prepare_security_group()
        self.firewall.prepare_port_filter(port_dict)
        with self.firewall.defer_apply():
            self.firewall.update_port_filter(port_dict)
        self.mock_bridge.apply_flows.assert_called_once()

    def test_update_port_filter_clean_when_port_not_found(self):
        """Check flows are cleaned if port is not found in the bridge."""
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self._prepare_security_group()
        self.firewall.prepare_port_filter(port_dict)
        self.mock_bridge.br.get_vif_port_by_id.return_value = None
        self.firewall.update_port_filter(port_dict)
        self.assertTrue(self.mock_bridge.br.delete_flows.called)
        self._assert_invalid_conntrack_entries_deleted(port_dict)

    def test_remove_port_filter(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self._prepare_security_group()
        self.firewall.prepare_port_filter(port_dict)
        self.firewall.remove_port_filter(port_dict)
        self.assertTrue(self.mock_bridge.br.delete_flows.called)
        self.assertIn(1, self.firewall.sg_to_delete)

    def test_remove_port_filter_port_security_disabled(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self.firewall.remove_port_filter(port_dict)
        self.assertFalse(self.mock_bridge.br.delete_flows.called)

    def test_update_security_group_rules(self):
        """Just make sure it doesn't crash"""
        new_rules = [
            {'ethertype': constants.IPv4,
             'direction': constants.INGRESS_DIRECTION,
             'protocol': constants.PROTO_NAME_ICMP},
            {'ethertype': constants.IPv4,
             'direction': constants.EGRESS_DIRECTION,
             'remote_group_id': 2}]
        self.firewall.update_security_group_rules(1, new_rules)

    def test_update_security_group_members(self):
        """Just make sure it doesn't crash"""
        new_members = {constants.IPv4: [1, 2, 3, 4]}
        self.firewall.update_security_group_members(2, new_members)

    def test__cleanup_stale_sg(self):
        self._prepare_security_group()
        self.firewall.sg_to_delete = {1}
        with mock.patch.object(self.firewall.conj_ip_manager,
                               'sg_removed') as sg_removed_mock,\
            mock.patch.object(self.firewall.sg_port_map,
                              'delete_sg') as delete_sg_mock:
            self.firewall._cleanup_stale_sg()
            sg_removed_mock.assert_called_once_with(1)
            delete_sg_mock.assert_called_once_with(1)

    def test_get_ovs_port(self):
        ovs_port = self.firewall.get_ovs_port('port_id')
        self.assertEqual(self.fake_ovs_port, ovs_port)

    def test_get_ovs_port_non_existent(self):
        self.mock_bridge.br.get_vif_port_by_id.return_value = None
        with testtools.ExpectedException(exceptions.OVSFWPortNotFound):
            self.firewall.get_ovs_port('port_id')

    def test_get_ovs_port_invalid(self):
        vif_port = ovs_lib.VifPort('name', 'ofport', 'id', 'mac', 'switch')
        self.mock_bridge.br.get_vif_port_by_id.return_value = vif_port
        for ofport in (ovs_lib.UNASSIGNED_OFPORT, ovs_lib.INVALID_OFPORT):
            vif_port.ofport = ofport
            with testtools.ExpectedException(exceptions.OVSFWPortNotFound):
                self.firewall.get_ovs_port('port_id')

    def test__initialize_egress_no_port_security_sends_to_egress(self):
        self.mock_bridge.br.db_get_val.return_value = {'tag': TESTING_VLAN_TAG}
        self.firewall._initialize_egress_no_port_security('port_id')
        expected_call = mock.call(
            table=ovs_consts.TRANSIENT_TABLE,
            priority=100,
            in_port=self.fake_ovs_port.ofport,
            actions='set_field:%d->reg%d,'
                    'set_field:%d->reg%d,'
                    'resubmit(,%d)' % (
                        self.fake_ovs_port.ofport,
                        ovsfw_consts.REG_PORT,
                        TESTING_VLAN_TAG,
                        ovsfw_consts.REG_NET,
                        ovs_consts.ACCEPT_OR_INGRESS_TABLE)
        )
        calls = self.mock_bridge.br.add_flow.call_args_list
        self.assertIn(expected_call, calls)

    def test__initialize_egress_no_port_security_no_tag(self):
        self.mock_bridge.br.db_get_val.return_value = {}
        self.firewall._initialize_egress_no_port_security('port_id')
        self.assertFalse(self.mock_bridge.br.add_flow.called)

    def test__remove_egress_no_port_security_deletes_flow(self):
        self.mock_bridge.br.db_get_val.return_value = {'tag': TESTING_VLAN_TAG}
        self.firewall.sg_port_map.unfiltered['port_id'] = (
            self.fake_ovs_port, 100)
        self.firewall._remove_egress_no_port_security('port_id')
        expected_call = mock.call(
            table=ovs_consts.TRANSIENT_TABLE,
            in_port=self.fake_ovs_port.ofport,
        )
        calls = self.mock_bridge.br.delete_flows.call_args_list
        self.assertIn(expected_call, calls)

    def test__remove_egress_no_port_security_non_existing_port(self):
        with testtools.ExpectedException(exceptions.OVSFWPortNotHandled):
            self.firewall._remove_egress_no_port_security('foo')

    def test__initialize_egress_ipv6_icmp(self):
        port_dict = {
            'device': 'port-id',
            'security_groups': [1],
            'fixed_ips': ["10.0.0.1"],
            'allowed_address_pairs': [
                {'mac_address': 'aa:bb:cc:dd:ee:ff',
                 'ip_address': '192.168.1.1'},
                {'mac_address': 'aa:bb:cc:dd:ee:ff',
                 'ip_address': '2003::1'}
            ]}
        of_port = create_ofport(port_dict)
        self.mock_bridge.br.db_get_val.return_value = {'tag': TESTING_VLAN_TAG}
        self.firewall._initialize_egress_ipv6_icmp(
            of_port, set([('aa:bb:cc:dd:ee:ff', '2003::1')]))
        expected_calls = []
        for icmp_type in agent_firewall.ICMPV6_ALLOWED_EGRESS_TYPES:
            expected_calls.append(
                mock.call(
                    table=ovs_consts.BASE_EGRESS_TABLE,
                    priority=95,
                    in_port=TESTING_VLAN_TAG,
                    reg5=TESTING_VLAN_TAG,
                    dl_type='0x86dd',
                    nw_proto=constants.PROTO_NUM_IPV6_ICMP,
                    icmp_type=icmp_type,
                    dl_src='aa:bb:cc:dd:ee:ff',
                    ipv6_src='2003::1',
                    actions='resubmit(,%d)' % (
                        ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)))
        for icmp_type in agent_firewall.ICMPV6_RESTRICTED_EGRESS_TYPES:
            expected_calls.append(
                mock.call(
                    table=ovs_consts.BASE_EGRESS_TABLE,
                    priority=95,
                    in_port=TESTING_VLAN_TAG,
                    reg5=TESTING_VLAN_TAG,
                    dl_type='0x86dd',
                    nw_proto=constants.PROTO_NUM_IPV6_ICMP,
                    icmp_type=icmp_type,
                    nd_target='2003::1',
                    actions='resubmit(,%d)' % (
                        ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)))
        self.mock_bridge.br.add_flow.assert_has_calls(expected_calls)

    def test_process_trusted_ports_caches_port_id(self):
        vif_port = ovs_lib.VifPort('name', 1, 'id', 'mac', mock.ANY)
        with mock.patch.object(self.firewall.int_br.br, 'get_vifs_by_ids',
                               return_value={'port_id': vif_port}):
            self.firewall.process_trusted_ports(['port_id'])
            self.assertEqual(1,
                             len(self.firewall.sg_port_map.unfiltered.keys()))
            ofport, _ = self.firewall.sg_port_map.unfiltered['port_id']
            self.assertEqual(vif_port.ofport, ofport.ofport)

    def test_process_trusted_ports_port_not_found(self):
        """Check that exception is not propagated outside."""
        with mock.patch.object(self.firewall.int_br.br, 'get_vifs_by_ids',
                               return_value={}):
            self.firewall.process_trusted_ports(['port_id'])
            # Processing should have failed so port is not cached
            self.assertEqual(0, len(self.firewall.sg_port_map.unfiltered))

    def test_remove_trusted_ports_clears_cached_port_id(self):
        self.firewall.sg_port_map.unfiltered['port_id'] = (
            self.fake_ovs_port, 100)
        self.firewall.remove_trusted_ports(['port_id'])
        self.assertNotIn('port_id', self.firewall.sg_port_map.unfiltered)

    def test_remove_trusted_ports_not_managed_port(self):
        """Check that exception is not propagated outside."""
        self.firewall.remove_trusted_ports(['port_id'])

    def _test_delete_flows_for_flow_state(self, addr_to_conj,
                                          explicitly_egress_direct=True):
        direction = 'one_direction'
        ethertype = 'ethertype'
        vlan_tag = 'taaag'
        with mock.patch.object(self.firewall, 'delete_flow_for_ip') as \
                mock_delete_flow_for_ip:
            flow_state = {'addr1': {8, 16, 24}, 'addr2': {32, 40}}
            cfg.CONF.set_override('explicitly_egress_direct',
                                  explicitly_egress_direct, 'AGENT')
            self.firewall.delete_flows_for_flow_state(
                flow_state, addr_to_conj, direction, ethertype, vlan_tag)
        calls = []
        for removed_ip in flow_state.keys() - addr_to_conj.keys():
            calls.append(mock.call(removed_ip, direction, ethertype, vlan_tag,
                                   flow_state[removed_ip]))
            if explicitly_egress_direct:
                calls.append(mock.call(removed_ip, direction, ethertype,
                                       vlan_tag, [0]))
        mock_delete_flow_for_ip.assert_has_calls(calls)

    def test_delete_flows_for_flow_state_no_removed_ips_exp_egress(self):
        addr_to_conj = {'addr1': {8, 16, 24}, 'addr2': {32, 40}}
        self._test_delete_flows_for_flow_state(addr_to_conj)

    def test_delete_flows_for_flow_state_no_removed_ips_no_exp_egress(self):
        addr_to_conj = {'addr1': {8, 16, 24}, 'addr2': {32, 40}}
        self._test_delete_flows_for_flow_state(addr_to_conj, False)

    def test_delete_flows_for_flow_state_removed_ips_exp_egress(self):
        addr_to_conj = {'addr2': {32, 40}}
        self._test_delete_flows_for_flow_state(addr_to_conj)

    def test_delete_flows_for_flow_state_removed_ips_no_exp_egress(self):
        addr_to_conj = {'addr1': {8, 16, 24}}
        self._test_delete_flows_for_flow_state(addr_to_conj, False)

    def test_delete_flow_for_ip_using_cookie_any(self):
        with mock.patch.object(self.firewall, '_delete_flows') as \
                mock_delete_flows:
            self.firewall.delete_flow_for_ip(('10.1.2.3', None),
                                             constants.INGRESS_DIRECTION,
                                             constants.IPv4, 100, [0])
            _, kwargs = mock_delete_flows.call_args
            self.assertIn('cookie', kwargs)
            self.assertIs(ovs_lib.COOKIE_ANY, kwargs['cookie'])


class TestCookieContext(base.BaseTestCase):
    def setUp(self):
        super(TestCookieContext, self).setUp()
        # Don't attempt to connect to ovsdb
        mock.patch('neutron.agent.ovsdb.impl_idl.api_factory').start()
        # Don't trigger iptables -> ovsfw migration
        mock.patch(
            'neutron.agent.linux.openvswitch_firewall.iptables.Helper').start()

        self.execute = mock.patch.object(
            utils, "execute", spec=utils.execute).start()
        bridge = ovs_bridge.OVSAgentBridge('foo', os_ken_app=mock.Mock())
        mock.patch.object(
            ovsfw.OVSFirewallDriver, 'initialize_bridge',
            return_value=bridge.deferred(
                full_ordered=True, use_bundle=True)).start()
        mock.patch.object(ovsfw.ConjIdMap, '_init_max_id',
                          return_value=0).start()

        securitygroups_rpc.register_securitygroups_opts()
        self.firewall = ovsfw.OVSFirewallDriver(bridge)
        # Remove calls from firewall initialization
        self.execute.reset_mock()

    def test_cookie_is_different_in_context(self):
        default_cookie = self.firewall.int_br.br.default_cookie
        with self.firewall.update_cookie_context():
            self.firewall._add_flow(actions='drop')
            update_cookie = self.firewall._update_cookie
        self.firewall._add_flow(actions='drop')
        expected_calls = [
            mock.call(
                mock.ANY,
                process_input='hard_timeout=0,idle_timeout=0,priority=1,'
                              'cookie=%d,actions=drop' % cookie,
                run_as_root=True, privsep_exec=True
            ) for cookie in (update_cookie, default_cookie)
        ]

        self.execute.assert_has_calls(expected_calls)

    def test_context_cookie_is_not_left_as_used(self):
        with self.firewall.update_cookie_context():
            update_cookie = self.firewall._update_cookie
        self.assertNotIn(
            update_cookie,
            self.firewall.int_br.br._reserved_cookies)
