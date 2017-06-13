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

import mock
from neutron_lib import constants
import testtools

from neutron.agent.common import ovs_lib
from neutron.agent import firewall
from neutron.agent.linux.openvswitch_firewall import constants as ovsfw_consts
from neutron.agent.linux.openvswitch_firewall import exceptions
from neutron.agent.linux.openvswitch_firewall import firewall as ovsfw
from neutron.common import constants as n_const
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants \
        as ovs_consts
from neutron.tests import base

TESTING_VLAN_TAG = 1


def create_ofport(port_dict):
    ovs_port = mock.Mock(vif_mac='00:00:00:00:00:00', ofport=1,
                         port_name="port-name")
    return ovsfw.OFPort(port_dict, ovs_port, vlan_tag=TESTING_VLAN_TAG)


class TestCreateRegNumbers(base.BaseTestCase):
    def test_no_registers_defined(self):
        flow = {'foo': 'bar'}
        ovsfw.create_reg_numbers(flow)
        self.assertEqual({'foo': 'bar'}, flow)

    def test_both_registers_defined(self):
        flow = {'foo': 'bar', 'reg_port': 1, 'reg_net': 2}
        expected_flow = {'foo': 'bar',
                         'reg{:d}'.format(ovsfw_consts.REG_PORT): 1,
                         'reg{:d}'.format(ovsfw_consts.REG_NET): 2}
        ovsfw.create_reg_numbers(flow)
        self.assertEqual(expected_flow, flow)


class TestSecurityGroup(base.BaseTestCase):
    def setUp(self):
        super(TestSecurityGroup, self).setUp()
        self.sg = ovsfw.SecurityGroup('123')
        self.sg.members = {'type': [1, 2, 3, 4]}

    def test_update_rules(self):
        rules = [
            {'foo': 'bar', 'rule': 'all'}, {'bar': 'foo'},
            {'remote_group_id': '123456', 'foo': 'bar'}]
        expected_raw_rules = [{'foo': 'bar', 'rule': 'all'}, {'bar': 'foo'}]
        expected_remote_rules = [{'remote_group_id': '123456', 'foo': 'bar'}]
        self.sg.update_rules(rules)

        self.assertEqual(expected_raw_rules, self.sg.raw_rules)
        self.assertEqual(expected_remote_rules, self.sg.remote_rules)

    def get_ethertype_filtered_addresses(self):
        addresses = self.sg.get_ethertype_filtered_addresses('type')
        expected_addresses = [1, 2, 3, 4]
        self.assertEqual(expected_addresses, addresses)

    def get_ethertype_filtered_addresses_with_excluded_addresses(self):
        addresses = self.sg.get_ethertype_filtered_addresses('type', [2, 3])
        expected_addresses = [1, 4]
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
        self.firewall = ovsfw.OVSFirewallDriver(mock_bridge)
        self.mock_bridge = self.firewall.int_br
        self.mock_bridge.reset_mock()
        self.fake_ovs_port = FakeOVSPort('port', 1, '00:00:00:00:00:00')
        self.mock_bridge.br.get_vif_port_by_id.return_value = \
            self.fake_ovs_port

    def _prepare_security_group(self):
        security_group_rules = [
            {'ethertype': constants.IPv4,
             'protocol': constants.PROTO_NAME_TCP,
             'direction': firewall.INGRESS_DIRECTION,
             'port_range_min': 123,
             'port_range_max': 123}]
        self.firewall.update_security_group_rules(1, security_group_rules)
        security_group_rules = [
            {'ethertype': constants.IPv4,
             'protocol': constants.PROTO_NAME_UDP,
             'direction': firewall.EGRESS_DIRECTION}]
        self.firewall.update_security_group_rules(2, security_group_rules)

    @property
    def port_ofport(self):
        return self.mock_bridge.br.get_vif_port_by_id.return_value.ofport

    @property
    def port_mac(self):
        return self.mock_bridge.br.get_vif_port_by_id.return_value.vif_mac

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
            table=ovs_consts.LOCAL_SWITCHING)
        exp_ingress_classifier = mock.call(
            actions='set_field:{:d}->reg5,set_field:{:d}->reg6,'
                    'resubmit(,{:d})'.format(
                        self.port_ofport, TESTING_VLAN_TAG,
                        ovs_consts.BASE_INGRESS_TABLE),
            dl_dst=self.port_mac,
            priority=90,
            table=ovs_consts.LOCAL_SWITCHING)
        filter_rule = mock.call(
            actions='ct(commit,zone=NXM_NX_REG6[0..15]),'
            'strip_vlan,output:{:d}'.format(self.port_ofport),
            dl_type="0x{:04x}".format(n_const.ETHERTYPE_IP),
            nw_proto=constants.PROTO_NUM_TCP,
            priority=70,
            reg5=self.port_ofport,
            ct_state=ovsfw_consts.OF_STATE_NEW_NOT_ESTABLISHED,
            table=ovs_consts.RULES_INGRESS_TABLE,
            tcp_dst='0x007b')
        calls = self.mock_bridge.br.add_flow.call_args_list
        for call in exp_ingress_classifier, exp_egress_classifier, filter_rule:
            self.assertIn(call, calls)

    def test_prepare_port_filter_port_security_disabled(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1],
                     'port_security_enabled': False}
        self._prepare_security_group()
        self.firewall.prepare_port_filter(port_dict)
        self.assertFalse(self.mock_bridge.br.add_flow.called)

    def test_prepare_port_filter_initialized_port(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self._prepare_security_group()
        self.firewall.prepare_port_filter(port_dict)
        self.assertFalse(self.mock_bridge.br.delete_flows.called)
        self.firewall.prepare_port_filter(port_dict)
        self.assertTrue(self.mock_bridge.br.delete_flows.called)

    def test_update_port_filter(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self._prepare_security_group()
        self.firewall.prepare_port_filter(port_dict)
        port_dict['security_groups'] = [2]
        self.mock_bridge.reset_mock()

        self.firewall.update_port_filter(port_dict)
        self.assertTrue(self.mock_bridge.br.delete_flows.called)
        add_calls = self.mock_bridge.br.add_flow.call_args_list
        filter_rule = mock.call(
            actions='resubmit(,{:d})'.format(
                ovs_consts.ACCEPT_OR_INGRESS_TABLE),
            dl_type="0x{:04x}".format(n_const.ETHERTYPE_IP),
            nw_proto=constants.PROTO_NUM_UDP,
            priority=70,
            ct_state=ovsfw_consts.OF_STATE_NEW_NOT_ESTABLISHED,
            reg5=self.port_ofport,
            table=ovs_consts.RULES_EGRESS_TABLE)
        self.assertIn(filter_rule, add_calls)

    def test_update_port_filter_create_new_port_if_not_present(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self._prepare_security_group()
        with mock.patch.object(
                self.firewall, 'prepare_port_filter') as prepare_mock:
            self.firewall.update_port_filter(port_dict)
        self.assertTrue(prepare_mock.called)

    def test_update_port_filter_port_security_disabled(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self._prepare_security_group()
        self.firewall.prepare_port_filter(port_dict)
        port_dict['port_security_enabled'] = False
        self.firewall.update_port_filter(port_dict)
        self.assertTrue(self.mock_bridge.br.delete_flows.called)

    def test_remove_port_filter(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self._prepare_security_group()
        self.firewall.prepare_port_filter(port_dict)
        self.firewall.remove_port_filter(port_dict)
        self.assertTrue(self.mock_bridge.br.delete_flows.called)

    def test_remove_port_filter_port_security_disabled(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self.firewall.remove_port_filter(port_dict)
        self.assertFalse(self.mock_bridge.br.delete_flows.called)

    def test_update_security_group_rules(self):
        """Just make sure it doesn't crash"""
        new_rules = [
            {'ethertype': constants.IPv4,
             'direction': firewall.INGRESS_DIRECTION,
             'protocol': constants.PROTO_NAME_ICMP},
            {'ethertype': constants.IPv4,
             'direction': firewall.EGRESS_DIRECTION,
             'remote_group_id': 2}]
        self.firewall.update_security_group_rules(1, new_rules)

    def test_update_security_group_members(self):
        """Just make sure it doesn't crash"""
        new_members = {constants.IPv4: [1, 2, 3, 4]}
        self.firewall.update_security_group_members(2, new_members)
