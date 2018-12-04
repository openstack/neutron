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
from neutron_lib.callbacks import events as callbacks_events
from neutron_lib.callbacks import registry as callbacks_registry
from neutron_lib.callbacks import resources as callbacks_resources
from neutron_lib import constants
import testtools

from neutron.agent.common import ovs_lib
from neutron.agent.common import utils
from neutron.agent.linux.openvswitch_firewall import constants as ovsfw_consts
from neutron.agent.linux.openvswitch_firewall import exceptions
from neutron.agent.linux.openvswitch_firewall import firewall as ovsfw
from neutron.common import constants as n_const
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants \
        as ovs_consts
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl \
    import ovs_bridge
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
            {'remote_group_id': '123456', 'foo': 'bar'}]
        expected_raw_rules = [{'foo': 'bar', 'rule': 'all'}, {'bar': 'foo'}]
        expected_remote_rules = [{'remote_group_id': '123456', 'foo': 'bar'}]
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
        self.conj_id_map = ovsfw.ConjIdMap()

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
        test_data = [('sg1', 'sg1'), ('sg1', 'sg2')]

        ids = []
        for sg_id, remote_sg_id in test_data:
            ids.append(self.conj_id_map.get_conj_id(
                sg_id, remote_sg_id,
                constants.INGRESS_DIRECTION, constants.IPv6))

        result = self.conj_id_map.delete_sg('sg1')
        self.assertIn(('sg1', ids[0]), result)
        self.assertIn(('sg2', ids[1]), result)
        self.assertFalse(self.conj_id_map.id_map)

        reallocated = self.conj_id_map.get_conj_id(
            'sg-foo', 'sg-foo', constants.INGRESS_DIRECTION,
            constants.IPv6)
        self.assertIn(reallocated, ids)


class TestConjIPFlowManager(base.BaseTestCase):
    def setUp(self):
        super(TestConjIPFlowManager, self).setUp()
        self.driver = mock.Mock()
        self.manager = ovsfw.ConjIPFlowManager(self.driver)
        self.vlan_tag = 100
        self.conj_id = 16

    def test_update_flows_for_vlan(self):
        remote_group = self.driver.sg_port_map.get_sg.return_value
        remote_group.get_ethertype_filtered_addresses.return_value = [
            '10.22.3.4']
        with mock.patch.object(self.manager.conj_id_map,
                               'get_conj_id') as get_conj_id_mock:
            get_conj_id_mock.return_value = self.conj_id
            self.manager.add(self.vlan_tag, 'sg', 'remote_id',
                             constants.INGRESS_DIRECTION, constants.IPv4, 0)
            self.manager.add(self.vlan_tag, 'sg', 'remote_id',
                             constants.INGRESS_DIRECTION, constants.IPv4, 3)
            self.manager.update_flows_for_vlan(self.vlan_tag)
        self.assertEqual(self.driver._add_flow.call_args_list,
            [mock.call(actions='conjunction(16,1/2)', ct_state='+est-rel-rpl',
                       dl_type=2048, nw_src='10.22.3.4/32', priority=70,
                       reg_net=self.vlan_tag, table=82),
             mock.call(actions='conjunction(17,1/2)', ct_state='+new-est',
                       dl_type=2048, nw_src='10.22.3.4/32', priority=70,
                       reg_net=self.vlan_tag, table=82),
             mock.call(actions='conjunction(22,1/2)', ct_state='+est-rel-rpl',
                       dl_type=2048, nw_src='10.22.3.4/32', priority=73,
                       reg_net=self.vlan_tag, table=82),
             mock.call(actions='conjunction(23,1/2)', ct_state='+new-est',
                       dl_type=2048, nw_src='10.22.3.4/32', priority=73,
                       reg_net=self.vlan_tag, table=82)])

    def test_sg_removed(self):
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

            self.manager.sg_removed('sg')
        self.driver._add_flow.assert_not_called()
        self.driver.delete_flows_for_ip_addresses.assert_called_once_with(
            {'10.22.3.4'}, constants.INGRESS_DIRECTION, constants.IPv4,
            self.vlan_tag)


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
             'direction': constants.EGRESS_DIRECTION}]
        self.firewall.update_security_group_rules(2, security_group_rules)

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
            dl_type="0x{:04x}".format(n_const.ETHERTYPE_IP),
            nw_proto=constants.PROTO_NUM_TCP,
            priority=77,
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
        with mock.patch.object(
                self.firewall, 'initialize_port_flows') as m_init_flows:
            self.firewall.prepare_port_filter(port_dict)
        self.assertFalse(m_init_flows.called)

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
        conj_id = self.firewall.conj_ip_manager.conj_id_map.get_conj_id(
            2, 2, constants.EGRESS_DIRECTION, constants.IPv6)
        filter_rules = [mock.call(
            actions='resubmit(,{:d})'.format(
                ovs_consts.ACCEPT_OR_INGRESS_TABLE),
            dl_type="0x{:04x}".format(n_const.ETHERTYPE_IP),
            nw_proto=constants.PROTO_NUM_UDP,
            priority=77,
            ct_state=ovsfw_consts.OF_STATE_NEW_NOT_ESTABLISHED,
            reg5=self.port_ofport,
            table=ovs_consts.RULES_EGRESS_TABLE),
                        mock.call(
            actions='conjunction({:d},2/2)'.format(conj_id + 6),
            ct_state=ovsfw_consts.OF_STATE_ESTABLISHED_NOT_REPLY,
            dl_type=mock.ANY,
            nw_proto=6,
            priority=73, reg5=self.port_ofport,
            table=ovs_consts.RULES_EGRESS_TABLE)]
        self.mock_bridge.br.add_flow.assert_has_calls(
            filter_rules, any_order=True)

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

    def test_update_port_filter_port_security_disabled(self):
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self._prepare_security_group()
        self.firewall.prepare_port_filter(port_dict)
        port_dict['port_security_enabled'] = False
        self.firewall.update_port_filter(port_dict)
        self.assertTrue(self.mock_bridge.br.delete_flows.called)

    def test_update_port_filter_applies_added_flows(self):
        """Check flows are applied right after _set_flows is called."""
        port_dict = {'device': 'port-id',
                     'security_groups': [1]}
        self._prepare_security_group()
        self.firewall.prepare_port_filter(port_dict)
        with self.firewall.defer_apply():
            self.firewall.update_port_filter(port_dict)
        self.assertEqual(2, self.mock_bridge.apply_flows.call_count)

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
        self.firewall.sg_port_map.unfiltered['port_id'] = 1
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

    def test_process_trusted_ports_caches_port_id(self):
        self.firewall.process_trusted_ports(['port_id'])
        self.assertIn('port_id', self.firewall.sg_port_map.unfiltered)

    def test_process_trusted_ports_port_not_found(self):
        """Check that exception is not propagated outside."""
        self.mock_bridge.br.get_vif_port_by_id.return_value = None
        self.firewall.process_trusted_ports(['port_id'])
        # Processing should have failed so port is not cached
        self.assertNotIn('port_id', self.firewall.sg_port_map.unfiltered)

    def test_remove_trusted_ports_clears_cached_port_id(self):
        self.firewall.sg_port_map.unfiltered['port_id'] = 1
        self.firewall.remove_trusted_ports(['port_id'])
        self.assertNotIn('port_id', self.firewall.sg_port_map.unfiltered)

    def test_remove_trusted_ports_not_managed_port(self):
        """Check that exception is not propagated outside."""
        self.firewall.remove_trusted_ports(['port_id'])


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
        bridge = ovs_bridge.OVSAgentBridge('foo')
        mock.patch.object(
            ovsfw.OVSFirewallDriver, 'initialize_bridge',
            return_value=bridge.deferred(
                full_ordered=True, use_bundle=True)).start()

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
                run_as_root=mock.ANY,
            ) for cookie in (update_cookie, default_cookie)
        ]

        self.execute.assert_has_calls(expected_calls)

    def test_context_cookie_is_not_left_as_used(self):
        with self.firewall.update_cookie_context():
            update_cookie = self.firewall._update_cookie
        self.assertNotIn(
            update_cookie,
            self.firewall.int_br.br._reserved_cookies)
