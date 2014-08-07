# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

from contextlib import contextmanager
from contextlib import nested

import mock
from mock import call
from oslo.config import cfg
from testtools import matchers
import webob.exc

from neutron.agent.common import config
from neutron.agent import firewall as firewall_base
from neutron.agent.linux import iptables_manager
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import constants as const
from neutron import context
from neutron.db import securitygroups_rpc_base as sg_db_rpc
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import securitygroup as ext_sg
from neutron.manager import NeutronManager
from neutron.openstack.common.rpc import proxy
from neutron.tests import base
from neutron.tests.unit import test_extension_security_group as test_sg
from neutron.tests.unit import test_iptables_firewall as test_fw


class FakeSGCallback(sg_db_rpc.SecurityGroupServerRpcCallbackMixin):
    def get_port_from_device(self, device):
        device = self.devices.get(device)
        if device:
            device['security_group_rules'] = []
            device['security_group_source_groups'] = []
            device['fixed_ips'] = [ip['ip_address']
                                   for ip in device['fixed_ips']]
        return device


class SGServerRpcCallBackMixinTestCase(test_sg.SecurityGroupDBTestCase):
    def setUp(self, plugin=None):
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        super(SGServerRpcCallBackMixinTestCase, self).setUp(plugin)
        self.rpc = FakeSGCallback()

    def test_security_group_rules_for_devices_ipv4_ingress(self):
        fake_prefix = test_fw.FAKE_PREFIX[const.IPv4]
        with self.network() as n:
            with nested(self.subnet(n),
                        self.security_group()) as (subnet_v4,
                                                   sg1):
                sg1_id = sg1['security_group']['id']
                rule1 = self._build_security_group_rule(
                    sg1_id,
                    'ingress', const.PROTO_NAME_TCP, '22',
                    '22')
                rule2 = self._build_security_group_rule(
                    sg1_id,
                    'ingress', const.PROTO_NAME_TCP, '23',
                    '23', fake_prefix)
                rules = {
                    'security_group_rules': [rule1['security_group_rule'],
                                             rule2['security_group_rule']]}
                res = self._create_security_group_rule(self.fmt, rules)
                self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)

                res1 = self._create_port(
                    self.fmt, n['network']['id'],
                    security_groups=[sg1_id])
                ports_rest1 = self.deserialize(self.fmt, res1)
                port_id1 = ports_rest1['port']['id']
                self.rpc.devices = {port_id1: ports_rest1['port']}
                devices = [port_id1, 'no_exist_device']
                ctx = context.get_admin_context()
                ports_rpc = self.rpc.security_group_rules_for_devices(
                    ctx, devices=devices)
                port_rpc = ports_rpc[port_id1]
                expected = [{'direction': 'egress', 'ethertype': const.IPv4,
                             'security_group_id': sg1_id},
                            {'direction': 'egress', 'ethertype': const.IPv6,
                             'security_group_id': sg1_id},
                            {'direction': 'ingress',
                             'protocol': const.PROTO_NAME_TCP,
                             'ethertype': const.IPv4,
                             'port_range_max': 22,
                             'security_group_id': sg1_id,
                             'port_range_min': 22},
                            {'direction': 'ingress',
                             'protocol': const.PROTO_NAME_TCP,
                             'ethertype': const.IPv4,
                             'port_range_max': 23, 'security_group_id': sg1_id,
                             'port_range_min': 23,
                             'source_ip_prefix': fake_prefix},
                            ]
                self.assertEqual(port_rpc['security_group_rules'],
                                 expected)
                self._delete('ports', port_id1)

    def test_security_group_rules_for_devices_ipv4_ingress_addr_pair(self):
        plugin_obj = NeutronManager.get_plugin()
        if ('allowed-address-pairs'
            not in plugin_obj.supported_extension_aliases):
            self.skipTest("Test depeneds on allowed-address-pairs extension")
        fake_prefix = test_fw.FAKE_PREFIX['IPv4']
        with self.network() as n:
            with nested(self.subnet(n),
                        self.security_group()) as (subnet_v4,
                                                   sg1):
                sg1_id = sg1['security_group']['id']
                rule1 = self._build_security_group_rule(
                    sg1_id,
                    'ingress', 'tcp', '22',
                    '22')
                rule2 = self._build_security_group_rule(
                    sg1_id,
                    'ingress', 'tcp', '23',
                    '23', fake_prefix)
                rules = {
                    'security_group_rules': [rule1['security_group_rule'],
                                             rule2['security_group_rule']]}
                res = self._create_security_group_rule(self.fmt, rules)
                self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, 201)
                address_pairs = [{'mac_address': '00:00:00:00:00:01',
                                  'ip_address': '10.0.0.0/24'},
                                 {'mac_address': '00:00:00:00:00:01',
                                  'ip_address': '11.0.0.1'}]
                res1 = self._create_port(
                    self.fmt, n['network']['id'],
                    security_groups=[sg1_id],
                    arg_list=(addr_pair.ADDRESS_PAIRS,),
                    allowed_address_pairs=address_pairs)
                ports_rest1 = self.deserialize(self.fmt, res1)
                port_id1 = ports_rest1['port']['id']
                self.rpc.devices = {port_id1: ports_rest1['port']}
                devices = [port_id1, 'no_exist_device']
                ctx = context.get_admin_context()
                ports_rpc = self.rpc.security_group_rules_for_devices(
                    ctx, devices=devices)
                port_rpc = ports_rpc[port_id1]
                expected = [{'direction': 'egress', 'ethertype': 'IPv4',
                             'security_group_id': sg1_id},
                            {'direction': 'egress', 'ethertype': 'IPv6',
                             'security_group_id': sg1_id},
                            {'direction': 'ingress',
                             'protocol': 'tcp', 'ethertype': 'IPv4',
                             'port_range_max': 22,
                             'security_group_id': sg1_id,
                             'port_range_min': 22},
                            {'direction': 'ingress', 'protocol': 'tcp',
                             'ethertype': 'IPv4',
                             'port_range_max': 23, 'security_group_id': sg1_id,
                             'port_range_min': 23,
                             'source_ip_prefix': fake_prefix},
                            ]
                self.assertEqual(port_rpc['security_group_rules'],
                                 expected)
                self.assertEqual(port_rpc['allowed_address_pairs'],
                                 address_pairs)
                self._delete('ports', port_id1)

    def test_security_group_rules_for_devices_ipv4_egress(self):
        fake_prefix = test_fw.FAKE_PREFIX[const.IPv4]
        with self.network() as n:
            with nested(self.subnet(n),
                        self.security_group()) as (subnet_v4,
                                                   sg1):
                sg1_id = sg1['security_group']['id']
                rule1 = self._build_security_group_rule(
                    sg1_id,
                    'egress', const.PROTO_NAME_TCP, '22',
                    '22')
                rule2 = self._build_security_group_rule(
                    sg1_id,
                    'egress', const.PROTO_NAME_UDP, '23',
                    '23', fake_prefix)
                rules = {
                    'security_group_rules': [rule1['security_group_rule'],
                                             rule2['security_group_rule']]}
                res = self._create_security_group_rule(self.fmt, rules)
                self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)

                res1 = self._create_port(
                    self.fmt, n['network']['id'],
                    security_groups=[sg1_id])
                ports_rest1 = self.deserialize(self.fmt, res1)
                port_id1 = ports_rest1['port']['id']
                self.rpc.devices = {port_id1: ports_rest1['port']}
                devices = [port_id1, 'no_exist_device']
                ctx = context.get_admin_context()
                ports_rpc = self.rpc.security_group_rules_for_devices(
                    ctx, devices=devices)
                port_rpc = ports_rpc[port_id1]
                expected = [{'direction': 'egress', 'ethertype': const.IPv4,
                             'security_group_id': sg1_id},
                            {'direction': 'egress', 'ethertype': const.IPv6,
                             'security_group_id': sg1_id},
                            {'direction': 'egress',
                             'protocol': const.PROTO_NAME_TCP,
                             'ethertype': const.IPv4,
                             'port_range_max': 22,
                             'security_group_id': sg1_id,
                             'port_range_min': 22},
                            {'direction': 'egress',
                             'protocol': const.PROTO_NAME_UDP,
                             'ethertype': const.IPv4,
                             'port_range_max': 23, 'security_group_id': sg1_id,
                             'port_range_min': 23,
                             'dest_ip_prefix': fake_prefix},
                            ]
                self.assertEqual(port_rpc['security_group_rules'],
                                 expected)
                self._delete('ports', port_id1)

    def test_security_group_rules_for_devices_ipv4_source_group(self):

        with self.network() as n:
            with nested(self.subnet(n),
                        self.security_group(),
                        self.security_group()) as (subnet_v4,
                                                   sg1,
                                                   sg2):
                sg1_id = sg1['security_group']['id']
                sg2_id = sg2['security_group']['id']
                rule1 = self._build_security_group_rule(
                    sg1_id,
                    'ingress', const.PROTO_NAME_TCP, '24',
                    '25', remote_group_id=sg2['security_group']['id'])
                rules = {
                    'security_group_rules': [rule1['security_group_rule']]}
                res = self._create_security_group_rule(self.fmt, rules)
                self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)

                res1 = self._create_port(
                    self.fmt, n['network']['id'],
                    security_groups=[sg1_id,
                                     sg2_id])
                ports_rest1 = self.deserialize(self.fmt, res1)
                port_id1 = ports_rest1['port']['id']
                self.rpc.devices = {port_id1: ports_rest1['port']}
                devices = [port_id1, 'no_exist_device']

                res2 = self._create_port(
                    self.fmt, n['network']['id'],
                    security_groups=[sg2_id])
                ports_rest2 = self.deserialize(self.fmt, res2)
                port_id2 = ports_rest2['port']['id']
                ctx = context.get_admin_context()
                ports_rpc = self.rpc.security_group_rules_for_devices(
                    ctx, devices=devices)
                port_rpc = ports_rpc[port_id1]
                expected = [{'direction': 'egress', 'ethertype': const.IPv4,
                             'security_group_id': sg1_id},
                            {'direction': 'egress', 'ethertype': const.IPv6,
                             'security_group_id': sg1_id},
                            {'direction': 'egress', 'ethertype': const.IPv4,
                             'security_group_id': sg2_id},
                            {'direction': 'egress', 'ethertype': const.IPv6,
                             'security_group_id': sg2_id},
                            {'direction': u'ingress',
                             'source_ip_prefix': u'10.0.0.3/32',
                             'protocol': const.PROTO_NAME_TCP,
                             'ethertype': const.IPv4,
                             'port_range_max': 25, 'port_range_min': 24,
                             'remote_group_id': sg2_id,
                             'security_group_id': sg1_id},
                            ]
                self.assertEqual(port_rpc['security_group_rules'],
                                 expected)
                self._delete('ports', port_id1)
                self._delete('ports', port_id2)

    def test_security_group_rules_for_devices_ipv6_ingress(self):
        fake_prefix = test_fw.FAKE_PREFIX[const.IPv6]
        with self.network() as n:
            with nested(self.subnet(n,
                                    cidr=fake_prefix,
                                    ip_version=6),
                        self.security_group()) as (subnet_v6,
                                                   sg1):
                sg1_id = sg1['security_group']['id']
                rule1 = self._build_security_group_rule(
                    sg1_id,
                    'ingress', const.PROTO_NAME_TCP, '22',
                    '22',
                    ethertype=const.IPv6)
                rule2 = self._build_security_group_rule(
                    sg1_id,
                    'ingress', const.PROTO_NAME_UDP, '23',
                    '23', fake_prefix,
                    ethertype=const.IPv6)
                rules = {
                    'security_group_rules': [rule1['security_group_rule'],
                                             rule2['security_group_rule']]}
                res = self._create_security_group_rule(self.fmt, rules)
                self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)

                res1 = self._create_port(
                    self.fmt, n['network']['id'],
                    fixed_ips=[{'subnet_id': subnet_v6['subnet']['id']}],
                    security_groups=[sg1_id])
                ports_rest1 = self.deserialize(self.fmt, res1)
                port_id1 = ports_rest1['port']['id']
                self.rpc.devices = {port_id1: ports_rest1['port']}
                devices = [port_id1, 'no_exist_device']
                ctx = context.get_admin_context()
                ports_rpc = self.rpc.security_group_rules_for_devices(
                    ctx, devices=devices)
                port_rpc = ports_rpc[port_id1]
                expected = [{'direction': 'egress', 'ethertype': const.IPv4,
                             'security_group_id': sg1_id},
                            {'direction': 'egress', 'ethertype': const.IPv6,
                             'security_group_id': sg1_id},
                            {'direction': 'ingress',
                             'protocol': const.PROTO_NAME_TCP,
                             'ethertype': const.IPv6,
                             'port_range_max': 22,
                             'security_group_id': sg1_id,
                             'port_range_min': 22},
                            {'direction': 'ingress',
                             'protocol': const.PROTO_NAME_UDP,
                             'ethertype': const.IPv6,
                             'port_range_max': 23, 'security_group_id': sg1_id,
                             'port_range_min': 23,
                             'source_ip_prefix': fake_prefix},
                            ]
                self.assertEqual(port_rpc['security_group_rules'],
                                 expected)
                self._delete('ports', port_id1)

    def test_security_group_rules_for_devices_ipv6_egress(self):
        fake_prefix = test_fw.FAKE_PREFIX[const.IPv6]
        with self.network() as n:
            with nested(self.subnet(n,
                                    cidr=fake_prefix,
                                    ip_version=6),
                        self.security_group()) as (subnet_v6,
                                                   sg1):
                sg1_id = sg1['security_group']['id']
                rule1 = self._build_security_group_rule(
                    sg1_id,
                    'egress', const.PROTO_NAME_TCP, '22',
                    '22',
                    ethertype=const.IPv6)
                rule2 = self._build_security_group_rule(
                    sg1_id,
                    'egress', const.PROTO_NAME_UDP, '23',
                    '23', fake_prefix,
                    ethertype=const.IPv6)
                rules = {
                    'security_group_rules': [rule1['security_group_rule'],
                                             rule2['security_group_rule']]}
                res = self._create_security_group_rule(self.fmt, rules)
                self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)

                res1 = self._create_port(
                    self.fmt, n['network']['id'],
                    fixed_ips=[{'subnet_id': subnet_v6['subnet']['id']}],
                    security_groups=[sg1_id])
                ports_rest1 = self.deserialize(self.fmt, res1)
                port_id1 = ports_rest1['port']['id']
                self.rpc.devices = {port_id1: ports_rest1['port']}
                devices = [port_id1, 'no_exist_device']

                ctx = context.get_admin_context()
                ports_rpc = self.rpc.security_group_rules_for_devices(
                    ctx, devices=devices)
                port_rpc = ports_rpc[port_id1]
                expected = [{'direction': 'egress', 'ethertype': const.IPv4,
                             'security_group_id': sg1_id},
                            {'direction': 'egress', 'ethertype': const.IPv6,
                             'security_group_id': sg1_id},
                            {'direction': 'egress',
                             'protocol': const.PROTO_NAME_TCP,
                             'ethertype': const.IPv6,
                             'port_range_max': 22,
                             'security_group_id': sg1_id,
                             'port_range_min': 22},
                            {'direction': 'egress',
                             'protocol': const.PROTO_NAME_UDP,
                             'ethertype': const.IPv6,
                             'port_range_max': 23,
                             'security_group_id': sg1_id,
                             'port_range_min': 23,
                             'dest_ip_prefix': fake_prefix},
                            ]
                self.assertEqual(port_rpc['security_group_rules'],
                                 expected)
                self._delete('ports', port_id1)

    def test_security_group_rules_for_devices_ipv6_source_group(self):
        fake_prefix = test_fw.FAKE_PREFIX[const.IPv6]
        with self.network() as n:
            with nested(self.subnet(n,
                                    cidr=fake_prefix,
                                    ip_version=6),
                        self.security_group(),
                        self.security_group()) as (subnet_v6,
                                                   sg1,
                                                   sg2):
                sg1_id = sg1['security_group']['id']
                sg2_id = sg2['security_group']['id']
                rule1 = self._build_security_group_rule(
                    sg1_id,
                    'ingress', const.PROTO_NAME_TCP, '24',
                    '25',
                    ethertype=const.IPv6,
                    remote_group_id=sg2['security_group']['id'])
                rules = {
                    'security_group_rules': [rule1['security_group_rule']]}
                res = self._create_security_group_rule(self.fmt, rules)
                self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)

                res1 = self._create_port(
                    self.fmt, n['network']['id'],
                    fixed_ips=[{'subnet_id': subnet_v6['subnet']['id']}],
                    security_groups=[sg1_id,
                                     sg2_id])
                ports_rest1 = self.deserialize(self.fmt, res1)
                port_id1 = ports_rest1['port']['id']
                self.rpc.devices = {port_id1: ports_rest1['port']}
                devices = [port_id1, 'no_exist_device']

                res2 = self._create_port(
                    self.fmt, n['network']['id'],
                    fixed_ips=[{'subnet_id': subnet_v6['subnet']['id']}],
                    security_groups=[sg2_id])
                ports_rest2 = self.deserialize(self.fmt, res2)
                port_id2 = ports_rest2['port']['id']

                ctx = context.get_admin_context()
                ports_rpc = self.rpc.security_group_rules_for_devices(
                    ctx, devices=devices)
                port_rpc = ports_rpc[port_id1]
                expected = [{'direction': 'egress', 'ethertype': const.IPv4,
                             'security_group_id': sg1_id},
                            {'direction': 'egress', 'ethertype': const.IPv6,
                             'security_group_id': sg1_id},
                            {'direction': 'egress', 'ethertype': const.IPv4,
                             'security_group_id': sg2_id},
                            {'direction': 'egress', 'ethertype': const.IPv6,
                             'security_group_id': sg2_id},
                            {'direction': 'ingress',
                             'source_ip_prefix': 'fe80::3/128',
                             'protocol': const.PROTO_NAME_TCP,
                             'ethertype': const.IPv6,
                             'port_range_max': 25, 'port_range_min': 24,
                             'remote_group_id': sg2_id,
                             'security_group_id': sg1_id},
                            ]
                self.assertEqual(port_rpc['security_group_rules'],
                                 expected)
                self._delete('ports', port_id1)
                self._delete('ports', port_id2)


class SGServerRpcCallBackMixinTestCaseXML(SGServerRpcCallBackMixinTestCase):
    fmt = 'xml'


class SGAgentRpcCallBackMixinTestCase(base.BaseTestCase):
    def setUp(self):
        super(SGAgentRpcCallBackMixinTestCase, self).setUp()
        self.rpc = sg_rpc.SecurityGroupAgentRpcCallbackMixin()
        self.rpc.sg_agent = mock.Mock()

    def test_security_groups_rule_updated(self):
        self.rpc.security_groups_rule_updated(None,
                                              security_groups=['fake_sgid'])
        self.rpc.sg_agent.assert_has_calls(
            [call.security_groups_rule_updated(['fake_sgid'])])

    def test_security_groups_member_updated(self):
        self.rpc.security_groups_member_updated(None,
                                                security_groups=['fake_sgid'])
        self.rpc.sg_agent.assert_has_calls(
            [call.security_groups_member_updated(['fake_sgid'])])

    def test_security_groups_provider_updated(self):
        self.rpc.security_groups_provider_updated(None)
        self.rpc.sg_agent.assert_has_calls(
            [call.security_groups_provider_updated()])


class SecurityGroupAgentRpcTestCaseForNoneDriver(base.BaseTestCase):
    def test_init_firewall_with_none_driver(self):
        cfg.CONF.set_override(
            'enable_security_group', False,
            group='SECURITYGROUP')
        agent = sg_rpc.SecurityGroupAgentRpcMixin()
        agent.init_firewall()
        self.assertEqual(agent.firewall.__class__.__name__,
                         'NoopFirewallDriver')


class SecurityGroupAgentRpcTestCase(base.BaseTestCase):
    def setUp(self, defer_refresh_firewall=False):
        super(SecurityGroupAgentRpcTestCase, self).setUp()
        cfg.CONF.set_default('firewall_driver',
                             'neutron.agent.firewall.NoopFirewallDriver',
                             group='SECURITYGROUP')
        self.agent = sg_rpc.SecurityGroupAgentRpcMixin()
        self.agent.context = None
        mock.patch('neutron.agent.linux.iptables_manager').start()
        self.agent.root_helper = 'sudo'
        self.agent.init_firewall(defer_refresh_firewall=defer_refresh_firewall)
        self.firewall = mock.Mock()
        firewall_object = firewall_base.FirewallDriver()
        self.firewall.defer_apply.side_effect = firewall_object.defer_apply
        self.agent.firewall = self.firewall
        rpc = mock.Mock()
        self.agent.plugin_rpc = rpc
        self.fake_device = {'device': 'fake_device',
                            'security_groups': ['fake_sgid1', 'fake_sgid2'],
                            'security_group_source_groups': ['fake_sgid2'],
                            'security_group_rules': [{'security_group_id':
                                                      'fake_sgid1',
                                                      'remote_group_id':
                                                      'fake_sgid2'}]}
        fake_devices = {'fake_device': self.fake_device}
        self.firewall.ports = fake_devices
        rpc.security_group_rules_for_devices.return_value = fake_devices

    def test_prepare_and_remove_devices_filter(self):
        self.agent.prepare_devices_filter(['fake_device'])
        self.agent.remove_devices_filter(['fake_device'])
        # ignore device which is not filtered
        self.firewall.assert_has_calls([call.defer_apply(),
                                        call.prepare_port_filter(
                                            self.fake_device),
                                        call.defer_apply(),
                                        call.remove_port_filter(
                                            self.fake_device),
                                        ])

    def test_security_groups_rule_updated(self):
        self.agent.refresh_firewall = mock.Mock()
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.security_groups_rule_updated(['fake_sgid1', 'fake_sgid3'])
        self.agent.refresh_firewall.assert_has_calls(
            [call.refresh_firewall([self.fake_device['device']])])

    def test_security_groups_rule_not_updated(self):
        self.agent.refresh_firewall = mock.Mock()
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.security_groups_rule_updated(['fake_sgid3', 'fake_sgid4'])
        self.agent.refresh_firewall.assert_has_calls([])

    def test_security_groups_member_updated(self):
        self.agent.refresh_firewall = mock.Mock()
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.security_groups_member_updated(['fake_sgid2', 'fake_sgid3'])
        self.agent.refresh_firewall.assert_has_calls(
            [call.refresh_firewall([self.fake_device['device']])])

    def test_security_groups_member_not_updated(self):
        self.agent.refresh_firewall = mock.Mock()
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.security_groups_member_updated(['fake_sgid3', 'fake_sgid4'])
        self.agent.refresh_firewall.assert_has_calls([])

    def test_security_groups_provider_updated(self):
        self.agent.refresh_firewall = mock.Mock()
        self.agent.security_groups_provider_updated()
        self.agent.refresh_firewall.assert_has_calls(
            [call.refresh_firewall()])

    def test_refresh_firewall(self):
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.refresh_firewall()
        calls = [call.defer_apply(),
                 call.prepare_port_filter(self.fake_device),
                 call.defer_apply(),
                 call.update_port_filter(self.fake_device)]
        self.firewall.assert_has_calls(calls)

    def test_refresh_firewall_devices(self):
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.refresh_firewall([self.fake_device])
        calls = [call.defer_apply(),
                 call.prepare_port_filter(self.fake_device),
                 call.defer_apply(),
                 call.update_port_filter(self.fake_device)]
        self.firewall.assert_has_calls(calls)

    def test_refresh_firewall_none(self):
        self.agent.refresh_firewall([])
        self.firewall.assert_has_calls([])


class SecurityGroupAgentRpcWithDeferredRefreshTestCase(
    SecurityGroupAgentRpcTestCase):

    def setUp(self):
        super(SecurityGroupAgentRpcWithDeferredRefreshTestCase, self).setUp(
            defer_refresh_firewall=True)

    @contextmanager
    def add_fake_device(self, device, sec_groups, source_sec_groups=None):
        fake_device = {'device': device,
                       'security_groups': sec_groups,
                       'security_group_source_groups': source_sec_groups or [],
                       'security_group_rules': [{'security_group_id':
                                                 'fake_sgid1',
                                                 'remote_group_id':
                                                 'fake_sgid2'}]}
        self.firewall.ports[device] = fake_device
        yield
        del self.firewall.ports[device]

    def test_security_groups_rule_updated(self):
        self.agent.security_groups_rule_updated(['fake_sgid1', 'fake_sgid3'])
        self.assertIn('fake_device', self.agent.devices_to_refilter)

    def test_multiple_security_groups_rule_updated_same_port(self):
        with self.add_fake_device(device='fake_device_2',
                                  sec_groups=['fake_sgidX']):
            self.agent.refresh_firewall = mock.Mock()
            self.agent.security_groups_rule_updated(['fake_sgid1'])
            self.agent.security_groups_rule_updated(['fake_sgid2'])
            self.assertIn('fake_device', self.agent.devices_to_refilter)
            self.assertNotIn('fake_device_2', self.agent.devices_to_refilter)

    def test_security_groups_rule_updated_multiple_ports(self):
        with self.add_fake_device(device='fake_device_2',
                                  sec_groups=['fake_sgid2']):
            self.agent.refresh_firewall = mock.Mock()
            self.agent.security_groups_rule_updated(['fake_sgid1',
                                                     'fake_sgid2'])
            self.assertIn('fake_device', self.agent.devices_to_refilter)
            self.assertIn('fake_device_2', self.agent.devices_to_refilter)

    def test_multiple_security_groups_rule_updated_multiple_ports(self):
        with self.add_fake_device(device='fake_device_2',
                                  sec_groups=['fake_sgid2']):
            self.agent.refresh_firewall = mock.Mock()
            self.agent.security_groups_rule_updated(['fake_sgid1'])
            self.agent.security_groups_rule_updated(['fake_sgid2'])
            self.assertIn('fake_device', self.agent.devices_to_refilter)
            self.assertIn('fake_device_2', self.agent.devices_to_refilter)

    def test_security_groups_member_updated(self):
        self.agent.security_groups_member_updated(['fake_sgid2', 'fake_sgid3'])
        self.assertIn('fake_device', self.agent.devices_to_refilter)

    def test_multiple_security_groups_member_updated_same_port(self):
        with self.add_fake_device(device='fake_device_2',
                                  sec_groups=['fake_sgid1', 'fake_sgid1B'],
                                  source_sec_groups=['fake_sgidX']):
            self.agent.refresh_firewall = mock.Mock()
            self.agent.security_groups_member_updated(['fake_sgid1',
                                                       'fake_sgid3'])
            self.agent.security_groups_member_updated(['fake_sgid2',
                                                       'fake_sgid3'])
            self.assertIn('fake_device', self.agent.devices_to_refilter)
            self.assertNotIn('fake_device_2', self.agent.devices_to_refilter)

    def test_security_groups_member_updated_multiple_ports(self):
        with self.add_fake_device(device='fake_device_2',
                                  sec_groups=['fake_sgid1', 'fake_sgid1B'],
                                  source_sec_groups=['fake_sgid2']):
            self.agent.security_groups_member_updated(['fake_sgid2'])
            self.assertIn('fake_device', self.agent.devices_to_refilter)
            self.assertIn('fake_device_2', self.agent.devices_to_refilter)

    def test_multiple_security_groups_member_updated_multiple_ports(self):
        with self.add_fake_device(device='fake_device_2',
                                  sec_groups=['fake_sgid1', 'fake_sgid1B'],
                                  source_sec_groups=['fake_sgid1B']):
            self.agent.security_groups_member_updated(['fake_sgid1B'])
            self.agent.security_groups_member_updated(['fake_sgid2'])
            self.assertIn('fake_device', self.agent.devices_to_refilter)
            self.assertIn('fake_device_2', self.agent.devices_to_refilter)

    def test_security_groups_provider_updated(self):
        self.agent.security_groups_provider_updated()
        self.assertTrue(self.agent.global_refresh_firewall)

    def test_setup_port_filters_new_ports_only(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set()
        self.agent.global_refresh_firewall = False
        self.agent.setup_port_filters(set(['fake_new_device']), set())
        self.assertFalse(self.agent.devices_to_refilter)
        self.assertFalse(self.agent.global_refresh_firewall)
        self.agent.prepare_devices_filter.assert_called_once_with(
            set(['fake_new_device']))
        self.assertFalse(self.agent.refresh_firewall.called)

    def test_setup_port_filters_updated_ports_only(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set()
        self.agent.global_refresh_firewall = False
        self.agent.setup_port_filters(set(), set(['fake_updated_device']))
        self.assertFalse(self.agent.devices_to_refilter)
        self.assertFalse(self.agent.global_refresh_firewall)
        self.agent.refresh_firewall.assert_called_once_with(
            set(['fake_updated_device']))
        self.assertFalse(self.agent.prepare_devices_filter.called)

    def test_setup_port_filter_new_and_updated_ports(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set()
        self.agent.global_refresh_firewall = False
        self.agent.setup_port_filters(set(['fake_new_device']),
                                      set(['fake_updated_device']))
        self.assertFalse(self.agent.devices_to_refilter)
        self.assertFalse(self.agent.global_refresh_firewall)
        self.agent.prepare_devices_filter.assert_called_once_with(
            set(['fake_new_device']))
        self.agent.refresh_firewall.assert_called_once_with(
            set(['fake_updated_device']))

    def test_setup_port_filters_sg_updates_only(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set(['fake_device'])
        self.agent.global_refresh_firewall = False
        self.agent.setup_port_filters(set(), set())
        self.assertFalse(self.agent.devices_to_refilter)
        self.assertFalse(self.agent.global_refresh_firewall)
        self.agent.refresh_firewall.assert_called_once_with(
            set(['fake_device']))
        self.assertFalse(self.agent.prepare_devices_filter.called)

    def test_setup_port_filters_sg_updates_and_new_ports(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set(['fake_device'])
        self.agent.global_refresh_firewall = False
        self.agent.setup_port_filters(set(['fake_new_device']), set())
        self.assertFalse(self.agent.devices_to_refilter)
        self.assertFalse(self.agent.global_refresh_firewall)
        self.agent.prepare_devices_filter.assert_called_once_with(
            set(['fake_new_device']))
        self.agent.refresh_firewall.assert_called_once_with(
            set(['fake_device']))

    def test_setup_port_filters_sg_updates_and_updated_ports(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set(['fake_device', 'fake_device_2'])
        self.agent.global_refresh_firewall = False
        self.agent.setup_port_filters(
            set(), set(['fake_device', 'fake_updated_device']))
        self.assertFalse(self.agent.devices_to_refilter)
        self.assertFalse(self.agent.global_refresh_firewall)
        self.agent.refresh_firewall.assert_called_once_with(
            set(['fake_device', 'fake_device_2', 'fake_updated_device']))
        self.assertFalse(self.agent.prepare_devices_filter.called)

    def test_setup_port_filters_all_updates(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set(['fake_device', 'fake_device_2'])
        self.agent.global_refresh_firewall = False
        self.agent.setup_port_filters(
            set(['fake_new_device']),
            set(['fake_device', 'fake_updated_device']))
        self.assertFalse(self.agent.devices_to_refilter)
        self.assertFalse(self.agent.global_refresh_firewall)
        self.agent.prepare_devices_filter.assert_called_once_with(
            set(['fake_new_device']))
        self.agent.refresh_firewall.assert_called_once_with(
            set(['fake_device', 'fake_device_2', 'fake_updated_device']))

    def test_setup_port_filters_no_update(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set()
        self.agent.global_refresh_firewall = False
        self.agent.setup_port_filters(set(), set())
        self.assertFalse(self.agent.devices_to_refilter)
        self.assertFalse(self.agent.global_refresh_firewall)
        self.assertFalse(self.agent.refresh_firewall.called)
        self.assertFalse(self.agent.prepare_devices_filter.called)

    def test_setup_port_filters_with_global_refresh(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set()
        self.agent.global_refresh_firewall = True
        self.agent.setup_port_filters(set(), set())
        self.assertFalse(self.agent.devices_to_refilter)
        self.assertFalse(self.agent.global_refresh_firewall)
        self.agent.refresh_firewall.assert_called_once_with()
        self.assertFalse(self.agent.prepare_devices_filter.called)


class FakeSGRpcApi(agent_rpc.PluginApi,
                   sg_rpc.SecurityGroupServerRpcApiMixin):
    pass


class SecurityGroupServerRpcApiTestCase(base.BaseTestCase):
    def setUp(self):
        super(SecurityGroupServerRpcApiTestCase, self).setUp()
        self.rpc = FakeSGRpcApi('fake_topic')
        self.rpc.call = mock.Mock()

    def test_security_group_rules_for_devices(self):
        self.rpc.security_group_rules_for_devices(None, ['fake_device'])
        self.rpc.call.assert_has_calls(
            [call(None,
             {'args':
                 {'devices': ['fake_device']},
              'method': 'security_group_rules_for_devices',
              'namespace': None},
             version=sg_rpc.SG_RPC_VERSION,
             topic='fake_topic')])


class FakeSGNotifierAPI(proxy.RpcProxy,
                        sg_rpc.SecurityGroupAgentRpcApiMixin):
    pass


class SecurityGroupAgentRpcApiTestCase(base.BaseTestCase):
    def setUp(self):
        super(SecurityGroupAgentRpcApiTestCase, self).setUp()
        self.notifier = FakeSGNotifierAPI(topic='fake',
                                          default_version='1.0')
        self.notifier.fanout_cast = mock.Mock()

    def test_security_groups_rule_updated(self):
        self.notifier.security_groups_rule_updated(
            None, security_groups=['fake_sgid'])
        self.notifier.fanout_cast.assert_has_calls(
            [call(None,
                  {'args':
                      {'security_groups': ['fake_sgid']},
                      'method': 'security_groups_rule_updated',
                      'namespace': None},
                  version=sg_rpc.SG_RPC_VERSION,
                  topic='fake-security_group-update')])

    def test_security_groups_member_updated(self):
        self.notifier.security_groups_member_updated(
            None, security_groups=['fake_sgid'])
        self.notifier.fanout_cast.assert_has_calls(
            [call(None,
                  {'args':
                      {'security_groups': ['fake_sgid']},
                      'method': 'security_groups_member_updated',
                      'namespace': None},
                  version=sg_rpc.SG_RPC_VERSION,
                  topic='fake-security_group-update')])

    def test_security_groups_rule_not_updated(self):
        self.notifier.security_groups_rule_updated(
            None, security_groups=[])
        self.assertEqual(False, self.notifier.fanout_cast.called)

    def test_security_groups_member_not_updated(self):
        self.notifier.security_groups_member_updated(
            None, security_groups=[])
        self.assertEqual(False, self.notifier.fanout_cast.called)

#Note(nati) bn -> binary_name
# id -> device_id

PHYSDEV_MOD = '-m physdev'
PHYSDEV_IS_BRIDGED = '--physdev-is-bridged'

IPTABLES_ARG = {'bn': iptables_manager.binary_name,
                'physdev_mod': PHYSDEV_MOD,
                'physdev_is_bridged': PHYSDEV_IS_BRIDGED}

CHAINS_NAT = 'OUTPUT|POSTROUTING|PREROUTING|float-snat|snat'
IPTABLES_ARG['chains'] = CHAINS_NAT

IPTABLES_NAT = """# Generated by iptables_manager
*nat
:neutron-postrouting-bottom - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
[0:0] -A PREROUTING -j %(bn)s-PREROUTING
[0:0] -A OUTPUT -j %(bn)s-OUTPUT
[0:0] -A POSTROUTING -j %(bn)s-POSTROUTING
[0:0] -A POSTROUTING -j neutron-postrouting-bottom
[0:0] -A neutron-postrouting-bottom -j %(bn)s-snat
[0:0] -A %(bn)s-snat -j %(bn)s-float-snat
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

CHAINS_EMPTY = 'FORWARD|INPUT|OUTPUT|local|sg-chain|sg-fallback'
CHAINS_1 = CHAINS_EMPTY + '|i_port1|o_port1|s_port1'
CHAINS_2 = CHAINS_1 + '|i_port2|o_port2|s_port2'

IPTABLES_ARG['chains'] = CHAINS_1

IPTABLES_FILTER_1 = """# Generated by iptables_manager
*filter
:neutron-filter-top - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
[0:0] -A FORWARD -j neutron-filter-top
[0:0] -A OUTPUT -j neutron-filter-top
[0:0] -A neutron-filter-top -j %(bn)s-local
[0:0] -A INPUT -j %(bn)s-INPUT
[0:0] -A OUTPUT -j %(bn)s-OUTPUT
[0:0] -A FORWARD -j %(bn)s-FORWARD
[0:0] -A %(bn)s-sg-fallback -j DROP
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-i_port1
[0:0] -A %(bn)s-i_port1 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-i_port1 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-i_port1 -s 10.0.0.2 -p udp -m udp --sport 67 --dport 68 -j \
RETURN
[0:0] -A %(bn)s-i_port1 -p tcp -m tcp --dport 22 -j RETURN
[0:0] -A %(bn)s-i_port1 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
[0:0] -A %(bn)s-INPUT %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
[0:0] -A %(bn)s-s_port1 -m mac --mac-source 12:34:56:78:9a:bc -s 10.0.0.3 -j \
RETURN
[0:0] -A %(bn)s-s_port1 -j DROP
[0:0] -A %(bn)s-o_port1 -p udp -m udp --sport 68 --dport 67 -j RETURN
[0:0] -A %(bn)s-o_port1 -j %(bn)s-s_port1
[0:0] -A %(bn)s-o_port1 -p udp -m udp --sport 67 --dport 68 -j DROP
[0:0] -A %(bn)s-o_port1 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-o_port1 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-o_port1 -j RETURN
[0:0] -A %(bn)s-o_port1 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-sg-chain -j ACCEPT
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG


IPTABLES_FILTER_1_2 = """# Generated by iptables_manager
*filter
:neutron-filter-top - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
[0:0] -A FORWARD -j neutron-filter-top
[0:0] -A OUTPUT -j neutron-filter-top
[0:0] -A neutron-filter-top -j %(bn)s-local
[0:0] -A INPUT -j %(bn)s-INPUT
[0:0] -A OUTPUT -j %(bn)s-OUTPUT
[0:0] -A FORWARD -j %(bn)s-FORWARD
[0:0] -A %(bn)s-sg-fallback -j DROP
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-i_port1
[0:0] -A %(bn)s-i_port1 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-i_port1 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-i_port1 -s 10.0.0.2 -p udp -m udp --sport 67 --dport 68 -j \
RETURN
[0:0] -A %(bn)s-i_port1 -p tcp -m tcp --dport 22 -j RETURN
[0:0] -A %(bn)s-i_port1 -s 10.0.0.4 -j RETURN
[0:0] -A %(bn)s-i_port1 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
[0:0] -A %(bn)s-INPUT %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
[0:0] -A %(bn)s-s_port1 -m mac --mac-source 12:34:56:78:9a:bc -s 10.0.0.3 -j \
RETURN
[0:0] -A %(bn)s-s_port1 -j DROP
[0:0] -A %(bn)s-o_port1 -p udp -m udp --sport 68 --dport 67 -j RETURN
[0:0] -A %(bn)s-o_port1 -j %(bn)s-s_port1
[0:0] -A %(bn)s-o_port1 -p udp -m udp --sport 67 --dport 68 -j DROP
[0:0] -A %(bn)s-o_port1 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-o_port1 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-o_port1 -j RETURN
[0:0] -A %(bn)s-o_port1 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-sg-chain -j ACCEPT
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_ARG['chains'] = CHAINS_2

IPTABLES_FILTER_2 = """# Generated by iptables_manager
*filter
:neutron-filter-top - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
[0:0] -A FORWARD -j neutron-filter-top
[0:0] -A OUTPUT -j neutron-filter-top
[0:0] -A neutron-filter-top -j %(bn)s-local
[0:0] -A INPUT -j %(bn)s-INPUT
[0:0] -A OUTPUT -j %(bn)s-OUTPUT
[0:0] -A FORWARD -j %(bn)s-FORWARD
[0:0] -A %(bn)s-sg-fallback -j DROP
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-i_port1
[0:0] -A %(bn)s-i_port1 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-i_port1 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-i_port1 -s 10.0.0.2 -p udp -m udp --sport 67 --dport 68 -j \
RETURN
[0:0] -A %(bn)s-i_port1 -p tcp -m tcp --dport 22 -j RETURN
[0:0] -A %(bn)s-i_port1 -s 10.0.0.4 -j RETURN
[0:0] -A %(bn)s-i_port1 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
[0:0] -A %(bn)s-INPUT %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
[0:0] -A %(bn)s-s_port1 -m mac --mac-source 12:34:56:78:9a:bc -s 10.0.0.3 \
-j RETURN
[0:0] -A %(bn)s-s_port1 -j DROP
[0:0] -A %(bn)s-o_port1 -p udp -m udp --sport 68 --dport 67 -j RETURN
[0:0] -A %(bn)s-o_port1 -j %(bn)s-s_port1
[0:0] -A %(bn)s-o_port1 -p udp -m udp --sport 67 --dport 68 -j DROP
[0:0] -A %(bn)s-o_port1 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-o_port1 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-o_port1 -j RETURN
[0:0] -A %(bn)s-o_port1 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-INGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-INGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-i_port2
[0:0] -A %(bn)s-i_port2 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-i_port2 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-i_port2 -s 10.0.0.2 -p udp -m udp --sport 67 --dport 68 -j \
RETURN
[0:0] -A %(bn)s-i_port2 -p tcp -m tcp --dport 22 -j RETURN
[0:0] -A %(bn)s-i_port2 -s 10.0.0.3 -j RETURN
[0:0] -A %(bn)s-i_port2 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-EGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-EGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-o_port2
[0:0] -A %(bn)s-INPUT %(physdev_mod)s --physdev-EGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-o_port2
[0:0] -A %(bn)s-s_port2 -m mac --mac-source 12:34:56:78:9a:bd -s 10.0.0.4 \
-j RETURN
[0:0] -A %(bn)s-s_port2 -j DROP
[0:0] -A %(bn)s-o_port2 -p udp -m udp --sport 68 --dport 67 -j RETURN
[0:0] -A %(bn)s-o_port2 -j %(bn)s-s_port2
[0:0] -A %(bn)s-o_port2 -p udp -m udp --sport 67 --dport 68 -j DROP
[0:0] -A %(bn)s-o_port2 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-o_port2 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-o_port2 -j RETURN
[0:0] -A %(bn)s-o_port2 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-sg-chain -j ACCEPT
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_FILTER_2_2 = """# Generated by iptables_manager
*filter
:neutron-filter-top - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
[0:0] -A FORWARD -j neutron-filter-top
[0:0] -A OUTPUT -j neutron-filter-top
[0:0] -A neutron-filter-top -j %(bn)s-local
[0:0] -A INPUT -j %(bn)s-INPUT
[0:0] -A OUTPUT -j %(bn)s-OUTPUT
[0:0] -A FORWARD -j %(bn)s-FORWARD
[0:0] -A %(bn)s-sg-fallback -j DROP
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-i_port1
[0:0] -A %(bn)s-i_port1 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-i_port1 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-i_port1 -s 10.0.0.2 -p udp -m udp --sport 67 --dport 68 -j \
RETURN
[0:0] -A %(bn)s-i_port1 -p tcp -m tcp --dport 22 -j RETURN
[0:0] -A %(bn)s-i_port1 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
[0:0] -A %(bn)s-INPUT %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
[0:0] -A %(bn)s-s_port1 -m mac --mac-source 12:34:56:78:9a:bc -s 10.0.0.3 -j \
RETURN
[0:0] -A %(bn)s-s_port1 -j DROP
[0:0] -A %(bn)s-o_port1 -p udp -m udp --sport 68 --dport 67 -j RETURN
[0:0] -A %(bn)s-o_port1 -j %(bn)s-s_port1
[0:0] -A %(bn)s-o_port1 -p udp -m udp --sport 67 --dport 68 -j DROP
[0:0] -A %(bn)s-o_port1 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-o_port1 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-o_port1 -j RETURN
[0:0] -A %(bn)s-o_port1 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-INGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-INGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-i_port2
[0:0] -A %(bn)s-i_port2 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-i_port2 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-i_port2 -s 10.0.0.2 -p udp -m udp --sport 67 --dport 68 -j \
RETURN
[0:0] -A %(bn)s-i_port2 -p tcp -m tcp --dport 22 -j RETURN
[0:0] -A %(bn)s-i_port2 -s 10.0.0.3 -j RETURN
[0:0] -A %(bn)s-i_port2 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-EGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-EGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-o_port2
[0:0] -A %(bn)s-INPUT %(physdev_mod)s --physdev-EGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-o_port2
[0:0] -A %(bn)s-s_port2 -m mac --mac-source 12:34:56:78:9a:bd -s 10.0.0.4 -j \
RETURN
[0:0] -A %(bn)s-s_port2 -j DROP
[0:0] -A %(bn)s-o_port2 -p udp -m udp --sport 68 --dport 67 -j RETURN
[0:0] -A %(bn)s-o_port2 -j %(bn)s-s_port2
[0:0] -A %(bn)s-o_port2 -p udp -m udp --sport 67 --dport 68 -j DROP
[0:0] -A %(bn)s-o_port2 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-o_port2 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-o_port2 -j RETURN
[0:0] -A %(bn)s-o_port2 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-sg-chain -j ACCEPT
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_FILTER_2_3 = """# Generated by iptables_manager
*filter
:neutron-filter-top - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
[0:0] -A FORWARD -j neutron-filter-top
[0:0] -A OUTPUT -j neutron-filter-top
[0:0] -A neutron-filter-top -j %(bn)s-local
[0:0] -A INPUT -j %(bn)s-INPUT
[0:0] -A OUTPUT -j %(bn)s-OUTPUT
[0:0] -A FORWARD -j %(bn)s-FORWARD
[0:0] -A %(bn)s-sg-fallback -j DROP
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-i_port1
[0:0] -A %(bn)s-i_port1 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-i_port1 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-i_port1 -s 10.0.0.2 -p udp -m udp --sport 67 --dport 68 -j \
RETURN
[0:0] -A %(bn)s-i_port1 -p tcp -m tcp --dport 22 -j RETURN
[0:0] -A %(bn)s-i_port1 -s 10.0.0.4 -j RETURN
[0:0] -A %(bn)s-i_port1 -p icmp -j RETURN
[0:0] -A %(bn)s-i_port1 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
[0:0] -A %(bn)s-INPUT %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
[0:0] -A %(bn)s-s_port1 -m mac --mac-source 12:34:56:78:9a:bc -s 10.0.0.3 -j \
RETURN
[0:0] -A %(bn)s-s_port1 -j DROP
[0:0] -A %(bn)s-o_port1 -p udp -m udp --sport 68 --dport 67 -j RETURN
[0:0] -A %(bn)s-o_port1 -j %(bn)s-s_port1
[0:0] -A %(bn)s-o_port1 -p udp -m udp --sport 67 --dport 68 -j DROP
[0:0] -A %(bn)s-o_port1 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-o_port1 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-o_port1 -j RETURN
[0:0] -A %(bn)s-o_port1 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-INGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-INGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-i_port2
[0:0] -A %(bn)s-i_port2 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-i_port2 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-i_port2 -s 10.0.0.2 -p udp -m udp --sport 67 --dport 68 -j \
RETURN
[0:0] -A %(bn)s-i_port2 -p tcp -m tcp --dport 22 -j RETURN
[0:0] -A %(bn)s-i_port2 -s 10.0.0.3 -j RETURN
[0:0] -A %(bn)s-i_port2 -p icmp -j RETURN
[0:0] -A %(bn)s-i_port2 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-EGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-EGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-o_port2
[0:0] -A %(bn)s-INPUT %(physdev_mod)s --physdev-EGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-o_port2
[0:0] -A %(bn)s-s_port2 -m mac --mac-source 12:34:56:78:9a:bd -s 10.0.0.4 -j \
RETURN
[0:0] -A %(bn)s-s_port2 -j DROP
[0:0] -A %(bn)s-o_port2 -p udp -m udp --sport 68 --dport 67 -j RETURN
[0:0] -A %(bn)s-o_port2 -j %(bn)s-s_port2
[0:0] -A %(bn)s-o_port2 -p udp -m udp --sport 67 --dport 68 -j DROP
[0:0] -A %(bn)s-o_port2 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-o_port2 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-o_port2 -j RETURN
[0:0] -A %(bn)s-o_port2 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-sg-chain -j ACCEPT
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG


IPTABLES_ARG['chains'] = CHAINS_EMPTY
IPTABLES_FILTER_EMPTY = """# Generated by iptables_manager
*filter
:neutron-filter-top - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
[0:0] -A FORWARD -j neutron-filter-top
[0:0] -A OUTPUT -j neutron-filter-top
[0:0] -A neutron-filter-top -j %(bn)s-local
[0:0] -A INPUT -j %(bn)s-INPUT
[0:0] -A OUTPUT -j %(bn)s-OUTPUT
[0:0] -A FORWARD -j %(bn)s-FORWARD
[0:0] -A %(bn)s-sg-fallback -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_ARG['chains'] = CHAINS_1
IPTABLES_FILTER_V6_1 = """# Generated by iptables_manager
*filter
:neutron-filter-top - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
[0:0] -A FORWARD -j neutron-filter-top
[0:0] -A OUTPUT -j neutron-filter-top
[0:0] -A neutron-filter-top -j %(bn)s-local
[0:0] -A INPUT -j %(bn)s-INPUT
[0:0] -A OUTPUT -j %(bn)s-OUTPUT
[0:0] -A FORWARD -j %(bn)s-FORWARD
[0:0] -A %(bn)s-sg-fallback -j DROP
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-i_port1
[0:0] -A %(bn)s-i_port1 -p icmpv6 --icmpv6-type 130 -j RETURN
[0:0] -A %(bn)s-i_port1 -p icmpv6 --icmpv6-type 131 -j RETURN
[0:0] -A %(bn)s-i_port1 -p icmpv6 --icmpv6-type 132 -j RETURN
[0:0] -A %(bn)s-i_port1 -p icmpv6 --icmpv6-type 134 -j RETURN
[0:0] -A %(bn)s-i_port1 -p icmpv6 --icmpv6-type 135 -j RETURN
[0:0] -A %(bn)s-i_port1 -p icmpv6 --icmpv6-type 136 -j RETURN
[0:0] -A %(bn)s-i_port1 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-i_port1 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-i_port1 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
[0:0] -A %(bn)s-INPUT %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
[0:0] -A %(bn)s-o_port1 -p icmpv6 -j RETURN
[0:0] -A %(bn)s-o_port1 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-o_port1 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-o_port1 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-sg-chain -j ACCEPT
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG


IPTABLES_ARG['chains'] = CHAINS_2

IPTABLES_FILTER_V6_2 = """# Generated by iptables_manager
*filter
:neutron-filter-top - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
[0:0] -A FORWARD -j neutron-filter-top
[0:0] -A OUTPUT -j neutron-filter-top
[0:0] -A neutron-filter-top -j %(bn)s-local
[0:0] -A INPUT -j %(bn)s-INPUT
[0:0] -A OUTPUT -j %(bn)s-OUTPUT
[0:0] -A FORWARD -j %(bn)s-FORWARD
[0:0] -A %(bn)s-sg-fallback -j DROP
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-i_port1
[0:0] -A %(bn)s-i_port1 -p icmpv6 --icmpv6-type 130 -j RETURN
[0:0] -A %(bn)s-i_port1 -p icmpv6 --icmpv6-type 131 -j RETURN
[0:0] -A %(bn)s-i_port1 -p icmpv6 --icmpv6-type 132 -j RETURN
[0:0] -A %(bn)s-i_port1 -p icmpv6 --icmpv6-type 134 -j RETURN
[0:0] -A %(bn)s-i_port1 -p icmpv6 --icmpv6-type 135 -j RETURN
[0:0] -A %(bn)s-i_port1 -p icmpv6 --icmpv6-type 136 -j RETURN
[0:0] -A %(bn)s-i_port1 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-i_port1 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-i_port1 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
[0:0] -A %(bn)s-INPUT %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
[0:0] -A %(bn)s-o_port1 -p icmpv6 -j RETURN
[0:0] -A %(bn)s-o_port1 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-o_port1 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-o_port1 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-INGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-INGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-i_port2
[0:0] -A %(bn)s-i_port2 -p icmpv6 --icmpv6-type 130 -j RETURN
[0:0] -A %(bn)s-i_port2 -p icmpv6 --icmpv6-type 131 -j RETURN
[0:0] -A %(bn)s-i_port2 -p icmpv6 --icmpv6-type 132 -j RETURN
[0:0] -A %(bn)s-i_port2 -p icmpv6 --icmpv6-type 134 -j RETURN
[0:0] -A %(bn)s-i_port2 -p icmpv6 --icmpv6-type 135 -j RETURN
[0:0] -A %(bn)s-i_port2 -p icmpv6 --icmpv6-type 136 -j RETURN
[0:0] -A %(bn)s-i_port2 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-i_port2 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-i_port2 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-FORWARD %(physdev_mod)s --physdev-EGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
[0:0] -A %(bn)s-sg-chain %(physdev_mod)s --physdev-EGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-o_port2
[0:0] -A %(bn)s-INPUT %(physdev_mod)s --physdev-EGRESS tap_port2 \
%(physdev_is_bridged)s -j %(bn)s-o_port2
[0:0] -A %(bn)s-o_port2 -p icmpv6 -j RETURN
[0:0] -A %(bn)s-o_port2 -m state --state INVALID -j DROP
[0:0] -A %(bn)s-o_port2 -m state --state RELATED,ESTABLISHED -j RETURN
[0:0] -A %(bn)s-o_port2 -j %(bn)s-sg-fallback
[0:0] -A %(bn)s-sg-chain -j ACCEPT
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_ARG['chains'] = CHAINS_EMPTY
IPTABLES_FILTER_V6_EMPTY = """# Generated by iptables_manager
*filter
:neutron-filter-top - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
[0:0] -A FORWARD -j neutron-filter-top
[0:0] -A OUTPUT -j neutron-filter-top
[0:0] -A neutron-filter-top -j %(bn)s-local
[0:0] -A INPUT -j %(bn)s-INPUT
[0:0] -A OUTPUT -j %(bn)s-OUTPUT
[0:0] -A FORWARD -j %(bn)s-FORWARD
[0:0] -A %(bn)s-sg-fallback -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

FIREWALL_BASE_PACKAGE = 'neutron.agent.linux.iptables_firewall.'
FIREWALL_IPTABLES_DRIVER = FIREWALL_BASE_PACKAGE + 'IptablesFirewallDriver'
FIREWALL_HYBRID_DRIVER = (FIREWALL_BASE_PACKAGE +
                          'OVSHybridIptablesFirewallDriver')
FIREWALL_NOOP_DRIVER = 'neutron.agent.firewall.NoopFirewallDriver'


def set_firewall_driver(firewall_driver):
    cfg.CONF.set_override('firewall_driver', firewall_driver,
                          group='SECURITYGROUP')


class TestSecurityGroupAgentWithIptables(base.BaseTestCase):
    FIREWALL_DRIVER = FIREWALL_IPTABLES_DRIVER
    PHYSDEV_INGRESS = 'physdev-out'
    PHYSDEV_EGRESS = 'physdev-in'

    def setUp(self, defer_refresh_firewall=False):
        super(TestSecurityGroupAgentWithIptables, self).setUp()
        config.register_root_helper(cfg.CONF)
        cfg.CONF.set_override(
            'lock_path',
            '$state_path/lock')
        cfg.CONF.set_override(
            'firewall_driver',
            self.FIREWALL_DRIVER,
            group='SECURITYGROUP')

        self.agent = sg_rpc.SecurityGroupAgentRpcMixin()
        self.agent.context = None

        self.root_helper = 'sudo'
        self.agent.root_helper = 'sudo'
        self.agent.init_firewall(defer_refresh_firewall=defer_refresh_firewall)

        self.iptables = self.agent.firewall.iptables
        # TODO(jlibosva) Get rid of mocking iptables execute and mock out
        # firewall instead
        self.iptables.use_ipv6 = True
        self.iptables_execute = mock.patch.object(self.iptables,
                                                  "execute").start()
        self.iptables_execute_return_values = []
        self.expected_call_count = 0
        self.expected_calls = []
        self.expected_process_inputs = []
        self.iptables_execute.side_effect = self.iptables_execute_return_values

        self.rpc = mock.Mock()
        self.agent.plugin_rpc = self.rpc
        rule1 = [{'direction': 'ingress',
                  'protocol': const.PROTO_NAME_UDP,
                  'ethertype': const.IPv4,
                  'source_ip_prefix': '10.0.0.2',
                  'source_port_range_min': 67,
                  'source_port_range_max': 67,
                  'port_range_min': 68,
                  'port_range_max': 68},
                 {'direction': 'ingress',
                  'protocol': const.PROTO_NAME_TCP,
                  'ethertype': const.IPv4,
                  'port_range_min': 22,
                  'port_range_max': 22},
                 {'direction': 'egress',
                  'ethertype': const.IPv4}]
        rule2 = rule1[:]
        rule2 += [{'direction': 'ingress',
                  'source_ip_prefix': '10.0.0.4',
                  'ethertype': const.IPv4}]
        rule3 = rule2[:]
        rule3 += [{'direction': 'ingress',
                  'protocol': const.PROTO_NAME_ICMP,
                  'ethertype': const.IPv4}]
        rule4 = rule1[:]
        rule4 += [{'direction': 'ingress',
                  'source_ip_prefix': '10.0.0.3',
                  'ethertype': const.IPv4}]
        rule5 = rule4[:]
        rule5 += [{'direction': 'ingress',
                  'protocol': const.PROTO_NAME_ICMP,
                  'ethertype': const.IPv4}]
        self.devices1 = {'tap_port1': self._device('tap_port1',
                                                   '10.0.0.3',
                                                   '12:34:56:78:9a:bc',
                                                   rule1)}
        self.devices2 = {'tap_port1': self._device('tap_port1',
                                                   '10.0.0.3',
                                                   '12:34:56:78:9a:bc',
                                                   rule2),
                         'tap_port2': self._device('tap_port2',
                                                   '10.0.0.4',
                                                   '12:34:56:78:9a:bd',
                                                   rule4)}
        self.devices3 = {'tap_port1': self._device('tap_port1',
                                                   '10.0.0.3',
                                                   '12:34:56:78:9a:bc',
                                                   rule3),
                         'tap_port2': self._device('tap_port2',
                                                   '10.0.0.4',
                                                   '12:34:56:78:9a:bd',
                                                   rule5)}

    def _device(self, device, ip, mac_address, rule):
        return {'device': device,
                'fixed_ips': [ip],
                'mac_address': mac_address,
                'security_groups': ['security_group1'],
                'security_group_rules': rule,
                'security_group_source_groups': [
                    'security_group1']}

    def _regex(self, value):
        value = value.replace('physdev-INGRESS', self.PHYSDEV_INGRESS)
        value = value.replace('physdev-EGRESS', self.PHYSDEV_EGRESS)
        value = value.replace('\n', '\\n')
        value = value.replace('[', '\[')
        value = value.replace(']', '\]')
        value = value.replace('*', '\*')
        return value

    def _register_mock_call(self, *args, **kwargs):
        return_value = kwargs.pop('return_value', None)
        self.iptables_execute_return_values.append(return_value)

        has_process_input = 'process_input' in kwargs
        process_input = kwargs.get('process_input')
        self.expected_process_inputs.append((has_process_input, process_input))

        if has_process_input:
            kwargs['process_input'] = mock.ANY
        self.expected_calls.append(call(*args, **kwargs))
        self.expected_call_count += 1

    def _verify_mock_calls(self):
        self.assertEqual(self.expected_call_count,
                         self.iptables_execute.call_count)
        self.iptables_execute.assert_has_calls(self.expected_calls)

        for i, expected in enumerate(self.expected_process_inputs):
            check, expected_regex = expected
            if not check:
                continue
            # The second or later arguments of self.iptables.execute
            # are keyword parameter, so keyword argument is extracted by [1]
            kwargs = self.iptables_execute.call_args_list[i][1]
            self.assertThat(kwargs['process_input'],
                            matchers.MatchesRegex(expected_regex))

    def _replay_iptables(self, v4_filter, v6_filter):
        self._register_mock_call(
            ['iptables-save', '-c'],
            root_helper=self.root_helper,
            return_value='')
        self._register_mock_call(
            ['iptables-restore', '-c'],
            process_input=self._regex(IPTABLES_NAT + v4_filter),
            root_helper=self.root_helper,
            return_value='')
        self._register_mock_call(
            ['ip6tables-save', '-c'],
            root_helper=self.root_helper,
            return_value='')
        self._register_mock_call(
            ['ip6tables-restore', '-c'],
            process_input=self._regex(v6_filter),
            root_helper=self.root_helper,
            return_value='')

    def test_prepare_remove_port(self):
        self.rpc.security_group_rules_for_devices.return_value = self.devices1
        self._replay_iptables(IPTABLES_FILTER_1, IPTABLES_FILTER_V6_1)
        self._replay_iptables(IPTABLES_FILTER_EMPTY, IPTABLES_FILTER_V6_EMPTY)

        self.agent.prepare_devices_filter(['tap_port1'])
        self.agent.remove_devices_filter(['tap_port1'])

        self._verify_mock_calls()

    def test_security_group_member_updated(self):
        self.rpc.security_group_rules_for_devices.return_value = self.devices1
        self._replay_iptables(IPTABLES_FILTER_1, IPTABLES_FILTER_V6_1)
        self._replay_iptables(IPTABLES_FILTER_1_2, IPTABLES_FILTER_V6_1)
        self._replay_iptables(IPTABLES_FILTER_2, IPTABLES_FILTER_V6_2)
        self._replay_iptables(IPTABLES_FILTER_2_2, IPTABLES_FILTER_V6_2)
        self._replay_iptables(IPTABLES_FILTER_1, IPTABLES_FILTER_V6_1)
        self._replay_iptables(IPTABLES_FILTER_EMPTY, IPTABLES_FILTER_V6_EMPTY)

        self.agent.prepare_devices_filter(['tap_port1'])
        self.rpc.security_group_rules_for_devices.return_value = self.devices2
        self.agent.security_groups_member_updated(['security_group1'])
        self.agent.prepare_devices_filter(['tap_port2'])
        self.rpc.security_group_rules_for_devices.return_value = self.devices1
        self.agent.security_groups_member_updated(['security_group1'])
        self.agent.remove_devices_filter(['tap_port2'])
        self.agent.remove_devices_filter(['tap_port1'])

        self._verify_mock_calls()

    def test_security_group_rule_updated(self):
        self.rpc.security_group_rules_for_devices.return_value = self.devices2
        self._replay_iptables(IPTABLES_FILTER_2, IPTABLES_FILTER_V6_2)
        self._replay_iptables(IPTABLES_FILTER_2_3, IPTABLES_FILTER_V6_2)

        self.agent.prepare_devices_filter(['tap_port1', 'tap_port3'])
        self.rpc.security_group_rules_for_devices.return_value = self.devices3
        self.agent.security_groups_rule_updated(['security_group1'])

        self._verify_mock_calls()


class SGNotificationTestMixin():
    def test_security_group_rule_updated(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            with self.security_group(name, description) as sg2:
                security_group_id = sg['security_group']['id']
                direction = "ingress"
                remote_group_id = sg2['security_group']['id']
                protocol = const.PROTO_NAME_TCP
                port_range_min = 88
                port_range_max = 88
                with self.security_group_rule(security_group_id, direction,
                                              protocol, port_range_min,
                                              port_range_max,
                                              remote_group_id=remote_group_id
                                              ):
                    pass
            self.notifier.assert_has_calls(
                [call.security_groups_rule_updated(mock.ANY,
                                                   [security_group_id]),
                 call.security_groups_rule_updated(mock.ANY,
                                                   [security_group_id])])

    def test_security_group_member_updated(self):
        with self.network() as n:
            with self.subnet(n):
                with self.security_group() as sg:
                    security_group_id = sg['security_group']['id']
                    res = self._create_port(self.fmt, n['network']['id'])
                    port = self.deserialize(self.fmt, res)

                    data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                                     'name': port['port']['name'],
                                     ext_sg.SECURITYGROUPS:
                                     [security_group_id]}}

                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                    self.assertEqual(res['port'][ext_sg.SECURITYGROUPS][0],
                                     security_group_id)
                    self._delete('ports', port['port']['id'])
                    self.notifier.assert_has_calls(
                        [call.security_groups_member_updated(
                            mock.ANY, [mock.ANY])])


class TestSecurityGroupAgentWithOVSIptables(
        TestSecurityGroupAgentWithIptables):

    FIREWALL_DRIVER = FIREWALL_HYBRID_DRIVER

    def _regex(self, value):
        #Note(nati): tap is prefixed on the device
        # in the OVSHybridIptablesFirewallDriver

        value = value.replace('tap_port', 'taptap_port')
        value = value.replace('o_port', 'otap_port')
        value = value.replace('i_port', 'itap_port')
        value = value.replace('s_port', 'stap_port')
        return super(
            TestSecurityGroupAgentWithOVSIptables,
            self)._regex(value)


class TestSecurityGroupExtensionControl(base.BaseTestCase):
    def test_disable_security_group_extension_by_config(self):
        cfg.CONF.set_override(
            'enable_security_group', False,
            group='SECURITYGROUP')
        exp_aliases = ['dummy1', 'dummy2']
        ext_aliases = ['dummy1', 'security-group', 'dummy2']
        sg_rpc.disable_security_group_extension_by_config(ext_aliases)
        self.assertEqual(ext_aliases, exp_aliases)

    def test_enable_security_group_extension_by_config(self):
        cfg.CONF.set_override(
            'enable_security_group', True,
            group='SECURITYGROUP')
        exp_aliases = ['dummy1', 'security-group', 'dummy2']
        ext_aliases = ['dummy1', 'security-group', 'dummy2']
        sg_rpc.disable_security_group_extension_by_config(ext_aliases)
        self.assertEqual(ext_aliases, exp_aliases)

    def test_is_invalid_drvier_combination_sg_enabled(self):
        cfg.CONF.set_override(
            'enable_security_group', True,
            group='SECURITYGROUP')
        cfg.CONF.set_override(
            'firewall_driver', 'neutron.agent.firewall.NoopFirewallDriver',
            group='SECURITYGROUP')
        self.assertFalse(sg_rpc._is_valid_driver_combination())

    def test_is_invalid_drvier_combination_sg_enabled_with_none(self):
        cfg.CONF.set_override(
            'enable_security_group', True,
            group='SECURITYGROUP')
        cfg.CONF.set_override(
            'firewall_driver', None,
            group='SECURITYGROUP')
        self.assertFalse(sg_rpc._is_valid_driver_combination())

    def test_is_invalid_drvier_combination_sg_disabled(self):
        cfg.CONF.set_override(
            'enable_security_group', False,
            group='SECURITYGROUP')
        cfg.CONF.set_override(
            'firewall_driver', 'NonNoopDriver',
            group='SECURITYGROUP')
        self.assertFalse(sg_rpc._is_valid_driver_combination())

    def test_is_valid_drvier_combination_sg_enabled(self):
        cfg.CONF.set_override(
            'enable_security_group', True,
            group='SECURITYGROUP')
        cfg.CONF.set_override(
            'firewall_driver', 'NonNoopDriver',
            group='SECURITYGROUP')
        self.assertTrue(sg_rpc._is_valid_driver_combination())

    def test_is_valid_drvier_combination_sg_disabled(self):
        cfg.CONF.set_override(
            'enable_security_group', False,
            group='SECURITYGROUP')
        cfg.CONF.set_override(
            'firewall_driver', 'neutron.agent.firewall.NoopFirewallDriver',
            group='SECURITYGROUP')
        self.assertTrue(sg_rpc._is_valid_driver_combination())

    def test_is_valid_drvier_combination_sg_disabled_with_none(self):
        cfg.CONF.set_override(
            'enable_security_group', False,
            group='SECURITYGROUP')
        cfg.CONF.set_override(
            'firewall_driver', None,
            group='SECURITYGROUP')
        self.assertTrue(sg_rpc._is_valid_driver_combination())
