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

import collections
import contextlib
from unittest import mock

import netaddr
from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib import constants as const
from neutron_lib import context
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from neutron_lib.tests import tools
from oslo_config import cfg
import oslo_messaging
from testtools import matchers
import webob.exc

from neutron.agent import firewall as firewall_base
from neutron.agent.linux import ip_conntrack
from neutron.agent.linux import iptables_manager
from neutron.agent.linux import utils as linux_utils
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api.rpc.handlers import securitygroups_rpc
from neutron.db import securitygroups_rpc_base as sg_db_rpc
from neutron.extensions import securitygroup as ext_sg
from neutron.tests import base
from neutron.tests.unit.extensions import test_securitygroup as test_sg

FAKE_PREFIX = {const.IPv4: '10.0.0.0/24',
               const.IPv6: '2001:db8::/64'}
FAKE_IP = {const.IPv4: '10.0.0.1',
           const.IPv6: 'fe80::1',
           'IPv6_GLOBAL': '2001:db8::1',
           'IPv6_LLA': 'fe80::123',
           'IPv6_DHCP': '2001:db8::3'}

TEST_PLUGIN_CLASS = ('neutron.tests.unit.agent.test_securitygroups_rpc.'
                     'SecurityGroupRpcTestPlugin')


FIREWALL_BASE_PACKAGE = 'neutron.agent.linux.iptables_firewall.'
FIREWALL_IPTABLES_DRIVER = FIREWALL_BASE_PACKAGE + 'IptablesFirewallDriver'
FIREWALL_HYBRID_DRIVER = (FIREWALL_BASE_PACKAGE +
                          'OVSHybridIptablesFirewallDriver')
FIREWALL_NOOP_DRIVER = 'neutron.agent.firewall.NoopFirewallDriver'


def ingress_address_assignment_rules(port):
    rules = []
    v4_addrs = [ip['ip_address'] for ip in port['port']['fixed_ips']
                if netaddr.IPNetwork(ip['ip_address']).version == 4]
    v6_addrs = [ip['ip_address'] for ip in port['port']['fixed_ips']
                if netaddr.IPNetwork(ip['ip_address']).version == 6]
    if v6_addrs:
        rules.append({'direction': 'ingress',
                      'ethertype': 'IPv6',
                      'protocol': 'ipv6-icmp',
                      'source_port_range_min': 134})
    for dest in v4_addrs + ['255.255.255.255']:
        rules.append({'direction': 'ingress',
                      'ethertype': 'IPv4',
                      'port_range_max': 68,
                      'port_range_min': 68,
                      'protocol': 'udp',
                      'source_port_range_max': 67,
                      'source_port_range_min': 67,
                      'dest_ip_prefix': '%s/32' % dest})
    for dest in v6_addrs:
        rules.append({'direction': 'ingress',
                      'ethertype': 'IPv6',
                      'port_range_max': 546,
                      'port_range_min': 546,
                      'protocol': 'udp',
                      'source_port_range_max': 547,
                      'source_port_range_min': 547,
                      'dest_ip_prefix': '%s/128' % dest})
    for dest in ['fe80::/64']:
        rules.append({'direction': 'ingress',
                      'ethertype': 'IPv6',
                      'port_range_max': 546,
                      'port_range_min': 546,
                      'protocol': 'udp',
                      'source_port_range_max': 547,
                      'source_port_range_min': 547,
                      'dest_ip_prefix': '%s' % dest})
    return rules


def set_enable_security_groups(enabled):
    cfg.CONF.set_override('enable_security_group', enabled,
                          group='SECURITYGROUP')


def set_firewall_driver(firewall_driver):
    cfg.CONF.set_override('firewall_driver', firewall_driver,
                          group='SECURITYGROUP')


class FakeFirewallDriver(firewall_base.FirewallDriver):
    """Fake FirewallDriver

    FirewallDriver is base class for other types of drivers. To be able to
    use it in tests, it's needed to overwrite all abstract methods.
    """
    def prepare_port_filter(self, port):
        raise NotImplementedError()

    def update_port_filter(self, port):
        raise NotImplementedError()


class SecurityGroupRpcTestPlugin(test_sg.SecurityGroupTestPlugin,
                                 sg_db_rpc.SecurityGroupServerRpcMixin):
    def __init__(self):
        super(SecurityGroupRpcTestPlugin, self).__init__()
        self.notifier = mock.Mock()
        self.devices = {}

    def create_port(self, context, port):
        result = super(SecurityGroupRpcTestPlugin,
                       self).create_port(context, port)
        self.devices[result['id']] = result
        self.notify_security_groups_member_updated(context, result)
        return result

    def update_port(self, context, id, port):
        original_port = self.get_port(context, id)
        updated_port = super(SecurityGroupRpcTestPlugin,
                             self).update_port(context, id, port)
        self.devices[id] = updated_port
        self.update_security_group_on_port(
            context, id, port, original_port, updated_port)
        return updated_port

    def delete_port(self, context, id):
        port = self.get_port(context, id)
        super(SecurityGroupRpcTestPlugin, self).delete_port(context, id)
        self.notify_security_groups_member_updated(context, port)
        del self.devices[id]

    def get_port_from_device(self, context, device):
        device = self.devices.get(device)
        if device:
            device['security_group_rules'] = []
            device['security_group_source_groups'] = []
            device['security_group_remote_address_groups'] = []
            device['fixed_ips'] = [ip['ip_address']
                                   for ip in device['fixed_ips']]
        return device


class SGServerRpcCallBackTestCase(test_sg.SecurityGroupDBTestCase):
    def setUp(self, plugin=None):
        plugin = plugin or TEST_PLUGIN_CLASS
        set_firewall_driver(FIREWALL_NOOP_DRIVER)
        super(SGServerRpcCallBackTestCase, self).setUp(plugin)
        self.notifier = directory.get_plugin().notifier
        self.rpc = securitygroups_rpc.SecurityGroupServerRpcCallback()

    def _test_security_group_port(self, device_owner, gw_ip,
                                  cidr, ip_version, ip_address):
        with self.network() as net:
            with self.subnet(net,
                             gateway_ip=gw_ip,
                             cidr=cidr,
                             ip_version=ip_version) as subnet:
                kwargs = {
                    'fixed_ips': [{'subnet_id': subnet['subnet']['id'],
                                   'ip_address': ip_address}]}
                if device_owner:
                    kwargs['device_owner'] = device_owner
                res = self._create_port(
                    self.fmt, net['network']['id'], **kwargs)
                res = self.deserialize(self.fmt, res)
                port_id = res['port']['id']
                if device_owner in const.ROUTER_INTERFACE_OWNERS:
                    data = {'port': {'fixed_ips': []}}
                    req = self.new_update_request('ports', data, port_id)
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                self._delete('ports', port_id)

    def _test_sg_rules_for_devices_ipv4_ingress_port_range(
            self, min_port, max_port):
        fake_prefix = FAKE_PREFIX[const.IPv4]
        with self.network() as n,\
                self.subnet(n),\
                self.security_group() as sg1:
            sg1_id = sg1['security_group']['id']
            rule1 = self._build_security_group_rule(
                sg1_id,
                'ingress', const.PROTO_NAME_TCP, str(min_port),
                str(max_port))
            rule2 = self._build_security_group_rule(
                sg1_id,
                'ingress', const.PROTO_NAME_TCP, '23',
                '23', fake_prefix)
            rules = {
                'security_group_rules': [rule1['security_group_rule'],
                                         rule2['security_group_rule']]}
            res = self._create_security_group_rule(self.fmt, rules)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

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
                         'port_range_max': max_port,
                         'security_group_id': sg1_id,
                         'port_range_min': min_port},
                        {'direction': 'ingress',
                         'protocol': const.PROTO_NAME_TCP,
                         'ethertype': const.IPv4,
                         'port_range_max': 23, 'security_group_id': sg1_id,
                         'port_range_min': 23,
                         'source_ip_prefix': fake_prefix},
                        ] + ingress_address_assignment_rules(ports_rest1)
            self.assertEqual(port_rpc['security_group_rules'],
                             expected)
            self._delete('ports', port_id1)

    def test_sg_rules_for_devices_ipv4_ingress_port_range_min_port_1(self):
        self._test_sg_rules_for_devices_ipv4_ingress_port_range(1, 10)

    def test_security_group_info_for_ports_with_no_rules(self):
        with self.network() as n,\
                self.subnet(n),\
                self.security_group() as sg:
            sg_id = sg['security_group']['id']
            self._delete_default_security_group_egress_rules(sg_id)

            res = self._create_port(
                self.fmt, n['network']['id'],
                security_groups=[sg_id])
            ports_rest = self.deserialize(self.fmt, res)
            port_id = ports_rest['port']['id']
            self.rpc.devices = {port_id: ports_rest['port']}
            devices = [port_id]
            ctx = context.get_admin_context()
            sg_info = self.rpc.security_group_info_for_devices(
                ctx, devices=devices)

            expected = {sg_id: []}
            self.assertEqual(expected, sg_info['security_groups'])
            self._delete('ports', port_id)

    @contextlib.contextmanager
    def _port_with_addr_pairs_and_security_group(self):
        plugin_obj = directory.get_plugin()
        if ('allowed-address-pairs'
                not in plugin_obj.supported_extension_aliases):
            self.skipTest("Test depends on allowed-address-pairs extension")
        fake_prefix = FAKE_PREFIX['IPv4']
        with self.network() as n,\
                self.subnet(n),\
                self.security_group() as sg1:
            sg1_id = sg1['security_group']['id']
            rule1 = self._build_security_group_rule(
                sg1_id,
                'ingress', 'tcp', '22',
                '22', remote_group_id=sg1_id)
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
                              'ip_address': '10.0.1.0/24'},
                             {'mac_address': '00:00:00:00:00:01',
                              'ip_address': '11.0.0.1'}]
            res1 = self._create_port(
                self.fmt, n['network']['id'],
                security_groups=[sg1_id],
                arg_list=(addr_apidef.ADDRESS_PAIRS,),
                allowed_address_pairs=address_pairs)
            yield self.deserialize(self.fmt, res1)

    def _test_security_group_info_for_devices_ipv4_addr_pair(
            self, call_version=None):
        with self._port_with_addr_pairs_and_security_group() as port:
            port_id = port['port']['id']
            sg_id = port['port']['security_groups'][0]
            devices = [port_id, 'no_exist_device']
            ctx = context.get_admin_context()
            # verify that address pairs are included in remote SG IPs
            if call_version is not None:
                sg_member_ips = self.rpc.security_group_info_for_devices(
                    ctx, devices=devices,
                    call_version=call_version)['sg_member_ips']
            else:
                sg_member_ips = self.rpc.security_group_info_for_devices(
                    ctx, devices=devices)['sg_member_ips']
            if call_version == '1.3':
                expected_member_ips = [
                    ('10.0.1.0/24', '00:00:00:00:00:01'),
                    ('11.0.0.1', '00:00:00:00:00:01'),
                    (port['port']['fixed_ips'][0]['ip_address'],
                     None)]
            else:
                expected_member_ips = [
                    '10.0.1.0/24',
                    '11.0.0.1',
                    port['port']['fixed_ips'][0]['ip_address']]
            self.assertEqual(sorted(expected_member_ips),
                             sorted(sg_member_ips[sg_id]['IPv4']))
            self._delete('ports', port_id)

    def test_security_group_info_for_devices_ipv4_addr_pair(self):
        self._test_security_group_info_for_devices_ipv4_addr_pair(
            call_version='1.3')

    def test_security_group_info_for_devices_ipv4_addr_pair_low_version(self):
        self._test_security_group_info_for_devices_ipv4_addr_pair(
            call_version='1.2')

    def test_security_group_info_for_devices_ipv4_addr_pair_backward_cmp(
            self):
        self._test_security_group_info_for_devices_ipv4_addr_pair()

    def test_security_group_rules_for_devices_ipv4_ingress_addr_pair(self):
        fake_prefix = FAKE_PREFIX[const.IPv4]
        with self._port_with_addr_pairs_and_security_group() as port:
            port_id = port['port']['id']
            sg_id = port['port']['security_groups'][0]
            devices = [port_id, 'no_exist_device']
            ctx = context.get_admin_context()
            ports_rpc = self.rpc.security_group_rules_for_devices(
                ctx, devices=devices)

            port_rpc = ports_rpc[port_id]
            expected = [{'direction': 'egress', 'ethertype': 'IPv4',
                         'security_group_id': sg_id},
                        {'direction': 'egress', 'ethertype': 'IPv6',
                         'security_group_id': sg_id},
                        {'direction': 'ingress',
                         'protocol': 'tcp', 'ethertype': 'IPv4',
                         'port_range_max': 22,
                         'remote_group_id': sg_id,
                         'security_group_id': sg_id,
                         'source_ip_prefix': '11.0.0.1/32',
                         'port_range_min': 22},
                        {'direction': 'ingress',
                         'protocol': 'tcp', 'ethertype': 'IPv4',
                         'port_range_max': 22,
                         'remote_group_id': sg_id,
                         'security_group_id': sg_id,
                         'source_ip_prefix': '10.0.1.0/24',
                         'port_range_min': 22},
                        {'direction': 'ingress', 'protocol': 'tcp',
                         'ethertype': 'IPv4',
                         'port_range_max': 23, 'security_group_id': sg_id,
                         'port_range_min': 23,
                         'source_ip_prefix': fake_prefix},
                        ] + ingress_address_assignment_rules(port)
            expected = tools.UnorderedList(expected)
            self.assertEqual(expected,
                             port_rpc['security_group_rules'])
            self.assertEqual(port['port']['allowed_address_pairs'],
                             port_rpc['allowed_address_pairs'])
            self._delete('ports', port_id)

    def test_security_group_rules_for_devices_ipv4_egress(self):
        fake_prefix = FAKE_PREFIX[const.IPv4]
        with self.network() as n,\
                self.subnet(n),\
                self.security_group() as sg1:
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
            self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

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
                        ] + ingress_address_assignment_rules(ports_rest1)
            self.assertEqual(port_rpc['security_group_rules'],
                             expected)
            self._delete('ports', port_id1)

    def test_security_group_rules_for_devices_ipv4_source_group(self):

        with self.network() as n,\
                self.subnet(n),\
                self.security_group() as sg1,\
                self.security_group() as sg2:
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
            self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

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
            port_fixed_ip2 = ports_rest2['port']['fixed_ips'][0]['ip_address']
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
                         'source_ip_prefix': port_fixed_ip2 + '/32',
                         'protocol': const.PROTO_NAME_TCP,
                         'ethertype': const.IPv4,
                         'port_range_max': 25, 'port_range_min': 24,
                         'remote_group_id': sg2_id,
                         'security_group_id': sg1_id},
                        ] + ingress_address_assignment_rules(ports_rest1)
            self.assertEqual(expected,
                             port_rpc['security_group_rules'])
            self._delete('ports', port_id1)
            self._delete('ports', port_id2)

    def test_security_group_info_for_devices_ipv4_source_group(self):

        with self.network() as n,\
                self.subnet(n),\
                self.security_group() as sg1,\
                self.security_group() as sg2,\
                self.address_group(addresses=['10.0.1.0/24']) as ag1:
            sg1_id = sg1['security_group']['id']
            sg2_id = sg2['security_group']['id']
            ag1_id = ag1['address_group']['id']
            ag1_ip = ag1['address_group']['addresses'][0]
            rule1 = self._build_security_group_rule(
                sg1_id,
                'ingress', const.PROTO_NAME_TCP, '24',
                '25', remote_group_id=sg2['security_group']['id'])
            rule2 = self._build_security_group_rule(
                sg1_id,
                'ingress', const.PROTO_NAME_TCP, '26',
                '27', remote_address_group_id=ag1_id)
            rules = {
                'security_group_rules': [rule1['security_group_rule'],
                                         rule2['security_group_rule']]}
            res = self._create_security_group_rule(self.fmt, rules)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

            res1 = self._create_port(
                self.fmt, n['network']['id'],
                security_groups=[sg1_id])
            ports_rest1 = self.deserialize(self.fmt, res1)
            port_id1 = ports_rest1['port']['id']
            self.rpc.devices = {port_id1: ports_rest1['port']}
            devices = [port_id1, 'no_exist_device']

            res2 = self._create_port(
                self.fmt, n['network']['id'],
                security_groups=[sg2_id])
            ports_rest2 = self.deserialize(self.fmt, res2)
            port_id2 = ports_rest2['port']['id']
            port_ip2 = ports_rest2['port']['fixed_ips'][0]['ip_address']
            ctx = context.get_admin_context()
            ports_rpc = self.rpc.security_group_info_for_devices(
                ctx, devices=devices, call_version='1.3')
            expected = {
                'security_groups': {sg1_id: [
                    {'direction': 'egress', 'ethertype': const.IPv4,
                     'stateful': True},
                    {'direction': 'egress', 'ethertype': const.IPv6,
                     'stateful': True},
                    {'direction': u'ingress',
                     'protocol': const.PROTO_NAME_TCP,
                     'ethertype': const.IPv4,
                     'port_range_max': 25, 'port_range_min': 24,
                     'remote_group_id': sg2_id,
                     'stateful': True},
                    {'direction': u'ingress',
                     'protocol': const.PROTO_NAME_TCP,
                     'ethertype': const.IPv4,
                     'port_range_max': 27, 'port_range_min': 26,
                     'remote_address_group_id': ag1_id,
                     'stateful': True},
                ]},
                'sg_member_ips': {
                    sg2_id: {
                        'IPv4': set([(port_ip2, None), ]),
                        'IPv6': set()
                    },
                    ag1_id: {
                        'IPv4': set([(ag1_ip, None), ]),
                        'IPv6': set()
                    },
                },
            }
            self.assertEqual(expected['security_groups'],
                             ports_rpc['security_groups'])
            self.assertEqual(expected['sg_member_ips'][sg2_id]['IPv4'],
                             ports_rpc['sg_member_ips'][sg2_id]['IPv4'])
            self.assertEqual(expected['sg_member_ips'][ag1_id]['IPv4'],
                             ports_rpc['sg_member_ips'][ag1_id]['IPv4'])
            self._delete('ports', port_id1)
            self._delete('ports', port_id2)

    def test_security_group_rules_for_devices_ipv6_ingress(self):
        fake_prefix = FAKE_PREFIX[const.IPv6]
        fake_gateway = FAKE_IP[const.IPv6]
        with self.network() as n,\
                self.subnet(n, gateway_ip=fake_gateway,
                            cidr=fake_prefix, ip_version=const.IP_VERSION_6
                            ) as subnet_v6,\
                self.security_group() as sg1:
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
            self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

            self._create_port(
                self.fmt, n['network']['id'],
                fixed_ips=[{'subnet_id': subnet_v6['subnet']['id'],
                            'ip_address': FAKE_IP['IPv6_DHCP']}],
                device_owner=const.DEVICE_OWNER_DHCP,
                security_groups=[sg1_id])

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
            source_port, dest_port, ethertype = sg_db_rpc.DHCP_RULE_PORT[6]
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
                         'port_range_max': 23,
                         'security_group_id': sg1_id,
                         'port_range_min': 23,
                         'source_ip_prefix': fake_prefix},
                        ] + ingress_address_assignment_rules(ports_rest1)
            self.assertEqual(port_rpc['security_group_rules'],
                             expected)
            self._delete('ports', port_id1)

    def test_security_group_info_for_devices_only_ipv6_rule(self):
        with self.network() as n,\
                self.subnet(n),\
                self.security_group() as sg1,\
                self.address_group(addresses=['2001::/16']) as ag1:
            sg1_id = sg1['security_group']['id']
            ag1_id = ag1['address_group']['id']
            ag1_ip = ag1['address_group']['addresses'][0]
            rule1 = self._build_security_group_rule(
                sg1_id,
                'ingress', const.PROTO_NAME_TCP, '22',
                '22', remote_group_id=sg1_id,
                ethertype=const.IPv6)
            rule2 = self._build_security_group_rule(
                sg1_id,
                'ingress', const.PROTO_NAME_TCP, '23',
                '23', remote_address_group_id=ag1_id,
                ethertype=const.IPv6)
            rules = {
                'security_group_rules': [rule1['security_group_rule'],
                                         rule2['security_group_rule']]}
            self._make_security_group_rule(self.fmt, rules)

            res1 = self._create_port(
                self.fmt, n['network']['id'],
                security_groups=[sg1_id])
            ports_rest1 = self.deserialize(self.fmt, res1)
            port_id1 = ports_rest1['port']['id']
            self.rpc.devices = {port_id1: ports_rest1['port']}
            devices = [port_id1, 'no_exist_device']

            ctx = context.get_admin_context()
            ports_rpc = self.rpc.security_group_info_for_devices(
                ctx, devices=devices)
            expected = {
                'security_groups': {sg1_id: [
                    {'direction': 'egress', 'ethertype': const.IPv4,
                     'stateful': True},
                    {'direction': 'egress', 'ethertype': const.IPv6,
                     'stateful': True},
                    {'direction': u'ingress',
                     'protocol': const.PROTO_NAME_TCP,
                     'ethertype': const.IPv6,
                     'port_range_max': 22, 'port_range_min': 22,
                     'remote_group_id': sg1_id,
                     'stateful': True},
                    {'direction': u'ingress',
                     'protocol': const.PROTO_NAME_TCP,
                     'ethertype': const.IPv6,
                     'port_range_max': 23, 'port_range_min': 23,
                     'remote_address_group_id': ag1_id,
                     'stateful': True},
                ]},
                'sg_member_ips': {
                    sg1_id: {'IPv6': set()},
                    # This test uses RPC version 1.2 which gets compatible
                    # member ips without mac address
                    ag1_id: {'IPv6': set([ag1_ip])}
                },
            }
            self.assertEqual(expected['security_groups'],
                             ports_rpc['security_groups'])
            self.assertEqual(expected['sg_member_ips'][sg1_id]['IPv6'],
                             ports_rpc['sg_member_ips'][sg1_id]['IPv6'])
            self.assertEqual(expected['sg_member_ips'][ag1_id]['IPv6'],
                             ports_rpc['sg_member_ips'][ag1_id]['IPv6'])
            self._delete('ports', port_id1)

    def test_security_group_rules_for_devices_ipv6_egress(self):
        fake_prefix = FAKE_PREFIX[const.IPv6]
        fake_gateway = FAKE_IP[const.IPv6]
        with self.network() as n,\
                self.subnet(n, gateway_ip=fake_gateway,
                            cidr=fake_prefix, ip_version=const.IP_VERSION_6
                            ) as subnet_v6,\
                self.security_group() as sg1:
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
            self._make_security_group_rule(self.fmt, rules)

            ports_rest1 = self._make_port(
                self.fmt, n['network']['id'],
                fixed_ips=[{'subnet_id': subnet_v6['subnet']['id']}],
                security_groups=[sg1_id])
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
                        ] + ingress_address_assignment_rules(ports_rest1)
            self.assertEqual(port_rpc['security_group_rules'],
                             expected)
            self._delete('ports', port_id1)

    def test_security_group_rules_for_devices_ipv6_source_group(self):
        fake_prefix = FAKE_PREFIX[const.IPv6]
        fake_gateway = FAKE_IP[const.IPv6]
        with self.network() as n,\
                self.subnet(n, gateway_ip=fake_gateway,
                            cidr=fake_prefix, ip_version=const.IP_VERSION_6
                            ) as subnet_v6,\
                self.security_group() as sg1,\
                self.security_group() as sg2:
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
            self._make_security_group_rule(self.fmt, rules)

            ports_rest1 = self._make_port(
                self.fmt, n['network']['id'],
                fixed_ips=[{'subnet_id': subnet_v6['subnet']['id']}],
                security_groups=[sg1_id,
                                 sg2_id])
            port_id1 = ports_rest1['port']['id']
            self.rpc.devices = {port_id1: ports_rest1['port']}
            devices = [port_id1, 'no_exist_device']

            ports_rest2 = self._make_port(
                self.fmt, n['network']['id'],
                fixed_ips=[{'subnet_id': subnet_v6['subnet']['id']}],
                security_groups=[sg2_id])
            port_id2 = ports_rest2['port']['id']
            port_ip2 = ports_rest2['port']['fixed_ips'][0]['ip_address']

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
                         'source_ip_prefix': port_ip2 + '/128',
                         'protocol': const.PROTO_NAME_TCP,
                         'ethertype': const.IPv6,
                         'port_range_max': 25, 'port_range_min': 24,
                         'remote_group_id': sg2_id,
                         'security_group_id': sg1_id},
                        ] + ingress_address_assignment_rules(ports_rest1)
            self.assertEqual(expected,
                             port_rpc['security_group_rules'])
            self._delete('ports', port_id1)
            self._delete('ports', port_id2)


class SecurityGroupAgentRpcTestCaseForNoneDriver(base.BaseTestCase):
    def test_init_firewall_with_none_driver(self):
        set_enable_security_groups(False)
        agent = sg_rpc.SecurityGroupAgentRpc(
                context=None, plugin_rpc=mock.Mock())
        self.assertEqual(agent.firewall.__class__.__name__,
                         'NoopFirewallDriver')

    def test_get_trusted_devices(self):
        agent = sg_rpc.SecurityGroupAgentRpc(
                context=None, plugin_rpc=mock.Mock())
        device_ids = ['port_1_id', 'tap_2', 'tap_3', 'port_4_id']
        devices = {
            'port_1_id': {'device': 'tap_1'},
            'port_3_id': {'device': 'tap_3'},
        }
        trusted_devices = agent._get_trusted_devices(
            device_ids, devices)
        self.assertEqual(['tap_2', 'port_4_id'], trusted_devices)


class BaseSecurityGroupAgentRpcTestCase(base.BaseTestCase):
    def setUp(self, defer_refresh_firewall=False):
        super(BaseSecurityGroupAgentRpcTestCase, self).setUp()
        set_firewall_driver(FIREWALL_NOOP_DRIVER)
        self.agent = sg_rpc.SecurityGroupAgentRpc(
                context=None, plugin_rpc=mock.Mock(),
                defer_refresh_firewall=defer_refresh_firewall)
        mock.patch('neutron.agent.linux.iptables_manager').start()
        self.default_firewall = self.agent.firewall
        self.firewall = mock.Mock()
        firewall_object = FakeFirewallDriver()
        self.firewall.defer_apply.side_effect = firewall_object.defer_apply
        self.agent.firewall = self.firewall
        self.fake_device = {'device': 'fake_device',
                            'network_id': 'fake_net',
                            'security_groups': ['fake_sgid1', 'fake_sgid2'],
                            'security_group_source_groups': ['fake_sgid2'],
                            'security_group_rules': [{'security_group_id':
                                                      'fake_sgid1',
                                                      'remote_group_id':
                                                      'fake_sgid2'}]}
        self.firewall.ports = {'fake_device': self.fake_device}
        self.firewall.security_group_updated = mock.Mock()


class SecurityGroupAgentRpcTestCase(BaseSecurityGroupAgentRpcTestCase):
    def setUp(self, defer_refresh_firewall=False):
        super(SecurityGroupAgentRpcTestCase, self).setUp(
            defer_refresh_firewall)
        rpc = self.agent.plugin_rpc
        rpc.security_group_info_for_devices.side_effect = (
                oslo_messaging.UnsupportedVersion('1.2'))
        rpc.security_group_rules_for_devices.return_value = (
            self.firewall.ports)

    def test_prepare_and_remove_devices_filter(self):
        self.agent.prepare_devices_filter(['fake_device'])
        self.agent.remove_devices_filter(['fake_device'])
        # ignore device which is not filtered
        self.firewall.assert_has_calls([mock.call.defer_apply(),
                                        mock.call.prepare_port_filter(
                                            self.fake_device),
                                        mock.call.process_trusted_ports([]),
                                        mock.call.defer_apply(),
                                        mock.call.remove_port_filter(
                                            self.fake_device),
                                        ])

    def test_prepare_devices_filter_with_noopfirewall(self):
        self.agent.firewall = self.default_firewall
        self.agent.plugin_rpc.security_group_info_for_devices = mock.Mock()
        self.agent.plugin_rpc.security_group_rules_for_devices = mock.Mock()
        self.agent.prepare_devices_filter(['fake_device'])
        self.assertFalse(self.agent.plugin_rpc.
                         security_group_info_for_devices.called)
        self.assertFalse(self.agent.plugin_rpc.
                         security_group_rules_for_devices.called)

    def test_prepare_devices_filter_with_firewall_disabled(self):
        cfg.CONF.set_override('enable_security_group', False, 'SECURITYGROUP')
        self.agent.plugin_rpc.security_group_info_for_devices = mock.Mock()
        self.agent.plugin_rpc.security_group_rules_for_devices = mock.Mock()
        self.agent.prepare_devices_filter(['fake_device'])
        self.assertFalse(self.agent.plugin_rpc.
                         security_group_info_for_devices.called)
        self.assertFalse(self.agent.plugin_rpc.
                         security_group_rules_for_devices.called)

    def test_prepare_devices_filter_with_trusted_ports(self):
        devices_to_filter = {k: {'device': k} for k in range(4, 8)}
        all_devices = range(10)
        expected_devices = [0, 1, 2, 3, 8, 9]
        self.agent._use_enhanced_rpc = True
        with mock.patch.object(
                self.agent.plugin_rpc,
                'security_group_info_for_devices',
                return_value={
                    'devices': devices_to_filter,
                    'security_groups': {},
                    'sg_member_ips': {}}):
            with mock.patch.object(
                    self.agent.firewall, 'process_trusted_ports') as m_process:
                self.agent.prepare_devices_filter(all_devices)
        m_process.assert_called_once_with(expected_devices)

    def test_remove_devices_filter_with_trusted_ports(self):
        all_devices = range(10)
        firewall_managed_ports = {k: k for k in range(4, 8)}
        trusted_port_ids = [0, 1, 2, 3, 8, 9]
        with mock.patch.object(self.agent, 'firewall') as mock_firewall:
            mock_firewall.ports = firewall_managed_ports
            self.agent.remove_devices_filter(all_devices)
        mock_firewall.remove_port_filter.assert_has_calls(
            [mock.call(i) for i in firewall_managed_ports.keys()])
        mock_firewall.remove_trusted_ports(
            [mock.call([i]) for i in trusted_port_ids])

    def test_security_groups_rule_updated(self):
        self.agent.refresh_firewall = mock.Mock()
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.security_groups_rule_updated(['fake_sgid1', 'fake_sgid3'])
        self.agent.refresh_firewall.assert_has_calls(
            [mock.call.refresh_firewall([self.fake_device['device']])])
        self.assertFalse(self.firewall.security_group_updated.called)

    def test_security_groups_rule_not_updated(self):
        self.agent.refresh_firewall = mock.Mock()
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.security_groups_rule_updated(['fake_sgid3', 'fake_sgid4'])
        self.assertFalse(self.agent.refresh_firewall.called)
        self.assertFalse(self.firewall.security_group_updated.called)

    def test_security_groups_member_updated(self):
        self.agent.refresh_firewall = mock.Mock()
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.security_groups_member_updated(['fake_sgid2', 'fake_sgid3'])
        self.agent.refresh_firewall.assert_has_calls(
            [mock.call.refresh_firewall([self.fake_device['device']])])
        self.assertFalse(self.firewall.security_group_updated.called)

    def test_security_groups_member_not_updated(self):
        self.agent.refresh_firewall = mock.Mock()
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.security_groups_member_updated(['fake_sgid3', 'fake_sgid4'])
        self.assertFalse(self.agent.refresh_firewall.called)
        self.assertFalse(self.firewall.security_group_updated.called)

    def test_address_group_updated(self):
        ag_list = ['fake_agid1', 'fake_agid2']
        sg_list = ['fake_sgid1', 'fake_sgid2']
        self.agent.plugin_rpc.get_secgroup_ids_for_address_group = mock.Mock(
            return_value=sg_list
        )
        self.agent.security_groups_rule_updated = mock.Mock()
        self.agent.address_group_updated(ag_list)
        self.agent.plugin_rpc.get_secgroup_ids_for_address_group.\
            assert_called_once_with(ag_list)
        self.agent.security_groups_rule_updated.assert_called_once_with(
            sg_list
        )

    def test_address_group_deleted(self):
        ag_list = ['fake_agid1', 'fake_agid2']
        sg_list = []
        self.agent.plugin_rpc.get_secgroup_ids_for_address_group = mock.Mock(
            return_value=sg_list
        )
        self.agent.security_groups_rule_updated = mock.Mock()
        self.agent.address_group_updated(ag_list)
        self.agent.plugin_rpc.get_secgroup_ids_for_address_group.\
            assert_called_once_with(ag_list)
        self.agent.security_groups_rule_updated.assert_called_once_with(
            sg_list
        )

    def test_refresh_firewall(self):
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.refresh_firewall()
        calls = [mock.call.defer_apply(),
                 mock.call.prepare_port_filter(self.fake_device),
                 mock.call.process_trusted_ports(['fake_port_id']),
                 mock.call.defer_apply(),
                 mock.call.update_port_filter(self.fake_device),
                 mock.call.process_trusted_ports([])]
        self.firewall.assert_has_calls(calls)

    def test_refresh_firewall_devices(self):
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.refresh_firewall([self.fake_device['device']])
        calls = [mock.call.defer_apply(),
                 mock.call.prepare_port_filter(self.fake_device),
                 mock.call.process_trusted_ports(['fake_port_id']),
                 mock.call.defer_apply(),
                 mock.call.update_port_filter(self.fake_device),
                 mock.call.process_trusted_ports([])]
        self.firewall.assert_has_calls(calls)

    def test_refresh_firewall_none(self):
        self.agent.refresh_firewall([])
        self.assertFalse(self.firewall.called)

    def test_refresh_firewall_with_firewall_disabled(self):
        cfg.CONF.set_override('enable_security_group', False, 'SECURITYGROUP')
        self.agent.plugin_rpc.security_group_info_for_devices = mock.Mock()
        self.agent.plugin_rpc.security_group_rules_for_devices = mock.Mock()
        self.agent.firewall.defer_apply = mock.Mock()
        self.agent.refresh_firewall([self.fake_device['device']])
        self.assertFalse(self.agent.plugin_rpc.
                         security_group_info_for_devices.called)
        self.assertFalse(self.agent.plugin_rpc.
                         security_group_rules_for_devices.called)
        self.assertFalse(self.agent.firewall.defer_apply.called)

    def test_refresh_firewall_with_noopfirewall(self):
        self.agent.firewall = self.default_firewall
        self.agent.plugin_rpc.security_group_info_for_devices = mock.Mock()
        self.agent.plugin_rpc.security_group_rules_for_devices = mock.Mock()
        self.agent.firewall.defer_apply = mock.Mock()
        self.agent.refresh_firewall([self.fake_device])
        self.assertFalse(self.agent.plugin_rpc.
                         security_group_info_for_devices.called)
        self.assertFalse(self.agent.plugin_rpc.
                         security_group_rules_for_devices.called)
        self.assertFalse(self.agent.firewall.defer_apply.called)


class SecurityGroupAgentEnhancedRpcTestCase(BaseSecurityGroupAgentRpcTestCase):

    def setUp(self, defer_refresh_firewall=False):
        super(SecurityGroupAgentEnhancedRpcTestCase, self).setUp(
            defer_refresh_firewall=defer_refresh_firewall)
        fake_sg_info = {
            'security_groups': collections.OrderedDict([
                ('fake_sgid2', []),
                ('fake_sgid1', [{'remote_group_id': 'fake_sgid2'},
                                {'remote_address_group_id': 'fake_agid1'}])]),
            'sg_member_ips': {'fake_sgid2': {'IPv4': [], 'IPv6': []},
                              'fake_agid1': {'IPv4': [], 'IPv6': []}},
            'devices': self.firewall.ports}
        self.agent.plugin_rpc.security_group_info_for_devices.return_value = (
            fake_sg_info)

    def test_prepare_and_remove_devices_filter_enhanced_rpc(self):
        self.agent.prepare_devices_filter(['fake_device'])
        self.agent.remove_devices_filter(['fake_device'])
        # these two mocks are too long, just use tmp_mock to replace them
        tmp_mock1 = mock.call.update_security_group_rules(
            'fake_sgid1', [{'remote_group_id': 'fake_sgid2'},
                           {'remote_address_group_id': 'fake_agid1'}])
        tmp_mock2 = mock.call.update_security_group_members(
            'fake_sgid2', {'IPv4': [], 'IPv6': []})
        tmp_mock3 = mock.call.update_security_group_members(
            'fake_agid1', {'IPv4': [], 'IPv6': []})
        # ignore device which is not filtered
        self.firewall.assert_has_calls([mock.call.defer_apply(),
                                        mock.call.update_security_group_rules(
                                            'fake_sgid2', []),
                                        tmp_mock1,
                                        tmp_mock2,
                                        tmp_mock3,
                                        mock.call.prepare_port_filter(
                                            self.fake_device),
                                        mock.call.process_trusted_ports([]),
                                        mock.call.defer_apply(),
                                        mock.call.remove_port_filter(
                                            self.fake_device),
                                        ], any_order=True)

    def test_security_groups_rule_updated_enhanced_rpc(self):
        sg_list = ['fake_sgid1', 'fake_sgid3']
        self.agent.refresh_firewall = mock.Mock()
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.security_groups_rule_updated(sg_list)
        self.agent.refresh_firewall.assert_called_once_with(
            [self.fake_device['device']])
        self.firewall.security_group_updated.assert_called_once_with(
            'sg_rule', set(sg_list))

    def test_security_groups_rule_not_updated_enhanced_rpc(self):
        self.agent.refresh_firewall = mock.Mock()
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.security_groups_rule_updated(['fake_sgid3', 'fake_sgid4'])
        self.assertFalse(self.agent.refresh_firewall.called)
        self.assertFalse(self.firewall.security_group_updated.called)

    def test_security_groups_member_updated_enhanced_rpc(self):
        sg_list = ['fake_sgid2', 'fake_sgid3']
        self.agent.refresh_firewall = mock.Mock()
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.security_groups_member_updated(sg_list)
        self.agent.refresh_firewall.assert_called_once_with(
            [self.fake_device['device']])
        self.firewall.security_group_updated.assert_called_once_with(
            'sg_member', set(sg_list))

    def test_security_groups_member_not_updated_enhanced_rpc(self):
        self.agent.refresh_firewall = mock.Mock()
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.security_groups_member_updated(
            ['fake_sgid3', 'fake_sgid4'])
        self.assertFalse(self.agent.refresh_firewall.called)
        self.assertFalse(self.firewall.security_group_updated.called)

    def test_refresh_firewall_enhanced_rpc(self):
        self.agent.prepare_devices_filter(['fake_port_id'])
        self.agent.refresh_firewall()
        calls = [mock.call.defer_apply(),
                 mock.call.update_security_group_rules('fake_sgid2', []),
                 mock.call.update_security_group_rules(
                     'fake_sgid1', [{'remote_group_id': 'fake_sgid2'},
                                    {'remote_address_group_id': 'fake_agid1'}
                                    ]),
                 mock.call.update_security_group_members(
                     'fake_sgid2', {'IPv4': [], 'IPv6': []}),
                 mock.call.update_security_group_members('fake_agid1', {
                     'IPv4': [], 'IPv6': []}),
                 mock.call.prepare_port_filter(self.fake_device),
                 mock.call.process_trusted_ports(['fake_port_id']),
                 mock.call.defer_apply(),
                 mock.call.update_security_group_rules('fake_sgid2', []),
                 mock.call.update_security_group_rules(
                     'fake_sgid1', [{'remote_group_id': 'fake_sgid2'},
                                    {'remote_address_group_id': 'fake_agid1'}
                                    ]),
                 mock.call.update_security_group_members(
                     'fake_sgid2', {'IPv4': [], 'IPv6': []}),
                 mock.call.update_security_group_members('fake_agid1', {
                     'IPv4': [], 'IPv6': []}),
                 mock.call.update_port_filter(self.fake_device),
                 mock.call.process_trusted_ports([])]

        self.firewall.assert_has_calls(calls, any_order=True)

    def test_refresh_firewall_devices_enhanced_rpc(self):
        self.agent.prepare_devices_filter(['fake_device'])
        self.agent.refresh_firewall([self.fake_device['device']])
        calls = [mock.call.defer_apply(),
                 mock.call.update_security_group_rules('fake_sgid2', []),
                 mock.call.update_security_group_rules('fake_sgid1', [
                     {'remote_group_id': 'fake_sgid2'},
                     {'remote_address_group_id': 'fake_agid1'}]),
                 mock.call.update_security_group_members('fake_sgid2', {
                     'IPv4': [], 'IPv6': []
                 }),
                 mock.call.update_security_group_members('fake_agid1', {
                     'IPv4': [], 'IPv6': []}),
                 mock.call.prepare_port_filter(self.fake_device),
                 mock.call.process_trusted_ports([]),
                 mock.call.defer_apply(),
                 mock.call.update_security_group_rules('fake_sgid2', []),
                 mock.call.update_security_group_rules('fake_sgid1', [
                     {'remote_group_id': 'fake_sgid2'},
                     {'remote_address_group_id': 'fake_agid1'}]),
                 mock.call.update_security_group_members('fake_sgid2', {
                     'IPv4': [], 'IPv6': []}),
                 mock.call.update_security_group_members('fake_agid1', {
                     'IPv4': [], 'IPv6': []}),
                 mock.call.update_port_filter(self.fake_device),
                 mock.call.process_trusted_ports([]),
                 ]
        self.firewall.assert_has_calls(calls, any_order=True)

    def test_refresh_firewall_none_enhanced_rpc(self):
        self.agent.refresh_firewall([])
        self.assertFalse(self.firewall.called)


class SecurityGroupAgentRpcWithDeferredRefreshTestCase(
        SecurityGroupAgentRpcTestCase):

    def setUp(self):
        super(SecurityGroupAgentRpcWithDeferredRefreshTestCase, self).setUp(
            defer_refresh_firewall=True)

    @contextlib.contextmanager
    def add_fake_device(self, device, sec_groups, source_sec_groups=None,
                        remote_address_groups=None):
        fake_device = {'device': device,
                       'security_groups': sec_groups,
                       'security_group_source_groups': source_sec_groups or [],
                       'security_group_remote_address_groups':
                           remote_address_groups or [],
                       'security_group_rules': [{'security_group_id':
                                                 'fake_sgid1',
                                                 'remote_group_id':
                                                 'fake_sgid2'},
                                                {'security_group_id':
                                                     'fake_sgid1',
                                                 'remote_address_group_id':
                                                     'fake_agid1'},
                                                ]}
        self.firewall.ports[device] = fake_device
        yield
        del self.firewall.ports[device]

    def test_security_groups_rule_updated(self):
        self.agent.security_groups_rule_updated(['fake_sgid1', 'fake_sgid3'])
        self.assertIn('fake_device', self.agent.devices_to_refilter)
        self.assertFalse(self.firewall.security_group_updated.called)

    def test_multiple_security_groups_rule_updated_same_port(self):
        with self.add_fake_device(device='fake_device_2',
                                  sec_groups=['fake_sgidX']):
            self.agent.refresh_firewall = mock.Mock()
            self.agent.security_groups_rule_updated(['fake_sgid1'])
            self.agent.security_groups_rule_updated(['fake_sgid2'])
            self.assertIn('fake_device', self.agent.devices_to_refilter)
            self.assertNotIn('fake_device_2', self.agent.devices_to_refilter)
            self.assertFalse(self.firewall.security_group_updated.called)

    def test_security_groups_rule_updated_multiple_ports(self):
        with self.add_fake_device(device='fake_device_2',
                                  sec_groups=['fake_sgid2']):
            self.agent.refresh_firewall = mock.Mock()
            self.agent.security_groups_rule_updated(['fake_sgid1',
                                                     'fake_sgid2'])
            self.assertIn('fake_device', self.agent.devices_to_refilter)
            self.assertIn('fake_device_2', self.agent.devices_to_refilter)
            self.assertFalse(self.firewall.security_group_updated.called)

    def test_multiple_security_groups_rule_updated_multiple_ports(self):
        with self.add_fake_device(device='fake_device_2',
                                  sec_groups=['fake_sgid2']):
            self.agent.refresh_firewall = mock.Mock()
            self.agent.security_groups_rule_updated(['fake_sgid1'])
            self.agent.security_groups_rule_updated(['fake_sgid2'])
            self.assertIn('fake_device', self.agent.devices_to_refilter)
            self.assertIn('fake_device_2', self.agent.devices_to_refilter)
            self.assertFalse(self.firewall.security_group_updated.called)

    def test_security_groups_member_updated(self):
        self.agent.security_groups_member_updated(['fake_sgid2', 'fake_sgid3'])
        self.assertIn('fake_device', self.agent.devices_to_refilter)
        self.assertFalse(self.firewall.security_group_updated.called)

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
            self.assertFalse(self.firewall.security_group_updated.called)

    def test_security_groups_member_updated_multiple_ports(self):
        with self.add_fake_device(device='fake_device_2',
                                  sec_groups=['fake_sgid1', 'fake_sgid1B'],
                                  source_sec_groups=['fake_sgid2']):
            self.agent.security_groups_member_updated(['fake_sgid2'])
            self.assertIn('fake_device', self.agent.devices_to_refilter)
            self.assertIn('fake_device_2', self.agent.devices_to_refilter)
            self.assertFalse(self.firewall.security_group_updated.called)

    def test_multiple_security_groups_member_updated_multiple_ports(self):
        with self.add_fake_device(device='fake_device_2',
                                  sec_groups=['fake_sgid1', 'fake_sgid1B'],
                                  source_sec_groups=['fake_sgid1B']):
            self.agent.security_groups_member_updated(['fake_sgid1B'])
            self.agent.security_groups_member_updated(['fake_sgid2'])
            self.assertIn('fake_device', self.agent.devices_to_refilter)
            self.assertIn('fake_device_2', self.agent.devices_to_refilter)
            self.assertFalse(self.firewall.security_group_updated.called)

    def test_setup_port_filters_new_ports_only(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set()
        self.agent.setup_port_filters(set(['fake_new_device']), set())
        self.assertFalse(self.agent.devices_to_refilter)
        self.agent.prepare_devices_filter.assert_called_once_with(
            set(['fake_new_device']))
        self.assertFalse(self.agent.refresh_firewall.called)
        self.assertFalse(self.firewall.security_group_updated.called)

    def test_setup_port_filters_updated_ports_only(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set()
        self.agent.setup_port_filters(set(), set(['fake_updated_device']))
        self.assertFalse(self.agent.devices_to_refilter)
        self.agent.refresh_firewall.assert_called_once_with(
            set(['fake_updated_device']))
        self.assertFalse(self.agent.prepare_devices_filter.called)
        self.assertFalse(self.firewall.security_group_updated.called)

    def test_setup_port_filter_new_and_updated_ports(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set()
        self.agent.setup_port_filters(set(['fake_new_device']),
                                      set(['fake_updated_device']))
        self.assertFalse(self.agent.devices_to_refilter)
        self.agent.prepare_devices_filter.assert_called_once_with(
            set(['fake_new_device']))
        self.agent.refresh_firewall.assert_called_once_with(
            set(['fake_updated_device']))
        self.assertFalse(self.firewall.security_group_updated.called)

    def test_setup_port_filters_sg_updates_only(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set(['fake_device'])
        self.agent.setup_port_filters(set(), set())
        self.assertFalse(self.agent.devices_to_refilter)
        self.agent.refresh_firewall.assert_called_once_with(
            set(['fake_device']))
        self.assertFalse(self.agent.prepare_devices_filter.called)
        self.assertFalse(self.firewall.security_group_updated.called)

    def test_setup_port_filters_sg_updates_and_new_ports(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set(['fake_device'])
        self.agent.setup_port_filters(set(['fake_new_device']), set())
        self.assertFalse(self.agent.devices_to_refilter)
        self.agent.prepare_devices_filter.assert_called_once_with(
            set(['fake_new_device']))
        self.agent.refresh_firewall.assert_called_once_with(
            set(['fake_device']))
        self.assertFalse(self.firewall.security_group_updated.called)

    def _test_prepare_devices_filter(self, devices):
        # simulate an RPC arriving and calling _security_group_updated()
        self.agent.devices_to_refilter |= set(['fake_new_device'])

    def test_setup_port_filters_new_port_and_rpc(self):
        # Make sure that if an RPC arrives and adds a device to
        # devices_to_refilter while we are in setup_port_filters()
        # that it is not cleared, and will be processed later.
        self.agent.prepare_devices_filter = self._test_prepare_devices_filter
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set(['new_device', 'fake_device'])
        self.agent.setup_port_filters(set(['new_device']), set())
        self.assertEqual(self.agent.devices_to_refilter,
                         set(['fake_new_device']))
        self.agent.refresh_firewall.assert_called_once_with(
            set(['fake_device']))
        self.assertFalse(self.firewall.security_group_updated.called)

    def test_setup_port_filters_sg_updates_and_updated_ports(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set(['fake_device', 'fake_device_2'])
        self.agent.setup_port_filters(
            set(), set(['fake_device', 'fake_updated_device']))
        self.assertFalse(self.agent.devices_to_refilter)
        self.agent.refresh_firewall.assert_called_once_with(
            set(['fake_device', 'fake_device_2', 'fake_updated_device']))
        self.assertFalse(self.agent.prepare_devices_filter.called)
        self.assertFalse(self.firewall.security_group_updated.called)

    def test_setup_port_filters_all_updates(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set(['fake_device', 'fake_device_2'])
        self.agent.setup_port_filters(
            set(['fake_new_device']),
            set(['fake_device', 'fake_updated_device']))
        self.assertFalse(self.agent.devices_to_refilter)
        self.agent.prepare_devices_filter.assert_called_once_with(
            set(['fake_new_device']))
        self.agent.refresh_firewall.assert_called_once_with(
            set(['fake_device', 'fake_device_2', 'fake_updated_device']))
        self.assertFalse(self.firewall.security_group_updated.called)

    def test_setup_port_filters_no_update(self):
        self.agent.prepare_devices_filter = mock.Mock()
        self.agent.refresh_firewall = mock.Mock()
        self.agent.devices_to_refilter = set()
        self.agent.setup_port_filters(set(), set())
        self.assertFalse(self.agent.devices_to_refilter)
        self.assertFalse(self.agent.refresh_firewall.called)
        self.assertFalse(self.agent.prepare_devices_filter.called)
        self.assertFalse(self.firewall.security_group_updated.called)


class FakeSGNotifierAPI(securitygroups_rpc.SecurityGroupAgentRpcApiMixin):
    def __init__(self):
        self.topic = 'fake'
        target = oslo_messaging.Target(topic=self.topic, version='1.0')
        self.client = n_rpc.get_client(target)


class SecurityGroupAgentRpcApiTestCase(base.BaseTestCase):
    def setUp(self):
        super(SecurityGroupAgentRpcApiTestCase, self).setUp()
        self.notifier = FakeSGNotifierAPI()
        self.mock_prepare = mock.patch.object(self.notifier.client, 'prepare',
                return_value=self.notifier.client).start()
        self.mock_cast = mock.patch.object(self.notifier.client,
                'cast').start()

    def test_security_groups_rule_updated(self):
        self.notifier.security_groups_rule_updated(
            None, security_groups=['fake_sgid'])
        self.mock_cast.assert_has_calls(
            [mock.call(None, 'security_groups_rule_updated',
                       security_groups=['fake_sgid'])])

    def test_security_groups_member_updated(self):
        self.notifier.security_groups_member_updated(
            None, security_groups=['fake_sgid'])
        self.mock_cast.assert_has_calls(
            [mock.call(None, 'security_groups_member_updated',
                       security_groups=['fake_sgid'])])

    def test_security_groups_rule_not_updated(self):
        self.notifier.security_groups_rule_updated(
            None, security_groups=[])
        self.assertFalse(self.mock_cast.called)

    def test_security_groups_member_not_updated(self):
        self.notifier.security_groups_member_updated(
            None, security_groups=[])
        self.assertFalse(self.mock_cast.called)


# Note(nati) bn -> binary_name
# id -> device_id
PHYSDEV_MOD = '-m physdev'
PHYSDEV_IS_BRIDGED = '--physdev-is-bridged'

IPTABLES_ARG = {'bn': iptables_manager.binary_name,
                'physdev_mod': PHYSDEV_MOD,
                'physdev_is_bridged': PHYSDEV_IS_BRIDGED}

CHAINS_MANGLE = 'FORWARD|INPUT|OUTPUT|POSTROUTING|PREROUTING|mark'
IPTABLES_ARG['chains'] = CHAINS_MANGLE

CHAINS_MANGLE_V6 = 'FORWARD|INPUT|OUTPUT|POSTROUTING|PREROUTING'
IPTABLES_ARG['chains'] = CHAINS_MANGLE_V6

CHAINS_NAT = 'OUTPUT|POSTROUTING|PREROUTING|float-snat|snat'

IPTABLES_ARG['port1'] = 'port1'
IPTABLES_ARG['port2'] = 'port2'
IPTABLES_ARG['port3'] = 'port3'
IPTABLES_ARG['mac1'] = '12:34:56:78:9A:BC'
IPTABLES_ARG['mac2'] = '12:34:56:78:9A:BD'
IPTABLES_ARG['ip1'] = '10.0.0.3/32'
IPTABLES_ARG['ip2'] = '10.0.0.4/32'
IPTABLES_ARG['chains'] = CHAINS_NAT

IPTABLES_RAW_DEFAULT = """# Generated by iptables_manager
*raw
:OUTPUT - [0:0]
:PREROUTING - [0:0]
:%(bn)s-OUTPUT - [0:0]
:%(bn)s-PREROUTING - [0:0]
-I OUTPUT 1 -j %(bn)s-OUTPUT
-I PREROUTING 1 -j %(bn)s-PREROUTING
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_RAW_BRIDGE_NET_1 = """# Generated by iptables_manager
*raw
:OUTPUT - [0:0]
:PREROUTING - [0:0]
:%(bn)s-OUTPUT - [0:0]
:%(bn)s-PREROUTING - [0:0]
-I OUTPUT 1 -j %(bn)s-OUTPUT
-I PREROUTING 1 -j %(bn)s-PREROUTING
-I %(bn)s-PREROUTING 1 -m physdev --physdev-in brqfakenet1 \
-m comment --comment "Set zone for port1" -j CT --zone 4097
-I %(bn)s-PREROUTING 2 -i brqfakenet1 \
-m comment --comment "Set zone for port1" -j CT --zone 4097
-I %(bn)s-PREROUTING 3 -m physdev --physdev-in tap_port1 \
-m comment --comment "Set zone for port1" -j CT --zone 4097
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_RAW_BRIDGE_NET_2 = """# Generated by iptables_manager
*raw
:OUTPUT - [0:0]
:PREROUTING - [0:0]
:%(bn)s-OUTPUT - [0:0]
:%(bn)s-PREROUTING - [0:0]
-I OUTPUT 1 -j %(bn)s-OUTPUT
-I PREROUTING 1 -j %(bn)s-PREROUTING
-I %(bn)s-PREROUTING 1 -m physdev --physdev-in brqfakenet1 \
-m comment --comment "Set zone for port1" -j CT --zone 4097
-I %(bn)s-PREROUTING 2 -i brqfakenet1 \
-m comment --comment "Set zone for port1" -j CT --zone 4097
-I %(bn)s-PREROUTING 3 -m physdev --physdev-in tap_port1 \
-m comment --comment "Set zone for port1" -j CT --zone 4097
-I %(bn)s-PREROUTING 4 -m physdev --physdev-in brqfakenet2 \
-m comment --comment "Set zone for port2" -j CT --zone 4098
-I %(bn)s-PREROUTING 5 -i brqfakenet2 \
-m comment --comment "Set zone for port2" -j CT --zone 4098
-I %(bn)s-PREROUTING 6 -m physdev --physdev-in tap_port2 \
-m comment --comment "Set zone for port2" -j CT --zone 4098
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_RAW_DEVICE_1 = """# Generated by iptables_manager
*raw
:OUTPUT - [0:0]
:PREROUTING - [0:0]
:%(bn)s-OUTPUT - [0:0]
:%(bn)s-PREROUTING - [0:0]
-I OUTPUT 1 -j %(bn)s-OUTPUT
-I PREROUTING 1 -j %(bn)s-PREROUTING
-I %(bn)s-PREROUTING 1 -m physdev --physdev-in qvbtap_port1 \
-m comment --comment "Set zone for %(port1)s" -j CT --zone 4097
-I %(bn)s-PREROUTING 2 -i qvbtap_port1 \
-m comment --comment "Set zone for %(port1)s" -j CT --zone 4097
-I %(bn)s-PREROUTING 3 -m physdev --physdev-in tap_port1 \
-m comment --comment "Set zone for %(port1)s" -j CT --zone 4097
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_RAW_DEVICE_2 = """# Generated by iptables_manager
*raw
:OUTPUT - [0:0]
:PREROUTING - [0:0]
:%(bn)s-OUTPUT - [0:0]
:%(bn)s-PREROUTING - [0:0]
-I OUTPUT 1 -j %(bn)s-OUTPUT
-I PREROUTING 1 -j %(bn)s-PREROUTING
-I %(bn)s-PREROUTING 1 -m physdev --physdev-in qvbtap_%(port1)s \
-m comment --comment "Set zone for %(port1)s" -j CT --zone 4097
-I %(bn)s-PREROUTING 2 -i qvbtap_%(port1)s \
-m comment --comment "Set zone for %(port1)s" -j CT --zone 4097
-I %(bn)s-PREROUTING 3 -m physdev --physdev-in tap_%(port1)s \
-m comment --comment "Set zone for %(port1)s" -j CT --zone 4097
-I %(bn)s-PREROUTING 4 -m physdev --physdev-in qvbtap_%(port2)s \
-m comment --comment "Set zone for %(port2)s" -j CT --zone 4098
-I %(bn)s-PREROUTING 5 -i qvbtap_%(port2)s \
-m comment --comment "Set zone for %(port2)s" -j CT --zone 4098
-I %(bn)s-PREROUTING 6 -m physdev --physdev-in tap_%(port2)s \
-m comment --comment "Set zone for %(port2)s" -j CT --zone 4098
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

CHAINS_RAW = 'OUTPUT|PREROUTING'
IPTABLES_ARG['chains'] = CHAINS_RAW

IPTABLES_RAW = """# Generated by iptables_manager
*raw
:OUTPUT - [0:0]
:PREROUTING - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
-I OUTPUT 1 -j %(bn)s-OUTPUT
-I PREROUTING 1 -j %(bn)s-PREROUTING
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

CHAINS_EMPTY = 'FORWARD|INPUT|OUTPUT|local|sg-chain|sg-fallback'
CHAINS_1 = CHAINS_EMPTY + '|i_port1|o_port1|s_port1'
CHAINS_2 = CHAINS_1 + '|i_port2|o_port2|s_port2'

IPTABLES_ARG['chains'] = CHAINS_1

IPSET_FILTER_1 = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
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
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-FORWARD 1 %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 2 %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-INPUT 1 %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
-I %(bn)s-i_port1 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_port1 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_port1 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_port1 4 -m set --match-set NIPv4security_group1 src -j \
RETURN
-I %(bn)s-i_port1 5 -m state --state INVALID -j DROP
-I %(bn)s-i_port1 6 -j %(bn)s-sg-fallback
-I %(bn)s-o_port1 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_port1 2 -j %(bn)s-s_port1
-I %(bn)s-o_port1 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_port1 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_port1 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_port1 6 -j RETURN
-I %(bn)s-o_port1 7 -m state --state INVALID -j DROP
-I %(bn)s-o_port1 8 -j %(bn)s-sg-fallback
-I %(bn)s-s_port1 1 -s 10.0.0.3/32 -m mac --mac-source 12:34:56:78:9A:BC \
-j RETURN
-I %(bn)s-s_port1 2 -j DROP
-I %(bn)s-sg-chain 1 %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-i_port1
-I %(bn)s-sg-chain 2 %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
-I %(bn)s-sg-chain 3 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_FILTER_1 = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
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
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-FORWARD 1 %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 2 %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-INPUT 1 %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
-I %(bn)s-i_port1 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_port1 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_port1 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_port1 4 -m state --state INVALID -j DROP
-I %(bn)s-i_port1 5 -j %(bn)s-sg-fallback
-I %(bn)s-o_port1 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_port1 2 -j %(bn)s-s_port1
-I %(bn)s-o_port1 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_port1 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_port1 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_port1 6 -j RETURN
-I %(bn)s-o_port1 7 -m state --state INVALID -j DROP
-I %(bn)s-o_port1 8 -j %(bn)s-sg-fallback
-I %(bn)s-s_port1 1 -s 10.0.0.3/32 -m mac --mac-source 12:34:56:78:9A:BC \
-j RETURN
-I %(bn)s-s_port1 2 -j DROP
-I %(bn)s-sg-chain 1 %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-i_port1
-I %(bn)s-sg-chain 2 %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
-I %(bn)s-sg-chain 3 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG


IPTABLES_FILTER_1_2 = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
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
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-FORWARD 1 %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 2 %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-INPUT 1 %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
-I %(bn)s-i_port1 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_port1 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_port1 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_port1 4 -s 10.0.0.4/32 -j RETURN
-I %(bn)s-i_port1 5 -m state --state INVALID -j DROP
-I %(bn)s-i_port1 6 -j %(bn)s-sg-fallback
-I %(bn)s-o_port1 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_port1 2 -j %(bn)s-s_port1
-I %(bn)s-o_port1 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_port1 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_port1 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_port1 6 -j RETURN
-I %(bn)s-o_port1 7 -m state --state INVALID -j DROP
-I %(bn)s-o_port1 8 -j %(bn)s-sg-fallback
-I %(bn)s-s_port1 1 -s 10.0.0.3/32 -m mac --mac-source 12:34:56:78:9A:BC \
-j RETURN
-I %(bn)s-s_port1 2 -j DROP
-I %(bn)s-sg-chain 1 %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-i_port1
-I %(bn)s-sg-chain 2 %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
-I %(bn)s-sg-chain 3 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_ARG['chains'] = CHAINS_2

IPSET_FILTER_2 = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
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
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-FORWARD 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-INPUT 1 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-INPUT 2 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-i_%(port1)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port1)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port1)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port1)s 4 -m set --match-set NIPv4security_group1 src -j RETURN
-I %(bn)s-i_%(port1)s 5 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port1)s 6 -j %(bn)s-sg-fallback
-I %(bn)s-i_%(port2)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port2)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port2)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port2)s 4 -m set --match-set NIPv4security_group1 src -j RETURN
-I %(bn)s-i_%(port2)s 5 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port2)s 6 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port1)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 2 -j %(bn)s-s_%(port1)s
-I %(bn)s-o_%(port1)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port1)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port1)s 6 -j RETURN
-I %(bn)s-o_%(port1)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port1)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port2)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 2 -j %(bn)s-s_%(port2)s
-I %(bn)s-o_%(port2)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port2)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port2)s 6 -j RETURN
-I %(bn)s-o_%(port2)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port2)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-s_%(port1)s 1 -s %(ip1)s -m mac --mac-source %(mac1)s -j RETURN
-I %(bn)s-s_%(port1)s 2 -j DROP
-I %(bn)s-s_%(port2)s 1 -s %(ip2)s -m mac --mac-source %(mac2)s -j RETURN
-I %(bn)s-s_%(port2)s 2 -j DROP
-I %(bn)s-sg-chain 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port1)s
-I %(bn)s-sg-chain 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-sg-chain 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port2)s
-I %(bn)s-sg-chain 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-sg-chain 5 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPSET_FILTER_2_TRUSTED = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
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
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-FORWARD 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 5 %(physdev_mod)s --physdev-INGRESS tap_%(port3)s \
%(physdev_is_bridged)s -j ACCEPT
-I %(bn)s-FORWARD 6 %(physdev_mod)s --physdev-EGRESS tap_%(port3)s \
%(physdev_is_bridged)s -j ACCEPT
-I %(bn)s-INPUT 1 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-INPUT 2 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-i_%(port1)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port1)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port1)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port1)s 4 -m set --match-set NIPv4security_group1 src -j RETURN
-I %(bn)s-i_%(port1)s 5 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port1)s 6 -j %(bn)s-sg-fallback
-I %(bn)s-i_%(port2)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port2)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port2)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port2)s 4 -m set --match-set NIPv4security_group1 src -j RETURN
-I %(bn)s-i_%(port2)s 5 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port2)s 6 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port1)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 2 -j %(bn)s-s_%(port1)s
-I %(bn)s-o_%(port1)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port1)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port1)s 6 -j RETURN
-I %(bn)s-o_%(port1)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port1)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port2)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 2 -j %(bn)s-s_%(port2)s
-I %(bn)s-o_%(port2)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port2)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port2)s 6 -j RETURN
-I %(bn)s-o_%(port2)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port2)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-s_%(port1)s 1 -s %(ip1)s -m mac --mac-source %(mac1)s -j RETURN
-I %(bn)s-s_%(port1)s 2 -j DROP
-I %(bn)s-s_%(port2)s 1 -s %(ip2)s -m mac --mac-source %(mac2)s -j RETURN
-I %(bn)s-s_%(port2)s 2 -j DROP
-I %(bn)s-sg-chain 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port1)s
-I %(bn)s-sg-chain 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-sg-chain 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port2)s
-I %(bn)s-sg-chain 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-sg-chain 5 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPSET_FILTER_2_3_TRUSTED = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
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
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-FORWARD 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 5 %(physdev_mod)s --physdev-INGRESS tap_%(port3)s \
%(physdev_is_bridged)s -j ACCEPT
-I %(bn)s-FORWARD 6 %(physdev_mod)s --physdev-EGRESS tap_%(port3)s \
%(physdev_is_bridged)s -j ACCEPT
-I %(bn)s-INPUT 1 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-INPUT 2 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-i_%(port1)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port1)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port1)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port1)s 4 -m set --match-set NIPv4security_group1 src -j RETURN
-I %(bn)s-i_%(port1)s 5 -p icmp -j RETURN
-I %(bn)s-i_%(port1)s 6 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port1)s 7 -j %(bn)s-sg-fallback
-I %(bn)s-i_%(port2)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port2)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port2)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port2)s 4 -m set --match-set NIPv4security_group1 src -j RETURN
-I %(bn)s-i_%(port2)s 5 -p icmp -j RETURN
-I %(bn)s-i_%(port2)s 6 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port2)s 7 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port1)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 2 -j %(bn)s-s_%(port1)s
-I %(bn)s-o_%(port1)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port1)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port1)s 6 -j RETURN
-I %(bn)s-o_%(port1)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port1)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port2)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 2 -j %(bn)s-s_%(port2)s
-I %(bn)s-o_%(port2)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port2)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port2)s 6 -j RETURN
-I %(bn)s-o_%(port2)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port2)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-s_%(port1)s 1 -s %(ip1)s -m mac --mac-source %(mac1)s -j RETURN
-I %(bn)s-s_%(port1)s 2 -j DROP
-I %(bn)s-s_%(port2)s 1 -s %(ip2)s -m mac --mac-source %(mac2)s -j RETURN
-I %(bn)s-s_%(port2)s 2 -j DROP
-I %(bn)s-sg-chain 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port1)s
-I %(bn)s-sg-chain 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-sg-chain 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port2)s
-I %(bn)s-sg-chain 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-sg-chain 5 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_FILTER_2 = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
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
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-FORWARD 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-INPUT 1 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-INPUT 2 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-i_%(port1)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port1)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port1)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port1)s 4 -s %(ip2)s -j RETURN
-I %(bn)s-i_%(port1)s 5 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port1)s 6 -j %(bn)s-sg-fallback
-I %(bn)s-i_%(port2)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port2)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port2)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port2)s 4 -s %(ip1)s -j RETURN
-I %(bn)s-i_%(port2)s 5 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port2)s 6 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port1)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 2 -j %(bn)s-s_%(port1)s
-I %(bn)s-o_%(port1)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port1)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port1)s 6 -j RETURN
-I %(bn)s-o_%(port1)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port1)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port2)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 2 -j %(bn)s-s_%(port2)s
-I %(bn)s-o_%(port2)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port2)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port2)s 6 -j RETURN
-I %(bn)s-o_%(port2)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port2)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-s_%(port1)s 1 -s %(ip1)s -m mac --mac-source %(mac1)s -j RETURN
-I %(bn)s-s_%(port1)s 2 -j DROP
-I %(bn)s-s_%(port2)s 1 -s %(ip2)s -m mac --mac-source %(mac2)s -j RETURN
-I %(bn)s-s_%(port2)s 2 -j DROP
-I %(bn)s-sg-chain 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port1)s
-I %(bn)s-sg-chain 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-sg-chain 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port2)s
-I %(bn)s-sg-chain 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-sg-chain 5 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_FILTER_2_TRUSTED = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
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
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-FORWARD 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 5 %(physdev_mod)s --physdev-INGRESS tap_%(port3)s \
%(physdev_is_bridged)s -j ACCEPT
-I %(bn)s-FORWARD 6 %(physdev_mod)s --physdev-EGRESS tap_%(port3)s \
%(physdev_is_bridged)s -j ACCEPT
-I %(bn)s-INPUT 1 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-INPUT 2 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-i_%(port1)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port1)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port1)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port1)s 4 -s %(ip2)s -j RETURN
-I %(bn)s-i_%(port1)s 5 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port1)s 6 -j %(bn)s-sg-fallback
-I %(bn)s-i_%(port2)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port2)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port2)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port2)s 4 -s %(ip1)s -j RETURN
-I %(bn)s-i_%(port2)s 5 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port2)s 6 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port1)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 2 -j %(bn)s-s_%(port1)s
-I %(bn)s-o_%(port1)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port1)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port1)s 6 -j RETURN
-I %(bn)s-o_%(port1)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port1)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port2)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 2 -j %(bn)s-s_%(port2)s
-I %(bn)s-o_%(port2)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port2)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port2)s 6 -j RETURN
-I %(bn)s-o_%(port2)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port2)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-s_%(port1)s 1 -s %(ip1)s -m mac --mac-source %(mac1)s -j RETURN
-I %(bn)s-s_%(port1)s 2 -j DROP
-I %(bn)s-s_%(port2)s 1 -s %(ip2)s -m mac --mac-source %(mac2)s -j RETURN
-I %(bn)s-s_%(port2)s 2 -j DROP
-I %(bn)s-sg-chain 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port1)s
-I %(bn)s-sg-chain 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-sg-chain 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port2)s
-I %(bn)s-sg-chain 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-sg-chain 5 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_FILTER_2_2 = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
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
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-FORWARD 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-INPUT 1 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-INPUT 2 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-i_%(port1)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port1)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port1)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port1)s 4 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port1)s 5 -j %(bn)s-sg-fallback
-I %(bn)s-i_%(port2)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port2)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port2)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port2)s 4 -s %(ip1)s -j RETURN
-I %(bn)s-i_%(port2)s 5 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port2)s 6 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port1)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 2 -j %(bn)s-s_%(port1)s
-I %(bn)s-o_%(port1)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port1)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port1)s 6 -j RETURN
-I %(bn)s-o_%(port1)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port1)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port2)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 2 -j %(bn)s-s_%(port2)s
-I %(bn)s-o_%(port2)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port2)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port2)s 6 -j RETURN
-I %(bn)s-o_%(port2)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port2)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-s_%(port1)s 1 -s %(ip1)s -m mac --mac-source %(mac1)s -j RETURN
-I %(bn)s-s_%(port1)s 2 -j DROP
-I %(bn)s-s_%(port2)s 1 -s %(ip2)s -m mac --mac-source %(mac2)s -j RETURN
-I %(bn)s-s_%(port2)s 2 -j DROP
-I %(bn)s-sg-chain 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port1)s
-I %(bn)s-sg-chain 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-sg-chain 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port2)s
-I %(bn)s-sg-chain 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-sg-chain 5 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_FILTER_2_3 = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
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
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-FORWARD 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-INPUT 1 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-INPUT 2 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-i_%(port1)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port1)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port1)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port1)s 4 -s %(ip2)s -j RETURN
-I %(bn)s-i_%(port1)s 5 -p icmp -j RETURN
-I %(bn)s-i_%(port1)s 6 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port1)s 7 -j %(bn)s-sg-fallback
-I %(bn)s-i_%(port2)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port2)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port2)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port2)s 4 -s %(ip1)s -j RETURN
-I %(bn)s-i_%(port2)s 5 -p icmp -j RETURN
-I %(bn)s-i_%(port2)s 6 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port2)s 7 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port1)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 2 -j %(bn)s-s_%(port1)s
-I %(bn)s-o_%(port1)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port1)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port1)s 6 -j RETURN
-I %(bn)s-o_%(port1)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port1)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port2)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 2 -j %(bn)s-s_%(port2)s
-I %(bn)s-o_%(port2)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port2)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port2)s 6 -j RETURN
-I %(bn)s-o_%(port2)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port2)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-s_%(port1)s 1 -s %(ip1)s -m mac --mac-source %(mac1)s -j RETURN
-I %(bn)s-s_%(port1)s 2 -j DROP
-I %(bn)s-s_%(port2)s 1 -s %(ip2)s -m mac --mac-source %(mac2)s -j RETURN
-I %(bn)s-s_%(port2)s 2 -j DROP
-I %(bn)s-sg-chain 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port1)s
-I %(bn)s-sg-chain 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-sg-chain 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port2)s
-I %(bn)s-sg-chain 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-sg-chain 5 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_FILTER_2_3_TRUSTED = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
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
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-FORWARD 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 5 %(physdev_mod)s --physdev-INGRESS tap_%(port3)s \
%(physdev_is_bridged)s -j ACCEPT
-I %(bn)s-FORWARD 6 %(physdev_mod)s --physdev-EGRESS tap_%(port3)s \
%(physdev_is_bridged)s -j ACCEPT
-I %(bn)s-INPUT 1 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-INPUT 2 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-i_%(port1)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port1)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port1)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port1)s 4 -s %(ip2)s -j RETURN
-I %(bn)s-i_%(port1)s 5 -p icmp -j RETURN
-I %(bn)s-i_%(port1)s 6 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port1)s 7 -j %(bn)s-sg-fallback
-I %(bn)s-i_%(port2)s 1 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port2)s 2 -s 10.0.0.2/32 -p udp -m udp --sport 67 \
--dport 68 -j RETURN
-I %(bn)s-i_%(port2)s 3 -p tcp -m tcp --dport 22 -j RETURN
-I %(bn)s-i_%(port2)s 4 -s %(ip1)s -j RETURN
-I %(bn)s-i_%(port2)s 5 -p icmp -j RETURN
-I %(bn)s-i_%(port2)s 6 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port2)s 7 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port1)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 2 -j %(bn)s-s_%(port1)s
-I %(bn)s-o_%(port1)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port1)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port1)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port1)s 6 -j RETURN
-I %(bn)s-o_%(port1)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port1)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port2)s 1 -s 0.0.0.0/32 -d 255.255.255.255/32 -p udp -m udp \
--sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 2 -j %(bn)s-s_%(port2)s
-I %(bn)s-o_%(port2)s 3 -p udp -m udp --sport 68 --dport 67 -j RETURN
-I %(bn)s-o_%(port2)s 4 -p udp -m udp --sport 67 --dport 68 -j DROP
-I %(bn)s-o_%(port2)s 5 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port2)s 6 -j RETURN
-I %(bn)s-o_%(port2)s 7 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port2)s 8 -j %(bn)s-sg-fallback
-I %(bn)s-s_%(port1)s 1 -s %(ip1)s -m mac --mac-source %(mac1)s -j RETURN
-I %(bn)s-s_%(port1)s 2 -j DROP
-I %(bn)s-s_%(port2)s 1 -s %(ip2)s -m mac --mac-source %(mac2)s -j RETURN
-I %(bn)s-s_%(port2)s 2 -j DROP
-I %(bn)s-sg-chain 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port1)s
-I %(bn)s-sg-chain 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-sg-chain 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port2)s
-I %(bn)s-sg-chain 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-sg-chain 5 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_ARG['chains'] = CHAINS_EMPTY
IPTABLES_FILTER_EMPTY = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
:neutron-filter-top - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-sg-chain 1 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_ARG['chains'] = CHAINS_1
IPTABLES_FILTER_V6_1 = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
:neutron-filter-top - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-FORWARD 1 %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 2 %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-INPUT 1 %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
-I %(bn)s-i_port1 1 -p ipv6-icmp -m icmp6 --icmpv6-type 130 -j RETURN
-I %(bn)s-i_port1 2 -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j RETURN
-I %(bn)s-i_port1 3 -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j RETURN
-I %(bn)s-i_port1 4 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_port1 5 -m state --state INVALID -j DROP
-I %(bn)s-i_port1 6 -j %(bn)s-sg-fallback
-I %(bn)s-o_port1 1 -s ::/128 -d ff02::/16 -p ipv6-icmp -m icmp6 \
--icmpv6-type 131 -j RETURN
-I %(bn)s-o_port1 2 -s ::/128 -d ff02::/16 -p ipv6-icmp -m icmp6 \
--icmpv6-type 135 -j RETURN
-I %(bn)s-o_port1 3 -s ::/128 -d ff02::/16 -p ipv6-icmp -m icmp6 \
--icmpv6-type 143 -j RETURN
-I %(bn)s-o_port1 4 -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j DROP
-I %(bn)s-o_port1 5 -p ipv6-icmp -j RETURN
-I %(bn)s-o_port1 6 -p udp -m udp --sport 546 --dport 547 -j RETURN
-I %(bn)s-o_port1 7 -p udp -m udp --sport 547 --dport 546 -j DROP
-I %(bn)s-o_port1 8 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_port1 9 -m state --state INVALID -j DROP
-I %(bn)s-o_port1 10 -j %(bn)s-sg-fallback
-I %(bn)s-sg-chain 1 %(physdev_mod)s --physdev-INGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-i_port1
-I %(bn)s-sg-chain 2 %(physdev_mod)s --physdev-EGRESS tap_port1 \
%(physdev_is_bridged)s -j %(bn)s-o_port1
-I %(bn)s-sg-chain 3 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG


IPTABLES_ARG['chains'] = CHAINS_2

IPTABLES_FILTER_V6_2 = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
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
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-FORWARD 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-INPUT 1 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-INPUT 2 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-i_%(port1)s 1 -p ipv6-icmp -m icmp6 --icmpv6-type 130 -j RETURN
-I %(bn)s-i_%(port1)s 2 -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j RETURN
-I %(bn)s-i_%(port1)s 3 -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j RETURN
-I %(bn)s-i_%(port1)s 4 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port1)s 5 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port1)s 6 -j %(bn)s-sg-fallback
-I %(bn)s-i_%(port2)s 1 -p ipv6-icmp -m icmp6 --icmpv6-type 130 -j RETURN
-I %(bn)s-i_%(port2)s 2 -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j RETURN
-I %(bn)s-i_%(port2)s 3 -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j RETURN
-I %(bn)s-i_%(port2)s 4 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port2)s 5 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port2)s 6 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port1)s 1 -s ::/128 -d ff02::/16 -p ipv6-icmp -m icmp6 \
--icmpv6-type 131 -j RETURN
-I %(bn)s-o_%(port1)s 2 -s ::/128 -d ff02::/16 -p ipv6-icmp -m icmp6 \
--icmpv6-type 135 -j RETURN
-I %(bn)s-o_%(port1)s 3 -s ::/128 -d ff02::/16 -p ipv6-icmp -m icmp6 \
--icmpv6-type 143 -j RETURN
-I %(bn)s-o_%(port1)s 4 -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j DROP
-I %(bn)s-o_%(port1)s 5 -p ipv6-icmp -j RETURN
-I %(bn)s-o_%(port1)s 6 -p udp -m udp --sport 546 --dport 547 -j RETURN
-I %(bn)s-o_%(port1)s 7 -p udp -m udp --sport 547 --dport 546 -j DROP
-I %(bn)s-o_%(port1)s 8 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port1)s 9 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port1)s 10 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port2)s 1 -s ::/128 -d ff02::/16 -p ipv6-icmp -m icmp6 \
--icmpv6-type 131 -j RETURN
-I %(bn)s-o_%(port2)s 2 -s ::/128 -d ff02::/16 -p ipv6-icmp -m icmp6 \
--icmpv6-type 135 -j RETURN
-I %(bn)s-o_%(port2)s 3 -s ::/128 -d ff02::/16 -p ipv6-icmp -m icmp6 \
--icmpv6-type 143 -j RETURN
-I %(bn)s-o_%(port2)s 4 -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j DROP
-I %(bn)s-o_%(port2)s 5 -p ipv6-icmp -j RETURN
-I %(bn)s-o_%(port2)s 6 -p udp -m udp --sport 546 --dport 547 -j RETURN
-I %(bn)s-o_%(port2)s 7 -p udp -m udp --sport 547 --dport 546 -j DROP
-I %(bn)s-o_%(port2)s 8 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port2)s 9 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port2)s 10 -j %(bn)s-sg-fallback
-I %(bn)s-sg-chain 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port1)s
-I %(bn)s-sg-chain 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-sg-chain 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port2)s
-I %(bn)s-sg-chain 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-sg-chain 5 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_FILTER_V6_2_TRUSTED = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
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
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-FORWARD 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-sg-chain
-I %(bn)s-FORWARD 5 %(physdev_mod)s --physdev-INGRESS tap_%(port3)s \
%(physdev_is_bridged)s -j ACCEPT
-I %(bn)s-FORWARD 6 %(physdev_mod)s --physdev-EGRESS tap_%(port3)s \
%(physdev_is_bridged)s -j ACCEPT
-I %(bn)s-INPUT 1 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-INPUT 2 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-i_%(port1)s 1 -p ipv6-icmp -m icmp6 --icmpv6-type 130 -j RETURN
-I %(bn)s-i_%(port1)s 2 -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j RETURN
-I %(bn)s-i_%(port1)s 3 -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j RETURN
-I %(bn)s-i_%(port1)s 4 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port1)s 5 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port1)s 6 -j %(bn)s-sg-fallback
-I %(bn)s-i_%(port2)s 1 -p ipv6-icmp -m icmp6 --icmpv6-type 130 -j RETURN
-I %(bn)s-i_%(port2)s 2 -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j RETURN
-I %(bn)s-i_%(port2)s 3 -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j RETURN
-I %(bn)s-i_%(port2)s 4 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-i_%(port2)s 5 -m state --state INVALID -j DROP
-I %(bn)s-i_%(port2)s 6 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port1)s 1 -s ::/128 -d ff02::/16 -p ipv6-icmp -m icmp6 \
--icmpv6-type 131 -j RETURN
-I %(bn)s-o_%(port1)s 2 -s ::/128 -d ff02::/16 -p ipv6-icmp -m icmp6 \
--icmpv6-type 135 -j RETURN
-I %(bn)s-o_%(port1)s 3 -s ::/128 -d ff02::/16 -p ipv6-icmp -m icmp6 \
--icmpv6-type 143 -j RETURN
-I %(bn)s-o_%(port1)s 4 -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j DROP
-I %(bn)s-o_%(port1)s 5 -p ipv6-icmp -j RETURN
-I %(bn)s-o_%(port1)s 6 -p udp -m udp --sport 546 --dport 547 -j RETURN
-I %(bn)s-o_%(port1)s 7 -p udp -m udp --sport 547 --dport 546 -j DROP
-I %(bn)s-o_%(port1)s 8 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port1)s 9 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port1)s 10 -j %(bn)s-sg-fallback
-I %(bn)s-o_%(port2)s 1 -s ::/128 -d ff02::/16 -p ipv6-icmp -m icmp6 \
--icmpv6-type 131 -j RETURN
-I %(bn)s-o_%(port2)s 2 -s ::/128 -d ff02::/16 -p ipv6-icmp -m icmp6 \
--icmpv6-type 135 -j RETURN
-I %(bn)s-o_%(port2)s 3 -s ::/128 -d ff02::/16 -p ipv6-icmp -m icmp6 \
--icmpv6-type 143 -j RETURN
-I %(bn)s-o_%(port2)s 4 -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j DROP
-I %(bn)s-o_%(port2)s 5 -p ipv6-icmp -j RETURN
-I %(bn)s-o_%(port2)s 6 -p udp -m udp --sport 546 --dport 547 -j RETURN
-I %(bn)s-o_%(port2)s 7 -p udp -m udp --sport 547 --dport 546 -j DROP
-I %(bn)s-o_%(port2)s 8 -m state --state RELATED,ESTABLISHED -j RETURN
-I %(bn)s-o_%(port2)s 9 -m state --state INVALID -j DROP
-I %(bn)s-o_%(port2)s 10 -j %(bn)s-sg-fallback
-I %(bn)s-sg-chain 1 %(physdev_mod)s --physdev-INGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port1)s
-I %(bn)s-sg-chain 2 %(physdev_mod)s --physdev-EGRESS tap_%(port1)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port1)s
-I %(bn)s-sg-chain 3 %(physdev_mod)s --physdev-INGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-i_%(port2)s
-I %(bn)s-sg-chain 4 %(physdev_mod)s --physdev-EGRESS tap_%(port2)s \
%(physdev_is_bridged)s -j %(bn)s-o_%(port2)s
-I %(bn)s-sg-chain 5 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG

IPTABLES_ARG['chains'] = CHAINS_EMPTY
IPTABLES_FILTER_V6_EMPTY = """# Generated by iptables_manager
*filter
:FORWARD - [0:0]
:INPUT - [0:0]
:OUTPUT - [0:0]
:neutron-filter-top - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
:%(bn)s-(%(chains)s) - [0:0]
-I FORWARD 1 -j neutron-filter-top
-I FORWARD 2 -j %(bn)s-FORWARD
-I INPUT 1 -j %(bn)s-INPUT
-I OUTPUT 1 -j neutron-filter-top
-I OUTPUT 2 -j %(bn)s-OUTPUT
-I neutron-filter-top 1 -j %(bn)s-local
-I %(bn)s-sg-chain 1 -j ACCEPT
-I %(bn)s-sg-fallback 1 -j DROP
COMMIT
# Completed by iptables_manager
""" % IPTABLES_ARG


class TestSecurityGroupAgentWithIptables(base.BaseTestCase):
    FIREWALL_DRIVER = FIREWALL_IPTABLES_DRIVER
    PHYSDEV_INGRESS = 'physdev-out'
    PHYSDEV_EGRESS = 'physdev-in'

    def setUp(self, defer_refresh_firewall=False, test_rpc_v1_1=True):
        clear_mgrs = lambda: ip_conntrack.CONTRACK_MGRS.clear()
        self.addCleanup(clear_mgrs)
        clear_mgrs()  # clear before start in case other tests didn't clean up
        super(TestSecurityGroupAgentWithIptables, self).setUp()
        set_firewall_driver(self.FIREWALL_DRIVER)
        cfg.CONF.set_override('enable_ipset', False, group='SECURITYGROUP')
        cfg.CONF.set_override('comment_iptables_rules', False, group='AGENT')

        self.utils_exec = mock.patch(
            'neutron.agent.linux.utils.execute').start()

        self.rpc = mock.Mock()
        self._init_agent(defer_refresh_firewall)

        if test_rpc_v1_1:
            self.rpc.security_group_info_for_devices.side_effect = (
                oslo_messaging.UnsupportedVersion('1.2'))

        self.iptables = self.agent.firewall.iptables
        self.ipconntrack = self.agent.firewall.ipconntrack
        # TODO(jlibosva) Get rid of mocking iptables execute and mock out
        # firewall instead
        self.iptables.use_ipv6 = True
        self.iptables_execute = mock.patch.object(linux_utils,
                                                  "execute").start()
        self.iptables_execute_return_values = []
        self.expected_call_count = 0
        self.expected_calls = []
        self.expected_process_inputs = []
        self.iptables_execute.side_effect = self.iptables_execute_return_values

        rule1 = [{'direction': 'ingress',
                  'protocol': const.PROTO_NAME_UDP,
                  'ethertype': const.IPv4,
                  'source_ip_prefix': '10.0.0.2/32',
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
                  'source_ip_prefix': '10.0.0.4/32',
                  'ethertype': const.IPv4}]
        rule3 = rule2[:]
        rule3 += [{'direction': 'ingress',
                  'protocol': const.PROTO_NAME_ICMP,
                  'ethertype': const.IPv4}]
        rule4 = rule1[:]
        rule4 += [{'direction': 'ingress',
                  'source_ip_prefix': '10.0.0.3/32',
                  'ethertype': const.IPv4}]
        rule5 = rule4[:]
        rule5 += [{'direction': 'ingress',
                  'protocol': const.PROTO_NAME_ICMP,
                  'ethertype': const.IPv4}]

        self.devices1 = {'tap_port1': self._device('tap_port1',
                                                   '10.0.0.3/32',
                                                   '12:34:56:78:9a:bc',
                                                   rule1)}
        self.devices2 = collections.OrderedDict([
            ('tap_port1', self._device('tap_port1',
                                       '10.0.0.3/32',
                                       '12:34:56:78:9a:bc',
                                       rule2)),
            ('tap_port2', self._device('tap_port2',
                                       '10.0.0.4/32',
                                       '12:34:56:78:9a:bd',
                                       rule4))
        ])
        self.devices3 = collections.OrderedDict([
            ('tap_port1', self._device('tap_port1',
                                       '10.0.0.3/32',
                                       '12:34:56:78:9a:bc',
                                       rule3)),
            ('tap_port2', self._device('tap_port2',
                                       '10.0.0.4/32',
                                       '12:34:56:78:9a:bd',
                                       rule5))
        ])
        self.agent.firewall.security_group_updated = mock.Mock()

    @staticmethod
    def _enforce_order_in_firewall(firewall):
        # for the sake of the test, eliminate any order randomness:
        # it helps to match iptables output against regexps consistently
        for attr in ('filtered_ports', 'unfiltered_ports'):
            setattr(firewall, attr, collections.OrderedDict())

    def _init_agent(self, defer_refresh_firewall):
        self.agent = sg_rpc.SecurityGroupAgentRpc(
            context=None, plugin_rpc=self.rpc,
            defer_refresh_firewall=defer_refresh_firewall)
        self._enforce_order_in_firewall(self.agent.firewall)
        # don't mess with sysctl knobs in unit tests
        self.agent.firewall._enabled_netfilter_for_bridges = True

    def _device(self, device, ip, mac_address, rule):
        return {'device': device,
                'network_id': 'fakenet%s' % device[-1:],
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
        value = value.replace('[', r'\[')
        value = value.replace(']', r'\]')
        value = value.replace('*', r'\*')
        return value

    def _register_mock_call(self, *args, **kwargs):
        return_value = kwargs.pop('return_value', None)
        self.iptables_execute_return_values.append(return_value)

        has_process_input = 'process_input' in kwargs
        process_input = kwargs.get('process_input')
        self.expected_process_inputs.append((has_process_input, process_input))

        if has_process_input:
            kwargs['process_input'] = mock.ANY
        self.expected_calls.append(mock.call(*args, **kwargs))
        self.expected_call_count += 1

    def _verify_mock_calls(self, exp_fw_sg_updated_call=False):
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

        self.assertEqual(exp_fw_sg_updated_call,
                         self.agent.firewall.security_group_updated.called)

    def _replay_iptables(self, v4_filter, v6_filter, raw):
        self._register_mock_call(
            ['iptables-save'], run_as_root=True, privsep_exec=True,
            return_value='')
        self._register_mock_call(
            ['iptables-restore', '-n'],
            process_input=self._regex(v4_filter + raw), run_as_root=True,
            privsep_exec=True, log_fail_as_error=False, return_value='')
        self._register_mock_call(
            ['ip6tables-save'], run_as_root=True, privsep_exec=True,
            return_value='')
        self._register_mock_call(
            ['ip6tables-restore', '-n'],
            process_input=self._regex(v6_filter + raw), run_as_root=True,
            privsep_exec=True, log_fail_as_error=False, return_value='')

    def test_prepare_remove_port(self):
        self.ipconntrack._device_zone_map = {}
        self.rpc.security_group_rules_for_devices.return_value = self.devices1
        self._replay_iptables(IPTABLES_FILTER_1, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_BRIDGE_NET_1)
        self._replay_iptables(IPTABLES_FILTER_EMPTY, IPTABLES_FILTER_V6_EMPTY,
                              IPTABLES_RAW_DEFAULT)

        self.agent.prepare_devices_filter(['tap_port1'])
        self.agent.remove_devices_filter(['tap_port1'])

        self._verify_mock_calls()

    def test_security_group_member_updated(self):
        self.rpc.security_group_rules_for_devices.return_value = self.devices1
        self._replay_iptables(IPTABLES_FILTER_1, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_BRIDGE_NET_1)
        self._replay_iptables(IPTABLES_FILTER_1_2, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_BRIDGE_NET_1)
        self._replay_iptables(IPTABLES_FILTER_2, IPTABLES_FILTER_V6_2,
                              IPTABLES_RAW_BRIDGE_NET_2)
        self._replay_iptables(IPTABLES_FILTER_2_2, IPTABLES_FILTER_V6_2,
                              IPTABLES_RAW_BRIDGE_NET_2)
        self._replay_iptables(IPTABLES_FILTER_1, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_BRIDGE_NET_1)
        self._replay_iptables(IPTABLES_FILTER_EMPTY, IPTABLES_FILTER_V6_EMPTY,
                              IPTABLES_RAW_DEFAULT)

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
        self._replay_iptables(
                IPTABLES_FILTER_2_TRUSTED, IPTABLES_FILTER_V6_2_TRUSTED,
                IPTABLES_RAW_BRIDGE_NET_2)
        self._replay_iptables(
                IPTABLES_FILTER_2_3_TRUSTED, IPTABLES_FILTER_V6_2_TRUSTED,
                IPTABLES_RAW_BRIDGE_NET_2)

        self.agent.prepare_devices_filter(['tap_port1', 'tap_port3'])
        self.rpc.security_group_rules_for_devices.return_value = self.devices3
        self.agent.security_groups_rule_updated(['security_group1'])

        self._verify_mock_calls()


class TestSecurityGroupAgentEnhancedRpcWithIptables(
        TestSecurityGroupAgentWithIptables):
    def setUp(self, defer_refresh_firewall=False):
        super(TestSecurityGroupAgentEnhancedRpcWithIptables, self).setUp(
            defer_refresh_firewall=defer_refresh_firewall, test_rpc_v1_1=False)
        self.sg_info = self.rpc.security_group_info_for_devices

        rule1 = [{'direction': 'ingress',
                  'protocol': const.PROTO_NAME_UDP,
                  'ethertype': const.IPv4,
                  'source_ip_prefix': '10.0.0.2/32',
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
                  'ethertype': const.IPv4},
                 {'direction': 'ingress',
                  'remote_group_id': 'security_group1',
                  'ethertype': const.IPv4}]
        rule2 = rule1[:]
        rule2 += [{'direction': 'ingress',
                  'protocol': const.PROTO_NAME_ICMP,
                  'ethertype': const.IPv4}]

        devices_info1 = {'tap_port1': self._device('tap_port1',
                                                   '10.0.0.3/32',
                                                   '12:34:56:78:9a:bc',
                                                   [])}
        self.devices_info1 = {'security_groups': {'security_group1': rule1},
                         'sg_member_ips': {
                             'security_group1': {
                                 'IPv4': [('10.0.0.3/32',
                                           'fa:16:3e:aa:bb:c1'), ],
                                 'IPv6': []}},
                         'devices': devices_info1}
        devices_info2 = collections.OrderedDict([
            ('tap_port1', self._device('tap_port1',
                                       '10.0.0.3/32',
                                       '12:34:56:78:9a:bc',
                                       [])),
            ('tap_port2', self._device('tap_port2',
                                       '10.0.0.4/32',
                                       '12:34:56:78:9a:bd',
                                       []))
        ])
        self.devices_info2 = {'security_groups': {'security_group1': rule1},
                         'sg_member_ips': {
                             'security_group1': {
                                 'IPv4': [('10.0.0.3/32',
                                           'fa:16:3e:aa:bb:c1'),
                                          ('10.0.0.4/32',
                                           'fa:16:3e:aa:bb:c2')],
                                 'IPv6': []}},
                         'devices': devices_info2}
        self.devices_info3 = {'security_groups': {'security_group1': rule2},
                         'sg_member_ips': {
                             'security_group1': {
                                 'IPv4': [('10.0.0.3/32',
                                           'fa:16:3e:aa:bb:c1'),
                                          ('10.0.0.4/32',
                                           'fa:16:3e:aa:bb:c2')],
                                 'IPv6': []}},
                         'devices': devices_info2}

    def test_prepare_remove_port(self):
        self.ipconntrack._device_zone_map = {}
        self.sg_info.return_value = self.devices_info1
        self._replay_iptables(IPTABLES_FILTER_1, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_BRIDGE_NET_1)
        self._replay_iptables(IPTABLES_FILTER_EMPTY, IPTABLES_FILTER_V6_EMPTY,
                              IPTABLES_RAW_DEFAULT)

        self.agent.prepare_devices_filter(['tap_port1'])
        self.agent.remove_devices_filter(['tap_port1'])

        self._verify_mock_calls()

    def test_security_group_member_updated(self):
        self.sg_info.return_value = self.devices_info1
        self._replay_iptables(IPTABLES_FILTER_1, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_BRIDGE_NET_1)
        self._replay_iptables(IPTABLES_FILTER_1_2, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_BRIDGE_NET_1)
        self._replay_iptables(IPTABLES_FILTER_2, IPTABLES_FILTER_V6_2,
                              IPTABLES_RAW_BRIDGE_NET_2)
        self._replay_iptables(IPTABLES_FILTER_2_2, IPTABLES_FILTER_V6_2,
                              IPTABLES_RAW_BRIDGE_NET_2)
        self._replay_iptables(IPTABLES_FILTER_1, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_BRIDGE_NET_1)
        self._replay_iptables(IPTABLES_FILTER_EMPTY, IPTABLES_FILTER_V6_EMPTY,
                              IPTABLES_RAW_DEFAULT)

        self.agent.prepare_devices_filter(['tap_port1'])
        self.sg_info.return_value = self.devices_info2
        self.agent.security_groups_member_updated(['security_group1'])
        self.agent.prepare_devices_filter(['tap_port2'])
        self.sg_info.return_value = self.devices_info1
        self.agent.security_groups_member_updated(['security_group1'])
        self.agent.remove_devices_filter(['tap_port2'])
        self.agent.remove_devices_filter(['tap_port1'])

        self._verify_mock_calls(True)
        self.assertEqual(
            2, self.agent.firewall.security_group_updated.call_count)

    def test_security_group_rule_updated(self):
        self.sg_info.return_value = self.devices_info2
        self._replay_iptables(
                IPTABLES_FILTER_2_TRUSTED, IPTABLES_FILTER_V6_2_TRUSTED,
                IPTABLES_RAW_BRIDGE_NET_2)
        self._replay_iptables(
                IPTABLES_FILTER_2_3_TRUSTED, IPTABLES_FILTER_V6_2_TRUSTED,
                IPTABLES_RAW_BRIDGE_NET_2)

        self.agent.prepare_devices_filter(['tap_port1', 'tap_port3'])
        self.sg_info.return_value = self.devices_info3
        self.agent.security_groups_rule_updated(['security_group1'])

        self._verify_mock_calls(True)
        self.agent.firewall.security_group_updated.assert_called_with(
            'sg_rule', set(['security_group1']))


class TestSecurityGroupAgentEnhancedIpsetWithIptables(
        TestSecurityGroupAgentEnhancedRpcWithIptables):
    def setUp(self, defer_refresh_firewall=False):
        super(TestSecurityGroupAgentEnhancedIpsetWithIptables, self).setUp(
            defer_refresh_firewall)
        self.agent.firewall.enable_ipset = True
        self.ipset = self.agent.firewall.ipset
        self.ipset_execute = mock.patch.object(self.ipset,
                                               "execute").start()

    def test_prepare_remove_port(self):
        self.ipconntrack._device_zone_map = {}
        self.sg_info.return_value = self.devices_info1
        self._replay_iptables(IPSET_FILTER_1, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_BRIDGE_NET_1)
        self._replay_iptables(IPTABLES_FILTER_EMPTY, IPTABLES_FILTER_V6_EMPTY,
                              IPTABLES_RAW_DEFAULT)

        self.agent.prepare_devices_filter(['tap_port1'])
        self.agent.remove_devices_filter(['tap_port1'])

        self._verify_mock_calls()

    def test_security_group_member_updated(self):
        self.sg_info.return_value = self.devices_info1
        self.ipset._get_new_set_ips = mock.Mock(return_value=['10.0.0.3'])
        self.ipset._get_deleted_set_ips = mock.Mock(return_value=[])
        self._replay_iptables(IPSET_FILTER_1, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_BRIDGE_NET_1)
        self._replay_iptables(IPSET_FILTER_1, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_BRIDGE_NET_1)
        self._replay_iptables(IPSET_FILTER_2, IPTABLES_FILTER_V6_2,
                              IPTABLES_RAW_BRIDGE_NET_2)
        self._replay_iptables(IPSET_FILTER_2, IPTABLES_FILTER_V6_2,
                              IPTABLES_RAW_BRIDGE_NET_2)
        self._replay_iptables(IPSET_FILTER_1, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_BRIDGE_NET_1)
        self._replay_iptables(IPTABLES_FILTER_EMPTY, IPTABLES_FILTER_V6_EMPTY,
                              IPTABLES_RAW_DEFAULT)

        self.agent.prepare_devices_filter(['tap_port1'])
        self.sg_info.return_value = self.devices_info2
        self.agent.security_groups_member_updated(['security_group1'])
        self.agent.prepare_devices_filter(['tap_port2'])
        self.sg_info.return_value = self.devices_info1
        self.agent.security_groups_member_updated(['security_group1'])
        self.agent.remove_devices_filter(['tap_port2'])
        self.agent.remove_devices_filter(['tap_port1'])

        self._verify_mock_calls(True)
        self.assertEqual(
            2, self.agent.firewall.security_group_updated.call_count)

    def test_security_group_rule_updated(self):
        self.ipset._get_new_set_ips = mock.Mock(return_value=['10.0.0.3'])
        self.ipset._get_deleted_set_ips = mock.Mock(return_value=[])
        self.sg_info.return_value = self.devices_info2
        self._replay_iptables(
                IPSET_FILTER_2_TRUSTED, IPTABLES_FILTER_V6_2_TRUSTED,
                IPTABLES_RAW_BRIDGE_NET_2)
        self._replay_iptables(
                IPSET_FILTER_2_3_TRUSTED, IPTABLES_FILTER_V6_2_TRUSTED,
                IPTABLES_RAW_BRIDGE_NET_2)

        self.agent.prepare_devices_filter(['tap_port1', 'tap_port3'])
        self.sg_info.return_value = self.devices_info3
        self.agent.security_groups_rule_updated(['security_group1'])

        self._verify_mock_calls(True)
        self.agent.firewall.security_group_updated.assert_called_with(
            'sg_rule', set(['security_group1']))


class SGNotificationTestMixin(object):
    def test_security_group_rule_updated(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            with self.security_group(name, description):
                security_group_id = sg['security_group']['id']

                rule = self._build_security_group_rule(
                    security_group_id,
                    direction='ingress',
                    proto=const.PROTO_NAME_TCP)
                security_group_rule = self._make_security_group_rule(self.fmt,
                                                                     rule)
                self._delete('security-group-rules',
                             security_group_rule['security_group_rule']['id'])

            self.notifier.assert_has_calls(
                [mock.call.security_groups_rule_updated(mock.ANY,
                                                        [security_group_id]),
                 mock.call.security_groups_rule_updated(mock.ANY,
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
                        [mock.call.security_groups_member_updated(
                            mock.ANY, [mock.ANY])])


class TestSecurityGroupAgentWithOVSIptables(
        TestSecurityGroupAgentWithIptables):

    FIREWALL_DRIVER = FIREWALL_HYBRID_DRIVER

    def setUp(self, defer_refresh_firewall=False, test_rpc_v1_1=True):
        super(TestSecurityGroupAgentWithOVSIptables, self).setUp(
                                                    defer_refresh_firewall,
                                                    test_rpc_v1_1)

    def _init_agent(self, defer_refresh_firewall):
        self.agent = sg_rpc.SecurityGroupAgentRpc(
            context=None, plugin_rpc=self.rpc,
            defer_refresh_firewall=defer_refresh_firewall)
        self._enforce_order_in_firewall(self.agent.firewall)
        # don't mess with sysctl knobs in unit tests
        self.agent.firewall._enabled_netfilter_for_bridges = True

    def test_prepare_remove_port(self):
        self.ipconntrack._device_zone_map = {}
        self.rpc.security_group_rules_for_devices.return_value = self.devices1
        self._replay_iptables(IPTABLES_FILTER_1, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_DEVICE_1)
        self._replay_iptables(IPTABLES_FILTER_EMPTY, IPTABLES_FILTER_V6_EMPTY,
                              IPTABLES_RAW_DEFAULT)

        self.agent.prepare_devices_filter(['tap_port1'])
        self.agent.remove_devices_filter(['tap_port1'])

        self._verify_mock_calls()

    def test_prepare_remove_port_no_ct_zone(self):
        self.ipconntrack.get_device_zone = mock.Mock()
        self.ipconntrack.get_device_zone.side_effect = [{}, {}]
        self.rpc.security_group_rules_for_devices.return_value = self.devices1
        self._replay_iptables(IPTABLES_FILTER_1, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_DEFAULT)
        self._replay_iptables(IPTABLES_FILTER_EMPTY, IPTABLES_FILTER_V6_EMPTY,
                              IPTABLES_RAW_DEFAULT)

        self.agent.prepare_devices_filter(['tap_port1'])
        self.agent.remove_devices_filter(['tap_port1'])

        self._verify_mock_calls()

    def test_security_group_member_updated(self):
        self.ipconntrack._device_zone_map = {}
        self.rpc.security_group_rules_for_devices.return_value = self.devices1
        self._replay_iptables(IPTABLES_FILTER_1, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_DEVICE_1)
        self._replay_iptables(IPTABLES_FILTER_1_2, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_DEVICE_1)
        self._replay_iptables(IPTABLES_FILTER_2, IPTABLES_FILTER_V6_2,
                              IPTABLES_RAW_DEVICE_2)
        self._replay_iptables(IPTABLES_FILTER_2_2, IPTABLES_FILTER_V6_2,
                              IPTABLES_RAW_DEVICE_2)
        self._replay_iptables(IPTABLES_FILTER_1, IPTABLES_FILTER_V6_1,
                              IPTABLES_RAW_DEVICE_1)
        self._replay_iptables(IPTABLES_FILTER_EMPTY, IPTABLES_FILTER_V6_EMPTY,
                              IPTABLES_RAW_DEFAULT)

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
        self.ipconntrack._device_zone_map = {}
        self.rpc.security_group_rules_for_devices.return_value = self.devices2
        self._replay_iptables(
                IPTABLES_FILTER_2_TRUSTED, IPTABLES_FILTER_V6_2_TRUSTED,
                IPTABLES_RAW_DEVICE_2)
        self._replay_iptables(
                IPTABLES_FILTER_2_3_TRUSTED, IPTABLES_FILTER_V6_2_TRUSTED,
                IPTABLES_RAW_DEVICE_2)

        self.agent.prepare_devices_filter(['tap_port1', 'tap_port3'])
        self.rpc.security_group_rules_for_devices.return_value = self.devices3
        self.agent.security_groups_rule_updated(['security_group1'])

        self._verify_mock_calls()

    def _regex(self, value):
        # Note(nati): tap is prefixed on the device
        # in the OVSHybridIptablesFirewallDriver

        value = value.replace('tap_port', 'taptap_port')
        value = value.replace('qvbtaptap_port', 'qvbtap_port')
        value = value.replace('o_port', 'otap_port')
        value = value.replace('i_port', 'itap_port')
        value = value.replace('s_port', 'stap_port')
        return super(
            TestSecurityGroupAgentWithOVSIptables,
            self)._regex(value)


class TestSecurityGroupExtensionControl(base.BaseTestCase):
    def test_disable_security_group_extension_by_config(self):
        set_enable_security_groups(False)
        exp_aliases = ['dummy1', 'dummy2']
        ext_aliases = ['dummy1', 'security-group', 'dummy2']
        sg_rpc.disable_security_group_extension_by_config(ext_aliases)
        self.assertEqual(ext_aliases, exp_aliases)

    def test_enable_security_group_extension_by_config(self):
        set_enable_security_groups(True)
        exp_aliases = ['dummy1', 'security-group', 'dummy2']
        ext_aliases = ['dummy1', 'security-group', 'dummy2']
        sg_rpc.disable_security_group_extension_by_config(ext_aliases)
        self.assertEqual(ext_aliases, exp_aliases)
