# Copyright 2018 Red Hat, Inc.
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

from collections import namedtuple
from os import path
from unittest import mock

import fixtures
import neutron_lib
from neutron_lib.api.definitions import extra_dhcp_opt as edo_ext
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as n_const
from oslo_config import cfg

from neutron.common.ovn import constants
from neutron.common.ovn import utils
from neutron.tests import base
from neutron.tests.unit import fake_resources as fakes

RESOLV_CONF_TEMPLATE = """# TEST TEST TEST
# Geneated by OVN test
nameserver 10.0.0.1
#nameserver 10.0.0.2
nameserver 10.0.0.3
nameserver foo 10.0.0.4
nameserver aef0::4
foo 10.0.0.5
"""
RESOLV_DNS_SERVERS = ['10.0.0.1', '10.0.0.3', 'aef0::4']
RESOLV_DNS_SERVERS_V4 = ['10.0.0.1', '10.0.0.3']
RESOLV_DNS_SERVERS_V6 = ['aef0::4']


class TestUtils(base.BaseTestCase):

    def test_get_system_dns_resolvers(self):
        tempdir = self.useFixture(fixtures.TempDir()).path
        resolver_file_name = tempdir + '/resolv.conf'
        tmp_resolv_file = open(resolver_file_name, 'w')
        tmp_resolv_file.writelines(RESOLV_CONF_TEMPLATE)
        tmp_resolv_file.close()
        expected_dns_resolvers = RESOLV_DNS_SERVERS
        observed_dns_resolvers = utils.get_system_dns_resolvers(
            resolver_file=resolver_file_name)
        self.assertEqual(expected_dns_resolvers, observed_dns_resolvers)

    def test_is_gateway_chassis(self):
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'external_ids': {'ovn-cms-options': 'enable-chassis-as-gw'}})
        non_gw_chassis_0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'external_ids': {'ovn-cms-options': ''}})
        non_gw_chassis_1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={})
        non_gw_chassis_2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'external_ids': {}})

        self.assertTrue(utils.is_gateway_chassis(chassis))
        self.assertFalse(utils.is_gateway_chassis(non_gw_chassis_0))
        self.assertFalse(utils.is_gateway_chassis(non_gw_chassis_1))
        self.assertFalse(utils.is_gateway_chassis(non_gw_chassis_2))

    def test_get_chassis_availability_zones_no_azs(self):
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'external_ids': {'ovn-cms-options': 'enable-chassis-as-gw'}})
        self.assertEqual(set(), utils.get_chassis_availability_zones(chassis))

    def test_get_chassis_availability_zones_one_az(self):
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'external_ids': {'ovn-cms-options':
                             'enable-chassis-as-gw,availability-zones=az0'}})
        self.assertEqual(
            {'az0'}, utils.get_chassis_availability_zones(chassis))

    def test_get_chassis_availability_zones_multiple_az(self):
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'external_ids': {
                'ovn-cms-options':
                'enable-chassis-as-gw,availability-zones=az0:az1 :az2:: :'}})
        self.assertEqual(
            {'az0', 'az1', 'az2'},
            utils.get_chassis_availability_zones(chassis))

    def test_get_chassis_availability_zones_malformed(self):
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'external_ids': {'ovn-cms-options':
                             'enable-chassis-as-gw,availability-zones:az0'}})
        self.assertEqual(
            set(), utils.get_chassis_availability_zones(chassis))

    def test_is_security_groups_enabled(self):
        self.assertTrue(utils.is_security_groups_enabled(
            {constants.PORT_SECURITYGROUPS: ['fake']}))
        self.assertFalse(utils.is_security_groups_enabled(
            {}))

    def test_parse_ovn_lb_port_forwarding(self):
        TC = namedtuple('TC', 'input output description')
        fake_ovn_lb = namedtuple('fake_ovn_lb', 'external_ids protocol vips')
        test_cases = [
            TC([], {}, "empty"),
            TC([{'external_ids': {'neutron:fip_id': 'fip1'},
                 'protocol': None,
                 'vips': {'172.24.4.8:2020': '10.0.0.10:22'}}],
                {'fip1': {'tcp': {'172.24.4.8:2020 10.0.0.10:22'}}},
                "simple"),
            TC([{'external_ids': {'neutron:fip_id': 'fip1'},
                 'protocol': [],
                 'vips': {'172.24.4.8:2020': '10.0.0.10:22',
                          '172.24.4.8:2021': '10.0.0.11:22',
                          '172.24.4.8:8080': '10.0.0.10:80'}}],
                {'fip1': {'tcp': {'172.24.4.8:8080 10.0.0.10:80',
                                  '172.24.4.8:2021 10.0.0.11:22',
                                  '172.24.4.8:2020 10.0.0.10:22'}}},
                "multiple vips"),
            TC([{'external_ids': {'neutron:fip_id': 'fip1'},
                 'protocol': ['tcp'],
                 'vips': {'ext_ip:ext_port1': 'int_ip1:int_port1'}},
                {'external_ids': {'neutron:fip_id': 'fip1'},
                 'protocol': ['udp'],
                 'vips': {'ext_ip:ext_port1': 'int_ip1:int_port1'}}],
                {'fip1': {'tcp': {'ext_ip:ext_port1 int_ip1:int_port1'},
                          'udp': {'ext_ip:ext_port1 int_ip1:int_port1'}}},
                "2 protocols"),
            TC([{'external_ids': {'neutron:fip_id': 'fip1'},
                 'protocol': ['tcp'],
                 'vips': {'ext_ip:ext_port1': 'int_ip1:int_port1'}},
                {'external_ids': {'neutron:fip_id': 'fip2'},
                 'protocol': ['tcp'],
                 'vips': {'ext_ip:ext_port1': 'int_ip1:int_port1'}}],
                {'fip1': {'tcp': {'ext_ip:ext_port1 int_ip1:int_port1'}},
                 'fip2': {'tcp': {'ext_ip:ext_port1 int_ip1:int_port1'}}},
                "2 fips"),
        ]
        for tc in test_cases:
            tc_lbs = [
                fake_ovn_lb(lb['external_ids'], lb['protocol'], lb['vips'])
                for lb in tc.input]
            rc = utils.parse_ovn_lb_port_forwarding(tc_lbs)
            self.assertEqual(rc, tc.output, tc.description)

    def test_get_chassis_in_azs(self):
        ch0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'name': 'ch0',
            'external_ids': {
                'ovn-cms-options':
                'enable-chassis-as-gw,availability-zones=az0:az1:az2'}})
        ch1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'name': 'ch1',
            'external_ids': {
                'ovn-cms-options': 'enable-chassis-as-gw'}})
        ch2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'name': 'ch2',
            'external_ids': {
                'ovn-cms-options':
                'enable-chassis-as-gw,availability-zones=az1:az5'}})

        chassis_list = [ch0, ch1, ch2]
        self.assertEqual(
            {'ch0', 'ch2'},
            utils.get_chassis_in_azs(chassis_list, ['az1', 'az5']))
        self.assertEqual(
            {'ch0'},
            utils.get_chassis_in_azs(chassis_list, ['az2', 'az6']))
        self.assertEqual(
            set(),
            utils.get_chassis_in_azs(chassis_list, ['az6']))

    def test_get_gateway_chassis_without_azs(self):
        ch0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'name': 'ch0',
            'external_ids': {
                'ovn-cms-options':
                'enable-chassis-as-gw,availability-zones=az0:az1:az2'}})
        ch1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'name': 'ch1',
            'external_ids': {
                'ovn-cms-options': 'enable-chassis-as-gw'}})
        ch2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'name': 'ch2',
            'external_ids': {
                'ovn-cms-options':
                'enable-chassis-as-gw,availability-zones=az1:az5'}})
        ch3 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'name': 'ch3',
            'external_ids': {}})

        chassis_list = [ch0, ch1, ch2, ch3]
        self.assertEqual(
            {'ch1'},
            utils.get_gateway_chassis_without_azs(chassis_list))


class TestGateWayChassisValidity(base.BaseTestCase):

    def setUp(self):
        super(TestGateWayChassisValidity, self).setUp()
        self.gw_chassis = ['host1', 'host2']
        self.chassis_name = self.gw_chassis[0]
        self.physnet = 'physical-nw-1'
        self.chassis_physnets = {self.chassis_name: [self.physnet]}

    def test_gateway_chassis_valid(self):
        # Return False, since everything is valid
        self.assertFalse(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets))

    def test_gateway_chassis_due_to_invalid_chassis_name(self):
        # Return True since chassis is invalid
        self.chassis_name = constants.OVN_GATEWAY_INVALID_CHASSIS
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets))

    def test_gateway_chassis_for_chassis_not_in_chassis_physnets(self):
        # Return True since chassis is not in chassis_physnets
        self.chassis_name = 'host-2'
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets))

    def test_gateway_chassis_for_undefined_physnet(self):
        # Return True since physnet is not defined
        self.chassis_name = 'host-1'
        self.physnet = None
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets))

    def test_gateway_chassis_for_physnet_not_in_chassis_physnets(self):
        # Return True since physnet is not in chassis_physnets
        self.physnet = 'physical-nw-2'
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets))

    def test_gateway_chassis_for_gw_chassis_empty(self):
        # Return False if gw_chassis is []
        # This condition states that the chassis is valid, has valid
        # physnets and there are no gw_chassis present in the system.
        self.gw_chassis = []
        self.assertFalse(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets))

    def test_gateway_chassis_for_chassis_not_in_gw_chassis_list(self):
        # Return True since chassis_name not in gw_chassis
        self.gw_chassis = ['host-2']
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets))


class TestDHCPUtils(base.BaseTestCase):

    def test_validate_port_extra_dhcp_opts_empty(self):
        port = {edo_ext.EXTRADHCPOPTS: []}
        result = utils.validate_port_extra_dhcp_opts(port)
        self.assertFalse(result.failed)
        self.assertEqual([], result.invalid_ipv4)
        self.assertEqual([], result.invalid_ipv6)

    def test_validate_port_extra_dhcp_opts_dhcp_disabled(self):
        opt0 = {'opt_name': 'not-valid-ipv4',
                'opt_value': 'joe rogan',
                'ip_version': 4}
        opt1 = {'opt_name': 'dhcp_disabled',
                'opt_value': 'True',
                'ip_version': 4}
        port = {edo_ext.EXTRADHCPOPTS: [opt0, opt1]}

        # Validation always succeeds if the "dhcp_disabled" option is enabled
        result = utils.validate_port_extra_dhcp_opts(port)
        self.assertFalse(result.failed)
        self.assertEqual([], result.invalid_ipv4)
        self.assertEqual([], result.invalid_ipv6)

    def test_validate_port_extra_dhcp_opts(self):
        opt0 = {'opt_name': 'bootfile-name',
                'opt_value': 'homer_simpson.bin',
                'ip_version': 4}
        opt1 = {'opt_name': 'dns-server',
                'opt_value': '2001:4860:4860::8888',
                'ip_version': 6}
        port = {edo_ext.EXTRADHCPOPTS: [opt0, opt1]}

        result = utils.validate_port_extra_dhcp_opts(port)
        self.assertFalse(result.failed)
        self.assertEqual([], result.invalid_ipv4)
        self.assertEqual([], result.invalid_ipv6)

    def test_validate_port_extra_dhcp_opts_invalid(self):
        # Two value options and two invalid, assert the validation
        # will fail and only the invalid options will be returned as
        # not supported
        opt0 = {'opt_name': 'bootfile-name',
                'opt_value': 'homer_simpson.bin',
                'ip_version': 4}
        opt1 = {'opt_name': 'dns-server',
                'opt_value': '2001:4860:4860::8888',
                'ip_version': 6}
        opt2 = {'opt_name': 'not-valid-ipv4',
                'opt_value': 'joe rogan',
                'ip_version': 4}
        opt3 = {'opt_name': 'not-valid-ipv6',
                'opt_value': 'young jamie',
                'ip_version': 6}
        port = {edo_ext.EXTRADHCPOPTS: [opt0, opt1, opt2, opt3]}

        result = utils.validate_port_extra_dhcp_opts(port)
        self.assertTrue(result.failed)
        self.assertEqual(['not-valid-ipv4'], result.invalid_ipv4)
        self.assertEqual(['not-valid-ipv6'], result.invalid_ipv6)

    def test_get_lsp_dhcp_opts_empty(self):
        port = {edo_ext.EXTRADHCPOPTS: []}
        dhcp_disabled, options = utils.get_lsp_dhcp_opts(port, 4)
        self.assertFalse(dhcp_disabled)
        self.assertEqual({}, options)

    def test_get_lsp_dhcp_opts_empty_dhcp_disabled(self):
        opt0 = {'opt_name': 'bootfile-name',
                'opt_value': 'homer_simpson.bin',
                'ip_version': 4}
        opt1 = {'opt_name': 'dhcp_disabled',
                'opt_value': 'True',
                'ip_version': 4}
        port = {edo_ext.EXTRADHCPOPTS: [opt0, opt1]}

        # Validation always succeeds if the "dhcp_disabled" option is enabled
        dhcp_disabled, options = utils.get_lsp_dhcp_opts(port, 4)
        self.assertTrue(dhcp_disabled)
        self.assertEqual({}, options)

    @mock.patch.object(utils, 'is_network_device_port')
    def test_get_lsp_dhcp_opts_is_network_device_port(self, mock_device_port):
        mock_device_port.return_value = True
        port = {}
        dhcp_disabled, options = utils.get_lsp_dhcp_opts(port, 4)
        # Assert OVN DHCP is disabled
        self.assertTrue(dhcp_disabled)
        self.assertEqual({}, options)

    def test_get_lsp_dhcp_opts(self):
        opt0 = {'opt_name': 'bootfile-name',
                'opt_value': 'homer_simpson.bin',
                'ip_version': 4}
        opt1 = {'opt_name': 'server-ip-address',
                'opt_value': '10.0.0.1',
                'ip_version': 4}
        opt2 = {'opt_name': '42',
                'opt_value': '10.0.2.1',
                'ip_version': 4}
        port = {edo_ext.EXTRADHCPOPTS: [opt0, opt1, opt2]}

        dhcp_disabled, options = utils.get_lsp_dhcp_opts(port, 4)
        self.assertFalse(dhcp_disabled)
        # Assert the names got translated to their OVN names
        expected_options = {'tftp_server_address': '10.0.0.1',
                            'ntp_server': '10.0.2.1',
                            'bootfile_name': 'homer_simpson.bin'}
        self.assertEqual(expected_options, options)


class TestConnectionConfigToTargetString(base.BaseTestCase):

    def test_strings(self):
        config_target = (
            ('ssl:1.2.3.4:5678', 'pssl:5678:1.2.3.4'),
            ('tcp:1.2.3.4:5678', 'ptcp:5678:1.2.3.4'),
            ('ssl:[::1]:5678', 'pssl:5678:[::1]'),
            ('tcp:[::1]:5678', 'ptcp:5678:[::1]'),
            ('unix:/var/run/ovs/db.sock', 'punix:/var/run/ovs/db.sock'),
            ('wrong_value', None))

        for config, target in config_target:
            output = utils.connection_config_to_target_string(config)
            self.assertEqual(target, output)


class TestGetDhcpDnsServers(base.BaseTestCase):

    def test_ipv4(self):
        # DNS servers from subnet.
        dns_servers = utils.get_dhcp_dns_servers(
            {'dns_nameservers': ['1.2.3.4', '5.6.7.8']})
        self.assertEqual(['1.2.3.4', '5.6.7.8'], dns_servers)

        # DNS servers from config parameter.
        cfg.CONF.set_override('dns_servers',
                              '1.1.2.2,3.3.4.4', group='ovn')
        dns_servers = utils.get_dhcp_dns_servers({})
        self.assertEqual(['1.1.2.2', '3.3.4.4'], dns_servers)

        # DNS servers from local DNS resolver.
        cfg.CONF.set_override('dns_servers', '', group='ovn')
        with mock.patch('builtins.open',
                        mock.mock_open(read_data=RESOLV_CONF_TEMPLATE)), \
                mock.patch.object(path, 'exists', return_value=True):
            dns_servers = utils.get_dhcp_dns_servers({})
            self.assertEqual(RESOLV_DNS_SERVERS_V4, dns_servers)

        # No DNS servers if only '0.0.0.0' configured.
        dns_servers = utils.get_dhcp_dns_servers(
            {'dns_nameservers': ['0.0.0.0', '5.6.7.8']})
        self.assertEqual(['0.0.0.0', '5.6.7.8'], dns_servers)
        dns_servers = utils.get_dhcp_dns_servers(
            {'dns_nameservers': ['0.0.0.0']})
        self.assertEqual([], dns_servers)

    def test_ipv6(self):
        # DNS servers from subnet.
        dns_servers = utils.get_dhcp_dns_servers(
            {'dns_nameservers': ['2001:4860:4860::8888',
                                 '2001:4860:4860::8844']},
            ip_version=n_const.IP_VERSION_6)
        self.assertEqual(['2001:4860:4860::8888',
                          '2001:4860:4860::8844'], dns_servers)

        # DNS servers from local DNS resolver.
        cfg.CONF.set_override('dns_servers', '', group='ovn')
        with mock.patch('builtins.open',
                        mock.mock_open(read_data=RESOLV_CONF_TEMPLATE)), \
                mock.patch.object(path, 'exists', return_value=True):
            dns_servers = utils.get_dhcp_dns_servers({}, ip_version=6)
            self.assertEqual(RESOLV_DNS_SERVERS_V6, dns_servers)

        # No DNS servers if only '::' configured.
        dns_servers = utils.get_dhcp_dns_servers(
            {'dns_nameservers': ['2001:4860:4860::8888', '::']},
            ip_version=n_const.IP_VERSION_6)
        self.assertEqual(['2001:4860:4860::8888', '::'], dns_servers)
        dns_servers = utils.get_dhcp_dns_servers(
            {'dns_nameservers': ['::']},
            ip_version=n_const.IP_VERSION_6)
        self.assertEqual([], dns_servers)


class TestValidateAndGetDataFromBindingProfile(base.BaseTestCase):

    def setUp(self):
        super(TestValidateAndGetDataFromBindingProfile, self).setUp()
        self.get_plugin = mock.patch(
            'neutron_lib.plugins.directory.get_plugin').start()
        self.VNIC_FAKE_NORMAL = 'fake-vnic-normal'
        self.VNIC_FAKE_OTHER = 'fake-vnic-other'

        # Replace constants.OVN_PORT_BINDING_PROFILE_PARAMS to allow synthesis
        _params = constants.OVN_PORT_BINDING_PROFILE_PARAMS.copy()
        _params.extend([
            constants.OVNPortBindingProfileParamSet(
                {'key': [str, type(None)]},
                self.VNIC_FAKE_NORMAL, None),
            constants.OVNPortBindingProfileParamSet(
                {'key': [str], 'other_key': [str]},
                self.VNIC_FAKE_OTHER, None),
            constants.OVNPortBindingProfileParamSet(
                {
                    'key': [str],
                    'other_key': [str],
                    'third_key': [str]
                },
                self.VNIC_FAKE_OTHER, constants.PORT_CAP_SWITCHDEV),
        ])
        self.OVN_PORT_BINDING_PROFILE_PARAMS = mock.patch.object(
            constants,
            'OVN_PORT_BINDING_PROFILE_PARAMS',
            _params).start()

    def test_get_port_raises(self):
        # Confirm that a exception from get_port bubbles up as intended
        self.get_plugin().get_port.side_effect = KeyError
        self.assertRaises(
            KeyError,
            utils.validate_and_get_data_from_binding_profile,
            {
                constants.OVN_PORT_BINDING_PROFILE: {
                    'parent_name': 'fake-parent-port-uuid',
                    'tag': 42
                },
            })

    def test_invalid_input_raises(self):
        # Confirm that invalid input raises an exception
        self.assertRaises(
            neutron_lib.exceptions.InvalidInput,
            utils.validate_and_get_data_from_binding_profile,
            {
                constants.OVN_PORT_BINDING_PROFILE: {
                    'parent_name': 'fake-parent-port-uuid',
                    'tag': 'notint'
                },
            })
        self.assertRaises(
            neutron_lib.exceptions.InvalidInput,
            utils.validate_and_get_data_from_binding_profile,
            {
                constants.OVN_PORT_BINDING_PROFILE: {
                    'parent_name': 51,
                    'tag': 42
                },
            })
        self.assertRaises(
            neutron_lib.exceptions.InvalidInput,
            utils.validate_and_get_data_from_binding_profile,
            {
                constants.OVN_PORT_BINDING_PROFILE: {
                    'parent_name': 'fake-parent-port-tag-missing',
                },
            })

    def test_valid_input(self):
        # Confirm valid input produces expected output
        expect = {
            'parent_name': 'fake-parent-port-uuid',
            'tag': 42
        }
        self.assertDictEqual(
            expect,
            utils.validate_and_get_data_from_binding_profile(
                {constants.OVN_PORT_BINDING_PROFILE: expect}))

        expect = {
            'vtep-physical-switch': 'fake-physical-switch-uuid',
            'vtep-logical-switch': 'fake-logical-switch-uuid',
        }
        self.assertDictEqual(
            expect,
            utils.validate_and_get_data_from_binding_profile(
                {constants.OVN_PORT_BINDING_PROFILE: expect}))

        binding_profile = {
            constants.PORT_CAP_PARAM: [constants.PORT_CAP_SWITCHDEV],
            'pci_vendor_info': 'dead:beef',
            'pci_slot': '0000:ca:fe.42',
            'physical_network': 'physnet1',

        }
        expect = binding_profile.copy()
        del(expect[constants.PORT_CAP_PARAM])
        self.assertDictEqual(
            expect,
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: portbindings.VNIC_DIRECT,
                 constants.OVN_PORT_BINDING_PROFILE: binding_profile}))

        binding_profile = {
            constants.PORT_CAP_PARAM: [constants.PORT_CAP_SWITCHDEV],
            'pci_vendor_info': 'dead:beef',
            'pci_slot': '0000:ca:fe.42',
            'physical_network': None,

        }
        expect = binding_profile.copy()
        del(expect[constants.PORT_CAP_PARAM])
        self.assertDictEqual(
            expect,
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: portbindings.VNIC_DIRECT,
                 constants.OVN_PORT_BINDING_PROFILE: binding_profile}))

        expect = {
            'pci_vendor_info': 'dead:beef',
            'pci_slot': '0000:ca:fe.42',
            'physical_network': 'physnet1',
            'card_serial_number': 'AB2000X00042',
            'pf_mac_address': '00:53:00:00:00:42',
            'vf_num': 42,
        }
        self.assertDictEqual(
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: portbindings.VNIC_REMOTE_MANAGED,
                 constants.OVN_PORT_BINDING_PROFILE: expect}),
            expect)

    def test_unknown_profile_items_pruned(self):
        # Confirm that unknown profile items are pruned
        self.assertEqual(
            {},
            utils.validate_and_get_data_from_binding_profile(
                {constants.OVN_PORT_BINDING_PROFILE: {
                    'unknown-key': 'unknown-data'}}))

    def test_polymorphic_validation(self):
        expect = {
            'key': 'value',
        }
        self.assertDictEqual(
            expect,
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: self.VNIC_FAKE_NORMAL,
                 constants.OVN_PORT_BINDING_PROFILE: expect}))
        expect = {
            'key': None,
        }
        self.assertDictEqual(
            expect,
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: self.VNIC_FAKE_NORMAL,
                 constants.OVN_PORT_BINDING_PROFILE: expect}))
        # Type ``int`` is not among the accepted types for this key
        expect = {
            'key': 51,
        }
        self.assertRaises(
            neutron_lib.exceptions.InvalidInput,
            utils.validate_and_get_data_from_binding_profile,
            {portbindings.VNIC_TYPE: self.VNIC_FAKE_NORMAL,
             constants.OVN_PORT_BINDING_PROFILE: expect})

    def test_overlapping_param_set_different_vnic_type(self):
        # Confirm overlapping param sets discerned by vnic_type
        expect = {
            'key': 'value',
            'other_key': 'value',
        }
        # This param set is not valid for VNIC_FAKE_NORMAL
        self.assertRaises(
            neutron_lib.exceptions.InvalidInput,
            utils.validate_and_get_data_from_binding_profile,
            {portbindings.VNIC_TYPE: self.VNIC_FAKE_NORMAL,
             constants.OVN_PORT_BINDING_PROFILE: expect})
        # It is valid for VNIC_FAKE_OTHER
        self.assertDictEqual(
            expect,
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: self.VNIC_FAKE_OTHER,
                 constants.OVN_PORT_BINDING_PROFILE: expect}))

    def test_overlapping_param_set_different_vnic_type_and_capability(self):
        # Confirm overlapping param sets discerned by vnic_type and capability
        expect = {
            'key': 'value',
            'other_key': 'value',
            'third_key': 'value',
        }
        # This param set is not valid for VNIC_FAKE_OTHER without capability
        self.assertRaises(
            neutron_lib.exceptions.InvalidInput,
            utils.validate_and_get_data_from_binding_profile,
            {portbindings.VNIC_TYPE: self.VNIC_FAKE_OTHER,
             constants.OVN_PORT_BINDING_PROFILE: expect})
        # This param set is also not valid as the capabilities do not match
        binding_profile = {
            constants.PORT_CAP_PARAM: ['fake-capability'],
            'key': 'value',
            'other_key': 'value',
            'third_key': 'value',
        }
        self.assertEqual(
            {},
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: self.VNIC_FAKE_OTHER,
                 constants.OVN_PORT_BINDING_PROFILE: binding_profile}))
        # It is valid for VNIC_FAKE_OTHER with PORT_CAP_SWITCHDEV capability
        binding_profile = {
            constants.PORT_CAP_PARAM: [constants.PORT_CAP_SWITCHDEV],
            'key': 'value',
            'other_key': 'value',
            'third_key': 'value',
        }
        expect = binding_profile.copy()
        del(expect[constants.PORT_CAP_PARAM])
        self.assertDictEqual(
            expect,
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: self.VNIC_FAKE_OTHER,
                 constants.OVN_PORT_BINDING_PROFILE: binding_profile}))

    def test_capability_only_allowed(self):
        # The end user exposed workflow for creation of instances with special
        # networking needs is to first create a port of certain type and/or
        # capability, and then pass that port to Nova as part of instance
        # creation.
        #
        # This means that it must be allowed to create port wihout a binding
        # profile, or with capability as the only binding profile key.
        binding_profile = {
            constants.PORT_CAP_PARAM: [constants.PORT_CAP_SWITCHDEV],
        }
        self.assertEqual(
            {},
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: self.VNIC_FAKE_OTHER,
                 constants.OVN_PORT_BINDING_PROFILE: binding_profile}))
