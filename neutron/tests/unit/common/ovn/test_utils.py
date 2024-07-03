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
import shlex
from unittest import mock

import fixtures
import neutron_lib
from neutron_lib.api.definitions import extra_dhcp_opt as edo_ext
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc
from oslo_concurrency import processutils
from oslo_config import cfg
import testtools

from neutron.common.ovn import constants
from neutron.common.ovn import exceptions as ovn_exc
from neutron.common.ovn import utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
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
        with open(resolver_file_name, 'w') as f:
            f.writelines(RESOLV_CONF_TEMPLATE)
        expected_dns_resolvers = RESOLV_DNS_SERVERS
        observed_dns_resolvers = utils.get_system_dns_resolvers(
            resolver_file=resolver_file_name)
        self.assertEqual(expected_dns_resolvers, observed_dns_resolvers)

    def _test_is_chassis(self, is_gateway=False, is_extport=False):
        if is_gateway:
            cms_option_value = constants.CMS_OPT_CHASSIS_AS_GW
            func = utils.is_gateway_chassis
        if is_extport:
            cms_option_value = constants.CMS_OPT_CHASSIS_AS_EXTPORT_HOST
            func = utils.is_extport_host_chassis

        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'other_config': {'ovn-cms-options': cms_option_value}})
        wrong_chassis_0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'other_config': {'ovn-cms-options': ''}})
        wrong_chassis_1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'other_config': {}})

        self.assertTrue(func(chassis))
        self.assertFalse(func(wrong_chassis_0))
        self.assertFalse(func(wrong_chassis_1))

    def test_is_gateway_chassis(self):
        self._test_is_chassis(is_gateway=True)

    def test_is_extport_host_chassis(self):
        self._test_is_chassis(is_extport=True)

    def test_get_chassis_availability_zones_no_azs(self):
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'other_config': {'ovn-cms-options': 'enable-chassis-as-gw'}})
        self.assertEqual(set(), utils.get_chassis_availability_zones(chassis))

    def test_get_chassis_availability_zones_one_az(self):
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'other_config': {'ovn-cms-options':
                             'enable-chassis-as-gw,availability-zones=az0'}})
        self.assertEqual(
            {'az0'}, utils.get_chassis_availability_zones(chassis))

    def test_get_chassis_availability_zones_multiple_az(self):
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'other_config': {
                'ovn-cms-options':
                'enable-chassis-as-gw,availability-zones=az0:az1 :az2:: :'}})
        self.assertEqual(
            {'az0', 'az1', 'az2'},
            utils.get_chassis_availability_zones(chassis))

    def test_get_chassis_availability_zones_malformed(self):
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'other_config': {'ovn-cms-options':
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
            'other_config': {
                'ovn-cms-options':
                'enable-chassis-as-gw,availability-zones=az0:az1:az2'}})
        ch1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'name': 'ch1',
            'other_config': {
                'ovn-cms-options': 'enable-chassis-as-gw'}})
        ch2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'name': 'ch2',
            'other_config': {
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

    def test_get_chassis_without_azs(self):
        ch0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'name': 'ch0',
            'other_config': {
                'ovn-cms-options':
                'enable-chassis-as-gw,availability-zones=az0:az1:az2'}})
        ch1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'name': 'ch1',
            'other_config': {
                'ovn-cms-options': 'enable-chassis-as-gw'}})
        ch2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'name': 'ch2',
            'other_config': {
                'ovn-cms-options':
                'enable-chassis-as-gw,availability-zones=az1:az5'}})
        ch3 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'name': 'ch3',
            'other_config': {}})

        chassis_list = [ch0, ch1, ch2, ch3]
        self.assertEqual(
            {'ch1', 'ch3'},
            utils.get_chassis_without_azs(chassis_list))

    def test_is_ovn_metadata_port(self):
        meta_port = {
            'device_owner': n_const.DEVICE_OWNER_DISTRIBUTED,
            'device_id': constants.OVN_METADATA_PREFIX + '12345'}
        non_meta_port_0 = {
            'device_owner': n_const.DEVICE_OWNER_DISTRIBUTED,
            'device_id': 'dhcp-12345'}
        non_meta_port_1 = {
            'device_owner': n_const.DEVICE_OWNER_DHCP,
            'device_id': constants.OVN_METADATA_PREFIX + '12345'}

        self.assertTrue(utils.is_ovn_metadata_port(meta_port))
        self.assertFalse(utils.is_ovn_metadata_port(non_meta_port_0))
        self.assertFalse(utils.is_ovn_metadata_port(non_meta_port_1))

    def test_is_ovn_lb_hm_port(self):
        ovn_lb_hm_port = {
            'device_owner': constants.OVN_LB_HM_PORT_DISTRIBUTED,
            'device_id': 'ovn-lb-hm-12345'}
        non_ovn_lb_hm_port_0 = {
            'device_owner': n_const.DEVICE_OWNER_DISTRIBUTED,
            'device_id': constants.OVN_METADATA_PREFIX + '12345'}
        non_ovn_lb_hm_port_1 = {
            'device_owner': n_const.DEVICE_OWNER_DHCP,
            'device_id': 'dhcp-12345'}

        self.assertTrue(utils.is_ovn_lb_hm_port(ovn_lb_hm_port))
        self.assertFalse(utils.is_ovn_lb_hm_port(non_ovn_lb_hm_port_0))
        self.assertFalse(utils.is_ovn_lb_hm_port(non_ovn_lb_hm_port_1))


class TestGateWayChassisValidity(base.BaseTestCase):

    def setUp(self):
        super(TestGateWayChassisValidity, self).setUp()
        self.gw_chassis = ['host1', 'host2']
        self.chassis_name = self.gw_chassis[0]
        self.physnet = 'physical-nw-1'
        self.chassis_physnets = {self.chassis_name: [self.physnet]}
        self.az_hints = ['ovn', ]
        self.chassis_azs = {self.chassis_name: self.az_hints}

    def test_gateway_chassis_valid(self):
        # Return False, since everything is valid
        self.assertFalse(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets, self.az_hints, self.chassis_azs))

    def test_gateway_chassis_due_to_invalid_chassis_name(self):
        # Return True since chassis is invalid
        self.chassis_name = None
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets, self.az_hints, self.chassis_azs))

    def test_gateway_chassis_for_chassis_not_in_chassis_physnets(self):
        # Return True since chassis is not in chassis_physnets
        self.chassis_name = 'host-2'
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets, self.az_hints, self.chassis_azs))

    def test_gateway_chassis_for_undefined_physnet(self):
        # Return True since physnet is not defined
        self.chassis_name = 'host-1'
        self.physnet = None
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets, self.az_hints, self.chassis_azs))

    def test_gateway_chassis_for_physnet_not_in_chassis_physnets(self):
        # Return True since physnet is not in chassis_physnets
        self.physnet = 'physical-nw-2'
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets, self.az_hints, self.chassis_azs))

    def test_gateway_chassis_for_gw_chassis_empty(self):
        # Return False if gw_chassis is []
        # This condition states that the chassis is valid, has valid
        # physnets and there are no gw_chassis present in the system.
        self.gw_chassis = []
        self.assertFalse(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets, self.az_hints, self.chassis_azs))

    def test_gateway_chassis_for_chassis_not_in_gw_chassis_list(self):
        # Return True since chassis_name not in gw_chassis
        self.gw_chassis = ['host-2']
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets, self.az_hints, self.chassis_azs))

    def test_gateway_chassis_for_chassis_az_hints_empty(self):
        # Return False since az_hints is []
        az_hints = []
        self.assertFalse(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets, az_hints, self.chassis_azs))

    def test_gateway_chassis_for_chassis_no_in_az_hints(self):
        # Return True since az_hints not match chassis_azs
        az_hints = ['ovs']
        self.assertTrue(utils.is_gateway_chassis_invalid(
            self.chassis_name, self.gw_chassis, self.physnet,
            self.chassis_physnets, az_hints, self.chassis_azs))


class TestDHCPUtils(base.BaseTestCase):

    def setUp(self):
        ovn_conf.register_opts()
        super(TestDHCPUtils, self).setUp()

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
        expected_options = {'next_server': '10.0.0.1',
                            'ntp_server': '10.0.2.1',
                            'bootfile_name': '"homer_simpson.bin"'}
        self.assertEqual(expected_options, options)

    def test_get_lsp_dhcp_opts_for_baremetal(self):
        opts = [{
            'opt_name': 'tag:ipxe,bootfile-name',
            'opt_value': 'http://172.7.27.29/ipxe',
            'ip_version': 4
        }, {
            'opt_name': 'tag:!ipxe,bootfile-name',
            'opt_value': 'undionly.kpxe',
            'ip_version': 4
        }, {
            'opt_name': 'tftp-server',
            'opt_value': '"172.7.27.29"',
            'ip_version': 4
        }, {
            'opt_name': 'tag:ipxe6,bootfile-name',
            'opt_value': 'http://[2001:db8::1]/ipxe',
            'ip_version': 6
        }, {
            'opt_name': 'tag:!ipxe6,bootfile-name',
            'opt_value': 'undionly.kpxe',
            'ip_version': 6
        }]
        port = {portbindings.VNIC_TYPE: portbindings.VNIC_BAREMETAL,
                edo_ext.EXTRADHCPOPTS: opts}

        dhcp_disabled, options = utils.get_lsp_dhcp_opts(port, 4)
        self.assertFalse(dhcp_disabled)
        # Assert the names got translated to their OVN names and the
        # options that weren't double-quoted are now double-quoted
        expected_options = {'tftp_server': '"172.7.27.29"',
                            'bootfile_name': '"http://172.7.27.29/ipxe"',
                            'bootfile_name_alt': '"undionly.kpxe"'}
        self.assertEqual(expected_options, options)
        # Now the same for IPv6 options
        dhcp_disabled, options = utils.get_lsp_dhcp_opts(port, 6)
        self.assertFalse(dhcp_disabled)
        expected_options = {'bootfile_name': '"http://[2001:db8::1]/ipxe"',
                            'bootfile_name_alt': '"undionly.kpxe"'}
        self.assertEqual(expected_options, options)

    def test_get_lsp_dhcp_opts_dhcp_disabled_for_baremetal(self):
        cfg.CONF.set_override(
            'disable_ovn_dhcp_for_baremetal_ports', True, group='ovn')

        opts = [{
            'opt_name': 'tag:ipxe,bootfile-name',
            'opt_value': 'http://172.7.27.29/ipxe',
            'ip_version': 4
        }, {
            'opt_name': 'tag:ipxe,bootfile-name',
            'opt_value': 'http://[2001:db8::1]/ipxe',
            'ip_version': 6
        }]
        port = {portbindings.VNIC_TYPE: portbindings.VNIC_BAREMETAL,
                edo_ext.EXTRADHCPOPTS: [opts]}

        dhcp_disabled, options = utils.get_lsp_dhcp_opts(port, 4)
        # Assert DHCP is disabled for this port
        self.assertTrue(dhcp_disabled)
        # Assert no options were passed
        self.assertEqual({}, options)

        # and the same for dhcpv6
        dhcp_disabled, options = utils.get_lsp_dhcp_opts(port, 6)
        # Assert DHCP is disabled for this port
        self.assertTrue(dhcp_disabled)
        # Assert no options were passed
        self.assertEqual({}, options)

    def test_get_lsp_dhcp_opts_for_domain_search(self):
        opt = {'opt_name': 'domain-search',
               'opt_value': 'openstack.org,ovn.org',
               'ip_version': 4}
        port = {portbindings.VNIC_TYPE: portbindings.VNIC_NORMAL,
                edo_ext.EXTRADHCPOPTS: [opt]}

        dhcp_disabled, options = utils.get_lsp_dhcp_opts(port, 4)
        self.assertFalse(dhcp_disabled)
        # Assert option got translated to "domain_search_list" and
        # the value is a string (double-quoted)
        expected_options = {'domain_search_list': '"openstack.org,ovn.org"'}
        self.assertEqual(expected_options, options)

    def test_get_lsp_dhcp_opts_sanitize_map(self):
        opt = {'opt_name': 'classless-static-route',
               'opt_value': '128.128.128.128/32,22.2.0.2',
               'ip_version': 4}
        port = {portbindings.VNIC_TYPE: portbindings.VNIC_NORMAL,
                edo_ext.EXTRADHCPOPTS: [opt]}
        dhcp_disabled, options = utils.get_lsp_dhcp_opts(port, 4)
        self.assertFalse(dhcp_disabled)
        # Assert option got translated to "classless_static_route" and
        # the value is a map (wrapped with {})
        expected_options = {
            'classless_static_route': '{128.128.128.128/32,22.2.0.2}'}
        self.assertEqual(expected_options, options)


class TestGetDhcpDnsServers(base.BaseTestCase):

    def setUp(self):
        ovn_conf.register_opts()
        super(TestGetDhcpDnsServers, self).setUp()

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
                    'other_key': [int],
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
        self.assertEqual(
            utils.BPInfo(expect, portbindings.VNIC_NORMAL, []),
            utils.validate_and_get_data_from_binding_profile(
                {constants.OVN_PORT_BINDING_PROFILE: expect}))

        expect = {
            'vtep-physical-switch': 'fake-physical-switch-uuid',
            'vtep-logical-switch': 'fake-logical-switch-uuid',
        }
        self.assertEqual(
            utils.BPInfo(expect, portbindings.VNIC_NORMAL, []),
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
        self.assertEqual(
            utils.BPInfo(expect, portbindings.VNIC_DIRECT,
                         [constants.PORT_CAP_SWITCHDEV]),
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
        self.assertEqual(
            utils.BPInfo(expect, portbindings.VNIC_DIRECT,
                         [constants.PORT_CAP_SWITCHDEV]),
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
        self.assertEqual(
            utils.BPInfo(expect, portbindings.VNIC_REMOTE_MANAGED, []),
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: portbindings.VNIC_REMOTE_MANAGED,
                 constants.OVN_PORT_BINDING_PROFILE: expect}))

    def test_valid_input_surplus_keys(self):
        # Confirm that extra keys are allowed
        binding_profile = {
            constants.PORT_CAP_PARAM: [constants.PORT_CAP_SWITCHDEV],
            'pci_vendor_info': 'dead:beef',
            'pci_slot': '0000:ca:fe.42',
            'physical_network': 'physnet1',
            'optional_information_provided_by_nova': 'not_consumed_by_neutron',
        }
        expect = binding_profile.copy()
        del(expect[constants.PORT_CAP_PARAM])
        del(expect['optional_information_provided_by_nova'])
        self.assertEqual(
            utils.BPInfo(expect, portbindings.VNIC_DIRECT,
                         [constants.PORT_CAP_SWITCHDEV]),
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: portbindings.VNIC_DIRECT,
                 constants.OVN_PORT_BINDING_PROFILE: binding_profile}))

    def test_valid_input_no_binding_profile(self):
        # Confirm that we treat a port without binding:profile as valid
        self.assertEqual(utils.BPInfo({}, None, []),
                         utils.validate_and_get_data_from_binding_profile({}))

    def test_unknown_profile_items_pruned(self):
        # Confirm that unknown profile items are pruned
        self.assertEqual(
            utils.BPInfo({}, portbindings.VNIC_NORMAL, []),
            utils.validate_and_get_data_from_binding_profile(
                {constants.OVN_PORT_BINDING_PROFILE: {
                    'unknown-key': 'unknown-data'}}))

    def test_polymorphic_validation(self):
        expect = {
            'key': 'value',
        }
        self.assertEqual(
            utils.BPInfo(expect, self.VNIC_FAKE_NORMAL, []),
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: self.VNIC_FAKE_NORMAL,
                 constants.OVN_PORT_BINDING_PROFILE: expect}))
        expect = {
            'key': None,
        }
        self.assertEqual(
            utils.BPInfo(expect, self.VNIC_FAKE_NORMAL, []),
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
        binding_profile = {
            'key': 'value',
            'other_key': 'value',
        }
        # This param set is valid for VNIC_FAKE_NORMAL with 'other_key' pruned.
        expected_bp = binding_profile.copy()
        del(expected_bp['other_key'])
        self.assertEqual(
            utils.BPInfo(expected_bp, self.VNIC_FAKE_NORMAL, []),
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: self.VNIC_FAKE_NORMAL,
                 constants.OVN_PORT_BINDING_PROFILE: binding_profile}))
        # It is valid for VNIC_FAKE_OTHER
        expected_bp = binding_profile.copy()
        self.assertEqual(
            utils.BPInfo(expected_bp, self.VNIC_FAKE_OTHER, []),
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: self.VNIC_FAKE_OTHER,
                 constants.OVN_PORT_BINDING_PROFILE: binding_profile}))

    def test_overlapping_param_set_different_vnic_type_and_capability(self):
        # Confirm overlapping param sets discerned by vnic_type and capability
        binding_profile = {
            'key': 'value',
            'other_key': 42,
            'third_key': 'value',
        }
        # This param set is not valid for VNIC_FAKE_OTHER without capability
        expect = binding_profile.copy()
        del(expect['third_key'])
        self.assertRaises(
            neutron_lib.exceptions.InvalidInput,
            utils.validate_and_get_data_from_binding_profile,
            {portbindings.VNIC_TYPE: self.VNIC_FAKE_OTHER,
             constants.OVN_PORT_BINDING_PROFILE: binding_profile})
        # This param set is also not valid as the capabilities do not match
        binding_profile = {
            constants.PORT_CAP_PARAM: ['fake-capability'],
            'key': 'value',
            'other_key': 'value',
            'third_key': 'value',
        }
        self.assertEqual(
            utils.BPInfo({}, self.VNIC_FAKE_OTHER, ['fake-capability']),
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: self.VNIC_FAKE_OTHER,
                 constants.OVN_PORT_BINDING_PROFILE: binding_profile}))
        # It is valid for VNIC_FAKE_OTHER with PORT_CAP_SWITCHDEV capability
        binding_profile = {
            constants.PORT_CAP_PARAM: [constants.PORT_CAP_SWITCHDEV],
            'key': 'value',
            'other_key': 42,
            'third_key': 'value',
        }
        expect = binding_profile.copy()
        del(expect[constants.PORT_CAP_PARAM])
        self.assertEqual(
            utils.BPInfo(expect, self.VNIC_FAKE_OTHER,
                         [constants.PORT_CAP_SWITCHDEV]),
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
            utils.BPInfo({}, self.VNIC_FAKE_OTHER,
                         [constants.PORT_CAP_SWITCHDEV]),
            utils.validate_and_get_data_from_binding_profile(
                {portbindings.VNIC_TYPE: self.VNIC_FAKE_OTHER,
                 constants.OVN_PORT_BINDING_PROFILE: binding_profile}))


class TestRetryDecorator(base.BaseTestCase):
    DEFAULT_RETRY_VALUE = 10

    def setUp(self):
        super().setUp()
        mock.patch.object(
            ovn_conf, "get_ovn_ovsdb_retry_max_interval",
            return_value=self.DEFAULT_RETRY_VALUE).start()

    def test_default_retry_value(self):
        with mock.patch('tenacity.wait_exponential') as m_wait:
            @utils.retry()
            def decorated_method():
                pass

            decorated_method()
        m_wait.assert_called_with(max=self.DEFAULT_RETRY_VALUE)

    def test_custom_retry_value(self):
        custom_value = 3
        with mock.patch('tenacity.wait_exponential') as m_wait:
            @utils.retry(max_=custom_value)
            def decorated_method():
                pass

            decorated_method()
        m_wait.assert_called_with(max=custom_value)

    def test_positive_result(self):
        number_of_exceptions = 3
        method = mock.Mock(
            side_effect=[Exception() for i in range(number_of_exceptions)])

        @utils.retry(max_=0.001)
        def decorated_method():
            try:
                method()
            except StopIteration:
                return

        decorated_method()

        # number of exceptions + one successful call
        self.assertEqual(number_of_exceptions + 1, method.call_count)


class TestOvsdbClientCommand(base.BaseTestCase):
    class OvsdbClientTestCommand(utils.OvsdbClientCommand):
        COMMAND = 'test'

    def setUp(self):
        super().setUp()
        self.nb_connection = 'ovn_nb_connection'
        self.sb_connection = 'ovn_sb_connection'

        ovn_conf.register_opts()
        ovn_conf.cfg.CONF.set_default(
            'ovn_nb_connection',
            self.nb_connection,
            group='ovn')
        ovn_conf.cfg.CONF.set_default(
            'ovn_sb_connection',
            self.sb_connection,
            group='ovn')
        self.m_exec = mock.patch.object(processutils, 'execute').start()

    def assert_exec_call(self, expected):
        self.m_exec.assert_called_with(
            *shlex.split(expected), log_errors=processutils.LOG_FINAL_ERROR)

    def test_run_northbound(self):
        expected = ('ovsdb-client %s %s --timeout 180 '
                    '\'["OVN_Northbound", "foo"]\'' % (
                        self.OvsdbClientTestCommand.COMMAND,
                        self.nb_connection))
        self.OvsdbClientTestCommand.run(['OVN_Northbound', 'foo'])
        self.assert_exec_call(expected)

    def test_run_southbound(self):
        expected = ('ovsdb-client %s %s --timeout 180 '
                    '\'["OVN_Southbound", "foo"]\'' % (
                        self.OvsdbClientTestCommand.COMMAND,
                        self.sb_connection))
        self.OvsdbClientTestCommand.run(['OVN_Southbound', 'foo'])
        self.assert_exec_call(expected)

    def test_run_northbound_with_ssl(self):
        private_key = 'north_pk'
        certificate = 'north_cert'
        ca_auth = 'north_ca_auth'

        ovn_conf.cfg.CONF.set_default(
            'ovn_nb_private_key',
            private_key,
            group='ovn')
        ovn_conf.cfg.CONF.set_default(
            'ovn_nb_certificate',
            certificate,
            group='ovn')
        ovn_conf.cfg.CONF.set_default(
            'ovn_nb_ca_cert',
            ca_auth,
            group='ovn')

        expected = ('ovsdb-client %s %s --timeout 180 '
                    '-p %s '
                    '-c %s '
                    '-C %s '
                    '\'["OVN_Northbound", "foo"]\'' % (
                        self.OvsdbClientTestCommand.COMMAND,
                        self.nb_connection,
                        private_key,
                        certificate,
                        ca_auth))

        self.OvsdbClientTestCommand.run(['OVN_Northbound', 'foo'])
        self.assert_exec_call(expected)

    def test_run_southbound_with_ssl(self):
        private_key = 'north_pk'
        certificate = 'north_cert'
        ca_auth = 'north_ca_auth'

        ovn_conf.cfg.CONF.set_default(
            'ovn_sb_private_key',
            private_key,
            group='ovn')
        ovn_conf.cfg.CONF.set_default(
            'ovn_sb_certificate',
            certificate,
            group='ovn')
        ovn_conf.cfg.CONF.set_default(
            'ovn_sb_ca_cert',
            ca_auth,
            group='ovn')

        expected = ('ovsdb-client %s %s --timeout 180 '
                    '-p %s '
                    '-c %s '
                    '-C %s '
                    '\'["OVN_Southbound", "foo"]\'' % (
                        self.OvsdbClientTestCommand.COMMAND,
                        self.sb_connection,
                        private_key,
                        certificate,
                        ca_auth))

        self.OvsdbClientTestCommand.run(['OVN_Southbound', 'foo'])
        self.assert_exec_call(expected)

    def test_run_empty_list(self):
        with testtools.ExpectedException(KeyError):
            self.OvsdbClientTestCommand.run([])

    def test_run_bad_schema(self):
        with testtools.ExpectedException(KeyError):
            self.OvsdbClientTestCommand.run(['foo'])


class GetSubnetsAddressScopeTestCase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.ml2_plugin = mock.Mock()

    def test_no_subnets(self):
        subnets_by_id = []
        fixed_ips = mock.ANY
        address4, address6 = utils.get_subnets_address_scopes(
            mock.ANY, subnets_by_id, fixed_ips, self.ml2_plugin)
        self.assertEqual(('', ''), (address4, address6))

    def test_no_subnetpool(self):
        subnets_by_id = {
            'subnet_id1': {'name': 'subnet1', 'subnetpool_id': None},
            'subnet_id2': {'name': 'subnet2', 'subnetpool_id': None},
        }
        fixed_ips = [
            {'subnet_id': 'subnet_id1'},
            {'subnet_id': 'subnet_id2'},
        ]
        address4, address6 = utils.get_subnets_address_scopes(
            mock.ANY, subnets_by_id, fixed_ips, self.ml2_plugin)
        self.assertEqual(('', ''), (address4, address6))

    def test_no_address_scope(self):
        subnets_by_id = {
            'subnet_id1': {'name': 'subnet1', 'subnetpool_id': 'pool_ipv4'},
            'subnet_id2': {'name': 'subnet2', 'subnetpool_id': 'pool_ipv6'},
        }
        fixed_ips = [
            {'subnet_id': 'subnet_id1'},
            {'subnet_id': 'subnet_id2'},
        ]
        self.ml2_plugin.get_subnetpool.side_effect = n_exc.SubnetPoolNotFound(
            subnetpool_id='snp')
        address4, address6 = utils.get_subnets_address_scopes(
            mock.ANY, subnets_by_id, fixed_ips, self.ml2_plugin)
        self.assertEqual(('', ''), (address4, address6))

    def test_address_scope(self):
        subnets_by_id = {
            'subnet_id1': {'name': 'subnet1', 'subnetpool_id': 'pool_ipv4'},
            'subnet_id2': {'name': 'subnet2', 'subnetpool_id': 'pool_ipv6'},
        }
        fixed_ips = [
            {'subnet_id': 'subnet_id1'},
            {'subnet_id': 'subnet_id2'},
        ]
        self.ml2_plugin.get_subnetpool.side_effect = [
            {'address_scope_id': 'scope4', 'ip_version': n_const.IP_VERSION_4},
            {'address_scope_id': 'scope6', 'ip_version': n_const.IP_VERSION_6},
        ]
        address4, address6 = utils.get_subnets_address_scopes(
            mock.ANY, subnets_by_id, fixed_ips, self.ml2_plugin)
        self.assertEqual(('scope4', 'scope6'), (address4, address6))


class GetPortTypeVirtualAndParentsTestCase(base.BaseTestCase):

    def test_no_subnets(self):
        subnets_by_id = []
        fixed_ips = []
        port_type, virtual_ip, virtual_parents = (
            utils.get_port_type_virtual_and_parents(subnets_by_id, fixed_ips,
                                                    'net1', 'port1', mock.ANY))
        self.assertEqual(('', None, None),
                         (port_type, virtual_ip, virtual_parents))

    @mock.patch.object(utils, 'get_virtual_port_parents', return_value=[])
    def test_no_parents(self, *args):
        subnets_by_id = {
            'subnet_id1': {'name': 'subnet1'},
            'subnet_id2': {'name': 'subnet2'},
        }
        fixed_ips = [
            {'subnet_id': 'subnet_id1', 'ip_address': '1.2.3.4'},
            {'subnet_id': 'subnet_id2', 'ip_address': '1.2.3.5'},
        ]
        port_type, virtual_ip, virtual_parents = (
            utils.get_port_type_virtual_and_parents(subnets_by_id, fixed_ips,
                                                    'net1', 'port1', mock.ANY))
        self.assertEqual(('', None, None),
                         (port_type, virtual_ip, virtual_parents))

    @mock.patch.object(utils, 'get_virtual_port_parents',
                       return_value=['parent1', 'parent2'])
    def test_with_parents(self, *args):
        subnets_by_id = {
            'subnet_id1': {'name': 'subnet1'},
            'subnet_id2': {'name': 'subnet2'},
        }
        fixed_ips = [
            {'subnet_id': 'subnet_id1', 'ip_address': '1.2.3.4'},
            {'subnet_id': 'subnet_id2', 'ip_address': '1.2.3.5'},
        ]
        port_type, virtual_ip, virtual_parents = (
            utils.get_port_type_virtual_and_parents(subnets_by_id, fixed_ips,
                                                    'net1', 'port1', mock.ANY))
        self.assertEqual((constants.LSP_TYPE_VIRTUAL, '1.2.3.4',
                          'parent1,parent2'),
                         (port_type, virtual_ip, virtual_parents))


class DetermineBindHostTestCase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.mock_sb_idl = mock.Mock()
        self.get_chassis_by_card_serial_from_cms_options = (
            self.mock_sb_idl.get_chassis_by_card_serial_from_cms_options)
        self.fake_smartnic_hostname = 'fake-chassis-hostname'
        self.get_chassis_by_card_serial_from_cms_options.return_value = (
            fakes.FakeChassis.create(
                attrs={'hostname': self.fake_smartnic_hostname}))

    def test_vnic_normal_unbound_port(self):
        self.assertEqual(
            '',
            utils.determine_bind_host(self.mock_sb_idl, {}))

    def test_vnic_normal_bound_port(self):
        port = {
            portbindings.HOST_ID: 'fake-binding-host-id',
        }
        self.assertEqual(
            'fake-binding-host-id',
            utils.determine_bind_host(self.mock_sb_idl, port))

    def test_vnic_normal_port_context(self):
        context = mock.MagicMock()
        context.host = 'fake-binding-host-id'
        self.assertEqual(
            'fake-binding-host-id',
            utils.determine_bind_host(self.mock_sb_idl, {},
                                      port_context=context))

    def test_vnic_remote_managed_unbound_port_no_binding_profile(self):
        port = {
            portbindings.VNIC_TYPE: portbindings.VNIC_REMOTE_MANAGED,
            constants.OVN_PORT_BINDING_PROFILE: {},
        }
        self.assertEqual(
            '',
            utils.determine_bind_host(self.mock_sb_idl, port))

    def test_vnic_remote_managed_unbound_port(self):
        port = {
            portbindings.VNIC_TYPE: portbindings.VNIC_REMOTE_MANAGED,
            constants.OVN_PORT_BINDING_PROFILE: {
                constants.VIF_DETAILS_PCI_VENDOR_INFO: 'fake-pci-vendor-info',
                constants.VIF_DETAILS_PCI_SLOT: 'fake-pci-slot',
                constants.VIF_DETAILS_PHYSICAL_NETWORK: None,
                constants.VIF_DETAILS_CARD_SERIAL_NUMBER: 'fake-serial',
                constants.VIF_DETAILS_PF_MAC_ADDRESS: 'fake-pf-mac',
                constants.VIF_DETAILS_VF_NUM: 42,
            },
        }
        self.assertEqual(
            self.fake_smartnic_hostname,
            utils.determine_bind_host(self.mock_sb_idl, port))

    def test_vnic_remote_managed_bound_port(self):
        port = {
            portbindings.VNIC_TYPE: portbindings.VNIC_REMOTE_MANAGED,
            portbindings.HOST_ID: 'fake-binding-host-id',
            constants.OVN_PORT_BINDING_PROFILE: {
                constants.VIF_DETAILS_PCI_VENDOR_INFO: 'fake-pci-vendor-info',
                constants.VIF_DETAILS_PCI_SLOT: 'fake-pci-slot',
                constants.VIF_DETAILS_PHYSICAL_NETWORK: None,
                constants.VIF_DETAILS_CARD_SERIAL_NUMBER: 'fake-serial',
                constants.VIF_DETAILS_PF_MAC_ADDRESS: 'fake-pf-mac',
                constants.VIF_DETAILS_VF_NUM: 42,
            },
        }
        self.assertEqual(
            self.fake_smartnic_hostname,
            utils.determine_bind_host(self.mock_sb_idl, port))

    def test_vnic_remote_managed_port_context(self):
        context = mock.MagicMock()
        context.current = {
            portbindings.VNIC_TYPE: portbindings.VNIC_REMOTE_MANAGED,
            constants.OVN_PORT_BINDING_PROFILE: {
                constants.VIF_DETAILS_PCI_VENDOR_INFO: 'fake-pci-vendor-info',
                constants.VIF_DETAILS_PCI_SLOT: 'fake-pci-slot',
                constants.VIF_DETAILS_PHYSICAL_NETWORK: None,
                constants.VIF_DETAILS_CARD_SERIAL_NUMBER: 'fake-serial',
                constants.VIF_DETAILS_PF_MAC_ADDRESS: 'fake-pf-mac',
                constants.VIF_DETAILS_VF_NUM: 42,
            },
        }
        context.host = 'fake-binding-host-id'
        self.assertEqual(
            self.fake_smartnic_hostname,
            utils.determine_bind_host(self.mock_sb_idl, {},
                                      port_context=context))


class ValidatePortForwardingConfigurationTestCase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        ovn_conf.register_opts()

    def test_validation_when_distributed_fip_disabled(self):
        cfg.CONF.set_override(
            'enable_distributed_floating_ip', False, group='ovn')
        cfg.CONF.set_override('service_plugins', 'some_plugin,port_forwarding')
        cfg.CONF.set_override('tenant_network_types', 'geneve,vlan',
                              group='ml2')
        utils.validate_port_forwarding_configuration()

    def test_validation_when_no_pf_plugin_enabled(self):
        cfg.CONF.set_override(
            'enable_distributed_floating_ip', True, group='ovn')
        cfg.CONF.set_override('service_plugins', 'some_plugin')
        cfg.CONF.set_override('tenant_network_types', 'geneve,vlan',
                              group='ml2')
        utils.validate_port_forwarding_configuration()

    def test_validation_when_no_provider_net_configured(self):
        cfg.CONF.set_override(
            'enable_distributed_floating_ip', True, group='ovn')
        cfg.CONF.set_override('service_plugins', 'some_plugin,port_forwarding')
        cfg.CONF.set_override('tenant_network_types', 'geneve,vxlan',
                              group='ml2')
        utils.validate_port_forwarding_configuration()

    def test_validation_when_pf_and_provider_net_enabled(self):
        cfg.CONF.set_override(
            'enable_distributed_floating_ip', True, group='ovn')
        cfg.CONF.set_override('service_plugins', 'some_plugin,port_forwarding')
        cfg.CONF.set_override('tenant_network_types', 'geneve,vlan',
                              group='ml2')
        self.assertRaises(
            ovn_exc.InvalidPortForwardingConfiguration,
            utils.validate_port_forwarding_configuration)
