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
from unittest import mock

import fixtures
from neutron_lib.api.definitions import extra_dhcp_opt as edo_ext

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


class TestUtils(base.BaseTestCase):

    def test_get_system_dns_resolvers(self):
        tempdir = self.useFixture(fixtures.TempDir()).path
        resolver_file_name = tempdir + '/resolv.conf'
        tmp_resolv_file = open(resolver_file_name, 'w')
        tmp_resolv_file.writelines(RESOLV_CONF_TEMPLATE)
        tmp_resolv_file.close()
        expected_dns_resolvers = ['10.0.0.1', '10.0.0.3']
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
        self.assertEqual([], utils.get_chassis_availability_zones(chassis))

    def test_get_chassis_availability_zones_one_az(self):
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'external_ids': {'ovn-cms-options':
                             'enable-chassis-as-gw,availability-zones=az0'}})
        self.assertEqual(
            ['az0'], utils.get_chassis_availability_zones(chassis))

    def test_get_chassis_availability_zones_multiple_az(self):
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'external_ids': {
                'ovn-cms-options':
                'enable-chassis-as-gw,availability-zones=az0:az1 :az2:: :'}})
        self.assertEqual(
            ['az0', 'az1', 'az2'],
            utils.get_chassis_availability_zones(chassis))

    def test_get_chassis_availability_zones_malformed(self):
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'external_ids': {'ovn-cms-options':
                             'enable-chassis-as-gw,availability-zones:az0'}})
        self.assertEqual(
            [], utils.get_chassis_availability_zones(chassis))

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
