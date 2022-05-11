# Copyright 2020 Red Hat, Inc.
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

import copy

import netaddr
from neutron_lib.api.definitions import dns as dns_apidef
from neutron_lib.utils import net as n_net
from oslo_config import cfg
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.common import utils as n_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf as ovn_config
from neutron.tests.functional import base


class TestNBDbResources(base.TestOVNFunctionalBase):
    _extension_drivers = ['dns']

    def _is_nb_global_ready(self):
        try:
            next(iter(self.nb_api.tables['NB_Global'].rows))
        except StopIteration:
            return False
        return True

    def setUp(self):
        super(TestNBDbResources, self).setUp()
        self.orig_get_random_mac = n_net.get_random_mac
        cfg.CONF.set_override('quota_subnet', -1, group='QUOTAS')
        ovn_config.cfg.CONF.set_override('ovn_metadata_enabled',
                                         False,
                                         group='ovn')
        ovn_config.cfg.CONF.set_override('dns_domain', 'ovn.test')

        # Wait for NB_Global table, for details see: LP #1956965
        n_utils.wait_until_true(
            self._is_nb_global_ready,
            timeout=15, sleep=1
        )

    # FIXME(lucasagomes): Map the revision numbers properly instead
    # of stripping them out. Currently, tests like test_dhcp_options()
    # are quite complex making it difficult to map the exact the revision
    # number that the DHCP Option will be at assertion time, we need to
    # refactor it a little to make it easier for mapping these updates.
    def _strip_revision_number(self, ext_ids):
        ext_ids.pop(ovn_const.OVN_REV_NUM_EXT_ID_KEY, None)
        return ext_ids

    def _verify_dhcp_option_rows(self, expected_dhcp_options_rows):
        expected_dhcp_options_rows = list(expected_dhcp_options_rows.values())
        observed_dhcp_options_rows = []
        for row in self.nb_api.tables['DHCP_Options'].rows.values():
            ext_ids = self._strip_revision_number(row.external_ids)
            observed_dhcp_options_rows.append({
                'cidr': row.cidr, 'external_ids': ext_ids,
                'options': row.options})

        self.assertCountEqual(expected_dhcp_options_rows,
                              observed_dhcp_options_rows)

    def _verify_dhcp_option_row_for_port(self, port_id,
                                         expected_lsp_dhcpv4_options,
                                         expected_lsp_dhcpv6_options=None):
        lsp = idlutils.row_by_value(self.nb_api.idl,
                                    'Logical_Switch_Port', 'name', port_id,
                                    None)

        if lsp.dhcpv4_options:
            ext_ids = self._strip_revision_number(
                lsp.dhcpv4_options[0].external_ids)
            observed_lsp_dhcpv4_options = {
                'cidr': lsp.dhcpv4_options[0].cidr,
                'external_ids': ext_ids,
                'options': lsp.dhcpv4_options[0].options}
        else:
            observed_lsp_dhcpv4_options = {}

        if lsp.dhcpv6_options:
            ext_ids = self._strip_revision_number(
                lsp.dhcpv6_options[0].external_ids)
            observed_lsp_dhcpv6_options = {
                'cidr': lsp.dhcpv6_options[0].cidr,
                'external_ids': ext_ids,
                'options': lsp.dhcpv6_options[0].options}
        else:
            observed_lsp_dhcpv6_options = {}

        if expected_lsp_dhcpv6_options is None:
            expected_lsp_dhcpv6_options = {}

        self.assertEqual(expected_lsp_dhcpv4_options,
                         observed_lsp_dhcpv4_options)
        self.assertEqual(expected_lsp_dhcpv6_options,
                         observed_lsp_dhcpv6_options)

    def _get_subnet_dhcp_mac(self, subnet):
        mac_key = 'server_id' if subnet['ip_version'] == 6 else 'server_mac'
        dhcp_options = self.mech_driver.nb_ovn.get_subnet_dhcp_options(
            subnet['id'])['subnet']
        return dhcp_options.get('options', {}).get(
            mac_key) if dhcp_options else None

    def test_dhcp_options(self):
        """Test for DHCP_Options table rows

        When a new subnet is created, a new row has to be created in the
        DHCP_Options table for this subnet with the dhcp options stored
        in the DHCP_Options.options column.
        When ports are created for this subnet (with IPv4 address set and
        DHCP enabled in the subnet), the
        Logical_Switch_Port.dhcpv4_options column should refer to the
        appropriate row of DHCP_Options.

        In cases where a port has extra DHCPv4 options defined, a new row
        in the DHCP_Options table should be created for this port and
        Logical_Switch_Port.dhcpv4_options colimn should refer to this row.

        In order to map the DHCP_Options row to the subnet (and to a port),
        subnet_id is stored in DHCP_Options.external_ids column.
        For DHCP_Options row which belongs to a port, port_id is also stored
        in the DHCP_Options.external_ids along with the subnet_id.
        """

        n1 = self._make_network(self.fmt, 'n1', True)
        created_subnets = {}
        expected_dhcp_options_rows = {}
        dhcp_mac = {}

        for cidr in ['10.0.0.0/24', '20.0.0.0/24', '30.0.0.0/24',
                     '40.0.0.0/24', 'aef0::/64', 'bef0::/64']:
            ip_version = netaddr.IPNetwork(cidr).ip.version

            res = self._create_subnet(self.fmt, n1['network']['id'], cidr,
                                      ip_version=ip_version)
            subnet = self.deserialize(self.fmt, res)['subnet']
            created_subnets[cidr] = subnet
            dhcp_mac[subnet['id']] = self._get_subnet_dhcp_mac(subnet)

            if ip_version == 4:
                options = {'server_id': cidr.replace('0/24', '1'),
                           'server_mac': dhcp_mac[subnet['id']],
                           'lease_time': str(12 * 60 * 60),
                           'domain_name': '"%s"' % cfg.CONF.dns_domain,
                           'dns_server': '{10.10.10.10}',
                           'mtu': str(n1['network']['mtu']),
                           'router': subnet['gateway_ip']}
            else:
                options = {'server_id': dhcp_mac[subnet['id']]}

            expected_dhcp_options_rows[subnet['id']] = {
                'cidr': cidr,
                'external_ids': {'subnet_id': subnet['id']},
                'options': options}

        for (cidr, enable_dhcp, gateway_ip) in [
                ('50.0.0.0/24', False, '50.0.0.1'),
                ('60.0.0.0/24', True, None),
                ('cef0::/64', False, 'cef0::1'),
                ('def0::/64', True, None)]:
            ip_version = netaddr.IPNetwork(cidr).ip.version
            res = self._create_subnet(self.fmt, n1['network']['id'], cidr,
                                      ip_version=ip_version,
                                      enable_dhcp=enable_dhcp,
                                      gateway_ip=gateway_ip)
            subnet = self.deserialize(self.fmt, res)['subnet']
            created_subnets[cidr] = subnet
            dhcp_mac[subnet['id']] = self._get_subnet_dhcp_mac(subnet)
            if enable_dhcp:
                if ip_version == 4:
                    options = {}
                else:
                    options = {'server_id': dhcp_mac[subnet['id']]}
                expected_dhcp_options_rows[subnet['id']] = {
                    'cidr': cidr,
                    'external_ids': {'subnet_id': subnet['id']},
                    'options': options}

        # create a subnet with dns nameservers and host routes
        n2 = self._make_network(self.fmt, 'n2', True)
        res = self._create_subnet(
            self.fmt, n2['network']['id'], '10.0.0.0/24',
            dns_nameservers=['7.7.7.7', '8.8.8.8'],
            host_routes=[{'destination': '30.0.0.0/24',
                          'nexthop': '10.0.0.4'},
                         {'destination': '40.0.0.0/24',
                          'nexthop': '10.0.0.8'}])

        subnet = self.deserialize(self.fmt, res)['subnet']
        dhcp_mac[subnet['id']] = self._get_subnet_dhcp_mac(subnet)

        static_routes = ('{30.0.0.0/24,10.0.0.4, 40.0.0.0/24,'
                         '10.0.0.8, 0.0.0.0/0,10.0.0.1}')
        expected_dhcp_options_rows[subnet['id']] = {
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': subnet['id']},
            'options': {'server_id': '10.0.0.1',
                        'server_mac': dhcp_mac[subnet['id']],
                        'lease_time': str(12 * 60 * 60),
                        'mtu': str(n2['network']['mtu']),
                        'router': subnet['gateway_ip'],
                        'domain_name': '"%s"' % cfg.CONF.dns_domain,
                        'dns_server': '{7.7.7.7, 8.8.8.8}',
                        'classless_static_route': static_routes}}

        # create an IPv6 subnet with dns nameservers
        res = self._create_subnet(
            self.fmt, n2['network']['id'], 'ae10::/64', ip_version=6,
            dns_nameservers=['be10::7', 'be10::8'])

        subnet = self.deserialize(self.fmt, res)['subnet']
        dhcp_mac[subnet['id']] = self._get_subnet_dhcp_mac(subnet)

        expected_dhcp_options_rows[subnet['id']] = {
            'cidr': 'ae10::/64',
            'external_ids': {'subnet_id': subnet['id']},
            'options': {'server_id': dhcp_mac[subnet['id']],
                        'dns_server': '{be10::7, be10::8}'}}

        # Verify that DHCP_Options rows are created for these subnets or not
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

        for cidr in ['20.0.0.0/24', 'aef0::/64']:
            subnet = created_subnets[cidr]
            # Disable dhcp in subnet and verify DHCP_Options
            data = {'subnet': {'enable_dhcp': False}}
            req = self.new_update_request('subnets', data, subnet['id'])
            req.get_response(self.api)
            options = expected_dhcp_options_rows.pop(subnet['id'])
            self._verify_dhcp_option_rows(expected_dhcp_options_rows)

            # Re-enable dhcp in subnet and verify DHCP_Options
            n_net.get_random_mac = mock.Mock()
            n_net.get_random_mac.return_value = dhcp_mac[subnet['id']]
            data = {'subnet': {'enable_dhcp': True}}
            req = self.new_update_request('subnets', data, subnet['id'])
            req.get_response(self.api)
            expected_dhcp_options_rows[subnet['id']] = options
            self._verify_dhcp_option_rows(expected_dhcp_options_rows)

        n_net.get_random_mac = self.orig_get_random_mac

        # Create a port and verify if Logical_Switch_Port.dhcpv4_options
        # is properly set or not
        subnet = created_subnets['40.0.0.0/24']
        subnet_v6 = created_subnets['aef0::/64']
        p = self._make_port(
            self.fmt, n1['network']['id'],
            fixed_ips=[
                {'subnet_id': subnet['id']},
                {'subnet_id': subnet_v6['id']}])

        self._verify_dhcp_option_row_for_port(
            p['port']['id'], expected_dhcp_options_rows[subnet['id']],
            expected_dhcp_options_rows[subnet_v6['id']])
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

        # create a port with dhcp disabled subnet
        subnet = created_subnets['50.0.0.0/24']

        p = self._make_port(self.fmt, n1['network']['id'],
                            fixed_ips=[{'subnet_id': subnet['id']}])

        self._verify_dhcp_option_row_for_port(p['port']['id'], {})
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

        # Delete the first subnet created
        subnet = created_subnets['10.0.0.0/24']
        req = self.new_delete_request('subnets', subnet['id'])
        req.get_response(self.api)

        # Verify that DHCP_Options rows are deleted or not
        del expected_dhcp_options_rows[subnet['id']]
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

    def test_port_dhcp_options(self):
        dhcp_mac = {}
        n1 = self._make_network(self.fmt, 'n1', True)
        res = self._create_subnet(self.fmt, n1['network']['id'], '10.0.0.0/24')
        subnet = self.deserialize(self.fmt, res)['subnet']
        dhcp_mac[subnet['id']] = self._get_subnet_dhcp_mac(subnet)
        res = self._create_subnet(self.fmt, n1['network']['id'], 'aef0::/64',
                                  ip_version=6)
        subnet_v6 = self.deserialize(self.fmt, res)['subnet']
        dhcp_mac[subnet_v6['id']] = self._get_subnet_dhcp_mac(subnet_v6)

        expected_dhcp_options_rows = {
            subnet['id']: {
                'cidr': '10.0.0.0/24',
                'external_ids': {'subnet_id': subnet['id']},
                'options': {'server_id': '10.0.0.1',
                            'server_mac': dhcp_mac[subnet['id']],
                            'lease_time': str(12 * 60 * 60),
                            'domain_name': '"%s"' % cfg.CONF.dns_domain,
                            'dns_server': '{10.10.10.10}',
                            'mtu': str(n1['network']['mtu']),
                            'router': subnet['gateway_ip']}},
            subnet_v6['id']: {
                'cidr': 'aef0::/64',
                'external_ids': {'subnet_id': subnet_v6['id']},
                'options': {'server_id': dhcp_mac[subnet_v6['id']]}}}
        expected_dhcp_v4_options_rows = {
            subnet['id']: expected_dhcp_options_rows[subnet['id']]}
        expected_dhcp_v6_options_rows = {
            subnet_v6['id']: expected_dhcp_options_rows[subnet_v6['id']]}
        data = {
            'port': {'network_id': n1['network']['id'],
                     'tenant_id': self._tenant_id,
                     'device_owner': 'compute:None',
                     'fixed_ips': [{'subnet_id': subnet['id']}],
                     'extra_dhcp_opts': [{'ip_version': 4, 'opt_name': 'mtu',
                                          'opt_value': '1100'},
                                         {'ip_version': 4,
                                          'opt_name': 'ntp-server',
                                          'opt_value': '8.8.8.8'}]}}
        port_req = self.new_create_request('ports', data, self.fmt)
        port_res = port_req.get_response(self.api)
        p1 = self.deserialize(self.fmt, port_res)

        expected_dhcp_options_rows['v4-' + p1['port']['id']] = {
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': subnet['id'],
                             'port_id': p1['port']['id']},
            'options': {'server_id': '10.0.0.1',
                        'server_mac': dhcp_mac[subnet['id']],
                        'lease_time': str(12 * 60 * 60),
                        'domain_name': '"%s"' % cfg.CONF.dns_domain,
                        'dns_server': '{10.10.10.10}',
                        'mtu': '1100',
                        'router': subnet['gateway_ip'],
                        'ntp_server': '8.8.8.8'}}
        expected_dhcp_v4_options_rows['v4-' + p1['port']['id']] = \
            expected_dhcp_options_rows['v4-' + p1['port']['id']]
        data = {
            'port': {'network_id': n1['network']['id'],
                     'tenant_id': self._tenant_id,
                     'device_owner': 'compute:None',
                     'fixed_ips': [{'subnet_id': subnet['id']}],
                     'extra_dhcp_opts': [{'ip_version': 4,
                                          'opt_name': 'ip-forward-enable',
                                          'opt_value': '1'},
                                         {'ip_version': 4,
                                          'opt_name': 'tftp-server',
                                          'opt_value': '10.0.0.100'},
                                         {'ip_version': 4,
                                          'opt_name': 'dns-server',
                                          'opt_value': '20.20.20.20'}]}}

        port_req = self.new_create_request('ports', data, self.fmt)
        port_res = port_req.get_response(self.api)
        p2 = self.deserialize(self.fmt, port_res)

        expected_dhcp_options_rows['v4-' + p2['port']['id']] = {
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': subnet['id'],
                             'port_id': p2['port']['id']},
            'options': {'server_id': '10.0.0.1',
                        'server_mac': dhcp_mac[subnet['id']],
                        'lease_time': str(12 * 60 * 60),
                        'mtu': str(n1['network']['mtu']),
                        'router': subnet['gateway_ip'],
                        'ip_forward_enable': '1',
                        'tftp_server': '"10.0.0.100"',
                        'domain_name': '"%s"' % cfg.CONF.dns_domain,
                        'dns_server': '20.20.20.20'}}
        expected_dhcp_v4_options_rows['v4-' + p2['port']['id']] = \
            expected_dhcp_options_rows['v4-' + p2['port']['id']]
        data = {
            'port': {'network_id': n1['network']['id'],
                     'tenant_id': self._tenant_id,
                     'device_owner': 'compute:None',
                     'fixed_ips': [{'subnet_id': subnet_v6['id']}],
                     'extra_dhcp_opts': [{'ip_version': 6,
                                          'opt_name': 'dns-server',
                                          'opt_value': 'aef0::1'},
                                         {'ip_version': 6,
                                          'opt_name': 'domain-search',
                                          'opt_value': 'foo-domain'}]}}
        port_req = self.new_create_request('ports', data, self.fmt)
        port_res = port_req.get_response(self.api)
        p3 = self.deserialize(self.fmt, port_res)
        expected_dhcp_options_rows['v6-' + p3['port']['id']] = {
            'cidr': 'aef0::/64',
            'external_ids': {'subnet_id': subnet_v6['id'],
                             'port_id': p3['port']['id']},
            'options': {'server_id': dhcp_mac[subnet_v6['id']],
                        'dns_server': 'aef0::1',
                        'domain_search': 'foo-domain'}}
        expected_dhcp_v6_options_rows['v6-' + p3['port']['id']] = \
            expected_dhcp_options_rows['v6-' + p3['port']['id']]
        data = {
            'port': {'network_id': n1['network']['id'],
                     'tenant_id': self._tenant_id,
                     'device_owner': 'compute:None',
                     'fixed_ips': [{'subnet_id': subnet['id']},
                                   {'subnet_id': subnet_v6['id']}],
                     'extra_dhcp_opts': [{'ip_version': 4,
                                          'opt_name': 'tftp-server',
                                          'opt_value': '100.0.0.100'},
                                         {'ip_version': 6,
                                          'opt_name': 'dns-server',
                                          'opt_value': 'aef0::100'},
                                         {'ip_version': 6,
                                          'opt_name': 'domain-search',
                                          'opt_value': 'bar-domain'}]}}
        port_req = self.new_create_request('ports', data, self.fmt)
        port_res = port_req.get_response(self.api)
        p4 = self.deserialize(self.fmt, port_res)
        expected_dhcp_options_rows['v6-' + p4['port']['id']] = {
            'cidr': 'aef0::/64',
            'external_ids': {'subnet_id': subnet_v6['id'],
                             'port_id': p4['port']['id']},
            'options': {'server_id': dhcp_mac[subnet_v6['id']],
                        'dns_server': 'aef0::100',
                        'domain_search': 'bar-domain'}}
        expected_dhcp_options_rows['v4-' + p4['port']['id']] = {
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': subnet['id'],
                             'port_id': p4['port']['id']},
            'options': {'server_id': '10.0.0.1',
                        'server_mac': dhcp_mac[subnet['id']],
                        'lease_time': str(12 * 60 * 60),
                        'domain_name': '"%s"' % cfg.CONF.dns_domain,
                        'dns_server': '{10.10.10.10}',
                        'mtu': str(n1['network']['mtu']),
                        'router': subnet['gateway_ip'],
                        'tftp_server': '"100.0.0.100"'}}
        expected_dhcp_v4_options_rows['v4-' + p4['port']['id']] = \
            expected_dhcp_options_rows['v4-' + p4['port']['id']]
        expected_dhcp_v6_options_rows['v6-' + p4['port']['id']] = \
            expected_dhcp_options_rows['v6-' + p4['port']['id']]

        # test port without extra_dhcp_opts but using subnet DHCP options
        data = {
            'port': {'network_id': n1['network']['id'],
                     'tenant_id': self._tenant_id,
                     'device_owner': 'compute:None',
                     'fixed_ips': [{'subnet_id': subnet['id']},
                                   {'subnet_id': subnet_v6['id']}]}}
        port_req = self.new_create_request('ports', data, self.fmt)
        port_res = port_req.get_response(self.api)
        p5 = self.deserialize(self.fmt, port_res)

        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

        self._verify_dhcp_option_row_for_port(
            p1['port']['id'],
            expected_dhcp_options_rows['v4-' + p1['port']['id']])
        self._verify_dhcp_option_row_for_port(
            p2['port']['id'],
            expected_dhcp_options_rows['v4-' + p2['port']['id']])
        self._verify_dhcp_option_row_for_port(
            p3['port']['id'], {},
            expected_lsp_dhcpv6_options=expected_dhcp_options_rows[
                'v6-' + p3['port']['id']])
        self._verify_dhcp_option_row_for_port(
            p4['port']['id'],
            expected_dhcp_options_rows['v4-' + p4['port']['id']],
            expected_lsp_dhcpv6_options=expected_dhcp_options_rows[
                'v6-' + p4['port']['id']])
        self._verify_dhcp_option_row_for_port(
            p5['port']['id'],
            expected_dhcp_options_rows[subnet['id']],
            expected_lsp_dhcpv6_options=expected_dhcp_options_rows[
                subnet_v6['id']])

        # Update the subnet with dns_server. It should get propagated
        # to the DHCP options of the p1. Note that it should not get
        # propagate to DHCP options of port p2 because, it has overridden
        # dns-server in the Extra DHCP options.
        data = {'subnet': {'dns_nameservers': ['7.7.7.7', '8.8.8.8']}}
        req = self.new_update_request('subnets', data, subnet['id'])
        req.get_response(self.api)

        for i in [subnet['id'], 'v4-' + p1['port']['id'],
                  'v4-' + p4['port']['id']]:
            expected_dhcp_options_rows[i]['options']['dns_server'] = (
                '{7.7.7.7, 8.8.8.8}')

        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

        # Update the port p2 by removing dns-server and tfp-server in the
        # extra DHCP options. dns-server option from the subnet DHCP options
        # should be updated in the p2 DHCP options
        data = {'port': {'extra_dhcp_opts': [{'ip_version': 4,
                                              'opt_name': 'ip-forward-enable',
                                              'opt_value': '0'},
                                             {'ip_version': 4,
                                              'opt_name': 'tftp-server',
                                              'opt_value': None},
                                             {'ip_version': 4,
                                              'opt_name': 'dns-server',
                                              'opt_value': None}]}}
        port_req = self.new_update_request('ports', data, p2['port']['id'])
        port_req.get_response(self.api)
        p2_expected = expected_dhcp_options_rows['v4-' + p2['port']['id']]
        p2_expected['options']['dns_server'] = '{7.7.7.7, 8.8.8.8}'

        p2_expected['options']['ip_forward_enable'] = '0'

        del p2_expected['options']['tftp_server']
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

        # Test subnet DHCP disabling and enabling
        for (subnet_id, expect_subnet_rows_disabled, expect_port_row_disabled
             ) in [
            (subnet['id'], expected_dhcp_v6_options_rows,
             [(p4, {}, expected_dhcp_options_rows['v6-' + p4['port']['id']]),
              (p5, {}, expected_dhcp_options_rows[subnet_v6['id']])]),
            (subnet_v6['id'], expected_dhcp_v4_options_rows,
             [(p4, expected_dhcp_options_rows['v4-' + p4['port']['id']], {}),
              (p5, expected_dhcp_options_rows[subnet['id']], {})])]:
            # Disable subnet's DHCP and verify DHCP_Options,
            data = {'subnet': {'enable_dhcp': False}}
            req = self.new_update_request('subnets', data, subnet_id)
            req.get_response(self.api)
            # DHCP_Options belonging to the subnet or it's ports should be all
            # removed, current DHCP_Options should be equal to
            # expect_subnet_rows_disabled
            self._verify_dhcp_option_rows(expect_subnet_rows_disabled)
            # Verify that the corresponding port DHCP options were cleared
            # and the others were not affected.
            for p in expect_port_row_disabled:
                self._verify_dhcp_option_row_for_port(
                    p[0]['port']['id'], p[1], p[2])
            # Re-enable dhcpv4 in subnet and verify DHCP_Options
            n_net.get_random_mac = mock.Mock()
            n_net.get_random_mac.return_value = dhcp_mac[subnet_id]
            data = {'subnet': {'enable_dhcp': True}}
            req = self.new_update_request('subnets', data, subnet_id)
            req.get_response(self.api)
            self._verify_dhcp_option_rows(expected_dhcp_options_rows)
            self._verify_dhcp_option_row_for_port(
                p4['port']['id'],
                expected_dhcp_options_rows['v4-' + p4['port']['id']],
                expected_dhcp_options_rows['v6-' + p4['port']['id']])
            self._verify_dhcp_option_row_for_port(
                p5['port']['id'],
                expected_dhcp_options_rows[subnet['id']],
                expected_lsp_dhcpv6_options=expected_dhcp_options_rows[
                    subnet_v6['id']])
        n_net.get_random_mac = self.orig_get_random_mac

        # Disable dhcp in p2
        data = {'port': {'extra_dhcp_opts': [{'ip_version': 4,
                                              'opt_name': 'dhcp_disabled',
                                              'opt_value': 'true'}]}}
        port_req = self.new_update_request('ports', data, p2['port']['id'])
        port_req.get_response(self.api)

        del expected_dhcp_options_rows['v4-' + p2['port']['id']]
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

        # delete port p1.
        port_req = self.new_delete_request('ports', p1['port']['id'])
        port_req.get_response(self.api)

        del expected_dhcp_options_rows['v4-' + p1['port']['id']]
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

        # delete the IPv6 extra DHCP options for p4
        data = {'port': {'extra_dhcp_opts': [{'ip_version': 6,
                                              'opt_name': 'dns-server',
                                              'opt_value': None},
                                             {'ip_version': 6,
                                              'opt_name': 'domain-search',
                                              'opt_value': None}]}}
        port_req = self.new_update_request('ports', data, p4['port']['id'])
        port_req.get_response(self.api)
        del expected_dhcp_options_rows['v6-' + p4['port']['id']]

        self._verify_dhcp_option_rows(expected_dhcp_options_rows)

    def test_port_dhcp_opts_add_and_remove_extra_dhcp_opts(self):
        """Orphaned DHCP_Options row.

        In this test case a port is created with extra DHCP options.
        Since it has extra DHCP options a new row in the DHCP_Options is
        created for this port.
        Next the port is updated to delete the extra DHCP options.
        After the update, the Logical_Switch_Port.dhcpv4_options for this port
        should refer to the subnet DHCP_Options and the DHCP_Options row
        created for this port earlier should be deleted.
        """
        dhcp_mac = {}
        n1 = self._make_network(self.fmt, 'n1', True)
        res = self._create_subnet(self.fmt, n1['network']['id'], '10.0.0.0/24')
        subnet = self.deserialize(self.fmt, res)['subnet']
        dhcp_mac[subnet['id']] = self._get_subnet_dhcp_mac(subnet)
        res = self._create_subnet(self.fmt, n1['network']['id'], 'aef0::/64',
                                  ip_version=6)
        subnet_v6 = self.deserialize(self.fmt, res)['subnet']
        dhcp_mac[subnet_v6['id']] = self._get_subnet_dhcp_mac(subnet_v6)
        expected_dhcp_options_rows = {
            subnet['id']: {
                'cidr': '10.0.0.0/24',
                'external_ids': {'subnet_id': subnet['id']},
                'options': {'server_id': '10.0.0.1',
                            'server_mac': dhcp_mac[subnet['id']],
                            'lease_time': str(12 * 60 * 60),
                            'domain_name': '"%s"' % cfg.CONF.dns_domain,
                            'dns_server': '{10.10.10.10}',
                            'mtu': str(n1['network']['mtu']),
                            'router': subnet['gateway_ip']}},
            subnet_v6['id']: {
                'cidr': 'aef0::/64',
                'external_ids': {'subnet_id': subnet_v6['id']},
                'options': {'server_id': dhcp_mac[subnet_v6['id']]}}}

        data = {
            'port': {'network_id': n1['network']['id'],
                     'tenant_id': self._tenant_id,
                     'device_owner': 'compute:None',
                     'extra_dhcp_opts': [{'ip_version': 4, 'opt_name': 'mtu',
                                          'opt_value': '1100'},
                                         {'ip_version': 4,
                                          'opt_name': 'ntp-server',
                                          'opt_value': '8.8.8.8'},
                                         {'ip_version': 6,
                                          'opt_name': 'dns-server',
                                          'opt_value': 'aef0::100'}]}}
        port_req = self.new_create_request('ports', data, self.fmt)
        port_res = port_req.get_response(self.api)
        p1 = self.deserialize(self.fmt, port_res)['port']

        expected_dhcp_options_rows['v4-' + p1['id']] = {
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': subnet['id'],
                             'port_id': p1['id']},
            'options': {'server_id': '10.0.0.1',
                        'server_mac': dhcp_mac[subnet['id']],
                        'lease_time': str(12 * 60 * 60),
                        'domain_name': '"%s"' % cfg.CONF.dns_domain,
                        'dns_server': '{10.10.10.10}',
                        'mtu': '1100',
                        'router': subnet['gateway_ip'],
                        'ntp_server': '8.8.8.8'}}

        expected_dhcp_options_rows['v6-' + p1['id']] = {
            'cidr': 'aef0::/64',
            'external_ids': {'subnet_id': subnet_v6['id'],
                             'port_id': p1['id']},
            'options': {'server_id': dhcp_mac[subnet_v6['id']],
                        'dns_server': 'aef0::100'}}

        self._verify_dhcp_option_rows(expected_dhcp_options_rows)
        # The Logical_Switch_Port.dhcp(v4/v6)_options should refer to the
        # port DHCP options.
        self._verify_dhcp_option_row_for_port(
            p1['id'], expected_dhcp_options_rows['v4-' + p1['id']],
            expected_dhcp_options_rows['v6-' + p1['id']])

        # Now update the port to delete the extra DHCP options
        data = {'port': {'extra_dhcp_opts': [{'ip_version': 4,
                                              'opt_name': 'mtu',
                                              'opt_value': None},
                                             {'ip_version': 4,
                                              'opt_name': 'ntp-server',
                                              'opt_value': None}]}}
        port_req = self.new_update_request('ports', data, p1['id'])
        port_req.get_response(self.api)

        # DHCP_Options row created for the port earlier should have been
        # deleted.
        del expected_dhcp_options_rows['v4-' + p1['id']]
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)
        # The Logical_Switch_Port.dhcpv4_options for this port should refer to
        # the subnet DHCP options.
        self._verify_dhcp_option_row_for_port(
            p1['id'], expected_dhcp_options_rows[subnet['id']],
            expected_dhcp_options_rows['v6-' + p1['id']])

        # update the port again with extra DHCP options.
        data = {'port': {'extra_dhcp_opts': [{'ip_version': 4,
                                              'opt_name': 'mtu',
                                              'opt_value': '1200'},
                                             {'ip_version': 4,
                                              'opt_name': 'tftp-server',
                                              'opt_value': '8.8.8.8'}]}}

        port_req = self.new_update_request('ports', data, p1['id'])
        port_req.get_response(self.api)

        expected_dhcp_options_rows['v4-' + p1['id']] = {
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': subnet['id'],
                             'port_id': p1['id']},
            'options': {'server_id': '10.0.0.1',
                        'server_mac': dhcp_mac[subnet['id']],
                        'lease_time': str(12 * 60 * 60),
                        'domain_name': '"%s"' % cfg.CONF.dns_domain,
                        'dns_server': '{10.10.10.10}',
                        'mtu': '1200',
                        'router': subnet['gateway_ip'],
                        'tftp_server': '"8.8.8.8"'}}
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)
        self._verify_dhcp_option_row_for_port(
            p1['id'], expected_dhcp_options_rows['v4-' + p1['id']],
            expected_dhcp_options_rows['v6-' + p1['id']])

        # Disable DHCPv4 for this port. The DHCP_Options row created for this
        # port should be get deleted.
        data = {'port': {'extra_dhcp_opts': [{'ip_version': 4,
                                              'opt_name': 'dhcp_disabled',
                                              'opt_value': 'true'}]}}
        port_req = self.new_update_request('ports', data, p1['id'])
        port_req.get_response(self.api)

        del expected_dhcp_options_rows['v4-' + p1['id']]
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)
        # The Logical_Switch_Port.dhcpv4_options for this port should be
        # empty.
        self._verify_dhcp_option_row_for_port(
            p1['id'], {}, expected_dhcp_options_rows['v6-' + p1['id']])

        # Disable DHCPv6 for this port. The DHCP_Options row created for this
        # port should be get deleted.
        data = {'port': {'extra_dhcp_opts': [{'ip_version': 6,
                                              'opt_name': 'dhcp_disabled',
                                              'opt_value': 'true'}]}}
        port_req = self.new_update_request('ports', data, p1['id'])
        port_req.get_response(self.api)

        del expected_dhcp_options_rows['v6-' + p1['id']]
        self._verify_dhcp_option_rows(expected_dhcp_options_rows)
        # The Logical_Switch_Port.dhcpv4_options for this port should be
        # empty.
        self._verify_dhcp_option_row_for_port(p1['id'], {})

    def test_dhcp_options_domain_name(self):
        """Test for DHCP_Options domain name option

        This test needs dns extension_driver to be enabled.
        Test test_dhcp_options* are too complex so this case
        has been moved to separated one.
        """

        cidr = '10.0.0.0/24'
        data = {
            'network':
                {'name': 'foo',
                 'dns_domain': 'foo.com.',
                 'tenant_id': self._tenant_id}}
        req = self.new_create_request('networks', data, self.fmt)
        res = req.get_response(self.api)
        net = self.deserialize(self.fmt, res)['network']

        res = self._create_subnet(self.fmt, net['id'], cidr)
        subnet = self.deserialize(self.fmt, res)['subnet']
        dhcp_mac = self._get_subnet_dhcp_mac(subnet)

        p = self._make_port(
            self.fmt, net['id'],
            fixed_ips=[
                {'subnet_id': subnet['id']}])

        # Ensure that 'foo' taken from network
        # is not configured as domain_name.
        # Parameter taken from configuration
        # should be set instead.
        mtu = str(1480 - cfg.CONF.ml2_type_geneve.max_header_size)
        expected_dhcp_options_rows = {
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': subnet['id']},
            'options': {'dns_server': '{10.10.10.10}',
                        'domain_name': '"%s"' % cfg.CONF.dns_domain,
                        'lease_time': '43200',
                        'mtu': mtu,
                        'router': '10.0.0.1',
                        'server_id': '10.0.0.1',
                        'server_mac': dhcp_mac}}
        self._verify_dhcp_option_row_for_port(
            p['port']['id'], expected_dhcp_options_rows)

    def test_dhcp_options_domain_name_not_set(self):
        ovn_config.cfg.CONF.set_override('dns_domain', '')
        n1 = self._make_network(self.fmt, 'n1', True)
        res = self._create_subnet(self.fmt, n1['network']['id'], '10.0.0.0/24')
        subnet = self.deserialize(self.fmt, res)['subnet']
        p = self._make_port(self.fmt, n1['network']['id'],
                            fixed_ips=[{'subnet_id': subnet['id']}])
        dhcp_mac = self._get_subnet_dhcp_mac(subnet)
        mtu = str(1480 - cfg.CONF.ml2_type_geneve.max_header_size)
        # Make sure that domain_name is not included.
        expected_dhcp_options_rows = {
            'cidr': '10.0.0.0/24',
            'external_ids': {'subnet_id': subnet['id']},
            'options': {'dns_server': '{10.10.10.10}',
                        'lease_time': '43200',
                        'mtu': mtu,
                        'router': '10.0.0.1',
                        'server_id': '10.0.0.1',
                        'server_mac': dhcp_mac}}
        self._verify_dhcp_option_row_for_port(
            p['port']['id'], expected_dhcp_options_rows)


class TestPortSecurity(base.TestOVNFunctionalBase):

    def _get_port_related_acls(self, port_id):
        ovn_port = self.nb_api.lookup('Logical_Switch_Port', port_id)
        port_acls = []
        for pg in self.nb_api.tables['Port_Group'].rows.values():
            for p in pg.ports:
                if ovn_port.uuid != p.uuid:
                    continue
                for a in pg.acls:
                    port_acls.append({'match': a.match,
                                      'action': a.action,
                                      'priority': a.priority,
                                      'direction': a.direction})
        return port_acls

    def _get_port_related_acls_port_group_not_supported(self, port_id):
        port_acls = []
        for acl in self.nb_api.tables['ACL'].rows.values():
            ext_ids = getattr(acl, 'external_ids', {})
            if ext_ids.get('neutron:lport') == port_id:
                port_acls.append({'match': acl.match,
                                  'action': acl.action,
                                  'priority': acl.priority,
                                  'direction': acl.direction})
        return port_acls

    def _verify_port_acls(self, port_id, expected_acls):
        port_acls = self._get_port_related_acls(port_id)
        self.assertCountEqual(expected_acls, port_acls)

    def test_port_security_port_group(self):
        n1 = self._make_network(self.fmt, 'n1', True)
        res = self._create_subnet(self.fmt, n1['network']['id'], '10.0.0.0/24')
        subnet = self.deserialize(self.fmt, res)['subnet']
        p = self._make_port(self.fmt, n1['network']['id'],
                            fixed_ips=[{'subnet_id': subnet['id']}])
        port_id = p['port']['id']
        sg_id = p['port']['security_groups'][0].replace('-', '_')
        pg_name = utils.ovn_port_group_name(sg_id)
        expected_acls_with_sg_ps_enabled = [
            {'match': 'inport == @neutron_pg_drop && ip',
             'action': 'drop',
             'priority': 1001,
             'direction': 'from-lport'},
            {'match': 'outport == @neutron_pg_drop && ip',
             'action': 'drop',
             'priority': 1001,
             'direction': 'to-lport'},
            {'match': 'inport == @' + pg_name + ' && ip6',
             'action': 'allow-related',
             'priority': 1002,
             'direction': 'from-lport'},
            {'match': 'inport == @' + pg_name + ' && ip4',
             'action': 'allow-related',
             'priority': 1002,
             'direction': 'from-lport'},
            {'match': 'outport == @' + pg_name + ' && ip4 && '
                      'ip4.src == $' + pg_name + '_ip4',
             'action': 'allow-related',
             'priority': 1002,
             'direction': 'to-lport'},
            {'match': 'outport == @' + pg_name + ' && ip6 && '
                      'ip6.src == $' + pg_name + '_ip6',
             'action': 'allow-related',
             'priority': 1002,
             'direction': 'to-lport'},
        ]
        self._verify_port_acls(port_id, expected_acls_with_sg_ps_enabled)

        # clear the security groups.
        data = {'port': {'security_groups': []}}
        port_req = self.new_update_request('ports', data, p['port']['id'])
        port_req.get_response(self.api)

        # No security groups and port security enabled - > ACLs should be
        # added to drop the packets.
        expected_acls_with_no_sg_ps_enabled = [
            {'match': 'inport == @neutron_pg_drop && ip',
             'action': 'drop',
             'priority': 1001,
             'direction': 'from-lport'},
            {'match': 'outport == @neutron_pg_drop && ip',
             'action': 'drop',
             'priority': 1001,
             'direction': 'to-lport'},
        ]
        self._verify_port_acls(port_id, expected_acls_with_no_sg_ps_enabled)

        # Disable port security
        data = {'port': {'port_security_enabled': False}}
        port_req = self.new_update_request('ports', data, p['port']['id'])
        port_req.get_response(self.api)
        # No security groups and port security disabled - > No ACLs should be
        # added (allowing all the traffic).
        self._verify_port_acls(port_id, [])

        # Enable port security again with no security groups - > ACLs should
        # be added back to drop the packets.
        data = {'port': {'port_security_enabled': True}}
        port_req = self.new_update_request('ports', data, p['port']['id'])
        port_req.get_response(self.api)
        self._verify_port_acls(port_id, expected_acls_with_no_sg_ps_enabled)

        # Set security groups back
        data = {'port': {'security_groups': p['port']['security_groups']}}
        port_req = self.new_update_request('ports', data, p['port']['id'])
        port_req.get_response(self.api)
        self._verify_port_acls(port_id, expected_acls_with_sg_ps_enabled)


class TestDNSRecords(base.TestOVNFunctionalBase):
    _extension_drivers = ['port_security', 'dns']

    def _validate_dns_records(self, expected_dns_records):
        observed_dns_records = []
        for dns_row in self.nb_api.tables['DNS'].rows.values():
            observed_dns_records.append(
                {'external_ids': dns_row.external_ids,
                 'records': dns_row.records})
        self.assertCountEqual(expected_dns_records, observed_dns_records)

    def _validate_ls_dns_records(self, lswitch_name, expected_dns_records):
        ls = idlutils.row_by_value(self.nb_api.idl,
                                   'Logical_Switch', 'name', lswitch_name)
        observed_dns_records = []
        for dns_row in ls.dns_records:
            observed_dns_records.append(
                {'external_ids': dns_row.external_ids,
                 'records': dns_row.records})
        self.assertCountEqual(expected_dns_records, observed_dns_records)

    def setUp(self):
        ovn_config.cfg.CONF.set_override('dns_domain', 'ovn.test')
        super(TestDNSRecords, self).setUp()

    def test_dns_records(self):
        expected_dns_records = []
        nets = []
        for n, cidr in [('n1', '10.0.0.0/24'), ('n2', '20.0.0.0/24')]:
            net_kwargs = {}
            if n == 'n1':
                net_kwargs = {dns_apidef.DNSDOMAIN: 'net-' + n + '.'}
                net_kwargs['arg_list'] = (dns_apidef.DNSDOMAIN,)
            res = self._create_network(self.fmt, n, True, **net_kwargs)
            net = self.deserialize(self.fmt, res)
            nets.append(net)
            res = self._create_subnet(self.fmt, net['network']['id'], cidr)
            self.deserialize(self.fmt, res)

        # At this point no dns records should be created
        n1_lswitch_name = utils.ovn_name(nets[0]['network']['id'])
        n2_lswitch_name = utils.ovn_name(nets[1]['network']['id'])
        self._validate_dns_records(expected_dns_records)
        self._validate_ls_dns_records(n1_lswitch_name, expected_dns_records)
        self._validate_ls_dns_records(n2_lswitch_name, expected_dns_records)

        port_kwargs = {'arg_list': (dns_apidef.DNSNAME,),
                       dns_apidef.DNSNAME: 'n1p1'}
        res = self._create_port(self.fmt, nets[0]['network']['id'],
                                device_id='n1p1', **port_kwargs)
        n1p1 = self.deserialize(self.fmt, res)
        port_ips = " ".join([f['ip_address']
                             for f in n1p1['port']['fixed_ips']])
        expected_dns_records = [
            {'external_ids': {'ls_name': n1_lswitch_name},
             'records': {'n1p1': port_ips, 'n1p1.ovn.test': port_ips,
                         'n1p1.net-n1': port_ips}}
        ]
        for ip in port_ips.split(" "):
            p_record = netaddr.IPAddress(ip).reverse_dns.rstrip(".")
            expected_dns_records[0]['records'][p_record] = 'n1p1.ovn.test'

        self._validate_dns_records(expected_dns_records)
        self._validate_ls_dns_records(n1_lswitch_name,
                                      [expected_dns_records[0]])
        self._validate_ls_dns_records(n2_lswitch_name, [])

        # Create another port, but don't set dns_name. dns record should not
        # be updated.
        res = self._create_port(self.fmt, nets[1]['network']['id'],
                                device_id='n2p1')
        n2p1 = self.deserialize(self.fmt, res)
        self._validate_dns_records(expected_dns_records)

        # Update port p2 with dns_name. The dns record should be updated.
        body = {'dns_name': 'n2p1'}
        data = {'port': body}
        req = self.new_update_request('ports', data, n2p1['port']['id'])
        res = req.get_response(self.api)
        self.assertEqual(200, res.status_int)

        port_ips = " ".join([f['ip_address']
                             for f in n2p1['port']['fixed_ips']])
        expected_dns_records.append(
            {'external_ids': {'ls_name': n2_lswitch_name},
             'records': {'n2p1': port_ips, 'n2p1.ovn.test': port_ips}})
        for ip in port_ips.split(" "):
            p_record = netaddr.IPAddress(ip).reverse_dns.rstrip(".")
            expected_dns_records[1]['records'][p_record] = 'n2p1.ovn.test'
        self._validate_dns_records(expected_dns_records)
        self._validate_ls_dns_records(n1_lswitch_name,
                                      [expected_dns_records[0]])
        self._validate_ls_dns_records(n2_lswitch_name,
                                      [expected_dns_records[1]])

        # Create n1p2
        port_kwargs = {'arg_list': (dns_apidef.DNSNAME,),
                       dns_apidef.DNSNAME: 'n1p2'}
        res = self._create_port(self.fmt, nets[0]['network']['id'],
                                device_id='n1p1', **port_kwargs)
        n1p2 = self.deserialize(self.fmt, res)
        port_ips = " ".join([f['ip_address']
                             for f in n1p2['port']['fixed_ips']])
        expected_dns_records[0]['records']['n1p2'] = port_ips
        expected_dns_records[0]['records']['n1p2.ovn.test'] = port_ips
        expected_dns_records[0]['records']['n1p2.net-n1'] = port_ips
        for ip in port_ips.split(" "):
            p_record = netaddr.IPAddress(ip).reverse_dns.rstrip(".")
            expected_dns_records[0]['records'][p_record] = 'n1p2.ovn.test'
        self._validate_dns_records(expected_dns_records)
        self._validate_ls_dns_records(n1_lswitch_name,
                                      [expected_dns_records[0]])
        self._validate_ls_dns_records(n2_lswitch_name,
                                      [expected_dns_records[1]])

        # Remove device_id from n1p1
        body = {'device_id': ''}
        data = {'port': body}
        req = self.new_update_request('ports', data, n1p1['port']['id'])
        res = req.get_response(self.api)
        self.assertEqual(200, res.status_int)
        expected_dns_records[0]['records'].pop('n1p1')
        port_ips = " ".join([f['ip_address']
                             for f in n1p1['port']['fixed_ips']])
        for ip in port_ips.split(" "):
            p_record = netaddr.IPAddress(ip).reverse_dns.rstrip(".")
            expected_dns_records[0]['records'].pop(p_record)
        expected_dns_records[0]['records'].pop('n1p1.ovn.test')
        expected_dns_records[0]['records'].pop('n1p1.net-n1')
        self._validate_dns_records(expected_dns_records)
        self._validate_ls_dns_records(n1_lswitch_name,
                                      [expected_dns_records[0]])
        self._validate_ls_dns_records(n2_lswitch_name,
                                      [expected_dns_records[1]])

        # Delete n2p1
        self._delete('ports', n2p1['port']['id'])
        expected_dns_records[1]['records'] = {}
        self._validate_dns_records(expected_dns_records)
        self._validate_ls_dns_records(n1_lswitch_name,
                                      [expected_dns_records[0]])
        self._validate_ls_dns_records(n2_lswitch_name,
                                      [expected_dns_records[1]])

        # Delete n2
        self._delete('networks', nets[1]['network']['id'])
        del expected_dns_records[1]
        self._validate_dns_records(expected_dns_records)
        self._validate_ls_dns_records(n1_lswitch_name,
                                      [expected_dns_records[0]])

        # Delete n1p1 and n1p2 and n1
        self._delete('ports', n1p1['port']['id'])
        self._delete('ports', n1p2['port']['id'])
        self._delete('networks', nets[0]['network']['id'])
        self._validate_dns_records([])


class TestPortExternalIds(base.TestOVNFunctionalBase):

    def _get_lsp_external_id(self, port_id):
        ovn_port = self.nb_api.lookup('Logical_Switch_Port', port_id)
        return copy.deepcopy(ovn_port.external_ids)

    def _set_lsp_external_id(self, port_id, **pairs):
        external_ids = self._get_lsp_external_id(port_id)
        for key, val in pairs.items():
            external_ids[key] = val
        self.nb_api.set_lswitch_port(lport_name=port_id,
                                     external_ids=external_ids).execute()

    def _create_lsp(self):
        n1 = self._make_network(self.fmt, 'n1', True)
        res = self._create_subnet(self.fmt, n1['network']['id'], '10.0.0.0/24')
        subnet = self.deserialize(self.fmt, res)['subnet']
        p = self._make_port(self.fmt, n1['network']['id'],
                            fixed_ips=[{'subnet_id': subnet['id']}])
        port_id = p['port']['id']
        return port_id, self._get_lsp_external_id(port_id)

    def test_port_update_has_ext_ids(self):
        port_id, ext_ids = self._create_lsp()
        self.assertIsNotNone(ext_ids)

    def test_port_update_add_ext_id(self):
        port_id, ext_ids = self._create_lsp()
        ext_ids['another'] = 'value'
        self._set_lsp_external_id(port_id, another='value')
        self.assertEqual(ext_ids, self._get_lsp_external_id(port_id))

    def test_port_update_change_ext_id_value(self):
        port_id, ext_ids = self._create_lsp()
        ext_ids['another'] = 'value'
        self._set_lsp_external_id(port_id, another='value')
        self.assertEqual(ext_ids, self._get_lsp_external_id(port_id))
        ext_ids['another'] = 'value2'
        self._set_lsp_external_id(port_id, another='value2')
        self.assertEqual(ext_ids, self._get_lsp_external_id(port_id))

    def test_port_update_with_foreign_ext_ids(self):
        port_id, ext_ids = self._create_lsp()
        new_ext_ids = {ovn_const.OVN_PORT_FIP_EXT_ID_KEY: '1.11.11.1',
                       'foreign_key2': 'value1234'}
        self._set_lsp_external_id(port_id, **new_ext_ids)
        ext_ids.update(new_ext_ids)
        self.assertEqual(ext_ids, self._get_lsp_external_id(port_id))
        # invoke port update and make sure the the values we added to the
        # external_ids remain undisturbed.
        data = {'port': {'extra_dhcp_opts': [{'ip_version': 4,
                                              'opt_name': 'ip-forward-enable',
                                              'opt_value': '0'}]}}
        port_req = self.new_update_request('ports', data, port_id)
        port_req.get_response(self.api)
        actual_ext_ids = self._get_lsp_external_id(port_id)
        # update port should have not removed keys it does not use from the
        # external ids of the lsp.
        self.assertEqual('1.11.11.1',
                         actual_ext_ids.get(ovn_const.OVN_PORT_FIP_EXT_ID_KEY))
        self.assertEqual('value1234', actual_ext_ids.get('foreign_key2'))


class TestNBDbResourcesOverTcp(TestNBDbResources):
    def get_ovsdb_server_protocol(self):
        return 'tcp'


class TestNBDbResourcesOverSsl(TestNBDbResources):
    def get_ovsdb_server_protocol(self):
        return 'ssl'
