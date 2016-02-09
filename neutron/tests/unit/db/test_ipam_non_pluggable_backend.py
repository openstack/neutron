# Copyright (c) 2012 OpenStack Foundation.
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

import mock
from neutron_lib import constants as n_const
from neutron_lib import exceptions as n_exc
from oslo_config import cfg

from neutron.common import constants
from neutron.common import ipv6_utils
from neutron.db import db_base_plugin_v2
from neutron.db import ipam_backend_mixin
from neutron.db import ipam_non_pluggable_backend as non_ipam
from neutron.db import models_v2
from neutron.tests import base


class TestIpamNonPluggableBackend(base.BaseTestCase):
    """Unit Tests for non pluggable IPAM Logic."""

    def test_generate_ip(self):
        with mock.patch.object(non_ipam.IpamNonPluggableBackend,
                               '_try_generate_ip') as generate:
            with mock.patch.object(non_ipam.IpamNonPluggableBackend,
                                   '_rebuild_availability_ranges') as rebuild:

                non_ipam.IpamNonPluggableBackend._generate_ip('c', 's')

        generate.assert_called_once_with('c', 's')
        self.assertEqual(0, rebuild.call_count)

    def test_generate_ip_exhausted_pool(self):
        with mock.patch.object(non_ipam.IpamNonPluggableBackend,
                               '_try_generate_ip') as generate:
            with mock.patch.object(non_ipam.IpamNonPluggableBackend,
                                   '_rebuild_availability_ranges') as rebuild:

                exception = n_exc.IpAddressGenerationFailure(net_id='n')
                # fail first call but not second
                generate.side_effect = [exception, None]
                non_ipam.IpamNonPluggableBackend._generate_ip('c', 's')

        self.assertEqual(2, generate.call_count)
        rebuild.assert_called_once_with('c', 's')

    def _validate_rebuild_availability_ranges(self, pools, allocations,
                                              expected):
        ip_qry = mock.Mock()
        ip_qry.with_lockmode.return_value = ip_qry
        ip_qry.filter_by.return_value = allocations

        pool_qry = mock.Mock()
        pool_qry.options.return_value = pool_qry
        pool_qry.with_lockmode.return_value = pool_qry
        pool_qry.filter_by.return_value = pools

        def return_queries_side_effect(*args, **kwargs):
            if args[0] == models_v2.IPAllocation:
                return ip_qry
            if args[0] == models_v2.IPAllocationPool:
                return pool_qry

        context = mock.Mock()
        context.session.query.side_effect = return_queries_side_effect
        subnets = [mock.MagicMock()]

        non_ipam.IpamNonPluggableBackend._rebuild_availability_ranges(
            context, subnets)

        actual = [[args[0].allocation_pool_id,
                   args[0].first_ip, args[0].last_ip]
                  for _name, args, _kwargs in context.session.add.mock_calls]
        self.assertEqual(expected, actual)

    def test_rebuild_availability_ranges(self):
        pools = [{'id': 'a',
                  'first_ip': '192.168.1.3',
                  'last_ip': '192.168.1.10'},
                 {'id': 'b',
                  'first_ip': '192.168.1.100',
                  'last_ip': '192.168.1.120'}]

        allocations = [{'ip_address': '192.168.1.3'},
                       {'ip_address': '192.168.1.78'},
                       {'ip_address': '192.168.1.7'},
                       {'ip_address': '192.168.1.110'},
                       {'ip_address': '192.168.1.11'},
                       {'ip_address': '192.168.1.4'},
                       {'ip_address': '192.168.1.111'}]

        expected = [['a', '192.168.1.5', '192.168.1.6'],
                    ['a', '192.168.1.8', '192.168.1.10'],
                    ['b', '192.168.1.100', '192.168.1.109'],
                    ['b', '192.168.1.112', '192.168.1.120']]

        self._validate_rebuild_availability_ranges(pools, allocations,
                                                   expected)

    def test_rebuild_ipv6_availability_ranges(self):
        pools = [{'id': 'a',
                  'first_ip': '2001::1',
                  'last_ip': '2001::50'},
                 {'id': 'b',
                  'first_ip': '2001::100',
                  'last_ip': '2001::ffff:ffff:ffff:fffe'}]

        allocations = [{'ip_address': '2001::10'},
                       {'ip_address': '2001::45'},
                       {'ip_address': '2001::60'},
                       {'ip_address': '2001::111'},
                       {'ip_address': '2001::200'},
                       {'ip_address': '2001::ffff:ffff:ffff:ff10'},
                       {'ip_address': '2001::ffff:ffff:ffff:f2f0'}]

        expected = [['a', '2001::1', '2001::f'],
                    ['a', '2001::11', '2001::44'],
                    ['a', '2001::46', '2001::50'],
                    ['b', '2001::100', '2001::110'],
                    ['b', '2001::112', '2001::1ff'],
                    ['b', '2001::201', '2001::ffff:ffff:ffff:f2ef'],
                    ['b', '2001::ffff:ffff:ffff:f2f1',
                     '2001::ffff:ffff:ffff:ff0f'],
                    ['b', '2001::ffff:ffff:ffff:ff11',
                     '2001::ffff:ffff:ffff:fffe']]

        self._validate_rebuild_availability_ranges(pools, allocations,
                                                   expected)

    def _test__allocate_ips_for_port(self, subnets, port, expected):
        # this test is incompatible with pluggable ipam, because subnets
        # were not actually created, so no ipam_subnet exists
        cfg.CONF.set_override("ipam_driver", None)
        plugin = db_base_plugin_v2.NeutronDbPluginV2()
        with mock.patch.object(ipam_backend_mixin.IpamBackendMixin,
                               '_ipam_get_subnets') as get_subnets:
            with mock.patch.object(non_ipam.IpamNonPluggableBackend,
                                   '_check_unique_ip') as check_unique:
                context = mock.Mock()
                get_subnets.return_value = subnets
                check_unique.return_value = True
                actual = plugin.ipam._allocate_ips_for_port(context, port)
                self.assertEqual(expected, actual)

    def test__allocate_ips_for_port_2_slaac_subnets(self):
        subnets = [
            {
                'cidr': u'2001:100::/64',
                'enable_dhcp': True,
                'gateway_ip': u'2001:100::1',
                'id': u'd1a28edd-bd83-480a-bd40-93d036c89f13',
                'network_id': 'fbb9b578-95eb-4b79-a116-78e5c4927176',
                'ip_version': 6,
                'ipv6_address_mode': None,
                'ipv6_ra_mode': u'slaac'},
            {
                'cidr': u'2001:200::/64',
                'enable_dhcp': True,
                'gateway_ip': u'2001:200::1',
                'id': u'dc813d3d-ed66-4184-8570-7325c8195e28',
                'network_id': 'fbb9b578-95eb-4b79-a116-78e5c4927176',
                'ip_version': 6,
                'ipv6_address_mode': None,
                'ipv6_ra_mode': u'slaac'}]
        port = {'port': {
            'network_id': 'fbb9b578-95eb-4b79-a116-78e5c4927176',
            'fixed_ips': n_const.ATTR_NOT_SPECIFIED,
            'mac_address': '12:34:56:78:44:ab',
            'device_owner': 'compute'}}
        expected = []
        for subnet in subnets:
            addr = str(ipv6_utils.get_ipv6_addr_by_EUI64(
                            subnet['cidr'], port['port']['mac_address']))
            expected.append({'ip_address': addr, 'subnet_id': subnet['id']})

        self._test__allocate_ips_for_port(subnets, port, expected)

    def test__allocate_ips_for_port_2_slaac_pd_subnets(self):
        subnets = [
            {
                'cidr': constants.PROVISIONAL_IPV6_PD_PREFIX,
                'enable_dhcp': True,
                'gateway_ip': '::1',
                'id': 'd1a28edd-bd83-480a-bd40-93d036c89f13',
                'network_id': 'fbb9b578-95eb-4b79-a116-78e5c4927176',
                'ip_version': 6,
                'ipv6_address_mode': None,
                'ipv6_ra_mode': 'slaac'},
            {
                'cidr': constants.PROVISIONAL_IPV6_PD_PREFIX,
                'enable_dhcp': True,
                'gateway_ip': '::1',
                'id': 'dc813d3d-ed66-4184-8570-7325c8195e28',
                'network_id': 'fbb9b578-95eb-4b79-a116-78e5c4927176',
                'ip_version': 6,
                'ipv6_address_mode': None,
                'ipv6_ra_mode': 'slaac'}]
        port = {'port': {
            'network_id': 'fbb9b578-95eb-4b79-a116-78e5c4927176',
            'fixed_ips': n_const.ATTR_NOT_SPECIFIED,
            'mac_address': '12:34:56:78:44:ab',
            'device_owner': 'compute'}}
        expected = []
        for subnet in subnets:
            addr = str(ipv6_utils.get_ipv6_addr_by_EUI64(
                            subnet['cidr'], port['port']['mac_address']))
            expected.append({'ip_address': addr, 'subnet_id': subnet['id']})

        self._test__allocate_ips_for_port(subnets, port, expected)
