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
from oslo_config import cfg

from neutron.common import constants
from neutron.common import ipv6_utils
from neutron.db import db_base_plugin_v2
from neutron.db import ipam_backend_mixin
from neutron.db import ipam_non_pluggable_backend as non_ipam
from neutron.tests import base


class TestIpamNonPluggableBackend(base.BaseTestCase):
    """Unit Tests for non pluggable IPAM Logic."""

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
