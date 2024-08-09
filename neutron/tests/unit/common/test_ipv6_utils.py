# Copyright 2013 IBM Corp.
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

from neutron_lib import constants

from neutron.common import ipv6_utils
from neutron.tests import base


class TestIsAutoAddressSubnet(base.BaseTestCase):

    def setUp(self):
        self.subnet = {
            'cidr': '2001:200::/64',
            'gateway_ip': '2001:200::1',
            'ip_version': constants.IP_VERSION_6,
            'ipv6_address_mode': None,
            'ipv6_ra_mode': None
        }
        super(TestIsAutoAddressSubnet, self).setUp()

    def test_combinations(self):
        Mode = collections.namedtuple('Mode', "addr_mode ra_mode "
                                              "is_auto_address")
        subnets = [
            Mode(None, None, False),
            Mode(constants.DHCPV6_STATEFUL, None, False),
            Mode(constants.DHCPV6_STATELESS, None, True),
            Mode(constants.IPV6_SLAAC, None, True),
            Mode(None, constants.DHCPV6_STATEFUL, False),
            Mode(None, constants.DHCPV6_STATELESS, True),
            Mode(None, constants.IPV6_SLAAC, True),
            Mode(constants.DHCPV6_STATEFUL, constants.DHCPV6_STATEFUL, False),
            Mode(constants.DHCPV6_STATELESS, constants.DHCPV6_STATELESS, True),
            Mode(constants.IPV6_SLAAC, constants.IPV6_SLAAC, True),
        ]
        for subnet in subnets:
            self.subnet['ipv6_address_mode'] = subnet.addr_mode
            self.subnet['ipv6_ra_mode'] = subnet.ra_mode
            self.assertEqual(subnet.is_auto_address,
                             ipv6_utils.is_auto_address_subnet(self.subnet))


class TestIsEui64Address(base.BaseTestCase):

    def _test_eui_64(self, ips, expected):
        for ip in ips:
            self.assertEqual(expected, ipv6_utils.is_eui64_address(ip),
                             "Error on %s" % ip)

    def test_invalid_eui64_addresses(self):
        ips = ('192.168.1.1',
               '192.168.1.0',
               '255.255.255.255',
               '0.0.0.0',
               'fffe::',
               'ff80::1',
               'fffe::0cad:12ff:ff44:5566',
               'fffe::0cad:12fe:fe44:5566',
               'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
        self._test_eui_64(ips, False)


class TestValidIpv6URL(base.BaseTestCase):

    def test_valid_ipv6_url(self):
        host = "::1"
        port = 443
        self.assertEqual("[::1]:443", ipv6_utils.valid_ipv6_url(host, port))

    def test_invalid_ipv6_url(self):
        host = "::1"
        port = 443
        self.assertNotEqual("::1:443", ipv6_utils.valid_ipv6_url(host, port))

    def test_valid_ipv4_url(self):
        host = "192.168.1.2"
        port = 443
        self.assertEqual("192.168.1.2:443",
                         ipv6_utils.valid_ipv6_url(host, port))

    def test_valid_hostname_url(self):
        host = "controller"
        port = 443
        self.assertEqual("controller:443",
                         ipv6_utils.valid_ipv6_url(host, port))


class TestNoscopeIpv6(base.BaseTestCase):
    def test_get_noscope_ipv6(self):
        self.assertEqual('2001:db8::f0:42:8329',
                         ipv6_utils.get_noscope_ipv6('2001:db8::f0:42:8329%1'))
        self.assertEqual('ff02::5678',
                         ipv6_utils.get_noscope_ipv6('ff02::5678%eth0'))
        self.assertEqual('fe80::1',
                         ipv6_utils.get_noscope_ipv6('fe80::1%eth0'))
        self.assertEqual('::1', ipv6_utils.get_noscope_ipv6('::1%eth0'))
        self.assertEqual('::1', ipv6_utils.get_noscope_ipv6('::1'))
        self.assertRaises(ValueError, ipv6_utils.get_noscope_ipv6, '::132:::')
