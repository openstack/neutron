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

import mock
from neutron_lib import constants

from neutron.common import ipv6_utils
from neutron.tests import base
from neutron.tests import tools


class TestIsEnabledAndBindByDefault(base.BaseTestCase):

    def setUp(self):
        super(TestIsEnabledAndBindByDefault, self).setUp()

        def reset_detection_flag():
            ipv6_utils._IS_IPV6_ENABLED = None
        reset_detection_flag()
        self.addCleanup(reset_detection_flag)
        self.mock_exists = mock.patch("os.path.exists",
                                      return_value=True).start()
        self.proc_path = '/proc/sys/net/ipv6/conf/default/disable_ipv6'

    def test_enabled(self):
        self.useFixture(tools.OpenFixture(self.proc_path, '0'))
        enabled = ipv6_utils.is_enabled_and_bind_by_default()
        self.assertTrue(enabled)

    def test_disabled(self):
        self.useFixture(tools.OpenFixture(self.proc_path, '1'))
        enabled = ipv6_utils.is_enabled_and_bind_by_default()
        self.assertFalse(enabled)

    def test_disabled_non_exists(self):
        mo = self.useFixture(tools.OpenFixture(self.proc_path, '1')).mock_open
        self.mock_exists.return_value = False
        enabled = ipv6_utils.is_enabled_and_bind_by_default()
        self.assertFalse(enabled)
        self.assertFalse(mo.called)

    def test_memoize(self):
        mo = self.useFixture(tools.OpenFixture(self.proc_path, '0')).mock_open
        ipv6_utils.is_enabled_and_bind_by_default()
        enabled = ipv6_utils.is_enabled_and_bind_by_default()
        self.assertTrue(enabled)
        mo.assert_called_once_with(self.proc_path, 'r')


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
