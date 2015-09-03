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

from neutron.common import constants
from neutron.common import ipv6_utils
from neutron.tests import base


class IPv6byEUI64TestCase(base.BaseTestCase):
    """Unit tests for generate IPv6 by EUI-64 operations."""

    def test_generate_IPv6_by_EUI64(self):
        addr = ipv6_utils.get_ipv6_addr_by_EUI64('2001:db8::',
                                                 '00:16:3e:33:44:55')
        self.assertEqual('2001:db8::216:3eff:fe33:4455', addr.format())

    def test_generate_IPv6_with_IPv4_prefix(self):
        ipv4_prefix = '10.0.8'
        mac = '00:16:3e:33:44:55'
        self.assertRaises(TypeError, lambda:
                          ipv6_utils.get_ipv6_addr_by_EUI64(ipv4_prefix, mac))

    def test_generate_IPv6_with_bad_mac(self):
        bad_mac = '00:16:3e:33:44:5Z'
        prefix = '2001:db8::'
        self.assertRaises(TypeError, lambda:
                          ipv6_utils.get_ipv6_addr_by_EUI64(prefix, bad_mac))

    def test_generate_IPv6_with_bad_prefix(self):
        mac = '00:16:3e:33:44:55'
        bad_prefix = 'bb'
        self.assertRaises(TypeError, lambda:
                          ipv6_utils.get_ipv6_addr_by_EUI64(bad_prefix, mac))

    def test_generate_IPv6_with_error_prefix_type(self):
        mac = '00:16:3e:33:44:55'
        prefix = 123
        self.assertRaises(TypeError, lambda:
                          ipv6_utils.get_ipv6_addr_by_EUI64(prefix, mac))


class TestIsEnabled(base.BaseTestCase):

    def setUp(self):
        super(TestIsEnabled, self).setUp()

        def reset_detection_flag():
            ipv6_utils._IS_IPV6_ENABLED = None
        reset_detection_flag()
        self.addCleanup(reset_detection_flag)
        self.mock_exists = mock.patch("os.path.exists",
                                      return_value=True).start()
        mock_open = mock.patch("six.moves.builtins.open").start()
        self.mock_read = mock_open.return_value.__enter__.return_value.read

    def test_enabled(self):
        self.mock_read.return_value = "0"
        enabled = ipv6_utils.is_enabled()
        self.assertTrue(enabled)

    def test_disabled(self):
        self.mock_read.return_value = "1"
        enabled = ipv6_utils.is_enabled()
        self.assertFalse(enabled)

    def test_disabled_non_exists(self):
        self.mock_exists.return_value = False
        enabled = ipv6_utils.is_enabled()
        self.assertFalse(enabled)
        self.assertFalse(self.mock_read.called)

    def test_memoize(self):
        self.mock_read.return_value = "0"
        ipv6_utils.is_enabled()
        enabled = ipv6_utils.is_enabled()
        self.assertTrue(enabled)
        self.mock_read.assert_called_once_with()


class TestIsAutoAddressSubnet(base.BaseTestCase):

    def setUp(self):
        self.subnet = {
            'cidr': '2001:200::/64',
            'gateway_ip': '2001:200::1',
            'ip_version': 6,
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

    def test_valid_eui64_addresses(self):
        ips = ('fffe::0cad:12ff:fe44:5566',
               ipv6_utils.get_ipv6_addr_by_EUI64('2001:db8::',
                                                 '00:16:3e:33:44:55'))
        self._test_eui_64(ips, True)

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
