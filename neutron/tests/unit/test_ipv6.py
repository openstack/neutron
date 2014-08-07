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

import mock

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
        ipv6_utils._IS_IPV6_ENABLED = None
        mock_open = mock.patch("__builtin__.open").start()
        self.mock_read = mock_open.return_value.__enter__.return_value.read

    def test_enabled(self):
        self.mock_read.return_value = "0"
        enabled = ipv6_utils.is_enabled()
        self.assertTrue(enabled)

    def test_disabled(self):
        self.mock_read.return_value = "1"
        enabled = ipv6_utils.is_enabled()
        self.assertFalse(enabled)

    def test_memoize(self):
        self.mock_read.return_value = "0"
        ipv6_utils.is_enabled()
        enabled = ipv6_utils.is_enabled()
        self.assertTrue(enabled)
        self.mock_read.assert_called_once_with()
