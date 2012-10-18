# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import unittest2

from quantum.api.v2 import attributes
from quantum.common import exceptions as q_exc


class TestAttributes(unittest2.TestCase):

    def test_mac_addresses(self):
        # Valid - 3 octets
        base_mac = "fa:16:3e:00:00:00"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        self.assertEquals(msg, None)

        # Valid - 4 octets
        base_mac = "fa:16:3e:4f:00:00"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        self.assertEquals(msg, None)

        # Invalid - not unicast
        base_mac = "01:16:3e:4f:00:00"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        error = '%s is not valid' % base_mac
        self.assertEquals(msg, error)

        # Invalid - invalid format
        base_mac = "a:16:3e:4f:00:00"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        error = '%s is not valid' % base_mac
        self.assertEquals(msg, error)

        # Invalid - invalid format
        base_mac = "ffa:16:3e:4f:00:00"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        error = '%s is not valid' % base_mac
        self.assertEquals(msg, error)

        # Invalid - invalid format
        base_mac = "01163e4f0000"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        error = '%s is not valid' % base_mac
        self.assertEquals(msg, error)

        # Invalid - invalid format
        base_mac = "01-16-3e-4f-00-00"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        error = '%s is not valid' % base_mac
        self.assertEquals(msg, error)

        # Invalid - invalid format
        base_mac = "00:16:3:f:00:00"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        error = '%s is not valid' % base_mac
        self.assertEquals(msg, error)

        # Invalid - invalid format
        base_mac = "12:3:4:5:67:89ab"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        error = '%s is not valid' % base_mac
        self.assertEquals(msg, error)

    def test_cidr(self):
        # Valid - IPv4
        cidr = "10.0.2.0/24"
        msg = attributes._validate_subnet(cidr,
                                          None)
        self.assertEquals(msg, None)

        # Valid - IPv6 without final octets
        cidr = "fe80::/24"
        msg = attributes._validate_subnet(cidr,
                                          None)
        self.assertEquals(msg, None)

        # Valid - IPv6 with final octets
        cidr = "fe80::0/24"
        msg = attributes._validate_subnet(cidr,
                                          None)
        self.assertEquals(msg, None)

        # Invalid - IPv4 missing mask
        cidr = "10.0.2.0"
        msg = attributes._validate_subnet(cidr,
                                          None)
        error = "%s is not a valid IP subnet" % cidr
        self.assertEquals(msg, error)

        # Invalid - IPv6 without final octets, missing mask
        cidr = "fe80::"
        msg = attributes._validate_subnet(cidr,
                                          None)
        error = "%s is not a valid IP subnet" % cidr
        self.assertEquals(msg, error)

        # Invalid - IPv6 with final octets, missing mask
        cidr = "fe80::0"
        msg = attributes._validate_subnet(cidr,
                                          None)
        error = "%s is not a valid IP subnet" % cidr
        self.assertEquals(msg, error)


class TestConvertKvp(unittest2.TestCase):

    def test_convert_kvp_list_to_dict_succeeds_for_missing_values(self):
        result = attributes.convert_kvp_list_to_dict(['True'])
        self.assertEqual({}, result)

    def test_convert_kvp_list_to_dict_succeeds_for_multiple_values(self):
        result = attributes.convert_kvp_list_to_dict(
            ['a=b', 'a=c', 'a=c', 'b=a'])
        self.assertEqual({'a': ['c', 'b'], 'b': ['a']}, result)

    def test_convert_kvp_list_to_dict_succeeds_for_values(self):
        result = attributes.convert_kvp_list_to_dict(['a=b', 'c=d'])
        self.assertEqual({'a': ['b'], 'c': ['d']}, result)

    def test_convert_kvp_str_to_list_fails_for_missing_key(self):
        with self.assertRaises(q_exc.InvalidInput):
            attributes.convert_kvp_str_to_list('=a')

    def test_convert_kvp_str_to_list_fails_for_missing_equals(self):
        with self.assertRaises(q_exc.InvalidInput):
            attributes.convert_kvp_str_to_list('a')

    def test_convert_kvp_str_to_list_succeeds_for_one_equals(self):
        result = attributes.convert_kvp_str_to_list('a=')
        self.assertEqual(['a', ''], result)

    def test_convert_kvp_str_to_list_succeeds_for_two_equals(self):
        result = attributes.convert_kvp_str_to_list('a=a=a')
        self.assertEqual(['a', 'a=a'], result)
