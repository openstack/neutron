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

    def test_is_attr_set(self):
        mock_obj = attributes.ATTR_NOT_SPECIFIED
        mock_none = None
        mock_str = "I'm set"
        self.assertIs(attributes.is_attr_set(mock_obj), False)
        self.assertIs(attributes.is_attr_set(mock_none), False)
        self.assertIs(attributes.is_attr_set(mock_str), True)

    def test_booleans(self):
        msg = attributes._validate_boolean(True)
        self.assertIsNone(msg)

        msg = attributes._validate_boolean(False)
        self.assertIsNone(msg)

        msg = attributes._validate_boolean('True')
        self.assertEquals(msg, "'True' is not boolean")

        msg = attributes._validate_boolean('true')
        self.assertEquals(msg, "'true' is not boolean")

        msg = attributes._validate_boolean('False')
        self.assertEquals(msg, "'False' is not boolean")

        msg = attributes._validate_boolean('false')
        self.assertEquals(msg, "'false' is not boolean")

        msg = attributes._validate_boolean('0')
        self.assertEquals(msg, "'0' is not boolean")

        msg = attributes._validate_boolean('1')
        self.assertEquals(msg, "'1' is not boolean")

        msg = attributes._validate_boolean('7')
        self.assertEquals(msg, "'7' is not boolean")

        msg = attributes._validate_boolean(0)
        self.assertEquals(msg, "'0' is not boolean")

        msg = attributes._validate_boolean(1)
        self.assertEquals(msg, "'1' is not boolean")

        msg = attributes._validate_boolean(7)
        self.assertEquals(msg, "'7' is not boolean")

        msg = attributes._validate_boolean(None)
        self.assertEquals(msg, "'None' is not boolean")

    def test_values(self):
        msg = attributes._validate_values(4, [4, 6])
        self.assertIsNone(msg)

        msg = attributes._validate_values(4, (4, 6))
        self.assertIsNone(msg)

        msg = attributes._validate_values(7, [4, 6])
        self.assertEquals(msg, "'7' is not in [4, 6]")

        msg = attributes._validate_values(7, (4, 6))
        self.assertEquals(msg, "'7' is not in (4, 6)")

    def test_strings(self):
        msg = attributes._validate_string(None, None)
        self.assertEquals(msg, "'None' is not a valid string")

        msg = attributes._validate_string("OK", None)
        self.assertEquals(msg, None)

        msg = attributes._validate_string("123456789", 9)
        self.assertIsNone(msg)

        msg = attributes._validate_string("1234567890", 9)
        self.assertIsNotNone(msg)

    def test_ip_pools(self):
        pools = [[{'end': '10.0.0.254'}],
                 [{'start': '10.0.0.254'}],
                 [{'start': '1000.0.0.254',
                   'end': '1.1.1.1'}],
                 [{'start': '10.0.0.2', 'end': '10.0.0.254',
                   'forza': 'juve'}],
                 [{'start': '10.0.0.2', 'end': '10.0.0.254'},
                  {'end': '10.0.0.254'}],
                 None]
        for pool in pools:
            msg = attributes._validate_ip_pools(pool, None)
            self.assertIsNotNone(msg)

        pools = [[{'end': '10.0.0.254', 'start': '10.0.0.2'},
                  {'start': '11.0.0.2', 'end': '11.1.1.1'}],
                 [{'start': '11.0.0.2', 'end': '11.0.0.100'}]]
        for pool in pools:
            msg = attributes._validate_ip_pools(pool, None)
            self.assertIsNone(msg)

    def test_fixed_ips(self):
        fixed_ips = [[{'subnet_id': '00000000-ffff-ffff-ffff-000000000000',
                       'ip_address': '1111.1.1.1'}],
                     [{'subnet_id': 'invalid'}],
                     None,
                     [{'subnet_id': '00000000-0fff-ffff-ffff-000000000000',
                       'ip_address': '1.1.1.1'},
                      {'subnet_id': '00000000-ffff-ffff-ffff-000000000000',
                       'ip_address': '1.1.1.1'}],
                     [{'subnet_id': '00000000-ffff-ffff-ffff-000000000000',
                       'ip_address': '1.1.1.1'},
                      {'subnet_id': '00000000-ffff-ffff-ffff-000000000000',
                       'ip_address': '1.1.1.1'}]]
        for fixed in fixed_ips:
            msg = attributes._validate_fixed_ips(fixed, None)
            self.assertIsNotNone(msg)

    def test_nameservers(self):
        ns_pools = [['1.1.1.2', '1.1.1.2'],
                    ['www.hostname.com', 'www.hostname.com'],
                    ['77.hostname.com'],
                    ['1000.0.0.1'],
                    None]

        for ns in ns_pools:
            msg = attributes._validate_nameservers(ns, None)
            self.assertIsNotNone(msg)

        ns_pools = [['100.0.0.2'],
                    ['www.hostname.com'],
                    ['www.great.marathons.to.travel'],
                    ['valid'],
                    ['www.internal.hostname.com']]

        for ns in ns_pools:
            msg = attributes._validate_nameservers(ns, None)
            self.assertIsNone(msg)

    def test_hostroutes(self):
        hostroute_pools = [[{'destination': '100.0.0.0/24'}],
                           [{'nexthop': '10.0.2.20'}],
                           [{'nexthop': '10.0.2.20',
                             'destination': '100.0.0.0/8'},
                            {'nexthop': '10.0.2.20',
                             'destination': '100.0.0.0/8'}],
                           None]
        for host_routes in hostroute_pools:
            msg = attributes._validate_hostroutes(host_routes, None)
            self.assertIsNotNone(msg)

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
        self.assertIsNotNone(msg)

        # Invalid - invalid format
        base_mac = "a:16:3e:4f:00:00"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        self.assertIsNotNone(msg)

        # Invalid - invalid format
        base_mac = "ffa:16:3e:4f:00:00"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        self.assertIsNotNone(msg)

        # Invalid - invalid format
        base_mac = "01163e4f0000"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        self.assertIsNotNone(msg)

        # Invalid - invalid format
        base_mac = "01-16-3e-4f-00-00"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        self.assertIsNotNone(msg)

        # Invalid - invalid format
        base_mac = "00:16:3:f:00:00"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        self.assertIsNotNone(msg)

        # Invalid - invalid format
        base_mac = "12:3:4:5:67:89ab"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        self.assertIsNotNone(msg)

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
        error = "'%s' is not a valid IP subnet" % cidr
        self.assertEquals(msg, error)

        # Invalid - IPv6 without final octets, missing mask
        cidr = "fe80::"
        msg = attributes._validate_subnet(cidr,
                                          None)
        error = "'%s' is not a valid IP subnet" % cidr
        self.assertEquals(msg, error)

        # Invalid - IPv6 with final octets, missing mask
        cidr = "fe80::0"
        msg = attributes._validate_subnet(cidr,
                                          None)
        error = "'%s' is not a valid IP subnet" % cidr
        self.assertEquals(msg, error)


class TestConvertToBoolean(unittest2.TestCase):

    def test_convert_to_boolean_bool(self):
        self.assertIs(attributes.convert_to_boolean(True), True)
        self.assertIs(attributes.convert_to_boolean(False), False)

    def test_convert_to_boolean_int(self):
        self.assertIs(attributes.convert_to_boolean(0), False)
        self.assertIs(attributes.convert_to_boolean(1), True)
        self.assertRaises(q_exc.InvalidInput,
                          attributes.convert_to_boolean,
                          7)

    def test_convert_to_boolean_str(self):
        self.assertIs(attributes.convert_to_boolean('True'), True)
        self.assertIs(attributes.convert_to_boolean('true'), True)
        self.assertIs(attributes.convert_to_boolean('False'), False)
        self.assertIs(attributes.convert_to_boolean('false'), False)
        self.assertIs(attributes.convert_to_boolean('0'), False)
        self.assertIs(attributes.convert_to_boolean('1'), True)
        self.assertRaises(q_exc.InvalidInput,
                          attributes.convert_to_boolean,
                          '7')


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
