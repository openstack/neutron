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
        data = attributes.ATTR_NOT_SPECIFIED
        self.assertIs(attributes.is_attr_set(data), False)

        data = None
        self.assertIs(attributes.is_attr_set(data), False)

        data = "I'm set"
        self.assertIs(attributes.is_attr_set(data), True)

    def test_validate_values(self):
        msg = attributes._validate_values(4, [4, 6])
        self.assertIsNone(msg)

        msg = attributes._validate_values(4, (4, 6))
        self.assertIsNone(msg)

        msg = attributes._validate_values(7, [4, 6])
        self.assertEquals(msg, "'7' is not in [4, 6]")

        msg = attributes._validate_values(7, (4, 6))
        self.assertEquals(msg, "'7' is not in (4, 6)")

    def test_validate_string(self):
        msg = attributes._validate_string(None, None)
        self.assertEquals(msg, "'None' is not a valid string")

        # 0 == len(data) == max_len
        msg = attributes._validate_string("", 0)
        self.assertIsNone(msg)

        # 0 == len(data) < max_len
        msg = attributes._validate_string("", 9)
        self.assertIsNone(msg)

        # 0 < len(data) < max_len
        msg = attributes._validate_string("123456789", 10)
        self.assertIsNone(msg)

        # 0 < len(data) == max_len
        msg = attributes._validate_string("123456789", 9)
        self.assertIsNone(msg)

        # 0 < max_len < len(data)
        msg = attributes._validate_string("1234567890", 9)
        self.assertEquals(msg, "'1234567890' exceeds maximum length of 9")

        msg = attributes._validate_string("123456789", None)
        self.assertIsNone(msg)

    def test_validate_range(self):
        msg = attributes._validate_range(1, [1, 9])
        self.assertIsNone(msg)

        msg = attributes._validate_range(5, [1, 9])
        self.assertIsNone(msg)

        msg = attributes._validate_range(9, [1, 9])
        self.assertIsNone(msg)

        msg = attributes._validate_range(1, (1, 9))
        self.assertIsNone(msg)

        msg = attributes._validate_range(5, (1, 9))
        self.assertIsNone(msg)

        msg = attributes._validate_range(9, (1, 9))
        self.assertIsNone(msg)

        msg = attributes._validate_range(0, [1, 9])
        self.assertEquals(msg, "'0' is not in range 1 through 9")

        msg = attributes._validate_range(10, (1, 9))
        self.assertEquals(msg, "'10' is not in range 1 through 9")

    def test_validate_mac_address(self):
        mac_addr = "ff:16:3e:4f:00:00"
        msg = attributes._validate_mac_address(mac_addr)
        self.assertIsNone(msg)

        mac_addr = "ffa:16:3e:4f:00:00"
        msg = attributes._validate_mac_address(mac_addr)
        self.assertEquals(msg, "'%s' is not a valid MAC address" % mac_addr)

    def test_validate_ip_address(self):
        ip_addr = '1.1.1.1'
        msg = attributes._validate_ip_address(ip_addr)
        self.assertIsNone(msg)

        ip_addr = '1111.1.1.1'
        msg = attributes._validate_ip_address(ip_addr)
        self.assertEquals(msg, "'%s' is not a valid IP address" % ip_addr)

    def test_validate_ip_pools(self):
        pools = [[{'end': '10.0.0.254'}],
                 [{'start': '10.0.0.254'}],
                 [{'start': '1000.0.0.254',
                   'end': '1.1.1.1'}],
                 [{'start': '10.0.0.2', 'end': '10.0.0.254',
                   'forza': 'juve'}],
                 [{'start': '10.0.0.2', 'end': '10.0.0.254'},
                  {'end': '10.0.0.254'}],
                 [None],
                 None]
        for pool in pools:
            msg = attributes._validate_ip_pools(pool)
            self.assertIsNotNone(msg)

        pools = [[{'end': '10.0.0.254', 'start': '10.0.0.2'},
                  {'start': '11.0.0.2', 'end': '11.1.1.1'}],
                 [{'start': '11.0.0.2', 'end': '11.0.0.100'}]]
        for pool in pools:
            msg = attributes._validate_ip_pools(pool)
            self.assertIsNone(msg)

    def test_validate_fixed_ips(self):
        fixed_ips = [[{'subnet_id': '00000000-ffff-ffff-ffff-000000000000',
                       'ip_address': '1111.1.1.1'}],
                     [{'subnet_id': 'invalid'}],
                     None,
                     [{'subnet_id': '00000000-0fff-ffff-ffff-000000000000',
                       'ip_address': '1.1.1.1'},
                      {'subnet_id': '00000000-ffff-ffff-ffff-000000000000',
                       'ip_address': '1.1.1.1'}]]
        for fixed in fixed_ips:
            msg = attributes._validate_fixed_ips(fixed)
            self.assertIsNotNone(msg)

        fixed_ips = [[{'subnet_id': '00000000-ffff-ffff-ffff-000000000000',
                       'ip_address': '1.1.1.1'}],
                     [{'subnet_id': '00000000-0fff-ffff-ffff-000000000000',
                       'ip_address': '1.1.1.1'},
                      {'subnet_id': '00000000-ffff-ffff-ffff-000000000000',
                       'ip_address': '1.1.1.2'}]]
        for fixed in fixed_ips:
            msg = attributes._validate_fixed_ips(fixed)
            self.assertIsNone(msg)

    def test_validate_nameservers(self):
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

    def test_validate_hostroutes(self):
        hostroute_pools = [[{'destination': '100.0.0.0/24'}],
                           [{'nexthop': '10.0.2.20'}],
                           [{'nexthop': '10.0.2.20',
                             'forza': 'juve',
                             'destination': '100.0.0.0/8'}],
                           [{'nexthop': '1110.0.2.20',
                             'destination': '100.0.0.0/8'}],
                           [{'nexthop': '10.0.2.20',
                             'destination': '100.0.0.0'}],
                           [{'nexthop': '10.0.2.20',
                             'destination': '100.0.0.0/8'},
                            {'nexthop': '10.0.2.20',
                             'destination': '100.0.0.0/8'}],
                           [None],
                           None]
        for host_routes in hostroute_pools:
            msg = attributes._validate_hostroutes(host_routes, None)
            self.assertIsNotNone(msg)

        hostroute_pools = [[{'destination': '100.0.0.0/24',
                             'nexthop': '10.0.2.20'}],
                           [{'nexthop': '10.0.2.20',
                             'destination': '100.0.0.0/8'},
                            {'nexthop': '10.0.2.20',
                             'destination': '100.0.0.1/8'}]]
        for host_routes in hostroute_pools:
            msg = attributes._validate_hostroutes(host_routes, None)
            self.assertIsNone(msg)

    def test_validate_ip_address_or_none(self):
        ip_addr = None
        msg = attributes._validate_ip_address_or_none(ip_addr)
        self.assertIsNone(msg)

        ip_addr = '1.1.1.1'
        msg = attributes._validate_ip_address_or_none(ip_addr)
        self.assertIsNone(msg)

        ip_addr = '1111.1.1.1'
        msg = attributes._validate_ip_address_or_none(ip_addr)
        self.assertEquals(msg, "'%s' is not a valid IP address" % ip_addr)

    def test_hostname_pattern(self):
        data = '@openstack'
        msg = attributes._validate_regex(data, attributes.HOSTNAME_PATTERN)
        self.assertIsNotNone(msg)

        data = 'www.openstack.org'
        msg = attributes._validate_regex(data, attributes.HOSTNAME_PATTERN)
        self.assertIsNone(msg)

    def test_uuid_pattern(self):
        data = 'garbage'
        msg = attributes._validate_regex(data, attributes.UUID_PATTERN)
        self.assertIsNotNone(msg)

        data = '00000000-ffff-ffff-ffff-000000000000'
        msg = attributes._validate_regex(data, attributes.UUID_PATTERN)
        self.assertIsNone(msg)

    def test_mac_pattern(self):
        # Valid - 3 octets
        base_mac = "fa:16:3e:00:00:00"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        self.assertIsNone(msg)

        # Valid - 4 octets
        base_mac = "fa:16:3e:4f:00:00"
        msg = attributes._validate_regex(base_mac,
                                         attributes.MAC_PATTERN)
        self.assertIsNone(msg)

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

    def test_validate_subnet(self):
        # Valid - IPv4
        cidr = "10.0.2.0/24"
        msg = attributes._validate_subnet(cidr,
                                          None)
        self.assertIsNone(msg)

        # Valid - IPv6 without final octets
        cidr = "fe80::/24"
        msg = attributes._validate_subnet(cidr,
                                          None)
        self.assertIsNone(msg)

        # Valid - IPv6 with final octets
        cidr = "fe80::0/24"
        msg = attributes._validate_subnet(cidr,
                                          None)
        self.assertIsNone(msg)

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

        # Invalid - Address format error
        cidr = 'invalid'
        msg = attributes._validate_subnet(cidr,
                                          None)
        error = "'%s' is not a valid IP subnet" % cidr
        self.assertEquals(msg, error)

    def test_validate_regex(self):
        pattern = '[hc]at'

        data = None
        msg = attributes._validate_regex(data, pattern)
        self.assertEquals(msg, "'%s' is not a valid input" % data)

        data = 'bat'
        msg = attributes._validate_regex(data, pattern)
        self.assertEquals(msg, "'%s' is not a valid input" % data)

        data = 'hat'
        msg = attributes._validate_regex(data, pattern)
        self.assertIsNone(msg)

        data = 'cat'
        msg = attributes._validate_regex(data, pattern)
        self.assertIsNone(msg)

    def test_validate_uuid(self):
        msg = attributes._validate_uuid('garbage')
        self.assertEquals(msg, "'garbage' is not a valid UUID")

        msg = attributes._validate_uuid('00000000-ffff-ffff-ffff-000000000000')
        self.assertIsNone(msg)


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


class TestConvertToInt(unittest2.TestCase):

    def test_convert_to_int_int(self):
        self.assertEquals(attributes.convert_to_int(-1), -1)
        self.assertEquals(attributes.convert_to_int(0), 0)
        self.assertEquals(attributes.convert_to_int(1), 1)

    def test_convert_to_int_str(self):
        self.assertEquals(attributes.convert_to_int('4'), 4)
        self.assertEquals(attributes.convert_to_int('6'), 6)
        self.assertRaises(q_exc.InvalidInput,
                          attributes.convert_to_int,
                          'garbage')

    def test_convert_to_int_none(self):
        self.assertRaises(q_exc.InvalidInput,
                          attributes.convert_to_int,
                          None)

    def test_convert_none_to_empty_list_none(self):
        self.assertEqual(
            [], attributes.convert_none_to_empty_list(None))

    def test_convert_none_to_empty_list_value(self):
        values = ['1', 3, [], [1], {}, {'a':3}]
        for value in values:
            self.assertEqual(
                value, attributes.convert_none_to_empty_list(value))


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
