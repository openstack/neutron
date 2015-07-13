# Copyright 2012 OpenStack Foundation
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

import string
import testtools

import mock

from neutron.api.v2 import attributes
from neutron.common import exceptions as n_exc
from neutron.tests import base


class TestAttributes(base.BaseTestCase):

    def _construct_dict_and_constraints(self):
        """Constructs a test dictionary and a definition of constraints.
        :return: A (dictionary, constraint) tuple
        """
        constraints = {'key1': {'type:values': ['val1', 'val2'],
                                'required': True},
                       'key2': {'type:string': None,
                                'required': False},
                       'key3': {'type:dict': {'k4': {'type:string': None,
                                                     'required': True}},
                                'required': True}}

        dictionary = {'key1': 'val1',
                      'key2': 'a string value',
                      'key3': {'k4': 'a string value'}}

        return dictionary, constraints

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
        self.assertEqual("'7' is not in [4, 6]", msg)

        msg = attributes._validate_values(7, (4, 6))
        self.assertEqual("'7' is not in (4, 6)", msg)

    def test_validate_not_empty_string(self):
        msg = attributes._validate_not_empty_string('    ', None)
        self.assertEqual(u"'    ' Blank strings are not permitted", msg)

    def test_validate_not_empty_string_or_none(self):
        msg = attributes._validate_not_empty_string_or_none('    ', None)
        self.assertEqual(u"'    ' Blank strings are not permitted", msg)

        msg = attributes._validate_not_empty_string_or_none(None, None)
        self.assertIsNone(msg)

    def test_validate_string_or_none(self):
        msg = attributes._validate_not_empty_string_or_none('test', None)
        self.assertIsNone(msg)

        msg = attributes._validate_not_empty_string_or_none(None, None)
        self.assertIsNone(msg)

    def test_validate_string(self):
        msg = attributes._validate_string(None, None)
        self.assertEqual("'None' is not a valid string", msg)

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
        self.assertEqual("'1234567890' exceeds maximum length of 9", msg)

        msg = attributes._validate_string("123456789", None)
        self.assertIsNone(msg)

    def test_validate_no_whitespace(self):
        data = 'no_white_space'
        result = attributes._validate_no_whitespace(data)
        self.assertEqual(data, result)

        self.assertRaises(n_exc.InvalidInput,
                          attributes._validate_no_whitespace,
                          'i have whitespace')

        self.assertRaises(n_exc.InvalidInput,
                          attributes._validate_no_whitespace,
                          'i\thave\twhitespace')

        for ws in string.whitespace:
            self.assertRaises(n_exc.InvalidInput,
                              attributes._validate_no_whitespace,
                              '%swhitespace-at-head' % ws)
            self.assertRaises(n_exc.InvalidInput,
                              attributes._validate_no_whitespace,
                              'whitespace-at-tail%s' % ws)

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
        self.assertEqual("'0' is too small - must be at least '1'", msg)

        msg = attributes._validate_range(10, (1, 9))
        self.assertEqual("'10' is too large - must be no larger than '9'", msg)

        msg = attributes._validate_range("bogus", (1, 9))
        self.assertEqual("'bogus' is not an integer", msg)

        msg = attributes._validate_range(10, (attributes.UNLIMITED,
                                              attributes.UNLIMITED))
        self.assertIsNone(msg)

        msg = attributes._validate_range(10, (1, attributes.UNLIMITED))
        self.assertIsNone(msg)

        msg = attributes._validate_range(1, (attributes.UNLIMITED, 9))
        self.assertIsNone(msg)

        msg = attributes._validate_range(-1, (0, attributes.UNLIMITED))
        self.assertEqual("'-1' is too small - must be at least '0'", msg)

        msg = attributes._validate_range(10, (attributes.UNLIMITED, 9))
        self.assertEqual("'10' is too large - must be no larger than '9'", msg)

    def _test_validate_mac_address(self, validator, allow_none=False):
        mac_addr = "ff:16:3e:4f:00:00"
        msg = validator(mac_addr)
        self.assertIsNone(msg)

        mac_addr = "ffa:16:3e:4f:00:00"
        msg = validator(mac_addr)
        err_msg = "'%s' is not a valid MAC address"
        self.assertEqual(err_msg % mac_addr, msg)

        mac_addr = "123"
        msg = validator(mac_addr)
        self.assertEqual(err_msg % mac_addr, msg)

        mac_addr = None
        msg = validator(mac_addr)
        if allow_none:
            self.assertIsNone(msg)
        else:
            self.assertEqual(err_msg % mac_addr, msg)

        mac_addr = "ff:16:3e:4f:00:00\r"
        msg = validator(mac_addr)
        self.assertEqual(err_msg % mac_addr, msg)

    def test_validate_mac_address(self):
        self._test_validate_mac_address(attributes._validate_mac_address)

    def test_validate_mac_address_or_none(self):
        self._test_validate_mac_address(
            attributes._validate_mac_address_or_none, allow_none=True)

    def test_validate_ip_address(self):
        ip_addr = '1.1.1.1'
        msg = attributes._validate_ip_address(ip_addr)
        self.assertIsNone(msg)

        ip_addr = '1111.1.1.1'
        msg = attributes._validate_ip_address(ip_addr)
        self.assertEqual("'%s' is not a valid IP address" % ip_addr, msg)

        # Depending on platform to run UTs, this case might or might not be
        # an equivalent to test_validate_ip_address_bsd.
        ip_addr = '1' * 59
        msg = attributes._validate_ip_address(ip_addr)
        self.assertEqual("'%s' is not a valid IP address" % ip_addr, msg)

        ip_addr = '1.1.1.1 has whitespace'
        msg = attributes._validate_ip_address(ip_addr)
        self.assertEqual("'%s' is not a valid IP address" % ip_addr, msg)

        ip_addr = '111.1.1.1\twhitespace'
        msg = attributes._validate_ip_address(ip_addr)
        self.assertEqual("'%s' is not a valid IP address" % ip_addr, msg)

        ip_addr = '111.1.1.1\nwhitespace'
        msg = attributes._validate_ip_address(ip_addr)
        self.assertEqual("'%s' is not a valid IP address" % ip_addr, msg)

        for ws in string.whitespace:
            ip_addr = '%s111.1.1.1' % ws
            msg = attributes._validate_ip_address(ip_addr)
            self.assertEqual("'%s' is not a valid IP address" % ip_addr, msg)

        for ws in string.whitespace:
            ip_addr = '111.1.1.1%s' % ws
            msg = attributes._validate_ip_address(ip_addr)
            self.assertEqual("'%s' is not a valid IP address" % ip_addr, msg)

    def test_validate_ip_address_bsd(self):
        # NOTE(yamamoto):  On NetBSD and OS X, netaddr.IPAddress() accepts
        # '1' * 59 as a valid address.  The behaviour is inherited from
        # libc behaviour there.  This test ensures that our validator reject
        # such addresses on such platforms by mocking netaddr to emulate
        # the behaviour.
        ip_addr = '1' * 59
        with mock.patch('netaddr.IPAddress') as ip_address_cls:
            msg = attributes._validate_ip_address(ip_addr)
        ip_address_cls.assert_called_once_with(ip_addr)
        self.assertEqual("'%s' is not a valid IP address" % ip_addr, msg)

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

        invalid_ip = '10.0.0.2\r'
        pools = [[{'end': '10.0.0.254', 'start': invalid_ip}]]
        for pool in pools:
            msg = attributes._validate_ip_pools(pool)
            self.assertEqual("'%s' is not a valid IP address" % invalid_ip,
                             msg)

    def test_validate_fixed_ips(self):
        fixed_ips = [
            {'data': [{'subnet_id': '00000000-ffff-ffff-ffff-000000000000',
                       'ip_address': '1111.1.1.1'}],
             'error_msg': "'1111.1.1.1' is not a valid IP address"},
            {'data': [{'subnet_id': 'invalid',
                       'ip_address': '1.1.1.1'}],
             'error_msg': "'invalid' is not a valid UUID"},
            {'data': None,
             'error_msg': "Invalid data format for fixed IP: 'None'"},
            {'data': "1.1.1.1",
             'error_msg': "Invalid data format for fixed IP: '1.1.1.1'"},
            {'data': ['00000000-ffff-ffff-ffff-000000000000', '1.1.1.1'],
             'error_msg': "Invalid data format for fixed IP: "
                          "'00000000-ffff-ffff-ffff-000000000000'"},
            {'data': [['00000000-ffff-ffff-ffff-000000000000', '1.1.1.1']],
             'error_msg': "Invalid data format for fixed IP: "
                          "'['00000000-ffff-ffff-ffff-000000000000', "
                          "'1.1.1.1']'"},
            {'data': [{'subnet_id': '00000000-0fff-ffff-ffff-000000000000',
                       'ip_address': '1.1.1.1'},
                      {'subnet_id': '00000000-ffff-ffff-ffff-000000000000',
                       'ip_address': '1.1.1.1'}],
             'error_msg': "Duplicate IP address '1.1.1.1'"}]
        for fixed in fixed_ips:
            msg = attributes._validate_fixed_ips(fixed['data'])
            self.assertEqual(fixed['error_msg'], msg)

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
                    ['1000.0.0.1'],
                    None]

        for ns in ns_pools:
            msg = attributes._validate_nameservers(ns, None)
            self.assertIsNotNone(msg)

        ns_pools = [['100.0.0.2'],
                    ['www.hostname.com'],
                    ['www.great.marathons.to.travel'],
                    ['valid'],
                    ['77.hostname.com'],
                    ['1' * 59],
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
                             'destination': '101.0.0.0/8'}]]
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
        self.assertEqual("'%s' is not a valid IP address" % ip_addr, msg)

    def test_hostname_pattern(self):
        bad_values = ['@openstack', 'ffff.abcdefg' * 26, 'f' * 80, '-hello',
                      'goodbye-', 'example..org']
        for data in bad_values:
            msg = attributes._validate_hostname(data)
            self.assertIsNotNone(msg)

        # All numeric hostnames are allowed per RFC 1123 section 2.1
        good_values = ['www.openstack.org', '1234x', '1234',
                       'openstack-1', 'v.xyz', '1' * 50, 'a1a',
                       'x.x1x', 'x.yz', 'example.org.']
        for data in good_values:
            msg = attributes._validate_hostname(data)
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

    def _test_validate_subnet(self, validator, allow_none=False):
        # Valid - IPv4
        cidr = "10.0.2.0/24"
        msg = validator(cidr, None)
        self.assertIsNone(msg)

        # Valid - IPv6 without final octets
        cidr = "fe80::/24"
        msg = validator(cidr, None)
        self.assertIsNone(msg)

        # Valid - IPv6 with final octets
        cidr = "fe80::/24"
        msg = validator(cidr, None)
        self.assertIsNone(msg)

        # Valid - uncompressed ipv6 address
        cidr = "fe80:0:0:0:0:0:0:0/128"
        msg = validator(cidr, None)
        self.assertIsNone(msg)

        # Valid - ipv6 address with multiple consecutive zero
        cidr = "2001:0db8:0:0:1::1/128"
        msg = validator(cidr, None)
        self.assertIsNone(msg)

        # Valid - ipv6 address with multiple consecutive zero
        cidr = "2001:0db8::1:0:0:1/128"
        msg = validator(cidr, None)
        self.assertIsNone(msg)

        # Valid - ipv6 address with multiple consecutive zero
        cidr = "2001::0:1:0:0:1100/120"
        msg = validator(cidr, None)
        self.assertIsNone(msg)

        # Valid - abbreviated ipv4 address
        cidr = "10/24"
        msg = validator(cidr, None)
        self.assertIsNone(msg)

        # Invalid - IPv4 missing mask
        cidr = "10.0.2.0"
        msg = validator(cidr, None)
        error = _("'%(data)s' isn't a recognized IP subnet cidr,"
                  " '%(cidr)s' is recommended") % {"data": cidr,
                                                   "cidr": "10.0.2.0/32"}
        self.assertEqual(error, msg)

        # Valid - IPv4 with non-zero masked bits is ok
        for i in range(1, 255):
            cidr = "192.168.1.%s/24" % i
            msg = validator(cidr, None)
            self.assertIsNone(msg)

        # Invalid - IPv6 without final octets, missing mask
        cidr = "fe80::"
        msg = validator(cidr, None)
        error = _("'%(data)s' isn't a recognized IP subnet cidr,"
                  " '%(cidr)s' is recommended") % {"data": cidr,
                                                   "cidr": "fe80::/128"}
        self.assertEqual(error, msg)

        # Invalid - IPv6 with final octets, missing mask
        cidr = "fe80::0"
        msg = validator(cidr, None)
        error = _("'%(data)s' isn't a recognized IP subnet cidr,"
                  " '%(cidr)s' is recommended") % {"data": cidr,
                                                   "cidr": "fe80::/128"}
        self.assertEqual(error, msg)

        # Invalid - Address format error
        cidr = 'invalid'
        msg = validator(cidr, None)
        error = "'%s' is not a valid IP subnet" % cidr
        self.assertEqual(error, msg)

        cidr = None
        msg = validator(cidr, None)
        if allow_none:
            self.assertIsNone(msg)
        else:
            error = "'%s' is not a valid IP subnet" % cidr
            self.assertEqual(error, msg)

        # Invalid - IPv4 with trailing CR
        cidr = "10.0.2.0/24\r"
        msg = validator(cidr, None)
        error = "'%s' is not a valid IP subnet" % cidr
        self.assertEqual(error, msg)

    def test_validate_subnet(self):
        self._test_validate_subnet(attributes._validate_subnet)

    def test_validate_subnet_or_none(self):
        self._test_validate_subnet(attributes._validate_subnet_or_none,
                                   allow_none=True)

    def _test_validate_regex(self, validator, allow_none=False):
        pattern = '[hc]at'

        data = None
        msg = validator(data, pattern)
        if allow_none:
            self.assertIsNone(msg)
        else:
            self.assertEqual("'None' is not a valid input", msg)

        data = 'bat'
        msg = validator(data, pattern)
        self.assertEqual("'%s' is not a valid input" % data, msg)

        data = 'hat'
        msg = validator(data, pattern)
        self.assertIsNone(msg)

        data = 'cat'
        msg = validator(data, pattern)
        self.assertIsNone(msg)

    def test_validate_regex(self):
        self._test_validate_regex(attributes._validate_regex)

    def test_validate_regex_or_none(self):
        self._test_validate_regex(attributes._validate_regex_or_none,
                                  allow_none=True)

    def test_validate_uuid(self):
        msg = attributes._validate_uuid('garbage')
        self.assertEqual("'garbage' is not a valid UUID", msg)

        msg = attributes._validate_uuid('00000000-ffff-ffff-ffff-000000000000')
        self.assertIsNone(msg)

    def test_validate_uuid_list(self):
        # check not a list
        uuids = [None,
                 123,
                 'e5069610-744b-42a7-8bd8-ceac1a229cd4',
                 '12345678123456781234567812345678',
                 {'uuid': 'e5069610-744b-42a7-8bd8-ceac1a229cd4'}]
        for uuid in uuids:
            msg = attributes._validate_uuid_list(uuid)
            error = "'%s' is not a list" % uuid
            self.assertEqual(error, msg)

        # check invalid uuid in a list
        invalid_uuid_lists = [[None],
                              [123],
                              [123, 'e5069610-744b-42a7-8bd8-ceac1a229cd4'],
                              ['123', '12345678123456781234567812345678'],
                              ['t5069610-744b-42a7-8bd8-ceac1a229cd4'],
                              ['e5069610-744b-42a7-8bd8-ceac1a229cd44'],
                              ['e50696100-744b-42a7-8bd8-ceac1a229cd4'],
                              ['e5069610-744bb-42a7-8bd8-ceac1a229cd4']]
        for uuid_list in invalid_uuid_lists:
            msg = attributes._validate_uuid_list(uuid_list)
            error = "'%s' is not a valid UUID" % uuid_list[0]
            self.assertEqual(error, msg)

        # check duplicate items in a list
        duplicate_uuids = ['e5069610-744b-42a7-8bd8-ceac1a229cd4',
                           'f3eeab00-8367-4524-b662-55e64d4cacb5',
                           'e5069610-744b-42a7-8bd8-ceac1a229cd4']
        msg = attributes._validate_uuid_list(duplicate_uuids)
        error = ("Duplicate items in the list: "
                 "'%s'" % ', '.join(duplicate_uuids))
        self.assertEqual(error, msg)

        # check valid uuid lists
        valid_uuid_lists = [['e5069610-744b-42a7-8bd8-ceac1a229cd4'],
                            ['f3eeab00-8367-4524-b662-55e64d4cacb5'],
                            ['e5069610-744b-42a7-8bd8-ceac1a229cd4',
                             'f3eeab00-8367-4524-b662-55e64d4cacb5']]
        for uuid_list in valid_uuid_lists:
            msg = attributes._validate_uuid_list(uuid_list)
            self.assertIsNone(msg)

    def test_validate_dict_type(self):
        for value in (None, True, '1', []):
            self.assertEqual("'%s' is not a dictionary" % value,
                             attributes._validate_dict(value))

    def test_validate_dict_without_constraints(self):
        msg = attributes._validate_dict({})
        self.assertIsNone(msg)

        # Validate a dictionary without constraints.
        msg = attributes._validate_dict({'key': 'value'})
        self.assertIsNone(msg)

    def test_validate_a_valid_dict_with_constraints(self):
        dictionary, constraints = self._construct_dict_and_constraints()

        msg = attributes._validate_dict(dictionary, constraints)
        self.assertIsNone(msg, 'Validation of a valid dictionary failed.')

    def test_validate_dict_with_invalid_validator(self):
        dictionary, constraints = self._construct_dict_and_constraints()

        constraints['key1'] = {'type:unsupported': None, 'required': True}
        msg = attributes._validate_dict(dictionary, constraints)
        self.assertEqual("Validator 'type:unsupported' does not exist.", msg)

    def test_validate_dict_not_required_keys(self):
        dictionary, constraints = self._construct_dict_and_constraints()

        del dictionary['key2']
        msg = attributes._validate_dict(dictionary, constraints)
        self.assertIsNone(msg, 'Field that was not required by the specs was'
                               'required by the validator.')

    def test_validate_dict_required_keys(self):
        dictionary, constraints = self._construct_dict_and_constraints()

        del dictionary['key1']
        msg = attributes._validate_dict(dictionary, constraints)
        self.assertIn('Expected keys:', msg)

    def test_validate_dict_wrong_values(self):
        dictionary, constraints = self._construct_dict_and_constraints()

        dictionary['key1'] = 'UNSUPPORTED'
        msg = attributes._validate_dict(dictionary, constraints)
        self.assertIsNotNone(msg)

    def test_validate_dict_convert_boolean(self):
        dictionary, constraints = self._construct_dict_and_constraints()

        constraints['key_bool'] = {
            'type:boolean': None,
            'required': False,
            'convert_to': attributes.convert_to_boolean}
        dictionary['key_bool'] = 'true'
        msg = attributes._validate_dict(dictionary, constraints)
        self.assertIsNone(msg)
        # Explicitly comparing with literal 'True' as assertTrue
        # succeeds also for 'true'
        self.assertIs(True, dictionary['key_bool'])

    def test_subdictionary(self):
        dictionary, constraints = self._construct_dict_and_constraints()

        del dictionary['key3']['k4']
        dictionary['key3']['k5'] = 'a string value'
        msg = attributes._validate_dict(dictionary, constraints)
        self.assertIn('Expected keys:', msg)

    def test_validate_dict_or_none(self):
        dictionary, constraints = self._construct_dict_and_constraints()

        # Check whether None is a valid value.
        msg = attributes._validate_dict_or_none(None, constraints)
        self.assertIsNone(msg, 'Validation of a None dictionary failed.')

        # Check validation of a regular dictionary.
        msg = attributes._validate_dict_or_none(dictionary, constraints)
        self.assertIsNone(msg, 'Validation of a valid dictionary failed.')

    def test_validate_dict_or_empty(self):
        dictionary, constraints = self._construct_dict_and_constraints()

        # Check whether an empty dictionary is valid.
        msg = attributes._validate_dict_or_empty({}, constraints)
        self.assertIsNone(msg, 'Validation of a None dictionary failed.')

        # Check validation of a regular dictionary.
        msg = attributes._validate_dict_or_none(dictionary, constraints)
        self.assertIsNone(msg, 'Validation of a valid dictionary failed.')
        self.assertIsNone(msg, 'Validation of a valid dictionary failed.')

    def test_validate_non_negative(self):
        for value in (-1, '-2'):
            self.assertEqual("'%s' should be non-negative" % value,
                             attributes._validate_non_negative(value))

        for value in (0, 1, '2', True, False):
            msg = attributes._validate_non_negative(value)
            self.assertIsNone(msg)


class TestConvertToBoolean(base.BaseTestCase):

    def test_convert_to_boolean_bool(self):
        self.assertIs(attributes.convert_to_boolean(True), True)
        self.assertIs(attributes.convert_to_boolean(False), False)

    def test_convert_to_boolean_int(self):
        self.assertIs(attributes.convert_to_boolean(0), False)
        self.assertIs(attributes.convert_to_boolean(1), True)
        self.assertRaises(n_exc.InvalidInput,
                          attributes.convert_to_boolean,
                          7)

    def test_convert_to_boolean_str(self):
        self.assertIs(attributes.convert_to_boolean('True'), True)
        self.assertIs(attributes.convert_to_boolean('true'), True)
        self.assertIs(attributes.convert_to_boolean('False'), False)
        self.assertIs(attributes.convert_to_boolean('false'), False)
        self.assertIs(attributes.convert_to_boolean('0'), False)
        self.assertIs(attributes.convert_to_boolean('1'), True)
        self.assertRaises(n_exc.InvalidInput,
                          attributes.convert_to_boolean,
                          '7')


class TestConvertToInt(base.BaseTestCase):

    def test_convert_to_int_int(self):
        self.assertEqual(-1, attributes.convert_to_int(-1))
        self.assertEqual(0, attributes.convert_to_int(0))
        self.assertEqual(1, attributes.convert_to_int(1))

    def test_convert_to_int_if_not_none(self):
        self.assertEqual(-1, attributes.convert_to_int_if_not_none(-1))
        self.assertEqual(0, attributes.convert_to_int_if_not_none(0))
        self.assertEqual(1, attributes.convert_to_int_if_not_none(1))
        self.assertIsNone(attributes.convert_to_int_if_not_none(None))

    def test_convert_to_int_str(self):
        self.assertEqual(4, attributes.convert_to_int('4'))
        self.assertEqual(6, attributes.convert_to_int('6'))
        self.assertRaises(n_exc.InvalidInput,
                          attributes.convert_to_int,
                          'garbage')

    def test_convert_to_int_none(self):
        self.assertRaises(n_exc.InvalidInput,
                          attributes.convert_to_int,
                          None)

    def test_convert_none_to_empty_list_none(self):
        self.assertEqual([], attributes.convert_none_to_empty_list(None))

    def test_convert_none_to_empty_dict(self):
        self.assertEqual({}, attributes.convert_none_to_empty_dict(None))

    def test_convert_none_to_empty_list_value(self):
        values = ['1', 3, [], [1], {}, {'a': 3}]
        for value in values:
            self.assertEqual(
                value, attributes.convert_none_to_empty_list(value))


class TestConvertToFloat(base.BaseTestCase):
    # NOTE: the routine being tested here is a plugin-specific extension
    # module. As the plugin split proceed towards its second phase this
    # test should either be remove, or the validation routine moved into
    # neutron.api.v2.attributes

    def test_convert_to_float_positve_value(self):
        self.assertEqual(
            1.111, attributes.convert_to_positive_float_or_none(1.111))
        self.assertEqual(1, attributes.convert_to_positive_float_or_none(1))
        self.assertEqual(0, attributes.convert_to_positive_float_or_none(0))

    def test_convert_to_float_negative_value(self):
        self.assertRaises(n_exc.InvalidInput,
                          attributes.convert_to_positive_float_or_none,
                          -1.11)

    def test_convert_to_float_string(self):
        self.assertEqual(4, attributes.convert_to_positive_float_or_none('4'))
        self.assertEqual(
            4.44, attributes.convert_to_positive_float_or_none('4.44'))
        self.assertRaises(n_exc.InvalidInput,
                          attributes.convert_to_positive_float_or_none,
                          'garbage')

    def test_convert_to_float_none_value(self):
        self.assertIsNone(attributes.convert_to_positive_float_or_none(None))


class TestConvertKvp(base.BaseTestCase):

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
        with testtools.ExpectedException(n_exc.InvalidInput):
            attributes.convert_kvp_str_to_list('=a')

    def test_convert_kvp_str_to_list_fails_for_missing_equals(self):
        with testtools.ExpectedException(n_exc.InvalidInput):
            attributes.convert_kvp_str_to_list('a')

    def test_convert_kvp_str_to_list_succeeds_for_one_equals(self):
        result = attributes.convert_kvp_str_to_list('a=')
        self.assertEqual(['a', ''], result)

    def test_convert_kvp_str_to_list_succeeds_for_two_equals(self):
        result = attributes.convert_kvp_str_to_list('a=a=a')
        self.assertEqual(['a', 'a=a'], result)


class TestConvertToList(base.BaseTestCase):

    def test_convert_to_empty_list(self):
        for item in (None, [], (), {}):
            self.assertEqual([], attributes.convert_to_list(item))

    def test_convert_to_list_string(self):
        for item in ('', 'foo'):
            self.assertEqual([item], attributes.convert_to_list(item))

    def test_convert_to_list_iterable(self):
        for item in ([None], [1, 2, 3], (1, 2, 3), set([1, 2, 3]), ['foo']):
            self.assertEqual(list(item), attributes.convert_to_list(item))

    def test_convert_to_list_non_iterable(self):
        for item in (True, False, 1, 1.2, object()):
            self.assertEqual([item], attributes.convert_to_list(item))
