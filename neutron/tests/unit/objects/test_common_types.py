# Copyright 2016 OpenStack Foundation
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

import abc
import itertools

from neutron_lib import constants as const
from neutron_lib.db import constants as db_const
from neutron_lib.utils import net
from oslo_serialization import jsonutils

from neutron.common import constants
from neutron.objects import common_types
from neutron.tests import base as test_base
from neutron.tests import tools


class TestField(object):

    def test_coerce_good_values(self):
        for in_val, out_val in self.coerce_good_values:
            self.assertEqual(out_val, self.field.coerce('obj', 'attr', in_val))

    def test_coerce_bad_values(self):
        for in_val in self.coerce_bad_values:
            self.assertRaises((TypeError, ValueError),
                              self.field.coerce, 'obj', 'attr', in_val)

    def test_to_primitive(self):
        for in_val, prim_val in self.to_primitive_values:
            self.assertEqual(prim_val, self.field.to_primitive('obj', 'attr',
                                                               in_val))

    def test_to_primitive_json_serializable(self):
        for in_val, _ in self.to_primitive_values:
            prim = self.field.to_primitive('obj', 'attr', in_val)
            jsencoded = jsonutils.dumps(prim)
            self.assertEqual(prim, jsonutils.loads(jsencoded))

    def test_from_primitive(self):
        class ObjectLikeThing(object):
            _context = 'context'

        for prim_val, out_val in self.from_primitive_values:
            from_prim = self.field.from_primitive(ObjectLikeThing, 'attr',
                                                  prim_val)
            self.assertEqual(out_val, from_prim)
            # ensure it's coercable for sanity
            self.field.coerce('obj', 'attr', from_prim)

    @abc.abstractmethod
    def test_stringify(self):
        '''This test should validate stringify() format for new field types.'''


class IPV6ModeEnumFieldTest(test_base.BaseTestCase, TestField):
    def setUp(self):
        super(IPV6ModeEnumFieldTest, self).setUp()
        self.field = common_types.IPV6ModeEnumField()
        self.coerce_good_values = [(mode, mode)
                                   for mode in const.IPV6_MODES]
        self.coerce_bad_values = ['6', 4, 'type', 'slaacc']
        self.to_primitive_values = self.coerce_good_values
        self.from_primitive_values = self.coerce_good_values

    def test_stringify(self):
        for in_val, out_val in self.coerce_good_values:
            self.assertEqual("'%s'" % in_val, self.field.stringify(in_val))


class DscpMarkFieldTest(test_base.BaseTestCase, TestField):
    def setUp(self):
        super(DscpMarkFieldTest, self).setUp()
        self.field = common_types.DscpMarkField()
        self.coerce_good_values = [(val, val)
                                   for val in const.VALID_DSCP_MARKS]
        self.coerce_bad_values = ['6', 'str', [], {}, object()]
        self.to_primitive_values = self.coerce_good_values
        self.from_primitive_values = self.coerce_good_values

    def test_stringify(self):
        for in_val, out_val in self.coerce_good_values:
            self.assertEqual("%s" % in_val, self.field.stringify(in_val))


class IPNetworkPrefixLenFieldTest(test_base.BaseTestCase, TestField):
    def setUp(self):
        super(IPNetworkPrefixLenFieldTest, self).setUp()
        self.field = common_types.IPNetworkPrefixLenField()
        self.coerce_good_values = [(x, x) for x in (0, 32, 128, 42)]
        self.coerce_bad_values = ['len', '1', 129, -1]
        self.to_primitive_values = self.coerce_good_values
        self.from_primitive_values = self.coerce_good_values

    def test_stringify(self):
        for in_val, out_val in self.coerce_good_values:
            self.assertEqual("%s" % in_val, self.field.stringify(in_val))


class MACAddressFieldTest(test_base.BaseTestCase, TestField):
    def setUp(self):
        super(MACAddressFieldTest, self).setUp()
        self.field = common_types.MACAddressField()
        mac1 = tools.get_random_EUI()
        mac2 = tools.get_random_EUI()
        self.coerce_good_values = [(mac1, mac1), (mac2, mac2)]
        self.coerce_bad_values = [
            'XXXX', 'ypp', 'g3:vvv',
            # the field type is strict and does not allow to pass strings, even
            # if they represent a valid MAC address
            net.get_random_mac('fe:16:3e:00:00:00'.split(':')),
        ]
        self.to_primitive_values = ((a1, str(a2))
                                    for a1, a2 in self.coerce_good_values)
        self.from_primitive_values = ((a2, a1)
                                      for a1, a2 in self.to_primitive_values)

    def test_stringify(self):
        for in_val, out_val in self.coerce_good_values:
            self.assertEqual('%s' % in_val, self.field.stringify(in_val))


class IPNetworkFieldTest(test_base.BaseTestCase, TestField):
    def setUp(self):
        super(IPNetworkFieldTest, self).setUp()
        self.field = common_types.IPNetworkField()
        addrs = [
            tools.get_random_ip_network(version=ip_version)
            for ip_version in constants.IP_ALLOWED_VERSIONS
        ]
        self.coerce_good_values = [(addr, addr) for addr in addrs]
        self.coerce_bad_values = [
            'ypp', 'g3:vvv',
            # the field type is strict and does not allow to pass strings, even
            # if they represent a valid IP network
            '10.0.0.0/24',
        ]
        self.to_primitive_values = ((a1, str(a2))
                                    for a1, a2 in self.coerce_good_values)
        self.from_primitive_values = ((a2, a1)
                                      for a1, a2 in self.to_primitive_values)

    def test_stringify(self):
        for in_val, out_val in self.coerce_good_values:
            self.assertEqual('%s' % in_val, self.field.stringify(in_val))


class IPVersionEnumFieldTest(test_base.BaseTestCase, TestField):
    def setUp(self):
        super(IPVersionEnumFieldTest, self).setUp()
        self.field = common_types.IPVersionEnumField()
        self.coerce_good_values = [(val, val)
                                   for val in constants.IP_ALLOWED_VERSIONS]
        self.coerce_bad_values = [5, 0, -1, 'str']
        self.to_primitive_values = self.coerce_good_values
        self.from_primitive_values = self.coerce_good_values

    def test_stringify(self):
        for in_val, out_val in self.coerce_good_values:
            self.assertEqual("%s" % in_val, self.field.stringify(in_val))


class FlowDirectionEnumFieldTest(test_base.BaseTestCase, TestField):
    def setUp(self):
        super(FlowDirectionEnumFieldTest, self).setUp()
        self.field = common_types.FlowDirectionEnumField()
        self.coerce_good_values = [(val, val)
                                   for val in const.VALID_DIRECTIONS]
        self.coerce_bad_values = ['test', '8', 10, []]
        self.to_primitive_values = self.coerce_good_values
        self.from_primitive_values = self.coerce_good_values

    def test_stringify(self):
        for in_val, out_val in self.coerce_good_values:
            self.assertEqual("'%s'" % in_val, self.field.stringify(in_val))


class DomainNameFieldTest(test_base.BaseTestCase, TestField):
    def setUp(self):
        super(DomainNameFieldTest, self).setUp()
        self.field = common_types.DomainNameField()
        self.coerce_good_values = [
            (val, val)
            for val in ('www.google.com', 'hostname', '1abc.com')
        ]
        self.coerce_bad_values = ['x' * (db_const.FQDN_FIELD_SIZE + 1), 10, []]
        self.to_primitive_values = self.coerce_good_values
        self.from_primitive_values = self.coerce_good_values

    def test_stringify(self):
        for in_val, out_val in self.coerce_good_values:
            self.assertEqual("'%s'" % in_val, self.field.stringify(in_val))


class EtherTypeEnumFieldTest(test_base.BaseTestCase, TestField):
    def setUp(self):
        super(EtherTypeEnumFieldTest, self).setUp()
        self.field = common_types.EtherTypeEnumField()
        self.coerce_good_values = [(val, val)
                                   for val in constants.VALID_ETHERTYPES]
        self.coerce_bad_values = ['IpV4', 8, 'str', 'ipv6']
        self.to_primitive_values = self.coerce_good_values
        self.from_primitive_values = self.coerce_good_values

    def test_stringify(self):
        for in_val, out_val in self.coerce_good_values:
            self.assertEqual("'%s'" % in_val, self.field.stringify(in_val))


class IpProtocolEnumFieldTest(test_base.BaseTestCase, TestField):
    def setUp(self):
        super(IpProtocolEnumFieldTest, self).setUp()
        self.field = common_types.IpProtocolEnumField()
        self.coerce_good_values = [
            (val, val)
            for val in itertools.chain(
                const.IP_PROTOCOL_MAP.keys(),
                [str(v) for v in range(256)]
            )
        ]
        self.coerce_bad_values = ['test', 'Udp', 256]
        self.to_primitive_values = self.coerce_good_values
        self.from_primitive_values = self.coerce_good_values

    def test_stringify(self):
        for in_val, out_val in self.coerce_good_values:
            self.assertEqual("'%s'" % in_val, self.field.stringify(in_val))


class UUIDFieldTest(test_base.BaseTestCase, TestField):
    def setUp(self):
        super(UUIDFieldTest, self).setUp()
        self.field = common_types.UUIDField()
        self.coerce_good_values = [
            ('f1d9cb3f-c263-45d3-907c-d12a9ef1629e',
                'f1d9cb3f-c263-45d3-907c-d12a9ef1629e'),
            ('7188f6637cbd4097a3b1d1bb7897c7c0',
                '7188f6637cbd4097a3b1d1bb7897c7c0')]
        self.coerce_bad_values = [
            'f1d9cb3f-c263-45d3-907c-d12a9ef16zzz',
            '7188f6637cbd4097a3b1d1bb7897']
        self.to_primitive_values = self.coerce_good_values
        self.from_primitive_values = self.coerce_good_values

    def test_stringify(self):
        for in_val, out_val in self.coerce_good_values:
            self.assertEqual('%s' % in_val, self.field.stringify(in_val))


class DictOfMiscValuesFieldTest(test_base.BaseTestCase, TestField):
    def setUp(self):
        super(DictOfMiscValuesFieldTest, self).setUp()
        self.field = common_types.DictOfMiscValues
        test_dict_1 = {'a': True,
                       'b': 1.23,
                       'c': ['1', 1.23, True],
                       'd': {'aa': 'zz'},
                       'e': '10.0.0.1'}
        test_dict_str = jsonutils.dumps(test_dict_1)
        self.coerce_good_values = [
            (test_dict_1, test_dict_1),
            (test_dict_str, test_dict_1)
        ]
        self.coerce_bad_values = [str(test_dict_1), '{"a":}']
        self.to_primitive_values = [
            (test_dict_1, test_dict_str)
        ]
        self.from_primitive_values = [
            (test_dict_str, test_dict_1)
        ]

    def test_stringify(self):
        for in_val, out_val in self.coerce_good_values:
            self.assertEqual(jsonutils.dumps(in_val),
                             self.field.stringify(in_val))
