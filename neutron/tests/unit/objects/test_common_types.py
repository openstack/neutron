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
import random

from neutron_lib import constants as const

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

    def test_from_primitive(self):
        class ObjectLikeThing(object):
            _context = 'context'

        for prim_val, out_val in self.from_primitive_values:
            self.assertEqual(out_val, self.field.from_primitive(
                ObjectLikeThing, 'attr', prim_val))

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
                                   for val in constants.VALID_DSCP_MARKS]
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
            tools.get_random_mac(),
        ]
        self.to_primitive_values = self.coerce_good_values
        self.from_primitive_values = self.coerce_good_values

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
        self.to_primitive_values = self.coerce_good_values
        self.from_primitive_values = self.coerce_good_values

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
                                   for val in constants.VALID_DIRECTIONS]
        self.coerce_bad_values = ['test', '8', 10, []]
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
                [str(v) for v in const.IP_PROTOCOL_MAP.values()]
            )
        ]
        self.coerce_bad_values = ['test', 'Udp', 256]
        try:
            # pick a random protocol number that is not in the map of supported
            # protocols
            self.coerce_bad_values.append(
                str(
                    random.choice(
                        list(
                            set(range(256)) -
                            set(const.IP_PROTOCOL_MAP.values())
                        )
                    )
                )
            )
        except IndexError:
            # stay paranoid and guard against the impossible future when all
            # protocols are in the map
            pass
        self.to_primitive_values = self.coerce_good_values
        self.from_primitive_values = self.coerce_good_values

    def test_stringify(self):
        for in_val, out_val in self.coerce_good_values:
            self.assertEqual("'%s'" % in_val, self.field.stringify(in_val))
