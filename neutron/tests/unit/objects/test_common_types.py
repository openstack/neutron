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

from neutron.common import constants
from neutron.objects import common_types
from neutron.tests import base as test_base


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

    def test_stringify(self):
        for in_val, out_val in self.coerce_good_values:
            self.assertEqual("'%s'" % in_val, self.field.stringify(in_val))

    def test_stringify_invalid(self):
        for in_val in self.coerce_bad_values:
            self.assertRaises(ValueError, self.field.stringify, in_val)


class IPV6ModeEnumFieldTest(test_base.BaseTestCase, TestField):
    def setUp(self):
        super(IPV6ModeEnumFieldTest, self).setUp()
        self.field = common_types.IPV6ModeEnumField()
        self.coerce_good_values = [(mode, mode)
                                   for mode in constants.IPV6_MODES]
        self.coerce_bad_values = ['6', 4, 'type', 'slaacc']
        self.to_primitive_values = self.coerce_good_values
        self.from_primitive_values = self.coerce_good_values
