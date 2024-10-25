# Copyright (c) 2015 Red Hat, Inc.
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

from neutron.db import db_base_plugin_common
from neutron.tests import base


class DummyObject:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def to_dict(self):
        return self.kwargs


class ConvertToDictTestCase(base.BaseTestCase):

    @db_base_plugin_common.convert_result_to_dict
    def method_dict(self, fields=None):
        return DummyObject(one=1, two=2, three=3)

    @db_base_plugin_common.convert_result_to_dict
    def method_list(self):
        return [DummyObject(one=1, two=2, three=3)] * 3

    def test_simple_object(self):
        expected = {'one': 1, 'two': 2, 'three': 3}
        observed = self.method_dict()
        self.assertEqual(expected, observed)

    def test_list_of_objects(self):
        expected = [{'one': 1, 'two': 2, 'three': 3}] * 3
        observed = self.method_list()
        self.assertEqual(expected, observed)


class FilterFieldsTestCase(base.BaseTestCase):

    @db_base_plugin_common.filter_fields
    def method_dict(self, fields=None):
        return {'one': 1, 'two': 2, 'three': 3}

    @db_base_plugin_common.filter_fields
    def method_list(self, fields=None):
        return [self.method_dict() for _ in range(3)]

    @db_base_plugin_common.filter_fields
    def method_multiple_arguments(self, not_used, fields=None,
                                  also_not_used=None):
        return {'one': 1, 'two': 2, 'three': 3}

    def test_no_fields(self):
        expected = {'one': 1, 'two': 2, 'three': 3}
        observed = self.method_dict()
        self.assertEqual(expected, observed)

    def test_dict(self):
        expected = {'two': 2}
        observed = self.method_dict(['two'])
        self.assertEqual(expected, observed)

    def test_list(self):
        expected = [{'two': 2}, {'two': 2}, {'two': 2}]
        observed = self.method_list(['two'])
        self.assertEqual(expected, observed)

    def test_multiple_arguments_positional(self):
        expected = {'two': 2}
        observed = self.method_multiple_arguments([], ['two'])
        self.assertEqual(expected, observed)

    def test_multiple_arguments_positional_and_keywords(self):
        expected = {'two': 2}
        observed = self.method_multiple_arguments(fields=['two'],
                                                  not_used=None)
        self.assertEqual(expected, observed)

    def test_multiple_arguments_keyword(self):
        expected = {'two': 2}
        observed = self.method_multiple_arguments([], fields=['two'])
        self.assertEqual(expected, observed)
