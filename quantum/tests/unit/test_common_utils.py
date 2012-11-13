# Copyright (c) 2012 OpenStack, LLC.
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

import unittest2 as unittest

from quantum.common import utils


class TestParseMappings(unittest.TestCase):
    def parse(self, mapping_list, unique_values=True):
        return utils.parse_mappings(mapping_list, unique_values)

    def test_parse_mappings_fails_for_missing_separator(self):
        with self.assertRaises(ValueError):
            self.parse(['key'])

    def test_parse_mappings_fails_for_missing_key(self):
        with self.assertRaises(ValueError):
            self.parse([':val'])

    def test_parse_mappings_fails_for_missing_value(self):
        with self.assertRaises(ValueError):
            self.parse(['key:'])

    def test_parse_mappings_fails_for_extra_separator(self):
        with self.assertRaises(ValueError):
            self.parse(['key:val:junk'])

    def test_parse_mappings_fails_for_duplicate_key(self):
        with self.assertRaises(ValueError):
            self.parse(['key:val1', 'key:val2'])

    def test_parse_mappings_fails_for_duplicate_value(self):
        with self.assertRaises(ValueError):
            self.parse(['key1:val', 'key2:val'])

    def test_parse_mappings_succeeds_for_one_mapping(self):
        self.assertEqual(self.parse(['key:val']), {'key': 'val'})

    def test_parse_mappings_succeeds_for_n_mappings(self):
        self.assertEqual(self.parse(['key1:val1', 'key2:val2']),
                         {'key1': 'val1', 'key2': 'val2'})

    def test_parse_mappings_succeeds_for_duplicate_value(self):
        self.assertEqual(self.parse(['key1:val', 'key2:val'], False),
                         {'key1': 'val', 'key2': 'val'})

    def test_parse_mappings_succeeds_for_no_mappings(self):
        self.assertEqual(self.parse(['']), {})
