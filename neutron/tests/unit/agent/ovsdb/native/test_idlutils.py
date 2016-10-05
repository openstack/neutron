# Copyright 2016, Mirantis Inc.
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

from neutron.agent.ovsdb import api
from neutron.agent.ovsdb.native import idlutils
from neutron.tests import base


class MockColumn(object):
    def __init__(self, name, type, is_optional=False, test_value=None):
        self.name = name
        self.type = mock.MagicMock(
            **{"key.type.name": type,
               "is_optional": mock.Mock(return_value=is_optional),
               })
        # for test purposes only to operate with some values in condition_match
        # testcase
        self.test_value = test_value


class MockTable(object):
    def __init__(self, name, *columns):
        # columns is a list of tuples (col_name, col_type)
        self.name = name
        self.columns = {c.name: c for c in columns}


class MockRow(object):
    def __init__(self, table):
        self._table = table

    def __getattr__(self, attr):
        if attr in self._table.columns:
            return self._table.columns[attr].test_value
        return super(MockRow, self).__getattr__(attr)


class MockCommand(api.Command):
    def __init__(self, result):
        self.result = result

    def execute(self, **kwargs):
        pass


class TestIdlUtils(base.BaseTestCase):
    def test_condition_match(self):
        """
        Make sure that the function respects the following:
        * if column type is_optional and value is a single element, value is
          transformed to a length-1-list
        * any other value is returned as it is, no type convertions
        """
        table = MockTable("SomeTable",
                          MockColumn("tag", "integer", is_optional=True,
                                     test_value=[42]),
                          MockColumn("num", "integer", is_optional=True,
                                     test_value=[]),
                          MockColumn("ids", "integer", is_optional=False,
                                     test_value=42),
                          MockColumn("comments", "string",
                                     test_value=["a", "b", "c"]),
                          MockColumn("status", "string",
                                     test_value="sorry for inconvenience"))
        row = MockRow(table=table)
        self.assertTrue(idlutils.condition_match(row, ("tag", "=", 42)))
        # optional types can be compared only as single elements
        self.assertRaises(ValueError,
                          idlutils.condition_match, row, ("tag", "!=", [42]))
        # empty list comparison is ok for optional types though
        self.assertTrue(idlutils.condition_match(row, ("tag", "!=", [])))
        self.assertTrue(idlutils.condition_match(row, ("num", "=", [])))
        # value = [] may be compared to a single elem if optional column type
        self.assertTrue(idlutils.condition_match(row, ("num", "!=", 42)))
        # no type conversion for non optional types
        self.assertTrue(idlutils.condition_match(row, ("ids", "=", 42)))
        self.assertTrue(idlutils.condition_match(
            row, ("status", "=", "sorry for inconvenience")))
        self.assertFalse(idlutils.condition_match(
            row, ("status", "=", "sorry")))
        # bad types
        self.assertRaises(ValueError,
                          idlutils.condition_match, row, ("ids", "=", "42"))
        self.assertRaises(ValueError,
                          idlutils.condition_match, row, ("ids", "!=", "42"))
        self.assertRaises(ValueError,
                          idlutils.condition_match, row,
                          ("ids", "!=", {"a": "b"}))
        # non optional list types are kept as they are
        self.assertTrue(idlutils.condition_match(
            row, ("comments", "=", ["c", "b", "a"])))
        # also true because list comparison is relaxed
        self.assertTrue(idlutils.condition_match(
            row, ("comments", "=", ["c", "b"])))
        self.assertTrue(idlutils.condition_match(
            row, ("comments", "!=", ["d"])))

    def test_db_replace_record_dict(self):
        obj = {'a': 1, 'b': 2}
        self.assertIs(obj, idlutils.db_replace_record(obj))

    def test_db_replace_record_dict_cmd(self):
        obj = {'a': 1, 'b': MockCommand(2)}
        res = {'a': 1, 'b': 2}
        self.assertEqual(res, idlutils.db_replace_record(obj))

    def test_db_replace_record_list(self):
        obj = [1, 2, 3]
        self.assertIs(obj, idlutils.db_replace_record(obj))

    def test_db_replace_record_list_cmd(self):
        obj = [1, MockCommand(2), 3]
        res = [1, 2, 3]
        self.assertEqual(res, idlutils.db_replace_record(obj))

    def test_db_replace_record_tuple(self):
        obj = (1, 2, 3)
        self.assertIs(obj, idlutils.db_replace_record(obj))

    def test_db_replace_record_tuple_cmd(self):
        obj = (1, MockCommand(2), 3)
        res = (1, 2, 3)
        self.assertEqual(res, idlutils.db_replace_record(obj))

    def test_db_replace_record(self):
        obj = "test"
        self.assertIs(obj, idlutils.db_replace_record(obj))

    def test_db_replace_record_cmd(self):
        obj = MockCommand("test")
        self.assertEqual("test", idlutils.db_replace_record(obj))
