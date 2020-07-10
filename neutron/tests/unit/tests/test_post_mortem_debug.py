# Copyright 2013 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import sys
from unittest import mock

from neutron.tests import base
from neutron.tests import post_mortem_debug


class TestTesttoolsExceptionHandler(base.BaseTestCase):

    def test_exception_handler(self):
        try:
            self.fail()
        except Exception:
            exc_info = sys.exc_info()
        with mock.patch('traceback.print_exception') as mock_print_exception:
            with mock.patch('pdb.post_mortem') as mock_post_mortem:
                with mock.patch.object(post_mortem_debug,
                                       'get_ignored_traceback',
                                       return_value=mock.Mock()):
                    post_mortem_debug.get_exception_handler('pdb')(exc_info)

        # traceback will become post_mortem_debug.FilteredTraceback
        filtered_exc_info = (exc_info[0], exc_info[1], mock.ANY)
        mock_print_exception.assert_called_once_with(*filtered_exc_info)
        mock_post_mortem.assert_called_once_with(mock.ANY)

    def test__get_debugger(self):
        def import_mock(name, *args):
            mod_mock = mock.Mock()
            mod_mock.__name__ = name
            mod_mock.post_mortem = mock.Mock()
            return mod_mock

        with mock.patch('builtins.__import__', side_effect=import_mock):
            pdb_debugger = post_mortem_debug._get_debugger('pdb')
            pudb_debugger = post_mortem_debug._get_debugger('pudb')
            self.assertEqual('pdb', pdb_debugger.__name__)
            self.assertEqual('pudb', pudb_debugger.__name__)


class TestFilteredTraceback(base.BaseTestCase):

    def test_filter_traceback(self):
        tb1 = mock.Mock()
        tb2 = mock.Mock()
        tb1.tb_next = tb2
        tb2.tb_next = None
        ftb1 = post_mortem_debug.FilteredTraceback(tb1, tb2)
        for attr in ['lasti', 'lineno', 'frame']:
            attr_name = 'tb_%s' % attr
            self.assertEqual(getattr(tb1, attr_name, None),
                             getattr(ftb1, attr_name, None))
        self.assertIsNone(ftb1.tb_next)


class TestGetIgnoredTraceback(base.BaseTestCase):

    def _test_get_ignored_traceback(self, ignored_bit_array, expected):
        root_tb = mock.Mock()

        tb = root_tb
        tracebacks = [tb]
        for x in range(len(ignored_bit_array) - 1):
            tb.tb_next = mock.Mock()
            tb = tb.tb_next
            tracebacks.append(tb)
        tb.tb_next = None

        tb = root_tb
        for ignored in ignored_bit_array:
            if ignored:
                tb.tb_frame.f_globals = ['__unittest']
            else:
                tb.tb_frame.f_globals = []
            tb = tb.tb_next

        actual = post_mortem_debug.get_ignored_traceback(root_tb)
        if expected is not None:
            expected = tracebacks[expected]
        self.assertEqual(expected, actual)

    def test_no_ignored_tracebacks(self):
        self._test_get_ignored_traceback([0, 0, 0], None)

    def test_single_member_trailing_chain(self):
        self._test_get_ignored_traceback([0, 0, 1], 2)

    def test_two_member_trailing_chain(self):
        self._test_get_ignored_traceback([0, 1, 1], 1)

    def test_first_traceback_ignored(self):
        self._test_get_ignored_traceback([1, 0, 0], None)

    def test_middle_traceback_ignored(self):
        self._test_get_ignored_traceback([0, 1, 0], None)
