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

import testtools

from neutron.hacking import checks
from neutron.tests import base


class HackingTestCase(base.BaseTestCase):

    def test_log_translations(self):
        expected_marks = {
            'error': '_LE',
            'info': '_LI',
            'warn': '_LW',
            'warning': '_LW',
            'critical': '_LC',
            'exception': '_LE',
        }
        logs = expected_marks.keys()
        debug = "LOG.debug('OK')"
        self.assertEqual(
            0, len(list(checks.validate_log_translations(debug, debug, 'f'))))
        for log in logs:
            bad = 'LOG.%s("Bad")' % log
            self.assertEqual(
                1, len(list(checks.validate_log_translations(bad, bad, 'f'))))
            ok = "LOG.%s('OK')    # noqa" % log
            self.assertEqual(
                0, len(list(checks.validate_log_translations(ok, ok, 'f'))))
            ok = "LOG.%s(variable)" % log
            self.assertEqual(
                0, len(list(checks.validate_log_translations(ok, ok, 'f'))))

            for mark in checks._all_hints:
                stmt = "LOG.%s(%s('test'))" % (log, mark)
                self.assertEqual(
                    0 if expected_marks[log] == mark else 1,
                    len(list(checks.validate_log_translations(stmt, stmt,
                                                              'f'))))

    def test_no_translate_debug_logs(self):
        for hint in checks._all_hints:
            bad = "LOG.debug(%s('bad'))" % hint
            self.assertEqual(
                1, len(list(checks.no_translate_debug_logs(bad, 'f'))))

    def test_use_jsonutils(self):
        def __get_msg(fun):
            msg = ("N321: jsonutils.%(fun)s must be used instead of "
                   "json.%(fun)s" % {'fun': fun})
            return [(0, msg)]

        for method in ('dump', 'dumps', 'load', 'loads'):
            self.assertEqual(
                __get_msg(method),
                list(checks.use_jsonutils("json.%s(" % method,
                                          "./neutron/common/rpc.py")))

            self.assertEqual(0,
                len(list(checks.use_jsonutils("jsonx.%s(" % method,
                                              "./neutron/common/rpc.py"))))

            self.assertEqual(0,
                len(list(checks.use_jsonutils("json.%sx(" % method,
                                              "./neutron/common/rpc.py"))))

            self.assertEqual(0,
                len(list(checks.use_jsonutils(
                    "json.%s" % method,
                    "./neutron/plugins/openvswitch/agent/xenapi/etc/xapi.d/"
                    "plugins/netwrap"))))

    def test_assert_called_once_with(self):
        fail_code1 = """
               mock = Mock()
               mock.method(1, 2, 3, test='wow')
               mock.method.assert_called_once()
               """
        fail_code2 = """
               mock = Mock()
               mock.method(1, 2, 3, test='wow')
               mock.method.assertCalledOnceWith()
               """
        fail_code3 = """
               mock = Mock()
               mock.method(1, 2, 3, test='wow')
               mock.method.assert_has_called()
               """
        pass_code = """
               mock = Mock()
               mock.method(1, 2, 3, test='wow')
               mock.method.assert_called_once_with()
               """
        pass_code2 = """
               mock = Mock()
               mock.method(1, 2, 3, test='wow')
               mock.method.assert_has_calls()
               """
        self.assertEqual(
            1, len(list(checks.check_assert_called_once_with(fail_code1,
                                            "neutron/tests/test_assert.py"))))
        self.assertEqual(
            1, len(list(checks.check_assert_called_once_with(fail_code2,
                                            "neutron/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(checks.check_assert_called_once_with(pass_code,
                                            "neutron/tests/test_assert.py"))))
        self.assertEqual(
            1, len(list(checks.check_assert_called_once_with(fail_code3,
                                            "neutron/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(checks.check_assert_called_once_with(pass_code2,
                                            "neutron/tests/test_assert.py"))))

    def test_check_oslo_namespace_imports(self):
        def check(s, fail=True):
            func = checks.check_oslo_namespace_imports
            if fail:
                self.assertIsInstance(next(func(s)), tuple)
            else:
                with testtools.ExpectedException(StopIteration):
                    next(func(s))

        check('from oslo_utils import importutils', fail=False)
        check('import oslo_messaging', fail=False)
        check('from oslo.utils import importutils')
        check('from oslo import messaging')
        check('import oslo.messaging')
