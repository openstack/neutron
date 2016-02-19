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

    def assertLinePasses(self, func, line):
        with testtools.ExpectedException(StopIteration):
            next(func(line))

    def assertLineFails(self, func, line):
        self.assertIsInstance(next(func(line)), tuple)

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
            bad = 'LOG.%s(_("Bad"))' % log
            self.assertEqual(
                1, len(list(checks.validate_log_translations(bad, bad, 'f'))))
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
                    "./neutron/plugins/ml2/drivers/openvswitch/agent/xenapi/"
                    "etc/xapi.d/plugins/netwrap"))))

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
               mock.method.called_once_with()
               """
        fail_code4 = """
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
            1, len(list(checks.check_assert_called_once_with(fail_code3,
                                            "neutron/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(checks.check_assert_called_once_with(pass_code,
                                            "neutron/tests/test_assert.py"))))
        self.assertEqual(
            1, len(list(checks.check_assert_called_once_with(fail_code4,
                                            "neutron/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(checks.check_assert_called_once_with(pass_code2,
                                            "neutron/tests/test_assert.py"))))

    def test_check_oslo_namespace_imports(self):
        f = checks.check_oslo_namespace_imports
        self.assertLinePasses(f, 'from oslo_utils import importutils')
        self.assertLinePasses(f, 'import oslo_messaging')
        self.assertLineFails(f, 'from oslo.utils import importutils')
        self.assertLineFails(f, 'from oslo import messaging')
        self.assertLineFails(f, 'import oslo.messaging')

    def test_check_python3_xrange(self):
        f = checks.check_python3_xrange
        self.assertLineFails(f, 'a = xrange(1000)')
        self.assertLineFails(f, 'b =xrange   (   42 )')
        self.assertLineFails(f, 'c = xrange(1, 10, 2)')
        self.assertLinePasses(f, 'd = range(1000)')
        self.assertLinePasses(f, 'e = six.moves.range(1337)')

    def test_no_basestring(self):
        self.assertEqual(1,
            len(list(checks.check_no_basestring("isinstance(x, basestring)"))))

    def test_check_python3_iteritems(self):
        f = checks.check_python3_no_iteritems
        self.assertLineFails(f, "d.iteritems()")
        self.assertLinePasses(f, "six.iteritems(d)")

    def test_asserttrue(self):
        fail_code1 = """
               test_bool = True
               self.assertEqual(True, test_bool)
               """
        fail_code2 = """
               test_bool = True
               self.assertEqual(test_bool, True)
               """
        pass_code = """
               test_bool = True
               self.assertTrue(test_bool)
               """
        self.assertEqual(
            1, len(list(checks.check_asserttrue(fail_code1,
                                            "neutron/tests/test_assert.py"))))
        self.assertEqual(
            1, len(list(checks.check_asserttrue(fail_code2,
                                            "neutron/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(checks.check_asserttrue(pass_code,
                                            "neutron/tests/test_assert.py"))))

    def test_no_mutable_default_args(self):
        self.assertEqual(1, len(list(checks.no_mutable_default_args(
            " def fake_suds_context(calls={}):"))))

        self.assertEqual(1, len(list(checks.no_mutable_default_args(
            "def get_info_from_bdm(virt_type, bdm, mapping=[])"))))

        self.assertEqual(0, len(list(checks.no_mutable_default_args(
            "defined = []"))))

        self.assertEqual(0, len(list(checks.no_mutable_default_args(
            "defined, undefined = [], {}"))))

    def test_assertfalse(self):
        fail_code1 = """
               test_bool = False
               self.assertEqual(False, test_bool)
               """
        fail_code2 = """
               test_bool = False
               self.assertEqual(test_bool, False)
               """
        pass_code = """
               test_bool = False
               self.assertFalse(test_bool)
               """
        self.assertEqual(
            1, len(list(checks.check_assertfalse(fail_code1,
                                            "neutron/tests/test_assert.py"))))
        self.assertEqual(
            1, len(list(checks.check_assertfalse(fail_code2,
                                            "neutron/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(checks.check_assertfalse(pass_code,
                                            "neutron/tests/test_assert.py"))))

    def test_assertempty(self):
        fail_code = """
                test_empty = %s
                self.assertEqual(test_empty, %s)
                """
        pass_code1 = """
                test_empty = %s
                self.assertEqual(%s, test_empty)
                """
        pass_code2 = """
                self.assertEqual(123, foo(abc, %s))
                """
        empty_cases = ['{}', '[]', '""', "''", '()', 'set()']
        for ec in empty_cases:
            self.assertEqual(
                1, len(list(checks.check_assertempty(fail_code % (ec, ec),
                                            "neutron/tests/test_assert.py"))))
            self.assertEqual(
                0, len(list(checks.check_assertfalse(pass_code1 % (ec, ec),
                                            "neutron/tests/test_assert.py"))))
            self.assertEqual(
                0, len(list(checks.check_assertfalse(pass_code2 % ec,
                                            "neutron/tests/test_assert.py"))))

    def test_assertisinstance(self):
        fail_code = """
               self.assertTrue(isinstance(observed, ANY_TYPE))
               """
        pass_code1 = """
               self.assertEqual(ANY_TYPE, type(observed))
               """
        pass_code2 = """
               self.assertIsInstance(observed, ANY_TYPE)
               """
        self.assertEqual(
            1, len(list(checks.check_assertisinstance(fail_code,
                                        "neutron/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(checks.check_assertisinstance(pass_code1,
                                            "neutron/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(checks.check_assertisinstance(pass_code2,
                                            "neutron/tests/test_assert.py"))))

    def test_assertequal_for_httpcode(self):
        fail_code = """
                self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
                """
        pass_code = """
                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)
                """
        self.assertEqual(
            1, len(list(checks.check_assertequal_for_httpcode(fail_code,
                                        "neutron/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(checks.check_assertequal_for_httpcode(pass_code,
                                        "neutron/tests/test_assert.py"))))
