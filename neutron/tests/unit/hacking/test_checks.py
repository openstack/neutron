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

import io
import re
import tokenize
from unittest import mock

import testtools

from neutron.hacking import checks
from neutron.tests import base


CREATE_DUMMY_MATCH_OBJECT = re.compile('a')


class HackingTestCase(base.BaseTestCase):

    def assertLinePasses(self, func, line, *args, **kwargs):
        with testtools.ExpectedException(StopIteration):
            next(func(line, *args, **kwargs))

    def assertLineFails(self, expected_code, func, line, *args, **kwargs):
        value = next(func(line, *args, **kwargs))
        self.assertIsInstance(value, tuple)
        self.assertIn(expected_code, value[1])

    def test_assert_called_once_with(self):
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
            1, len(list(
                checks.check_assert_called_once_with(
                    fail_code2, "neutron/tests/test_assert.py"))))
        self.assertEqual(
            1, len(list(
                checks.check_assert_called_once_with(
                    fail_code3, "neutron/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(
                checks.check_assert_called_once_with(
                    pass_code, "neutron/tests/test_assert.py"))))
        self.assertEqual(
            1, len(list(
                checks.check_assert_called_once_with(
                    fail_code4, "neutron/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(
                checks.check_assert_called_once_with(
                    pass_code2, "neutron/tests/test_assert.py"))))

    def test_asserttruefalse(self):
        true_fail_code1 = """
               test_bool = True
               self.assertEqual(True, test_bool)
               """
        true_fail_code2 = """
               test_bool = True
               self.assertEqual(test_bool, True)
               """
        true_pass_code = """
               test_bool = True
               self.assertTrue(test_bool)
               """
        false_fail_code1 = """
               test_bool = False
               self.assertEqual(False, test_bool)
               """
        false_fail_code2 = """
               test_bool = False
               self.assertEqual(test_bool, False)
               """
        false_pass_code = """
               test_bool = False
               self.assertFalse(test_bool)
               """
        self.assertEqual(
            1, len(list(
                checks.check_asserttruefalse(true_fail_code1,
                                             "neutron/tests/test_assert.py"))))
        self.assertEqual(
            1, len(list(
                checks.check_asserttruefalse(true_fail_code2,
                                             "neutron/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(
                checks.check_asserttruefalse(true_pass_code,
                                             "neutron/tests/test_assert.py"))))
        self.assertEqual(
            1, len(list(
                checks.check_asserttruefalse(false_fail_code1,
                                             "neutron/tests/test_assert.py"))))
        self.assertEqual(
            1, len(list(
                checks.check_asserttruefalse(false_fail_code2,
                                             "neutron/tests/test_assert.py"))))
        self.assertFalse(
            list(
                checks.check_asserttruefalse(false_pass_code,
                                             "neutron/tests/test_assert.py")))

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
                1, len(list(
                    checks.check_assertempty(
                        fail_code % (ec, ec),
                        "neutron/tests/test_assert.py"))))
            self.assertEqual(
                0, len(list(
                    checks.check_asserttruefalse(
                        pass_code1 % (ec, ec),
                        "neutron/tests/test_assert.py"))))
            self.assertEqual(
                0, len(list(
                    checks.check_asserttruefalse(
                        pass_code2 % ec,
                        "neutron/tests/test_assert.py"))))

    def test_assertequal_for_httpcode(self):
        fail_code = """
                self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)
                """
        pass_code = """
                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)
                """
        self.assertEqual(
            1, len(list(
                checks.check_assertequal_for_httpcode(
                    fail_code, "neutron/tests/test_assert.py"))))
        self.assertEqual(
            0, len(list(
                checks.check_assertequal_for_httpcode(
                    pass_code, "neutron/tests/test_assert.py"))))

    def test_check_no_imports_from_tests(self):
        fail_codes = ('from neutron import tests',
                      'from neutron.tests import base',
                      'import neutron.tests.base')
        for fail_code in fail_codes:
            self.assertEqual(
                1, len(list(
                    checks.check_no_imports_from_tests(
                        fail_code, "neutron/common/utils.py", None))))
            self.assertEqual(
                0, len(list(
                    checks.check_no_imports_from_tests(
                        fail_code, "neutron/tests/test_fake.py", None))))

    def test_check_python3_no_filter(self):
        f = checks.check_python3_no_filter
        self.assertLineFails('N344', f, "filter(lambda obj: test(obj), data)")
        self.assertLinePasses(f, "[obj for obj in data if test(obj)]")
        self.assertLinePasses(f, "filter(function, range(0,10))")
        self.assertLinePasses(f, "lambda x, y: x+y")

    def test_check_no_import_six(self):
        pass_line = 'from other_library import six'
        fail_lines = ('import six',
                      'import six as six_lib',
                      'from six import moves')
        self.assertEqual(
            0,
            len(list(checks.check_no_import_six(pass_line, mock.ANY, None))))
        for fail_line in fail_lines:
            self.assertEqual(
                1, len(list(checks.check_no_import_six(
                    fail_line, mock.ANY, None))))

    def test_check_no_import_packaging(self):
        pass_line = 'import other_library import packaging'
        fail_lines = ('import packaging',
                      'from packaging import version')
        self.assertEqual(
            0,
            len(list(checks.check_no_import_packaging(pass_line, mock.ANY,
                                                      None))))
        for fail_line in fail_lines:
            self.assertEqual(
                1, len(list(checks.check_no_import_packaging(
                    fail_line, mock.ANY, None))))

    def test_check_oslo_i18n_wrapper(self):
        def _pass(line, filename, noqa=False):
            self.assertLinePasses(
                checks.check_oslo_i18n_wrapper,
                line, filename, noqa)

        def _fail(line, filename):
            self.assertLineFails(
                "N340", checks.check_oslo_i18n_wrapper,
                line, filename, noqa=False)

        _pass("from neutron._i18n import _", "neutron/foo/bar.py")
        _pass("from neutron_fwaas._i18n import _", "neutron_fwaas/foo/bar.py")
        _fail("from neutron.i18n import _", "neutron/foo/bar.py")
        _fail("from neutron_fwaas.i18n import _", "neutron_fwaas/foo/bar.py")
        _fail("from neutron.i18n import _", "neutron_fwaas/foo/bar.py")
        _fail("from neutron._i18n import _", "neutron_fwaas/foo/bar.py")
        _pass("from neutron.i18n import _", "neutron/foo/bar.py", noqa=True)

    def test_check_builtins_gettext(self):
        # NOTE: check_builtins_gettext() takes two additional arguments,
        # "tokens" and "lines". "tokens" is a list of tokens from the target
        # logical line, and "lines" is a list of lines of the input file.
        # Considering this, test functions (_pass and _fail) take "lines"
        # as an argument and calls the hacking check function line by line
        # after generating tokens from the target line.

        def _get_tokens(line):
            return tokenize.tokenize(io.BytesIO(line.encode('utf-8')).readline)

        def _pass(lines, filename, noqa=False):
            for line in lines:
                self.assertLinePasses(
                    checks.check_builtins_gettext,
                    line, _get_tokens(line), filename, lines, noqa)

        def _fail(lines, filename):
            for line in lines:
                self.assertLineFails(
                    "N341", checks.check_builtins_gettext,
                    line, _get_tokens(line), filename, lines, noqa=False)

        _pass(["from neutron._i18n import _", "_('foo')"], "neutron/foo.py")
        _fail(["_('foo')"], "neutron/foo.py")
        _pass(["_('foo')"], "neutron/_i18n.py")
        _pass(["_('foo')"], "neutron/i18n.py")
        _pass(["_('foo')"], "neutron/foo.py", noqa=True)

    def test_check_no_sqlalchemy_lazy_subquery(self):
        f = checks.check_no_sqlalchemy_lazy_subquery
        self.assertLineFails(
            'N350', f,
            "backref=orm.backref('tags', lazy='subquery', viewonly=True),")
        self.assertLineFails(
            'N350', f,
            "query.options(orm.subqueryload(ml2_models.PortBinding.port))")
        self.assertLinePasses(
            f, "backref=orm.backref('tags', lazy='selectin', viewonly=True),")
        self.assertLinePasses(
            f, "query.options(orm.selectinload(ml2_models.PortBinding.port))")
