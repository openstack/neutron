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

import re

from flake8 import engine
from hacking.tests import test_doctest as hacking_doctest
import pkg_resources
import pycodestyle
import testscenarios
import testtools
from testtools import content
from testtools import matchers

from neutron.hacking import checks
from neutron.tests import base


CREATE_DUMMY_MATCH_OBJECT = re.compile('a')


class HackingTestCase(base.BaseTestCase):

    def assertLinePasses(self, func, line):
        with testtools.ExpectedException(StopIteration):
            next(func(line))

    def assertLineFails(self, func, line):
        self.assertIsInstance(next(func(line)), tuple)

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
                1, len(list(checks.check_assertempty(fail_code % (ec, ec),
                                            "neutron/tests/test_assert.py"))))
            self.assertEqual(
                0, len(list(checks.check_asserttruefalse(pass_code1 % (ec, ec),
                                            "neutron/tests/test_assert.py"))))
            self.assertEqual(
                0, len(list(checks.check_asserttruefalse(pass_code2 % ec,
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

    def test_unittest_imports(self):
        f = checks.check_unittest_imports

        self.assertLinePasses(f, 'from unittest2')
        self.assertLinePasses(f, 'import unittest2')
        self.assertLinePasses(f, 'from unitest2 import case')
        self.assertLinePasses(f, 'unittest2.TestSuite')

        self.assertLineFails(f, 'from unittest import case')
        self.assertLineFails(f, 'from unittest.TestSuite')
        self.assertLineFails(f, 'import unittest')

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

    def test_check_python3_filter(self):
        f = checks.check_python3_no_filter
        self.assertLineFails(f, "filter(lambda obj: test(obj), data)")
        self.assertLinePasses(f, "[obj for obj in data if test(obj)]")
        self.assertLinePasses(f, "filter(function, range(0,10))")
        self.assertLinePasses(f, "lambda x, y: x+y")


# The following is borrowed from hacking/tests/test_doctest.py.
# Tests defined in docstring is easier to understand
# in some cases, for example, hacking rules which take tokens as argument.

# TODO(amotoki): Migrate existing unit tests above to docstring tests.
# NOTE(amotoki): Is it better to enhance HackingDocTestCase in hacking repo to
# pass filename to pycodestyle.Checker so that we can reuse it in this test.
# I am not sure whether unit test class is public.

SELFTEST_REGEX = re.compile(r'\b(Okay|N\d{3})(\((\S+)\))?:\s(.*)')


# Each scenario is (name, dict(filename=..., lines=.., options=..., code=...))
file_cases = []


class HackingDocTestCase(hacking_doctest.HackingTestCase):

    scenarios = file_cases

    def test_pycodestyle(self):

        # NOTE(jecarey): Add tests marked as off_by_default to enable testing
        turn_on = set(['H106'])
        if self.options.select:
            turn_on.update(self.options.select)
        self.options.select = tuple(turn_on)
        self.options.ignore = ('N530',)

        report = pycodestyle.BaseReport(self.options)
        checker = pycodestyle.Checker(filename=self.filename, lines=self.lines,
                               options=self.options, report=report)
        checker.check_all()
        self.addDetail('doctest', content.text_content(self.raw))
        if self.code == 'Okay':
            self.assertThat(
                len(report.counters),
                matchers.Not(matchers.GreaterThan(
                    len(self.options.benchmark_keys))),
                "incorrectly found %s" % ', '.join(
                    [key for key in report.counters
                     if key not in self.options.benchmark_keys]))
        else:
            self.addDetail('reason',
                           content.text_content("Failed to trigger rule %s" %
                                                self.code))
            self.assertIn(self.code, report.counters)


def _get_lines(check):
    for line in check.__doc__.splitlines():
        line = line.lstrip()
        match = SELFTEST_REGEX.match(line)
        if match is None:
            continue
        yield (line, match.groups())


def load_tests(loader, tests, pattern):

    default_checks = [e.name for e
                      in pkg_resources.iter_entry_points('flake8.extension')]
    flake8_style = engine.get_style_guide(
        parse_argv=False,
        # We are testing neutron-specific hacking rules, so there is no need
        # to run the checks registered by hacking or other flake8 extensions.
        ignore=default_checks)
    options = flake8_style.options

    for name, check in checks.__dict__.items():
        if not hasattr(check, 'name'):
            continue
        if check.name != checks.__name__:
            continue
        if not check.__doc__:
            continue
        for (lineno, (raw, line)) in enumerate(_get_lines(check)):
            code, __, filename, source = line
            lines = [part.replace(r'\t', '\t') + '\n'
                     for part in source.split(r'\n')]
            file_cases.append(("%s-line-%s" % (name, lineno),
                              dict(lines=lines, raw=raw, options=options,
                                   code=code, filename=filename)))
    return testscenarios.load_tests_apply_scenarios(loader, tests, pattern)
