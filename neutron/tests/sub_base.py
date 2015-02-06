# Copyright 2014 OpenStack Foundation
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

"""Base test case for all tests.

To change behavoir only for tests that do not rely on Tempest, please
target the neutron.tests.base module instead.

There should be no non-test Neutron imports in this module to ensure
that the functional API tests can import Tempest without triggering
errors due to duplicate configuration definitions.
"""

import contextlib
import logging as std_logging
import os
import os.path
import random
import traceback

import eventlet.timeout
import fixtures
import mock
from oslo_utils import strutils
import testtools

from neutron.tests import post_mortem_debug


LOG_FORMAT = "%(asctime)s %(levelname)8s [%(name)s] %(message)s"


def get_rand_name(max_length=None, prefix='test'):
    name = prefix + str(random.randint(1, 0x7fffffff))
    return name[:max_length] if max_length is not None else name


def bool_from_env(key, strict=False, default=False):
    value = os.environ.get(key)
    return strutils.bool_from_string(value, strict=strict, default=default)


class SubBaseTestCase(testtools.TestCase):

    def setUp(self):
        super(SubBaseTestCase, self).setUp()

        # Configure this first to ensure pm debugging support for setUp()
        debugger = os.environ.get('OS_POST_MORTEM_DEBUGGER')
        if debugger:
            self.addOnException(post_mortem_debug.get_exception_handler(
                debugger))

        if bool_from_env('OS_DEBUG'):
            _level = std_logging.DEBUG
        else:
            _level = std_logging.INFO
        capture_logs = bool_from_env('OS_LOG_CAPTURE')
        if not capture_logs:
            std_logging.basicConfig(format=LOG_FORMAT, level=_level)
        self.log_fixture = self.useFixture(
            fixtures.FakeLogger(
                format=LOG_FORMAT,
                level=_level,
                nuke_handlers=capture_logs,
            ))

        test_timeout = int(os.environ.get('OS_TEST_TIMEOUT', 0))
        if test_timeout == -1:
            test_timeout = 0
        if test_timeout > 0:
            self.useFixture(fixtures.Timeout(test_timeout, gentle=True))

        # If someone does use tempfile directly, ensure that it's cleaned up
        self.useFixture(fixtures.NestedTempfile())
        self.useFixture(fixtures.TempHomeDir())

        self.addCleanup(mock.patch.stopall)

        if bool_from_env('OS_STDOUT_CAPTURE'):
            stdout = self.useFixture(fixtures.StringStream('stdout')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stdout', stdout))
        if bool_from_env('OS_STDERR_CAPTURE'):
            stderr = self.useFixture(fixtures.StringStream('stderr')).stream
            self.useFixture(fixtures.MonkeyPatch('sys.stderr', stderr))

        self.addOnException(self.check_for_systemexit)

    def check_for_systemexit(self, exc_info):
        if isinstance(exc_info[1], SystemExit):
            self.fail("A SystemExit was raised during the test. %s"
                      % traceback.format_exception(*exc_info))

    @contextlib.contextmanager
    def assert_max_execution_time(self, max_execution_time=5):
        with eventlet.timeout.Timeout(max_execution_time, False):
            yield
            return
        self.fail('Execution of this test timed out')

    def assertOrderedEqual(self, expected, actual):
        expect_val = self.sort_dict_lists(expected)
        actual_val = self.sort_dict_lists(actual)
        self.assertEqual(expect_val, actual_val)

    def sort_dict_lists(self, dic):
        for key, value in dic.iteritems():
            if isinstance(value, list):
                dic[key] = sorted(value)
            elif isinstance(value, dict):
                dic[key] = self.sort_dict_lists(value)
        return dic

    def assertDictSupersetOf(self, expected_subset, actual_superset):
        """Checks that actual dict contains the expected dict.

        After checking that the arguments are of the right type, this checks
        that each item in expected_subset is in, and matches, what is in
        actual_superset. Separate tests are done, so that detailed info can
        be reported upon failure.
        """
        if not isinstance(expected_subset, dict):
            self.fail("expected_subset (%s) is not an instance of dict" %
                      type(expected_subset))
        if not isinstance(actual_superset, dict):
            self.fail("actual_superset (%s) is not an instance of dict" %
                      type(actual_superset))
        for k, v in expected_subset.items():
            self.assertIn(k, actual_superset)
            self.assertEqual(v, actual_superset[k],
                             "Key %(key)s expected: %(exp)r, actual %(act)r" %
                             {'key': k, 'exp': v, 'act': actual_superset[k]})
