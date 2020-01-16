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

"""Tests to test the test framework"""

import sys
import unittest

import eventlet.timeout

from neutron.tests import base


class BrokenExceptionHandlerTestCase(base.DietTestCase):
    # Embedded to hide from the regular test discovery
    class MyTestCase(base.DietTestCase):
        def setUp(self):
            super(BrokenExceptionHandlerTestCase.MyTestCase, self).setUp()
            self.addOnException(self._diag_collect)

        def _diag_collect(self, exc_info):
            raise ValueError('whoopsie daisy')

        def runTest(self):
            raise IndexError("Thou shalt not pass by reference")

    def test_broken_exception_handler(self):
        result = self.MyTestCase().run()
        # ensure both exceptions are logged
        self.assertIn('Thou shalt', result.errors[0][1])
        self.assertIn('whoopsie', result.errors[0][1])
        self.assertFalse(result.wasSuccessful())


class SystemExitTestCase(base.DietTestCase):
    # Embedded to hide from the regular test discovery
    class MyTestCase(base.DietTestCase):
        def __init__(self, exitcode):
            super(SystemExitTestCase.MyTestCase, self).__init__()
            self.exitcode = exitcode

        def runTest(self):
            if self.exitcode is not None:
                sys.exit(self.exitcode)

    def test_no_sysexit(self):
        result = self.MyTestCase(exitcode=None).run()
        self.assertTrue(result.wasSuccessful())

    def test_sysexit(self):
        expectedFails = [self.MyTestCase(exitcode) for exitcode in (0, 1)]

        suite = unittest.TestSuite(tests=expectedFails)
        result = self.defaultTestResult()
        try:
            suite.run(result)
        except SystemExit:
            self.fail('SystemExit escaped!')

        self.assertEqual([], result.errors)
        self.assertItemsEqual(set(id(t) for t in expectedFails),
                              set(id(t) for (t, traceback) in result.failures))


class CatchTimeoutTestCase(base.DietTestCase):
    # Embedded to hide from the regular test discovery
    class MyTestCase(base.DietTestCase):
        def test_case(self):
            raise eventlet.Timeout()

        def runTest(self):
            return self.test_case()

    def test_catch_timeout(self):
        try:
            result = self.MyTestCase().run()
            self.assertFalse(result.wasSuccessful())
        except eventlet.Timeout:
            self.fail('Timeout escaped!')
