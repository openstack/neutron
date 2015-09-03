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
import unittest2

from neutron.tests import base


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

        suite = unittest2.TestSuite(tests=expectedFails)
        result = self.defaultTestResult()
        try:
            suite.run(result)
        except SystemExit:
            self.fail('SystemExit escaped!')

        self.assertEqual([], result.errors)
        self.assertItemsEqual(set(id(t) for t in expectedFails),
                              set(id(t) for (t, traceback) in result.failures))
