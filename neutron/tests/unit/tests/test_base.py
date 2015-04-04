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

from neutron.tests import base


class SystemExitTestCase(base.BaseTestCase):

    def setUp(self):
        def _fail_SystemExit(exc_info):
            if isinstance(exc_info[1], SystemExit):
                self.fail("A SystemExit was allowed out")
        super(SystemExitTestCase, self).setUp()
        # add the handler last so reaching it means the handler in BaseTestCase
        # didn't do it's job
        self.addOnException(_fail_SystemExit)

    def run(self, *args, **kwargs):
        exc = self.assertRaises(AssertionError,
                                super(SystemExitTestCase, self).run,
                                *args, **kwargs)
        # this message should be generated when SystemExit is raised by a test
        self.assertIn('A SystemExit was raised during the test.', str(exc))

    def test_system_exit(self):
        # this should generate a failure that mentions SystemExit was used
        sys.exit(1)
