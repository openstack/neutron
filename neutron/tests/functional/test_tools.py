# Copyright (c) 2015 Thales Services SAS
# All Rights Reserved.
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

import fixtures
import testscenarios

from neutron.tests import base
from neutron.tests import tools


class NoErrorFixture(tools.SafeFixture):

    def __init__(self):
        super(NoErrorFixture, self).__init__()
        self.cleaned = False
        self.called = False

    def setUp(self):
        super(NoErrorFixture, self).setUp()
        self.called = True

    def cleanUp(self):
        self.cleaned = True
        super(NoErrorFixture, self).cleanUp()


class ErrorAfterFixtureSetup(NoErrorFixture):

    def setUp(self):
        super(tools.SafeFixture, self).setUp()
        raise ValueError


class ErrorBeforeFixtureSetup(NoErrorFixture):

        def setUp(self):
            raise ValueError


class TestSafeFixture(testscenarios.WithScenarios, base.BaseTestCase):
    scenarios = [
        ('testtools useFixture', dict(fixtures=False)),
        ('fixtures useFixture', dict(fixtures=True)),
    ]

    def setUp(self):
        super(TestSafeFixture, self).setUp()
        if self.fixtures:
            self.parent = self.useFixture(fixtures.Fixture())
        else:
            self.parent = self

    def test_no_error(self):
        fixture = NoErrorFixture()
        self.parent.useFixture(fixture)
        self.assertTrue(fixture.called)
        self.assertFalse(fixture.cleaned)

    def test_error_after_root_setup(self):
        fixture = ErrorAfterFixtureSetup()
        self.assertRaises(ValueError, self.parent.useFixture, fixture)
        self.assertTrue(fixture.cleaned)

    def test_error_before_root_setup(self):
        fixture = ErrorBeforeFixtureSetup()
        # NOTE(cbrandily); testtools.useFixture crashs badly if Fixture.setUp
        # is not called or fails.
        self.assertRaises(AttributeError, self.parent.useFixture, fixture)
        self.assertFalse(fixture.cleaned)
