# Copyright 2013 Red Hat, Inc.
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

import mock

from neutron.agent.common import base_polling as polling
from neutron.tests import base


class TestBasePollingManager(base.BaseTestCase):

    def setUp(self):
        super(TestBasePollingManager, self).setUp()
        self.pm = polling.BasePollingManager()

    def test__is_polling_required_should_not_be_implemented(self):
        self.assertRaises(NotImplementedError, self.pm._is_polling_required)

    def test_force_polling_sets_interval_attribute(self):
        self.assertFalse(self.pm._force_polling)
        self.pm.force_polling()
        self.assertTrue(self.pm._force_polling)

    def test_polling_completed_sets_interval_attribute(self):
        self.pm._polling_completed = False
        self.pm.polling_completed()
        self.assertTrue(self.pm._polling_completed)

    def mock_is_polling_required(self, return_value):
        return mock.patch.object(self.pm, '_is_polling_required',
                                 return_value=return_value)

    def test_is_polling_required_returns_true_when_forced(self):
        with self.mock_is_polling_required(False):
            self.pm.force_polling()
            self.assertTrue(self.pm.is_polling_required)
            self.assertFalse(self.pm._force_polling)

    def test_is_polling_required_returns_true_when_polling_not_completed(self):
        with self.mock_is_polling_required(False):
            self.pm._polling_completed = False
            self.assertTrue(self.pm.is_polling_required)

    def test_is_polling_required_returns_true_when_updates_are_present(self):
        with self.mock_is_polling_required(True):
            self.assertTrue(self.pm.is_polling_required)
            self.assertFalse(self.pm._polling_completed)

    def test_is_polling_required_returns_false_for_no_updates(self):
        with self.mock_is_polling_required(False):
            self.assertFalse(self.pm.is_polling_required)


class TestAlwaysPoll(base.BaseTestCase):

    def test_is_polling_required_always_returns_true(self):
        pm = polling.AlwaysPoll()
        self.assertTrue(pm.is_polling_required)
