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

from unittest import mock

from neutron.agent.common import base_polling
from neutron.agent.common import polling
from neutron.agent.ovsdb.native import helpers
from neutron.tests import base


class TestBasePollingManager(base.BaseTestCase):

    def setUp(self):
        super(TestBasePollingManager, self).setUp()
        self.pm = base_polling.BasePollingManager()

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
        pm = base_polling.AlwaysPoll()
        self.assertTrue(pm.is_polling_required)


class TestGetPollingManager(base.BaseTestCase):

    def setUp(self):
        super(TestGetPollingManager, self).setUp()
        mock.patch.object(helpers, 'enable_connection_uri').start()

    def test_return_always_poll_by_default(self):
        with polling.get_polling_manager() as pm:
            self.assertEqual(pm.__class__, base_polling.AlwaysPoll)

    def test_manage_polling_minimizer(self):
        mock_target = 'neutron.agent.common.polling.InterfacePollingMinimizer'
        with mock.patch('%s.start' % mock_target) as mock_start:
            with mock.patch('%s.stop' % mock_target) as mock_stop:
                with polling.get_polling_manager(minimize_polling=True) as pm:
                    self.assertEqual(pm.__class__,
                                     polling.InterfacePollingMinimizer)
                mock_stop.assert_has_calls([mock.call()])
            mock_start.assert_has_calls([mock.call()])


class TestInterfacePollingMinimizer(base.BaseTestCase):

    def setUp(self):
        super(TestInterfacePollingMinimizer, self).setUp()
        mock.patch.object(helpers, 'enable_connection_uri').start()
        self.pm = polling.InterfacePollingMinimizer()

    def test_start_calls_monitor_start(self):
        with mock.patch.object(self.pm._monitor, 'start') as mock_start:
            self.pm.start()
        mock_start.assert_called_with(block=True)

    def test_stop_calls_monitor_stop(self):
        with mock.patch.object(self.pm._monitor, 'stop') as mock_stop:
            self.pm.stop()
        mock_stop.assert_called_with()

    def mock_has_updates(self, return_value):
        target = ('neutron.agent.common.ovsdb_monitor.SimpleInterfaceMonitor'
                  '.has_updates')
        return mock.patch(
            target,
            new_callable=mock.PropertyMock(return_value=return_value),
        )

    def test__is_polling_required_returns_when_updates_are_present(self):
        with self.mock_has_updates(True):
            self.assertTrue(self.pm._is_polling_required())
