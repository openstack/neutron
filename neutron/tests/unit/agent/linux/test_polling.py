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

from neutron.agent.common import base_polling
from neutron.agent.linux import polling
from neutron.tests import base


class TestGetPollingManager(base.BaseTestCase):

    def test_return_always_poll_by_default(self):
        with polling.get_polling_manager() as pm:
            self.assertEqual(pm.__class__, base_polling.AlwaysPoll)

    def test_manage_polling_minimizer(self):
        mock_target = 'neutron.agent.linux.polling.InterfacePollingMinimizer'
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
        self.pm = polling.InterfacePollingMinimizer()

    def test_start_calls_monitor_start(self):
        with mock.patch.object(self.pm._monitor, 'start') as mock_start:
            self.pm.start()
        mock_start.assert_called_with()

    def test_stop_calls_monitor_stop(self):
        with mock.patch.object(self.pm._monitor, 'stop') as mock_stop:
            self.pm.stop()
        mock_stop.assert_called_with()

    def mock_has_updates(self, return_value):
        target = ('neutron.agent.linux.ovsdb_monitor.SimpleInterfaceMonitor'
                  '.has_updates')
        return mock.patch(
            target,
            new_callable=mock.PropertyMock(return_value=return_value),
        )

    def test__is_polling_required_returns_when_updates_are_present(self):
        with self.mock_has_updates(True):
            self.assertTrue(self.pm._is_polling_required())
