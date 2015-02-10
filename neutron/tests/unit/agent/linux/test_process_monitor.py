# Copyright 2014 Red Hat Inc.
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
#

import mock

from neutron.agent.linux import external_process
from neutron.tests import base

TEST_UUID = 'test-uuid'
TEST_SERVICE = 'testsvc'
TEST_PID = 1234


class BaseTestProcessMonitor(base.BaseTestCase):

    def setUp(self):
        super(BaseTestProcessMonitor, self).setUp()
        self.log_patch = mock.patch("neutron.agent.linux.external_process."
                                    "LOG.error")
        self.error_log = self.log_patch.start()

        self.spawn_patch = mock.patch("eventlet.spawn")
        self.eventlent_spawn = self.spawn_patch.start()

        # create a default process monitor
        self.create_child_process_monitor('respawn')

    def create_child_process_monitor(self, action):
        conf = mock.Mock()
        conf.AGENT.check_child_processes_action = action
        conf.AGENT.check_child_processes = True
        self.pmonitor = external_process.ProcessMonitor(
            config=conf,
            resource_type='test')

    def get_monitored_process(self, uuid, service=None):
        monitored_process = mock.Mock()
        self.pmonitor.register(uuid=uuid,
                               service_name=service,
                               monitored_process=monitored_process)
        return monitored_process


class TestProcessMonitor(BaseTestProcessMonitor):

    def test_error_logged(self):
        pm = self.get_monitored_process(TEST_UUID)
        pm.active = False
        self.pmonitor._check_child_processes()
        self.assertTrue(self.error_log.called)

    def test_exit_handler(self):
        self.create_child_process_monitor('exit')
        pm = self.get_monitored_process(TEST_UUID)
        pm.active = False
        with mock.patch.object(external_process.ProcessMonitor,
                               '_exit_handler') as exit_handler:
            self.pmonitor._check_child_processes()
            exit_handler.assert_called_once_with(TEST_UUID, None)

    def test_register(self):
        pm = self.get_monitored_process(TEST_UUID)
        self.assertEqual(len(self.pmonitor._monitored_processes), 1)
        self.assertIn(pm, self.pmonitor._monitored_processes.values())

    def test_register_same_service_twice(self):
        self.get_monitored_process(TEST_UUID)
        self.get_monitored_process(TEST_UUID)
        self.assertEqual(len(self.pmonitor._monitored_processes), 1)

    def test_register_different_service_types(self):
        self.get_monitored_process(TEST_UUID)
        self.get_monitored_process(TEST_UUID, TEST_SERVICE)
        self.assertEqual(len(self.pmonitor._monitored_processes), 2)

    def test_unregister(self):
        self.get_monitored_process(TEST_UUID)
        self.pmonitor.unregister(TEST_UUID, None)
        self.assertEqual(len(self.pmonitor._monitored_processes), 0)

    def test_unregister_unknown_process(self):
        self.pmonitor.unregister(TEST_UUID, None)
        self.assertEqual(len(self.pmonitor._monitored_processes), 0)
