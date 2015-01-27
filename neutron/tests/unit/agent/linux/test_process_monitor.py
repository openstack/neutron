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
TEST_SERVICE1 = 'testsvc'
TEST_PID = 1234


class BaseTestProcessMonitor(base.BaseTestCase):

    def setUp(self):
        super(BaseTestProcessMonitor, self).setUp()
        self.pm_patch = mock.patch("neutron.agent.linux.external_process."
                                   "ProcessManager", side_effect=mock.Mock)
        self.pmanager = self.pm_patch.start()

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
            root_helper=None,
            resource_type='test')

    def get_monitored_process_manager(self, uuid, service=None):
        self.pmonitor.enable(uuid=uuid, service=service, cmd_callback=None)
        return self.pmonitor.get_process_manager(uuid, service)


class TestProcessMonitor(BaseTestProcessMonitor):

    def test_error_logged(self):
        pm = self.get_monitored_process_manager(TEST_UUID)
        pm.active = False
        self.pmonitor._check_child_processes()
        self.assertTrue(self.error_log.called)

    def test_exit_handler(self):
        self.create_child_process_monitor('exit')
        pm = self.get_monitored_process_manager(TEST_UUID)
        pm.active = False
        with mock.patch.object(external_process.ProcessMonitor,
                               '_exit_handler') as exit_handler:
            self.pmonitor._check_child_processes()
            exit_handler.assert_called_once_with(TEST_UUID, None)

    def test_different_service_types(self):
        pm_none = self.get_monitored_process_manager(TEST_UUID)
        pm_svc1 = self.get_monitored_process_manager(TEST_UUID, TEST_SERVICE1)
        self.assertNotEqual(pm_none, pm_svc1)

    def test_active_method(self, service=None):
        pm = self.get_monitored_process_manager(TEST_UUID, service)
        pm.active = False
        self.assertFalse(self.pmonitor.is_active(TEST_UUID, service))
        pm.active = True
        self.assertTrue(self.pmonitor.is_active(TEST_UUID, service))

    def test_active_method_with_service(self):
        self.test_active_method(TEST_SERVICE1)

    def test_pid_method(self, service=None):
        pm = self.get_monitored_process_manager(TEST_UUID, service)
        pm.pid = TEST_PID
        self.assertEqual(TEST_PID, self.pmonitor.get_pid(TEST_UUID, service))

    def test_pid_method_with_service(self):
        self.test_pid_method(TEST_PID)
