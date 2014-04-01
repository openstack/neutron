# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

"""
Tests in this module will be skipped unless:

 - ovsdb-client is installed

 - ovsdb-client can be invoked via password-less sudo

 - OS_SUDO_TESTING is set to '1' or 'True' in the test execution
   environment


The jenkins gate does not allow direct sudo invocation during test
runs, but configuring OS_SUDO_TESTING ensures that developers are
still able to execute tests that require the capability.
"""

import eventlet

from neutron.agent.linux import ovsdb_monitor
from neutron.tests.functional.agent.linux import base as base_agent


class BaseMonitorTest(base_agent.BaseOVSLinuxTestCase):

    def setUp(self):
        # Emulate using a rootwrap script with sudo
        super(BaseMonitorTest, self).setUp(root_helper='sudo sudo')

        self._check_test_requirements()
        self.bridge = self.create_ovs_bridge()

    def _check_test_requirements(self):
        self.check_sudo_enabled()
        self.check_command(['which', 'ovsdb-client'],
                           'Exit code: 1', 'ovsdb-client is not installed')
        self.check_command(['sudo', '-n', 'ovsdb-client', 'list-dbs'],
                           'Exit code: 1',
                           'password-less sudo not granted for ovsdb-client')


class TestOvsdbMonitor(BaseMonitorTest):

    def setUp(self):
        super(TestOvsdbMonitor, self).setUp()

        self.monitor = ovsdb_monitor.OvsdbMonitor('Bridge',
                                                  root_helper=self.root_helper)
        self.addCleanup(self.monitor.stop)
        self.monitor.start()

    def collect_initial_output(self):
        while True:
            output = list(self.monitor.iter_stdout())
            if output:
                return output[0]
            eventlet.sleep(0.01)

    def test_killed_monitor_respawns(self):
        with self.assert_max_execution_time():
            self.monitor.respawn_interval = 0
            old_pid = self.monitor._process.pid
            output1 = self.collect_initial_output()
            pid = self.monitor._get_pid_to_kill()
            self.monitor._kill_process(pid)
            self.monitor._reset_queues()
            while (self.monitor._process.pid == old_pid):
                eventlet.sleep(0.01)
            output2 = self.collect_initial_output()
            # Initial output should appear twice
            self.assertEqual(output1, output2)


class TestSimpleInterfaceMonitor(BaseMonitorTest):

    def setUp(self):
        super(TestSimpleInterfaceMonitor, self).setUp()

        self.monitor = ovsdb_monitor.SimpleInterfaceMonitor(
            root_helper=self.root_helper)
        self.addCleanup(self.monitor.stop)
        self.monitor.start(block=True)

    def test_has_updates(self):
        self.assertTrue(self.monitor.has_updates,
                        'Initial call should always be true')
        self.assertFalse(self.monitor.has_updates,
                         'has_updates without port addition should be False')
        self.create_resource('test-port-', self.bridge.add_port)
        with self.assert_max_execution_time():
            # has_updates after port addition should become True
            while not self.monitor.has_updates:
                eventlet.sleep(0.01)
