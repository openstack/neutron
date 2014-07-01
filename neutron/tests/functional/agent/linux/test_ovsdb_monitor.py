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

import os
import random

import eventlet

from neutron.agent.linux import ovs_lib
from neutron.agent.linux import ovsdb_monitor
from neutron.agent.linux import utils
from neutron.tests import base


def get_rand_name(name='test'):
    return name + str(random.randint(1, 0x7fffffff))


def create_ovs_resource(name_prefix, creation_func):
    """Create a new ovs resource that does not already exist.

    :param name_prefix: The prefix for a randomly generated name
    :param creation_func: A function taking the name of the resource
           to be created.  An error is assumed to indicate a name
           collision.
    """
    while True:
        name = get_rand_name(name_prefix)
        try:
            return creation_func(name)
        except RuntimeError:
            continue
        break


class BaseMonitorTest(base.BaseTestCase):

    def setUp(self):
        super(BaseMonitorTest, self).setUp()

        self._check_test_requirements()

        # Emulate using a rootwrap script with sudo
        self.root_helper = 'sudo sudo'
        self.ovs = ovs_lib.BaseOVS(self.root_helper)
        self.bridge = create_ovs_resource('test-br-', self.ovs.add_bridge)

        def cleanup_bridge():
            self.bridge.destroy()
        self.addCleanup(cleanup_bridge)

    def _check_command(self, cmd, error_text, skip_msg):
        try:
            utils.execute(cmd)
        except RuntimeError as e:
            if error_text in str(e):
                self.skipTest(skip_msg)
            raise

    def _check_test_requirements(self):
        if os.environ.get('OS_SUDO_TESTING') not in base.TRUE_STRING:
            self.skipTest('testing with sudo is not enabled')
        self._check_command(['which', 'ovsdb-client'],
                            'Exit code: 1',
                            'ovsdb-client is not installed')
        self._check_command(['sudo', '-n', 'ovsdb-client', 'list-dbs'],
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
                # Output[0] is header row with spaces for column separation.
                # The column widths can vary depending on the data in the
                # columns, so compress multiple spaces to one for testing.
                return ' '.join(output[0].split())
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
        create_ovs_resource('test-port-', self.bridge.add_port)
        with self.assert_max_execution_time():
            # has_updates after port addition should become True
            while not self.monitor.has_updates:
                eventlet.sleep(0.01)
