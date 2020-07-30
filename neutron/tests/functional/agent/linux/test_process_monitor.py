# Copyright 2014 Red Hat, Inc.
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

import os
import sys

from oslo_config import cfg

from neutron.agent.linux import external_process
from neutron.common import utils
from neutron.tests.functional.agent.linux import simple_daemon
from neutron.tests.functional import base


UUID_FORMAT = "test-uuid-%d"
SERVICE_NAME = "service"


class BaseTestProcessMonitor(base.BaseLoggingTestCase):

    def setUp(self):
        super(BaseTestProcessMonitor, self).setUp()
        cfg.CONF.set_override('check_child_processes_interval', 1, 'AGENT')
        self._child_processes = []
        self._process_monitor = None
        self.create_child_processes_manager('respawn')
        self.addCleanup(self.cleanup_spawned_children)

    def create_child_processes_manager(self, action):
        cfg.CONF.set_override('check_child_processes_action', action, 'AGENT')
        self._process_monitor = self.build_process_monitor()

    def build_process_monitor(self):
        return external_process.ProcessMonitor(
            config=cfg.CONF,
            resource_type='test')

    def _make_cmdline_callback(self, uuid):
        def _cmdline_callback(pidfile):
            cmdline = [sys.executable, simple_daemon.__file__,
                       "--uuid=%s" % uuid,
                       "--pid_file=%s" % pidfile]
            return cmdline
        return _cmdline_callback

    def spawn_n_children(self, n, service=None):
        self._child_processes = []
        for child_number in range(n):
            uuid = self._child_uuid(child_number)
            _callback = self._make_cmdline_callback(uuid)
            pm = external_process.ProcessManager(
                conf=cfg.CONF,
                uuid=uuid,
                default_cmd_callback=_callback,
                service=service)
            pm.enable()
            self._process_monitor.register(uuid, SERVICE_NAME, pm)

            self._child_processes.append(pm)

    @staticmethod
    def _child_uuid(child_number):
        return UUID_FORMAT % child_number

    def _kill_last_child(self):
        self._child_processes[-1].disable()

    def wait_for_all_children_spawned(self):
        def all_children_active():
            return all(pm.active for pm in self._child_processes)

        for pm in self._child_processes:
            directory = os.path.dirname(pm.get_pid_file_name())
            self.assertEqual(0o755, os.stat(directory).st_mode & 0o777)

        # we need to allow extra_time for the check process to happen
        # and properly execute action over the gone processes under
        # high load conditions
        max_wait_time = (
            cfg.CONF.AGENT.check_child_processes_interval + 5)
        utils.wait_until_true(
            all_children_active,
            timeout=max_wait_time,
            sleep=0.01,
            exception=RuntimeError('Not all children (re)spawned.'))

    def cleanup_spawned_children(self):
        self._process_monitor.stop()
        for pm in self._child_processes:
            pm.disable()


class TestProcessMonitor(BaseTestProcessMonitor):

    def test_respawn_handler(self):
        self.spawn_n_children(2)
        self.wait_for_all_children_spawned()
        self._kill_last_child()
        self.wait_for_all_children_spawned()
