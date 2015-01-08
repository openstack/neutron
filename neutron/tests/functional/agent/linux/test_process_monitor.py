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

import eventlet
from oslo_config import cfg
from six import moves

from neutron.agent.linux import external_process
from neutron.tests.functional.agent.linux import simple_daemon
from neutron.tests.functional import base


UUID_FORMAT = "test-uuid-%d"


class BaseTestProcessMonitor(base.BaseSudoTestCase):

    def setUp(self):
        super(BaseTestProcessMonitor, self).setUp()
        cfg.CONF.set_override('check_child_processes_interval', 1, 'AGENT')
        self._child_processes = []
        self._ext_processes = None
        self.create_child_processes_manager('respawn')
        self.addCleanup(self.cleanup_spawned_children)

    def create_child_processes_manager(self, action):
        cfg.CONF.set_override('check_child_processes_action', action, 'AGENT')
        self._ext_processes = self.build_process_monitor()

    def build_process_monitor(self):
        return external_process.ProcessMonitor(
            config=cfg.CONF,
            root_helper=None,
            resource_type='test')

    def _make_cmdline_callback(self, uuid):
        def _cmdline_callback(pidfile):
            cmdline = ["python", simple_daemon.__file__,
                       "--uuid=%s" % uuid,
                       "--pid_file=%s" % pidfile]
            return cmdline
        return _cmdline_callback

    def spawn_n_children(self, n, service=None):
        self._child_processes = []
        for child_number in moves.xrange(n):
            uuid = self._child_uuid(child_number)
            _callback = self._make_cmdline_callback(uuid)
            self._ext_processes.enable(uuid=uuid,
                                       cmd_callback=_callback,
                                       service=service)

            pm = self._ext_processes.get_process_manager(uuid, service)
            self._child_processes.append(pm)

    @staticmethod
    def _child_uuid(child_number):
        return UUID_FORMAT % child_number

    def _kill_last_child(self):
        self._child_processes[-1].disable()

    def spawn_child_processes_and_kill_last(self, service=None, number=2):
        self.spawn_n_children(number, service)
        self._kill_last_child()
        self.assertFalse(self._child_processes[-1].active)

    def wait_for_all_childs_respawned(self):
        def all_childs_active():
            return all(pm.active for pm in self._child_processes)

        self._wait_for_condition(all_childs_active)

    def _wait_for_condition(self, exit_condition, extra_time=5):
        # we need to allow extra_time for the check process to happen
        # and properly execute action over the gone processes under
        # high load conditions
        max_wait_time = (
            cfg.CONF.AGENT.check_child_processes_interval + extra_time)
        with self.assert_max_execution_time(max_wait_time):
            while not exit_condition():
                eventlet.sleep(0.01)

    def cleanup_spawned_children(self):
        if self._ext_processes:
            self._ext_processes.disable_all()


class TestProcessMonitor(BaseTestProcessMonitor):

    def test_respawn_handler(self):
        self.spawn_child_processes_and_kill_last()
        self.wait_for_all_childs_respawned()

    def test_new_process_monitor_finds_old_process(self):
        self.spawn_n_children(1)
        spawn_process = self._child_processes[-1]
        uuid = spawn_process.uuid

        another_pm = self.build_process_monitor()
        self.assertTrue(another_pm.is_active(uuid))
        self.assertEqual(another_pm.get_pid(uuid), spawn_process.pid)

    def test_tries_to_get_pid_for_unknown_uuid(self):
        self.assertIsNone(self._ext_processes.get_pid('bad-uuid'))
