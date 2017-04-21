# Copyright (c) 2014 Red Hat, Inc.
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

from oslo_config import cfg

from neutron._i18n import _
from neutron.agent.linux import external_process
from neutron.agent.linux import keepalived
from neutron.agent.linux import utils
from neutron.common import utils as common_utils
from neutron.tests.functional.agent.linux import helpers
from neutron.tests.functional import base
from neutron.tests.unit.agent.linux import test_keepalived


class KeepalivedManagerTestCase(base.BaseLoggingTestCase,
                                test_keepalived.KeepalivedConfBaseMixin):

    def setUp(self):
        super(KeepalivedManagerTestCase, self).setUp()
        cfg.CONF.set_override('check_child_processes_interval', 1, 'AGENT')

        self.expected_config = self._get_config()
        self.process_monitor = external_process.ProcessMonitor(cfg.CONF,
                                                               'router')
        self.manager = keepalived.KeepalivedManager(
            'router1', self.expected_config, self.process_monitor,
            conf_path=cfg.CONF.state_path)
        self.addCleanup(self.manager.disable)

    def _spawn_keepalived(self, keepalived_manager):
        keepalived_manager.spawn()
        process = keepalived_manager.get_process()
        common_utils.wait_until_true(
            lambda: process.active,
            timeout=5,
            sleep=0.01,
            exception=RuntimeError(_("Keepalived didn't spawn")))
        return process

    def test_keepalived_spawn(self):
        self._spawn_keepalived(self.manager)

        self.assertEqual(self.expected_config.get_config_str(),
                         self.manager.get_conf_on_disk())

    def _test_keepalived_respawns(self, normal_exit=True):
        process = self._spawn_keepalived(self.manager)
        pid = process.pid
        exit_code = '-15' if normal_exit else '-9'

        # Exit the process, and see that when it comes back
        # It's indeed a different process
        utils.execute(['kill', exit_code, pid])
        common_utils.wait_until_true(
            lambda: process.active and pid != process.pid,
            timeout=5,
            sleep=0.01,
            exception=RuntimeError(_("Keepalived didn't respawn")))

    def test_keepalived_respawns(self):
        self._test_keepalived_respawns()

    def test_keepalived_respawn_with_unexpected_exit(self):
        self._test_keepalived_respawns(False)

    def _test_keepalived_spawns_conflicting_pid(self, process, pid_file):
        # Test the situation when keepalived PID file contains PID of an
        # existing non-keepalived process. This situation can happen e.g.
        # after hard node reset.

        spawn_process = helpers.SleepyProcessFixture()
        self.useFixture(spawn_process)

        with open(pid_file, "w") as f_pid_file:
            f_pid_file.write("%s" % spawn_process.pid)

        self._spawn_keepalived(self.manager)

    def test_keepalived_spawns_conflicting_pid_base_process(self):
        process = self.manager.get_process()
        pid_file = process.get_pid_file_name()
        self._test_keepalived_spawns_conflicting_pid(process, pid_file)

    def test_keepalived_spawns_conflicting_pid_vrrp_subprocess(self):
        process = self.manager.get_process()
        pid_file = process.get_pid_file_name()
        self._test_keepalived_spawns_conflicting_pid(
            process,
            self.manager.get_vrrp_pid_file_name(pid_file))
