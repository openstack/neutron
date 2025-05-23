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

import errno

from oslo_config import cfg

from neutron._i18n import _
from neutron.agent.linux import conntrackd
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.common import utils as common_utils
from neutron.conf.agent.l3 import config as l3_config
from neutron.conf.agent.l3 import ha as ha_config
from neutron.tests.common import net_helpers
from neutron.tests.functional import base
from neutron.tests.unit.agent.l3.test_agent import FAKE_ID
from neutron.tests.unit.agent.linux.test_conntrackd import \
    ConntrackdConfigTestCase
from neutron_lib.exceptions import ProcessExecutionError


class ConntrackdManagerTestCase(base.BaseSudoTestCase):

    def setUp(self):
        super().setUp()
        l3_config.register_l3_agent_config_opts(l3_config.OPTS, cfg.CONF)
        ha_config.register_l3_agent_ha_opts()
        self.config(check_child_processes_interval=1, group='AGENT')

        self.process_monitor = external_process.ProcessMonitor(cfg.CONF,
                                                               'router')
        self.namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        self.ip_wrapper = ip_lib.IPWrapper(namespace=self.namespace)
        self._prepare_device()

        self.manager = conntrackd.ConntrackdManager(
            FAKE_ID,
            self.process_monitor,
            cfg.CONF,
            '192.168.0.5',
            3,
            'eth0',
            namespace=self.namespace)
        self.addCleanup(self._stop_conntrackd_manager)

    def _stop_conntrackd_manager(self):
        try:
            self.manager.disable()
        except ProcessExecutionError as process_err:
            # self.manager.disable() will perform SIGTERM->wait->SIGKILL
            # (if needed) on the process. However, it is sometimes possible
            # that SIGKILL gets called on a process that just exited due to
            # SIGTERM. Ignore this condition so the test is not marked as
            # failed.
            if not (len(process_err.args) > 0 and
                    "No such process" in process_err.args[0]):
                raise

    def _prepare_device(self):
        # NOTE(gaudenz): this is the device used in the conntrackd config
        # file
        ip_device = self.ip_wrapper.add_dummy('eth0')
        ip_device.link.set_up()
        ip_device.addr.add('192.168.0.5/24')

    def _spawn_conntrackd(self, conntrackd_manager):
        conntrackd_manager.spawn()
        process = conntrackd_manager.get_process()
        common_utils.wait_until_true(
            lambda: process.active,
            timeout=5,
            sleep=0.01,
            exception=RuntimeError(_("Conntrackd didn't spawn")))
        return process

    def _get_conf_on_disk(self):
        config_path = self.manager.get_conffile_path()
        try:
            with open(config_path) as conf:
                return conf.read()
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
        return ''

    def test_conntrackd_config(self):
        self._spawn_conntrackd(self.manager)

        expected_config = ConntrackdConfigTestCase.get_expected(
            cfg.CONF.ha_confs_path,
        )
        self.assertEqual(expected_config,
                         self._get_conf_on_disk())

    def test_conntrackd_spawn(self):
        process = self._spawn_conntrackd(self.manager)

        self.assertTrue(process.active)

    def _test_conntrackd_respawns(self, normal_exit=True):
        process = self._spawn_conntrackd(self.manager)
        pid = process.pid
        exit_code = '-15' if normal_exit else '-9'

        # Exit the process, and see that when it comes back
        # It's indeed a different process
        self.ip_wrapper.netns.execute(['kill', exit_code, pid],
                                      privsep_exec=True)
        common_utils.wait_until_true(
            lambda: process.active and pid != process.pid,
            timeout=5,
            sleep=0.01,
            exception=RuntimeError(_("Conntrackd didn't respawn")))

    def test_conntrackd_respawns(self):
        self._test_conntrackd_respawns()

    def test_conntrackd_respawn_with_unexpected_exit(self):
        self._test_conntrackd_respawns(False)
