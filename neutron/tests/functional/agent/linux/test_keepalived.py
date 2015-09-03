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

from neutron.agent.linux import external_process
from neutron.agent.linux import keepalived
from neutron.agent.linux import utils
from neutron.tests import base
from neutron.tests.unit.agent.linux import test_keepalived


class KeepalivedManagerTestCase(base.BaseTestCase,
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

    def test_keepalived_spawn(self):
        self.manager.spawn()
        process = external_process.ProcessManager(
            cfg.CONF,
            'router1',
            namespace=None,
            pids_path=cfg.CONF.state_path)
        self.assertTrue(process.active)

        self.assertEqual(self.expected_config.get_config_str(),
                         self.manager.get_conf_on_disk())

    def test_keepalived_respawns(self):
        self.manager.spawn()
        process = self.manager.get_process()
        self.assertTrue(process.active)

        process.disable(sig='15')

        utils.wait_until_true(
            lambda: process.active,
            timeout=5,
            sleep=0.01,
            exception=RuntimeError(_("Keepalived didn't respawn")))
