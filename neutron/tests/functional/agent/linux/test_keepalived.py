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
from neutron.tests.functional import base as functional_base
from neutron.tests.unit.agent.linux import test_keepalived


class KeepalivedManagerTestCase(functional_base.BaseSudoTestCase,
                                test_keepalived.KeepalivedConfBaseMixin):
    def setUp(self):
        super(KeepalivedManagerTestCase, self).setUp()
        self.check_sudo_enabled()

    def test_keepalived_spawn(self):
        expected_config = self._get_config()
        manager = keepalived.KeepalivedManager('router1', expected_config,
                                               conf_path=cfg.CONF.state_path,
                                               root_helper=self.root_helper)
        self.addCleanup(manager.disable)

        manager.spawn()
        process = external_process.ProcessManager(
            cfg.CONF,
            'router1',
            namespace=None,
            pids_path=cfg.CONF.state_path)
        self.assertTrue(process.active)

        self.assertEqual(expected_config.get_config_str(),
                         manager.get_conf_on_disk())
