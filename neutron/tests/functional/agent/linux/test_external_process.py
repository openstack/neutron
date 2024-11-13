# Copyright (c) 2024 Red Hat, Inc.
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

import os
import signal
import tempfile

from oslo_config import cfg

from neutron.agent.common import async_process
from neutron.agent.linux import external_process as ep
from neutron.agent.linux import utils as agent_utils
from neutron.common import utils as common_utils
from neutron.tests.common import net_helpers
from neutron.tests.functional import base as functional_base


class ProcessManagerTestCase(functional_base.BaseSudoTestCase):

    def _create_sleep_process(self, time=None):
        if time is None:
            cmd = ['sleep', 'infinity']
        else:
            cmd = ['sleep', str(time)]
        process = async_process.AsyncProcess(cmd)
        process.start()

        with tempfile.NamedTemporaryFile('w+', delete=False) as pid_file:
            pid_file.write(process.pid)
        os.chmod(pid_file.name, 0o777)
        uuid = 'sleep infinity'
        namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        return ep.ProcessManager(cfg.CONF, uuid, namespace,
                                 pid_file=pid_file.name)

    def test__kill_process(self):
        pm = self._create_sleep_process()
        self.assertTrue(pm.active)

        pm._kill_process(pm.get_kill_cmd(int(signal.SIGKILL), pm.pid), pm.pid)
        # Delete the PID file used by ``pm.active``.
        agent_utils.delete_if_exists(pm.get_pid_file_name())
        self.assertFalse(pm.active)

    def test__kill_process_process_not_present(self):
        pm = self._create_sleep_process(time=0)
        # "sleep 0" should end immediately, but we add an active wait of 3
        # seconds just to avoid any race condition.
        try:
            common_utils.wait_until_true(lambda: not pm.active, timeout=3)
        except common_utils.WaitTimeout:
            self.fail('The process "sleep 0" (PID: %s) did not finish' %
                      pm.pid)

        # '_kill_process' should not raise any exception.
        pm._kill_process(pm.get_kill_cmd(int(signal.SIGKILL), pm.pid), pm.pid)
        self.assertFalse(pm.active)
