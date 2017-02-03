# Copyright 2015 Red Hat, Inc.
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

import functools

from neutron.agent.linux import async_process
from neutron.agent.linux import utils
from neutron.common import utils as common_utils
from neutron.tests.functional.agent.linux import test_async_process
from neutron.tests.functional import base as functional_base


class TestPIDHelpers(test_async_process.AsyncProcessTestFramework):
    def test_get_cmdline_from_pid_and_pid_invoked_with_cmdline(self):
        cmd = ['tail', '-f', self.test_file_path]
        proc = async_process.AsyncProcess(cmd)
        proc.start(block=True)
        self.addCleanup(proc.stop)

        pid = proc.pid
        self.assertEqual(cmd, utils.get_cmdline_from_pid(pid))
        self.assertTrue(utils.pid_invoked_with_cmdline(pid, cmd))
        self.assertEqual([], utils.get_cmdline_from_pid(-1))


class TestGetRootHelperChildPid(functional_base.BaseSudoTestCase):
    def _addcleanup_sleep_process(self, parent_pid):
        sleep_pid = utils.execute(
            ['ps', '--ppid', parent_pid, '-o', 'pid=']).strip()
        self.addCleanup(
            utils.execute,
            ['kill', '-9', sleep_pid],
            check_exit_code=False,
            run_as_root=True)

    def test_get_root_helper_child_pid_returns_first_child(self):
        """Test that the first child, not lowest child pid is returned.

        Test creates following process tree:
          sudo +
               |
               +--rootwrap +
                           |
                           +--bash+
                                  |
                                  +--sleep 100

        and tests that pid of `bash' command is returned.
        """

        def wait_for_sleep_is_spawned(parent_pid):
            proc_tree = utils.execute(
                ['pstree', parent_pid], check_exit_code=False)
            processes = [command.strip() for command in proc_tree.split('---')
                         if command]
            if processes:
                return 'sleep' == processes[-1]

        cmd = ['bash', '-c', '(sleep 100)']
        proc = async_process.AsyncProcess(cmd, run_as_root=True)
        proc.start()

        # root helpers spawn their child processes asynchronously, and we
        # don't want to use proc.start(block=True) as that uses
        # get_root_helper_child_pid (The method under test) internally.
        sudo_pid = proc._process.pid
        common_utils.wait_until_true(
            functools.partial(
                wait_for_sleep_is_spawned,
                sudo_pid),
            sleep=0.1)

        child_pid = utils.get_root_helper_child_pid(
            sudo_pid, cmd, run_as_root=True)
        self.assertIsNotNone(
            child_pid,
            "get_root_helper_child_pid is expected to return the pid of the "
            "bash process")
        self._addcleanup_sleep_process(child_pid)
        with open('/proc/%s/cmdline' % child_pid, 'r') as f_proc_cmdline:
            cmdline = f_proc_cmdline.readline().split('\0')[0]
        self.assertIn('bash', cmdline)
