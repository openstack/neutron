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
import os
import signal

from neutron.agent.common import async_process
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


class TestFindParentPid(functional_base.BaseSudoTestCase):

    def _stop_process(self, process):
        process.stop(kill_signal=signal.SIGKILL)

    def _test_process(self, run_as_root):
        test_pid = str(os.getppid())
        cmd = ['bash', '-c', '(sleep 10)']
        proc = async_process.AsyncProcess(cmd, run_as_root=run_as_root)
        proc.start()
        self.addCleanup(self._stop_process, proc)
        common_utils.wait_until_true(lambda: proc._process.pid,
                                     sleep=0.5, timeout=10)

        bash_pid = utils.find_parent_pid(proc._process.pid)
        testcase_pid = utils.find_parent_pid(bash_pid)
        self.assertEqual(test_pid, testcase_pid)

    def test_root_process(self):
        self._test_process(run_as_root=True)

    def test_non_root_process(self):
        self._test_process(run_as_root=False)


class TestGetProcessCountByName(functional_base.BaseSudoTestCase):

    def _stop_processes(self, processes):
        for process in processes:
            process.stop(kill_signal=signal.SIGKILL)

    def test_root_process(self):
        cmd = ['sleep', '100']
        processes = []
        for _ in range(20):
            process = async_process.AsyncProcess(cmd)
            process.start()
            processes.append(process)
        for process in processes:
            common_utils.wait_until_true(lambda: process._process.pid,
                                         sleep=0.5, timeout=5)
        self.addCleanup(self._stop_processes, processes)
        number_of_sleep = utils.get_process_count_by_name('sleep')
        # NOTE(ralonsoh): other tests can spawn sleep processes too, but at
        # this point we know there are, at least, 20 "sleep" processes running.
        self.assertLessEqual(20, number_of_sleep)


class TestFindChildPids(functional_base.BaseSudoTestCase):

    def _stop_process(self, process):
        process.stop(kill_signal=signal.SIGKILL)

    def test_find_child_pids(self):
        pid = os.getppid()
        child_pids = utils.find_child_pids(pid)
        child_pids_recursive = utils.find_child_pids(pid, recursive=True)
        for _pid in child_pids:
            self.assertIn(_pid, child_pids_recursive)

        cmd = ['sleep', '100']
        process = async_process.AsyncProcess(cmd)
        process.start()
        common_utils.wait_until_true(lambda: process._process.pid,
                                     sleep=0.5, timeout=10)
        self.addCleanup(self._stop_process, process)

        child_pids_after = utils.find_child_pids(pid)
        child_pids_recursive_after = utils.find_child_pids(pid, recursive=True)
        self.assertEqual(child_pids, child_pids_after)
        for _pid in child_pids + [process.pid]:
            self.assertIn(_pid, child_pids_recursive_after)

    def test_find_non_existing_process(self):
        with open('/proc/sys/kernel/pid_max', 'r') as fd:
            pid_max = int(fd.readline().strip())
        self.assertEqual([], utils.find_child_pids(pid_max))
