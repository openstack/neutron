# Copyright 2018 Cloudbase Solutions.
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

import io

import ddt
import eventlet
from eventlet import tpool
import mock
from neutron_lib import exceptions
import six

from neutron.agent.windows import utils
from neutron.tests import base


@ddt.ddt
class WindowsUtilsTestCase(base.BaseTestCase):
    @mock.patch('os.environ', {mock.sentinel.key0: mock.sentinel.val0})
    @mock.patch.object(utils.subprocess, 'Popen')
    @mock.patch.object(tpool, 'Proxy')
    @mock.patch.object(eventlet, 'getcurrent')
    def test_create_process(self, mock_get_current_gt,
                            mock_tpool_proxy, mock_popen):
        cmd = ['fake_cmd']

        popen_obj, ret_cmd = utils.create_process(
            cmd,
            run_as_root=mock.sentinel.run_as_root,
            addl_env={mock.sentinel.key1: mock.sentinel.val1},
            tpool_proxy=True)

        exp_env = {mock.sentinel.key0: mock.sentinel.val0,
                   mock.sentinel.key1: mock.sentinel.val1}

        mock_popen.assert_called_once_with(
            cmd,
            shell=False,
            stdin=utils.subprocess.PIPE,
            stdout=utils.subprocess.PIPE,
            stderr=utils.subprocess.PIPE,
            env=exp_env,
            preexec_fn=None,
            close_fds=False)

        file_type = getattr(six.moves.builtins, 'file', io.IOBase)
        mock_tpool_proxy.assert_called_once_with(
            mock_popen.return_value, autowrap=(file_type, ))

        self.assertEqual(mock_tpool_proxy.return_value, popen_obj)
        self.assertEqual(ret_cmd, cmd)

    @ddt.data({},
              {'pid': None},
              {'process_exists': True})
    @ddt.unpack
    @mock.patch.object(utils, 'wmi', create=True)
    def test_get_wmi_process(self, mock_wmi,
                             pid=mock.sentinel.pid,
                             process_exists=False):
        mock_conn = mock_wmi.WMI.return_value

        if not pid:
            exp_process = None
        elif process_exists:
            exp_process = mock.sentinel.wmi_obj
            mock_conn.Win32_Process.return_value = [exp_process]
        else:
            exp_process = None
            mock_conn.Win32_Process.return_value = []

        wmi_obj = utils._get_wmi_process(pid)
        self.assertEqual(exp_process, wmi_obj)

        if pid:
            mock_conn.Win32_Process.assert_called_once_with(ProcessId=pid)

    @ddt.data(True, False)
    @mock.patch.object(utils, '_get_wmi_process')
    def test_kill_process(self, process_exists, mock_get_process):
        if not process_exists:
            mock_get_process.return_value = None

        utils.kill_process(mock.sentinel.pid, mock.sentinel.signal,
                           run_as_root=False)

        mock_get_process.assert_called_once_with(mock.sentinel.pid)
        if process_exists:
            mock_get_process.return_value.Terminate.assert_called_once_with()

    @ddt.data(True, False)
    @mock.patch.object(utils, '_get_wmi_process')
    def test_kill_process_exception(self, process_still_running,
                                    mock_get_process):
        mock_process = mock.Mock()
        mock_process.Terminate.side_effect = OSError

        mock_get_process.side_effect = [
            mock_process,
            mock_process if process_still_running else None]

        if process_still_running:
            self.assertRaises(OSError,
                              utils.kill_process,
                              mock.sentinel.pid,
                              mock.sentinel.signal)
        else:
            utils.kill_process(mock.sentinel.pid,
                               mock.sentinel.signal)

    @ddt.data({'return_stder': True},
              {'returncode': 1,
               'check_exit_code': False,
               'log_fail_as_error': True},
              {'returncode': 1,
               'log_fail_as_error': True,
               'extra_ok_codes': [1]},
              {'returncode': 1,
               'log_fail_as_error': True,
               'exp_fail': True})
    @ddt.unpack
    @mock.patch.object(utils, 'create_process')
    @mock.patch.object(utils, 'avoid_blocking_call')
    def test_execute(self, mock_avoid_blocking_call, mock_create_process,
                     returncode=0, check_exit_code=True, return_stder=True,
                     log_fail_as_error=True, extra_ok_codes=None,
                     exp_fail=False):
        fake_stdin = 'fake_stdin'
        fake_stdout = 'fake_stdout'
        fake_stderr = 'fake_stderr'

        mock_popen = mock.Mock()
        mock_popen.communicate.return_value = fake_stdout, fake_stderr
        mock_popen.returncode = returncode

        mock_create_process.return_value = mock_popen, mock.sentinel.cmd
        mock_avoid_blocking_call.side_effect = (
            lambda func, *args, **kwargs: func(*args, **kwargs))

        args = (mock.sentinel.cmd, fake_stdin, mock.sentinel.env,
                check_exit_code, return_stder, log_fail_as_error,
                extra_ok_codes)

        if exp_fail:
            self.assertRaises(exceptions.ProcessExecutionError,
                              utils.execute,
                              *args)
        else:
            ret_val = utils.execute(*args)
            if return_stder:
                exp_ret_val = (fake_stdout, fake_stderr)
            else:
                exp_ret_val = fake_stdout

            self.assertEqual(exp_ret_val, ret_val)

        mock_create_process.assert_called_once_with(
            mock.sentinel.cmd, addl_env=mock.sentinel.env,
            tpool_proxy=False)
        mock_avoid_blocking_call.assert_called_once_with(
            mock_popen.communicate, six.b(fake_stdin))
        mock_popen.communicate.assert_called_once_with(six.b(fake_stdin))
        mock_popen.stdin.close.assert_called_once_with()

    def test_get_root_helper_child_pid(self):
        pid = utils.get_root_helper_child_pid(
            mock.sentinel.pid,
            mock.sentinel.exp_cmd,
            run_as_root=False)
        self.assertEqual(str(mock.sentinel.pid), pid)

    @ddt.data(True, False)
    @mock.patch.object(utils, '_get_wmi_process')
    def test_process_is_running(self, process_running, mock_get_process):
        mock_get_process.return_value = (
            mock.sentinel.wmi_obj if process_running else None)

        self.assertEqual(process_running,
                         utils.process_is_running(mock.sentinel.pid))
        mock_get_process.assert_called_once_with(mock.sentinel.pid)

    @ddt.data({},
              {'process_running': False},
              {'command_matches': False})
    @ddt.unpack
    @mock.patch.object(utils, '_get_wmi_process')
    def test_pid_invoked_with_cmdline(self, mock_get_process,
                                      process_running=True,
                                      command_matches=False):
        exp_cmd = 'exp_cmd'
        mock_process = mock.Mock()

        mock_get_process.return_value = (
            mock_process if process_running else None)
        mock_process.CommandLine = (
            exp_cmd if command_matches else 'unexpected_cmd')

        exp_result = process_running and command_matches
        result = utils.pid_invoked_with_cmdline(mock.sentinel.pid,
                                                [exp_cmd])

        self.assertEqual(exp_result, result)
        mock_get_process.assert_called_once_with(mock.sentinel.pid)
