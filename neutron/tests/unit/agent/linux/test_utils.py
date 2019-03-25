# Copyright 2012, VMware, Inc.
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

import signal
import socket

import mock
import six
import testtools

from oslo_config import cfg
import oslo_i18n

from neutron.agent.linux import utils
from neutron.common import exceptions as n_exc
from neutron.tests import base
from neutron.tests.common import helpers
from neutron.tests import tools


_marker = object()


class AgentUtilsExecuteTest(base.BaseTestCase):
    def setUp(self):
        super(AgentUtilsExecuteTest, self).setUp()
        self.test_file = self.get_temp_file_path('test_execute.tmp')
        open(self.test_file, 'w').close()
        self.process = mock.patch('eventlet.green.subprocess.Popen').start()
        self.process.return_value.returncode = 0
        self.mock_popen = self.process.return_value.communicate

    def test_xenapi_root_helper(self):
        token = utils.xenapi_root_helper.ROOT_HELPER_DAEMON_TOKEN
        self.config(group='AGENT', root_helper_daemon=token)
        with mock.patch(
                'neutron.agent.linux.utils.xenapi_root_helper.XenAPIClient')\
                as mock_xenapi_class:
            mock_client = mock_xenapi_class.return_value
            cmd_client = utils.RootwrapDaemonHelper.get_client()
            self.assertEqual(cmd_client, mock_client)

    def test_without_helper(self):
        expected = "%s\n" % self.test_file
        self.mock_popen.return_value = [expected, ""]
        result = utils.execute(["ls", self.test_file])
        self.assertEqual(result, expected)

    def test_with_helper(self):
        expected = "ls %s\n" % self.test_file
        self.mock_popen.return_value = [expected, ""]
        self.config(group='AGENT', root_helper='echo')
        result = utils.execute(["ls", self.test_file], run_as_root=True)
        self.assertEqual(result, expected)

    @mock.patch.object(utils.RootwrapDaemonHelper, 'get_client')
    def test_with_helper_exception(self, get_client):
        client_inst = mock.Mock()
        client_inst.execute.side_effect = RuntimeError
        get_client.return_value = client_inst
        self.config(group='AGENT', root_helper_daemon='echo')
        with mock.patch.object(utils, 'LOG') as log:
            self.assertRaises(RuntimeError, utils.execute,
                              ['ls'], run_as_root=True)
            self.assertTrue(log.error.called)

    def test_stderr_true(self):
        expected = "%s\n" % self.test_file
        self.mock_popen.return_value = [expected, ""]
        out = utils.execute(["ls", self.test_file], return_stderr=True)
        self.assertIsInstance(out, tuple)
        self.assertEqual(out, (expected, ""))

    def test_check_exit_code(self):
        self.mock_popen.return_value = ["", ""]
        stdout = utils.execute(["ls", self.test_file[:-1]],
                               check_exit_code=False)
        self.assertEqual("", stdout)

    def test_execute_raises(self):
        self.mock_popen.side_effect = RuntimeError
        self.assertRaises(RuntimeError, utils.execute,
                          ["ls", self.test_file[:-1]])

    def test_process_input(self):
        expected = "%s\n" % self.test_file[:-1]
        self.mock_popen.return_value = [expected, ""]
        result = utils.execute(["cat"], process_input="%s\n" %
                               self.test_file[:-1])
        self.assertEqual(result, expected)

    def test_with_addl_env(self):
        expected = "%s\n" % self.test_file
        self.mock_popen.return_value = [expected, ""]
        result = utils.execute(["ls", self.test_file],
                               addl_env={'foo': 'bar'})
        self.assertEqual(result, expected)

    def test_return_code_log_error_raise_runtime(self):
        self.mock_popen.return_value = ('', '')
        self.process.return_value.returncode = 1
        with mock.patch.object(utils, 'LOG') as log:
            self.assertRaises(RuntimeError, utils.execute,
                              ['ls'])
            self.assertTrue(log.error.called)

    def test_return_code_log_error_no_raise_runtime(self):
        self.mock_popen.return_value = ('', '')
        self.process.return_value.returncode = 1
        with mock.patch.object(utils, 'LOG') as log:
            utils.execute(['ls'], check_exit_code=False)
            self.assertTrue(log.error.called)

    def test_return_code_log_debug(self):
        self.mock_popen.return_value = ('', '')
        with mock.patch.object(utils, 'LOG') as log:
            utils.execute(['ls'])
            self.assertTrue(log.debug.called)

    def test_return_code_log_error_change_locale(self):
        ja_output = 'std_out in Japanese'
        ja_error = 'std_err in Japanese'
        ja_message_out = oslo_i18n._message.Message(ja_output)
        ja_message_err = oslo_i18n._message.Message(ja_error)
        ja_translate_out = oslo_i18n._translate.translate(ja_message_out, 'ja')
        ja_translate_err = oslo_i18n._translate.translate(ja_message_err, 'ja')
        self.mock_popen.return_value = (ja_translate_out, ja_translate_err)
        self.process.return_value.returncode = 1

        with mock.patch.object(utils, 'LOG') as log:
            utils.execute(['ls'], check_exit_code=False)
            self.assertIn(ja_translate_out, str(log.error.call_args_list))
            self.assertIn(ja_translate_err, str(log.error.call_args_list))

    def test_return_code_raise_runtime_do_not_log_fail_as_error(self):
        self.mock_popen.return_value = ('', '')
        self.process.return_value.returncode = 1
        with mock.patch.object(utils, 'LOG') as log:
            self.assertRaises(n_exc.ProcessExecutionError, utils.execute,
                              ['ls'], log_fail_as_error=False)
            self.assertFalse(log.error.called)

    def test_encode_process_input(self):
        str_idata = "%s\n" % self.test_file[:-1]
        str_odata = "%s\n" % self.test_file
        if six.PY3:
            bytes_idata = str_idata.encode(encoding='utf-8')
            bytes_odata = str_odata.encode(encoding='utf-8')
            self.mock_popen.return_value = [bytes_odata, b'']
            result = utils.execute(['cat'], process_input=str_idata)
            self.mock_popen.assert_called_once_with(bytes_idata)
        else:
            self.mock_popen.return_value = [str_odata, '']
            result = utils.execute(['cat'], process_input=str_idata)
            self.mock_popen.assert_called_once_with(str_idata)
        self.assertEqual(str_odata, result)

    def test_return_str_data(self):
        str_data = "%s\n" % self.test_file
        self.mock_popen.return_value = [str_data, '']
        result = utils.execute(['ls', self.test_file], return_stderr=True)
        self.assertEqual((str_data, ''), result)

    @helpers.requires_py3
    def test_surrogateescape_in_decoding_out_data(self):
        bytes_err_data = b'\xed\xa0\xbd'
        err_data = bytes_err_data.decode('utf-8', 'surrogateescape')
        out_data = "%s\n" % self.test_file
        bytes_out_data = out_data.encode(encoding='utf-8')
        self.mock_popen.return_value = [bytes_out_data, bytes_err_data]
        result = utils.execute(['ls', self.test_file], return_stderr=True)
        self.assertEqual((out_data, err_data), result)


class AgentUtilsExecuteEncodeTest(base.BaseTestCase):
    def setUp(self):
        super(AgentUtilsExecuteEncodeTest, self).setUp()
        self.test_file = self.get_temp_file_path('test_execute.tmp')
        open(self.test_file, 'w').close()

    def test_decode_return_data(self):
        str_data = "%s\n" % self.test_file
        result = utils.execute(['ls', self.test_file], return_stderr=True)
        self.assertEqual((str_data, ''), result)


class TestFindParentPid(base.BaseTestCase):
    def setUp(self):
        super(TestFindParentPid, self).setUp()
        self.m_execute = mock.patch.object(utils, 'execute').start()

    def test_returns_none_for_no_valid_pid(self):
        self.m_execute.side_effect = n_exc.ProcessExecutionError('',
                                                                 returncode=1)
        self.assertIsNone(utils.find_parent_pid(-1))

    def test_returns_parent_id_for_good_ouput(self):
        self.m_execute.return_value = '123 \n'
        self.assertEqual(utils.find_parent_pid(-1), '123')

    def test_raises_exception_returncode_0(self):
        with testtools.ExpectedException(n_exc.ProcessExecutionError):
            self.m_execute.side_effect = \
                n_exc.ProcessExecutionError('', returncode=0)
            utils.find_parent_pid(-1)

    def test_raises_unknown_exception(self):
        with testtools.ExpectedException(RuntimeError):
            self.m_execute.side_effect = RuntimeError()
            utils.find_parent_pid(-1)


class TestFindForkTopParent(base.BaseTestCase):
    def _test_find_fork_top_parent(self, expected=_marker,
                                   find_parent_pid_retvals=None,
                                   pid_invoked_with_cmdline_retvals=None):
        def _find_parent_pid(x):
            if find_parent_pid_retvals:
                return find_parent_pid_retvals.pop(0)

        pid_invoked_with_cmdline = {}
        if pid_invoked_with_cmdline_retvals:
            pid_invoked_with_cmdline['side_effect'] = (
                pid_invoked_with_cmdline_retvals)
        else:
            pid_invoked_with_cmdline['return_value'] = False
        with mock.patch.object(utils, 'find_parent_pid',
                               side_effect=_find_parent_pid), \
                mock.patch.object(utils, 'pid_invoked_with_cmdline',
                                  **pid_invoked_with_cmdline):
            actual = utils.find_fork_top_parent(_marker)
        self.assertEqual(expected, actual)

    def test_returns_own_pid_no_parent(self):
        self._test_find_fork_top_parent()

    def test_returns_own_pid_nofork(self):
        self._test_find_fork_top_parent(find_parent_pid_retvals=['2', '3'])

    def test_returns_first_parent_pid_fork(self):
        self._test_find_fork_top_parent(
            expected='2',
            find_parent_pid_retvals=['2', '3', '4'],
            pid_invoked_with_cmdline_retvals=[True, False, False])

    def test_returns_top_parent_pid_fork(self):
        self._test_find_fork_top_parent(
            expected='4',
            find_parent_pid_retvals=['2', '3', '4'],
            pid_invoked_with_cmdline_retvals=[True, True, True])


class TestKillProcess(base.BaseTestCase):
    def _test_kill_process(self, pid, raise_exception=False,
                           kill_signal=signal.SIGKILL, pid_killed=True):
        if raise_exception:
            exc = n_exc.ProcessExecutionError('', returncode=0)
        else:
            exc = None
        with mock.patch.object(utils, 'execute',
                               side_effect=exc) as mock_execute:
            with mock.patch.object(utils, 'process_is_running',
                                   return_value=not pid_killed):
                utils.kill_process(pid, kill_signal, run_as_root=True)

        mock_execute.assert_called_with(['kill', '-%d' % kill_signal, pid],
                                        run_as_root=True)

    def test_kill_process_returns_none_for_valid_pid(self):
        self._test_kill_process('1')

    def test_kill_process_returns_none_for_stale_pid(self):
        self._test_kill_process('1', raise_exception=True)

    def test_kill_process_raises_exception_for_execute_exception(self):
        with testtools.ExpectedException(n_exc.ProcessExecutionError):
            # Simulate that the process is running after trying to kill due to
            # any reason such as, for example, Permission denied
            self._test_kill_process('1', raise_exception=True,
                                    pid_killed=False)

    def test_kill_process_with_different_signal(self):
        self._test_kill_process('1', kill_signal=signal.SIGTERM)


class TestGetCmdlineFromPid(base.BaseTestCase):

    def setUp(self):
        super(TestGetCmdlineFromPid, self).setUp()
        self.pid = 34
        self.process_is_running_mock = mock.patch.object(
            utils, "process_is_running").start()

    def _test_cmdline(self, process, expected_cmd):
        self.process_is_running_mock.return_value = True
        mock_open = self.useFixture(
            tools.OpenFixture('/proc/%s/cmdline' % self.pid, process)
        ).mock_open
        cmdline = utils.get_cmdline_from_pid(self.pid)
        mock_open.assert_called_once_with('/proc/%s/cmdline' % self.pid, 'r')
        self.assertEqual(expected_cmd, cmdline)

    def test_cmdline_separated_with_null_char(self):
        process_cmd = "python3\0test-binary\0test option\0"
        expected_cmdline = ["python3", "test-binary", "test option"]
        self._test_cmdline(process_cmd, expected_cmdline)

    def test_cmdline_separated_with_space_char(self):
        process_cmd = "python3 test-binary test option\0"
        expected_cmdline = ["python3", "test-binary", "test", "option"]
        self._test_cmdline(process_cmd, expected_cmdline)

    def test_no_process_running(self):
        self.process_is_running_mock.return_value = False
        mock_open = self.useFixture(
            tools.OpenFixture('/proc/%s/cmdline' % self.pid)
        ).mock_open
        cmdline = utils.get_cmdline_from_pid(self.pid)
        mock_open.assert_not_called()
        self.assertEqual([], cmdline)


class TestFindChildPids(base.BaseTestCase):

    def test_returns_empty_list_for_exit_code_1(self):
        with mock.patch.object(utils, 'execute',
                               side_effect=n_exc.ProcessExecutionError(
                                   '', returncode=1)):
            self.assertEqual([], utils.find_child_pids(-1))

    def test_returns_empty_list_for_no_output(self):
        with mock.patch.object(utils, 'execute', return_value=''):
            self.assertEqual([], utils.find_child_pids(-1))

    def test_returns_list_of_child_process_ids_for_good_ouput(self):
        with mock.patch.object(utils, 'execute', return_value=' 123 \n 185\n'):
            self.assertEqual(utils.find_child_pids(-1), ['123', '185'])

    def test_returns_list_of_child_process_ids_recursively(self):
        with mock.patch.object(utils, 'execute',
                               side_effect=[' 123 \n 185\n',
                                            ' 40 \n', '\n',
                                            '41\n', '\n']):
            actual = utils.find_child_pids(-1, True)
            self.assertEqual(actual, ['123', '185', '40', '41'])

    def test_raises_unknown_exception(self):
        with testtools.ExpectedException(RuntimeError):
            with mock.patch.object(utils, 'execute',
                                   side_effect=RuntimeError()):
                utils.find_child_pids(-1)


class TestGetRoothelperChildPid(base.BaseTestCase):
    def _test_get_root_helper_child_pid(self, expected=_marker,
                                        run_as_root=False, pids=None,
                                        cmds=None):
        def _find_child_pids(x):
            if not pids:
                return []
            pids.pop(0)
            return pids

        mock_pid = object()
        pid_invoked_with_cmdline = {}
        if cmds:
            pid_invoked_with_cmdline['side_effect'] = cmds
        else:
            pid_invoked_with_cmdline['return_value'] = False
        with mock.patch.object(utils, 'find_child_pids',
                               side_effect=_find_child_pids), \
                mock.patch.object(utils, 'pid_invoked_with_cmdline',
                                  **pid_invoked_with_cmdline):
            actual = utils.get_root_helper_child_pid(
                mock_pid, mock.ANY, run_as_root)
        if expected is _marker:
            expected = str(mock_pid)
        self.assertEqual(expected, actual)

    def test_returns_process_pid_not_root(self):
        self._test_get_root_helper_child_pid()

    def test_returns_child_pid_as_root(self):
        self._test_get_root_helper_child_pid(expected='2', pids=['1', '2'],
                                             run_as_root=True,
                                             cmds=[True])

    def test_returns_last_child_pid_as_root(self):
        self._test_get_root_helper_child_pid(expected='3',
                                             pids=['1', '2', '3'],
                                             run_as_root=True,
                                             cmds=[False, True])

    def test_returns_first_non_root_helper_child(self):
        self._test_get_root_helper_child_pid(
                expected='2',
                pids=['1', '2', '3'],
                run_as_root=True,
                cmds=[True, False])

    def test_returns_none_as_root(self):
        self._test_get_root_helper_child_pid(expected=None, run_as_root=True)


class TestPathUtilities(base.BaseTestCase):
    def test_remove_abs_path(self):
        self.assertEqual(['ping', '8.8.8.8'],
                         utils.remove_abs_path(['/usr/bin/ping', '8.8.8.8']))

    def test_cmd_matches_expected_matches_abs_path(self):
        cmd = ['/bar/../foo']
        self.assertTrue(utils.cmd_matches_expected(cmd, cmd))

    def test_cmd_matches_expected_matches_script(self):
        self.assertTrue(utils.cmd_matches_expected(['python', 'script'],
                                                   ['script']))

    def test_cmd_matches_expected_doesnt_match(self):
        self.assertFalse(utils.cmd_matches_expected('foo', 'bar'))


class FakeUser(object):
    def __init__(self, name):
        self.pw_name = name


class FakeGroup(object):
    def __init__(self, name):
        self.gr_name = name


class TestBaseOSUtils(base.BaseTestCase):

    EUID = 123
    EUNAME = 'user'
    EGID = 456
    EGNAME = 'group'

    @mock.patch('os.geteuid', return_value=EUID)
    @mock.patch('pwd.getpwuid', return_value=FakeUser(EUNAME))
    def test_is_effective_user_id(self, getpwuid, geteuid):
        self.assertTrue(utils.is_effective_user(self.EUID))
        geteuid.assert_called_once_with()
        self.assertFalse(getpwuid.called)

    @mock.patch('os.geteuid', return_value=EUID)
    @mock.patch('pwd.getpwuid', return_value=FakeUser(EUNAME))
    def test_is_effective_user_str_id(self, getpwuid, geteuid):
        self.assertTrue(utils.is_effective_user(str(self.EUID)))
        geteuid.assert_called_once_with()
        self.assertFalse(getpwuid.called)

    @mock.patch('os.geteuid', return_value=EUID)
    @mock.patch('pwd.getpwuid', return_value=FakeUser(EUNAME))
    def test_is_effective_user_name(self, getpwuid, geteuid):
        self.assertTrue(utils.is_effective_user(self.EUNAME))
        geteuid.assert_called_once_with()
        getpwuid.assert_called_once_with(self.EUID)

    @mock.patch('os.geteuid', return_value=EUID)
    @mock.patch('pwd.getpwuid', return_value=FakeUser(EUNAME))
    def test_is_not_effective_user(self, getpwuid, geteuid):
        self.assertFalse(utils.is_effective_user('wrong'))
        geteuid.assert_called_once_with()
        getpwuid.assert_called_once_with(self.EUID)

    @mock.patch('os.getegid', return_value=EGID)
    @mock.patch('grp.getgrgid', return_value=FakeGroup(EGNAME))
    def test_is_effective_group_id(self, getgrgid, getegid):
        self.assertTrue(utils.is_effective_group(self.EGID))
        getegid.assert_called_once_with()
        self.assertFalse(getgrgid.called)

    @mock.patch('os.getegid', return_value=EGID)
    @mock.patch('grp.getgrgid', return_value=FakeGroup(EGNAME))
    def test_is_effective_group_str_id(self, getgrgid, getegid):
        self.assertTrue(utils.is_effective_group(str(self.EGID)))
        getegid.assert_called_once_with()
        self.assertFalse(getgrgid.called)

    @mock.patch('os.getegid', return_value=EGID)
    @mock.patch('grp.getgrgid', return_value=FakeGroup(EGNAME))
    def test_is_effective_group_name(self, getgrgid, getegid):
        self.assertTrue(utils.is_effective_group(self.EGNAME))
        getegid.assert_called_once_with()
        getgrgid.assert_called_once_with(self.EGID)

    @mock.patch('os.getegid', return_value=EGID)
    @mock.patch('grp.getgrgid', return_value=FakeGroup(EGNAME))
    def test_is_not_effective_group(self, getgrgid, getegid):
        self.assertFalse(utils.is_effective_group('wrong'))
        getegid.assert_called_once_with()
        getgrgid.assert_called_once_with(self.EGID)


class TestUnixDomainHttpConnection(base.BaseTestCase):
    def test_connect(self):
        with mock.patch.object(utils, 'cfg') as cfg:
            cfg.CONF.metadata_proxy_socket = '/the/path'
            with mock.patch('socket.socket') as socket_create:
                conn = utils.UnixDomainHTTPConnection('169.254.169.254',
                                                      timeout=3)
                conn.connect()

                socket_create.assert_has_calls([
                    mock.call(socket.AF_UNIX, socket.SOCK_STREAM),
                    mock.call().settimeout(3),
                    mock.call().connect('/the/path')]
                )
                self.assertEqual(conn.timeout, 3)


class TestUnixDomainHttpProtocol(base.BaseTestCase):
    def test_init_empty_client(self):
        for addr in ('', b''):
            u = utils.UnixDomainHttpProtocol(mock.Mock(), addr, mock.Mock())
            self.assertEqual(u.client_address, ('<local>', 0))

    def test_init_with_client(self):
        u = utils.UnixDomainHttpProtocol(mock.Mock(), 'foo', mock.Mock())
        self.assertEqual(u.client_address, 'foo')


class TestUnixDomainWSGIServer(base.BaseTestCase):
    def setUp(self):
        super(TestUnixDomainWSGIServer, self).setUp()
        self.eventlet_p = mock.patch.object(utils, 'eventlet')
        self.eventlet = self.eventlet_p.start()

    def test_start(self):
        self.server = utils.UnixDomainWSGIServer('test')
        mock_app = mock.Mock()
        with mock.patch.object(self.server, '_launch') as launcher:
            self.server.start(mock_app, '/the/path', workers=5, backlog=128)
            self.eventlet.assert_has_calls([
                mock.call.listen(
                    '/the/path',
                    family=socket.AF_UNIX,
                    backlog=128
                )]
            )
            launcher.assert_called_once_with(mock_app, workers=5)

    def test_run(self):
        self.server = utils.UnixDomainWSGIServer('test')
        self.server._run('app', 'sock')

        self.eventlet.wsgi.server.assert_called_once_with(
            'sock',
            'app',
            protocol=utils.UnixDomainHttpProtocol,
            log=mock.ANY,
            log_format=cfg.CONF.wsgi_log_format,
            max_size=self.server.num_threads
        )

    def test_num_threads(self):
        num_threads = 8
        self.server = utils.UnixDomainWSGIServer('test',
                                                 num_threads=num_threads)
        self.server._run('app', 'sock')

        self.eventlet.wsgi.server.assert_called_once_with(
            'sock',
            'app',
            protocol=utils.UnixDomainHttpProtocol,
            log=mock.ANY,
            log_format=cfg.CONF.wsgi_log_format,
            max_size=num_threads
        )
