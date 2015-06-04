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

import errno
import mock
import socket
import testtools

from neutron.agent.linux import utils
from neutron.tests import base


_marker = object()


class AgentUtilsExecuteTest(base.BaseTestCase):
    def setUp(self):
        super(AgentUtilsExecuteTest, self).setUp()
        self.test_file = self.get_temp_file_path('test_execute.tmp')
        open(self.test_file, 'w').close()
        self.process = mock.patch('eventlet.green.subprocess.Popen').start()
        self.process.return_value.returncode = 0
        self.mock_popen = self.process.return_value.communicate

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
        self.assertEqual(stdout, "")

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

    def test_return_code_raise_runtime_do_not_log_fail_as_error(self):
        self.mock_popen.return_value = ('', '')
        self.process.return_value.returncode = 1
        with mock.patch.object(utils, 'LOG') as log:
            self.assertRaises(RuntimeError, utils.execute,
                              ['ls'], log_fail_as_error=False)
            self.assertFalse(log.error.called)


class AgentUtilsGetInterfaceMAC(base.BaseTestCase):
    def test_get_interface_mac(self):
        expect_val = '01:02:03:04:05:06'
        with mock.patch('fcntl.ioctl') as ioctl:
            ioctl.return_value = ''.join(['\x00' * 18,
                                          '\x01\x02\x03\x04\x05\x06',
                                          '\x00' * 232])
            actual_val = utils.get_interface_mac('eth0')
        self.assertEqual(actual_val, expect_val)


class AgentUtilsReplaceFile(base.BaseTestCase):
    def test_replace_file(self):
        # make file to replace
        with mock.patch('tempfile.NamedTemporaryFile') as ntf:
            ntf.return_value.name = '/baz'
            with mock.patch('os.chmod') as chmod:
                with mock.patch('os.rename') as rename:
                    utils.replace_file('/foo', 'bar')

                    expected = [mock.call('w+', dir='/', delete=False),
                                mock.call().write('bar'),
                                mock.call().close()]

                    ntf.assert_has_calls(expected)
                    chmod.assert_called_once_with('/baz', 0o644)
                    rename.assert_called_once_with('/baz', '/foo')


class TestFindChildPids(base.BaseTestCase):

    def test_returns_empty_list_for_exit_code_1(self):
        with mock.patch.object(utils, 'execute',
                               side_effect=RuntimeError('Exit code: 1')):
            self.assertEqual(utils.find_child_pids(-1), [])

    def test_returns_empty_list_for_no_output(self):
        with mock.patch.object(utils, 'execute', return_value=''):
            self.assertEqual(utils.find_child_pids(-1), [])

    def test_returns_list_of_child_process_ids_for_good_ouput(self):
        with mock.patch.object(utils, 'execute', return_value=' 123 \n 185\n'):
            self.assertEqual(utils.find_child_pids(-1), ['123', '185'])

    def test_raises_unknown_exception(self):
        with testtools.ExpectedException(RuntimeError):
            with mock.patch.object(utils, 'execute',
                                   side_effect=RuntimeError()):
                utils.find_child_pids(-1)


class TestGetRoothelperChildPid(base.BaseTestCase):
    def _test_get_root_helper_child_pid(self, expected=_marker,
                                        run_as_root=False, pids=None):
        def _find_child_pids(x):
            if not pids:
                return []
            pids.pop(0)
            return pids

        mock_pid = object()
        with mock.patch.object(utils, 'find_child_pids',
                               side_effect=_find_child_pids):
            actual = utils.get_root_helper_child_pid(mock_pid, run_as_root)
        if expected is _marker:
            expected = str(mock_pid)
        self.assertEqual(expected, actual)

    def test_returns_process_pid_not_root(self):
        self._test_get_root_helper_child_pid()

    def test_returns_child_pid_as_root(self):
        self._test_get_root_helper_child_pid(expected='2', pids=['1', '2'],
                                             run_as_root=True)

    def test_returns_last_child_pid_as_root(self):
        self._test_get_root_helper_child_pid(expected='3',
                                             pids=['1', '2', '3'],
                                             run_as_root=True)

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

    @mock.patch('os.makedirs')
    @mock.patch('os.path.exists', return_value=False)
    def test_ensure_dir_no_fail_if_exists(self, path_exists, makedirs):
        error = OSError()
        error.errno = errno.EEXIST
        makedirs.side_effect = error
        utils.ensure_dir("/etc/create/concurrently")


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
        u = utils.UnixDomainHttpProtocol(mock.Mock(), '', mock.Mock())
        self.assertEqual(u.client_address, ('<local>', 0))

    def test_init_with_client(self):
        u = utils.UnixDomainHttpProtocol(mock.Mock(), 'foo', mock.Mock())
        self.assertEqual(u.client_address, 'foo')


class TestUnixDomainWSGIServer(base.BaseTestCase):
    def setUp(self):
        super(TestUnixDomainWSGIServer, self).setUp()
        self.eventlet_p = mock.patch.object(utils, 'eventlet')
        self.eventlet = self.eventlet_p.start()
        self.server = utils.UnixDomainWSGIServer('test')

    def test_start(self):
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
        self.server._run('app', 'sock')

        self.eventlet.wsgi.server.assert_called_once_with(
            'sock',
            'app',
            protocol=utils.UnixDomainHttpProtocol,
            log=mock.ANY,
            max_size=self.server.num_threads
        )
