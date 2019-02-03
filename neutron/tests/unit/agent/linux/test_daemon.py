#
# Copyright 2012 New Dream Network, LLC (DreamHost)
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

import logging
from logging import handlers
import os
import sys

import mock
from neutron_lib import exceptions
import testtools

from neutron.agent.linux import daemon
from neutron.tests import base
from neutron.tests import tools

FAKE_FD = 8


class FakeEntry(object):
    def __init__(self, name, value):
        setattr(self, name, value)


class TestUnwatchLog(base.BaseTestCase):
    def setUp(self):
        super(TestUnwatchLog, self).setUp()
        self.temp_file = self.get_temp_file_path('unwatch_log_temp_file')

    def test_unwatch_log(self):
        stream_handler = logging.StreamHandler()
        logger = logging.Logger('fake')
        logger.addHandler(stream_handler)
        logger.addHandler(handlers.WatchedFileHandler(self.temp_file))

        with mock.patch('logging.getLogger', return_value=logger):
            daemon.unwatch_log()
            self.assertEqual(2, len(logger.handlers))
            logger.handlers.remove(stream_handler)
            observed = logger.handlers[0]
            self.assertEqual(logging.FileHandler, type(observed))
            self.assertEqual(self.temp_file, observed.baseFilename)


class TestPrivileges(base.BaseTestCase):
    def test_setuid_with_name(self):
        with mock.patch('pwd.getpwnam', return_value=FakeEntry('pw_uid', 123)):
            with mock.patch('os.setuid') as setuid_mock:
                daemon.setuid('user')
                setuid_mock.assert_called_once_with(123)

    def test_setuid_with_id(self):
        with mock.patch('os.setuid') as setuid_mock:
            daemon.setuid('321')
            setuid_mock.assert_called_once_with(321)

    def test_setuid_fails(self):
        with mock.patch('os.setuid', side_effect=OSError()):
            with mock.patch.object(daemon.LOG, 'critical') as log_critical:
                self.assertRaises(exceptions.FailToDropPrivilegesExit,
                                  daemon.setuid, '321')
                log_critical.assert_called_once_with(mock.ANY)

    def test_setgid_with_name(self):
        with mock.patch('grp.getgrnam', return_value=FakeEntry('gr_gid', 123)):
            with mock.patch('os.setgid') as setgid_mock:
                daemon.setgid('group')
                setgid_mock.assert_called_once_with(123)

    def test_setgid_with_id(self):
        with mock.patch('os.setgid') as setgid_mock:
            daemon.setgid('321')
            setgid_mock.assert_called_once_with(321)

    def test_setgid_fails(self):
        with mock.patch('os.setgid', side_effect=OSError()):
            with mock.patch.object(daemon.LOG, 'critical') as log_critical:
                self.assertRaises(exceptions.FailToDropPrivilegesExit,
                                  daemon.setgid, '321')
                log_critical.assert_called_once_with(mock.ANY)

    @mock.patch.object(os, 'setgroups')
    @mock.patch.object(daemon, 'setgid')
    @mock.patch.object(daemon, 'setuid')
    def test_drop_no_privileges(self, mock_setuid, mock_setgid,
                                mock_setgroups):
        daemon.drop_privileges()
        for cursor in (mock_setuid, mock_setgid, mock_setgroups):
            self.assertFalse(cursor.called)

    @mock.patch.object(os, 'geteuid', return_value=0)
    @mock.patch.object(os, 'setgroups')
    @mock.patch.object(daemon, 'setgid')
    @mock.patch.object(daemon, 'setuid')
    def _test_drop_privileges(self, setuid, setgid, setgroups,
                              geteuid, user=None, group=None):
        daemon.drop_privileges(user=user, group=group)
        if user:
            setuid.assert_called_once_with(user)
        else:
            self.assertFalse(setuid.called)
        if group:
            setgroups.assert_called_once_with([])
            setgid.assert_called_once_with(group)
        else:
            self.assertFalse(setgroups.called)
            self.assertFalse(setgid.called)

    def test_drop_user_privileges(self):
        self._test_drop_privileges(user='user')

    def test_drop_uid_privileges(self):
        self._test_drop_privileges(user='321')

    def test_drop_group_privileges(self):
        self._test_drop_privileges(group='group')

    def test_drop_gid_privileges(self):
        self._test_drop_privileges(group='654')

    def test_drop_privileges_without_root_permissions(self):
        with mock.patch('os.geteuid', return_value=1):
            with mock.patch.object(daemon.LOG, 'critical') as log_critical:
                self.assertRaises(exceptions.FailToDropPrivilegesExit,
                                  daemon.drop_privileges, 'user')
                log_critical.assert_called_once_with(mock.ANY)


class TestPidfile(base.BaseTestCase):
    def setUp(self):
        super(TestPidfile, self).setUp()
        self.os_p = mock.patch.object(daemon, 'os')
        self.os = self.os_p.start()
        self.os.open.return_value = FAKE_FD

        self.fcntl_p = mock.patch.object(daemon, 'fcntl')
        self.fcntl = self.fcntl_p.start()
        self.fcntl.flock.return_value = 0

    def test_init(self):
        self.os.O_CREAT = os.O_CREAT
        self.os.O_RDWR = os.O_RDWR

        daemon.Pidfile('thefile', 'python')
        self.os.open.assert_called_once_with('thefile', os.O_CREAT | os.O_RDWR)
        self.fcntl.flock.assert_called_once_with(FAKE_FD, self.fcntl.LOCK_EX |
                                                 self.fcntl.LOCK_NB)

    def test_init_open_fail(self):
        self.os.open.side_effect = IOError

        with mock.patch.object(daemon.sys, 'stderr'):
            with testtools.ExpectedException(SystemExit):
                daemon.Pidfile('thefile', 'python')
                sys.assert_has_calls([
                    mock.call.stderr.write(mock.ANY),
                    mock.call.exit(1)]
                )

    def test_unlock(self):
        p = daemon.Pidfile('thefile', 'python')
        p.unlock()
        self.fcntl.flock.assert_has_calls([
            mock.call(FAKE_FD, self.fcntl.LOCK_EX | self.fcntl.LOCK_NB),
            mock.call(FAKE_FD, self.fcntl.LOCK_UN)]
        )

    def test_write(self):
        p = daemon.Pidfile('thefile', 'python')
        p.write(34)

        self.os.assert_has_calls([
            mock.call.ftruncate(FAKE_FD, 0),
            mock.call.write(FAKE_FD, b'34'),
            mock.call.fsync(FAKE_FD)]
        )

    def test_read(self):
        self.os.read.return_value = '34'
        p = daemon.Pidfile('thefile', 'python')
        self.assertEqual(34, p.read())

    def test_is_running(self):
        mock_open = self.useFixture(
            tools.OpenFixture('/proc/34/cmdline', 'python')).mock_open
        p = daemon.Pidfile('thefile', 'python')

        with mock.patch.object(p, 'read') as read:
            read.return_value = 34
            self.assertTrue(p.is_running())

        mock_open.assert_called_once_with('/proc/34/cmdline', 'r')

    def test_is_running_uuid_true(self):
        mock_open = self.useFixture(
            tools.OpenFixture('/proc/34/cmdline', 'python 1234')).mock_open
        p = daemon.Pidfile('thefile', 'python', uuid='1234')

        with mock.patch.object(p, 'read') as read:
            read.return_value = 34
            self.assertTrue(p.is_running())

        mock_open.assert_called_once_with('/proc/34/cmdline', 'r')

    def test_is_running_uuid_false(self):
        mock_open = self.useFixture(
            tools.OpenFixture('/proc/34/cmdline', 'python 1234')).mock_open
        p = daemon.Pidfile('thefile', 'python', uuid='6789')

        with mock.patch.object(p, 'read') as read:
            read.return_value = 34
            self.assertFalse(p.is_running())

        mock_open.assert_called_once_with('/proc/34/cmdline', 'r')


class TestDaemon(base.BaseTestCase):
    def setUp(self):
        super(TestDaemon, self).setUp()
        self.os_p = mock.patch.object(daemon, 'os')
        self.os = self.os_p.start()

        self.pidfile_p = mock.patch.object(daemon, 'Pidfile')
        self.pidfile = self.pidfile_p.start()

    def test_init(self):
        d = daemon.Daemon('pidfile')
        self.assertEqual(d.procname, 'python')

    def test_init_nopidfile(self):
        d = daemon.Daemon(pidfile=None)
        self.assertEqual(d.procname, 'python')
        self.assertFalse(self.pidfile.called)

    def test_fork_parent(self):
        self.os.fork.return_value = 1
        d = daemon.Daemon('pidfile')
        d._fork()
        self.os._exit.assert_called_once_with(mock.ANY)

    def test_fork_child(self):
        self.os.fork.return_value = 0
        d = daemon.Daemon('pidfile')
        self.assertIsNone(d._fork())

    def test_fork_error(self):
        self.os.fork.side_effect = OSError(1)
        with mock.patch.object(daemon.sys, 'stderr'):
            with testtools.ExpectedException(SystemExit):
                d = daemon.Daemon('pidfile', 'stdin')
                d._fork()

    def test_daemonize(self):
        self.os.devnull = '/dev/null'

        d = daemon.Daemon('pidfile')
        with mock.patch.object(d, '_fork') as fork:
            with mock.patch.object(daemon, 'atexit') as atexit:
                with mock.patch.object(daemon, 'signal') as signal:
                    signal.SIGTERM = 15
                    with mock.patch.object(daemon, 'sys') as sys:
                        sys.stdin.fileno.return_value = 0
                        sys.stdout.fileno.return_value = 1
                        sys.stderr.fileno.return_value = 2
                        d.daemonize()

                    signal.signal.assert_called_once_with(15, d.handle_sigterm)
                atexit.register.assert_called_once_with(d.delete_pid)
            fork.assert_has_calls([mock.call(), mock.call()])

        self.os.assert_has_calls([
            mock.call.chdir('/'),
            mock.call.setsid(),
            mock.call.umask(0),
            mock.call.dup2(mock.ANY, 0),
            mock.call.dup2(mock.ANY, 1),
            mock.call.dup2(mock.ANY, 2),
            mock.call.getpid()]
        )

    def test_delete_pid(self):
        self.pidfile.return_value.__str__.return_value = 'pidfile'
        d = daemon.Daemon('pidfile')
        d.delete_pid()
        self.os.remove.assert_called_once_with('pidfile')

    def test_handle_sigterm(self):
        d = daemon.Daemon('pidfile')
        with mock.patch.object(daemon, 'sys') as sys:
            d.handle_sigterm(15, 1234)
            sys.exit.assert_called_once_with(0)

    def test_start(self):
        self.pidfile.return_value.is_running.return_value = False
        d = daemon.Daemon('pidfile')

        with mock.patch.object(d, 'daemonize') as daemonize:
            with mock.patch.object(d, 'run') as run:
                d.start()
                run.assert_called_once_with()
                daemonize.assert_called_once_with()

    def test_start_running(self):
        self.pidfile.return_value.is_running.return_value = True
        d = daemon.Daemon('pidfile')

        with mock.patch.object(daemon.sys, 'stderr'):
            with mock.patch.object(d, 'daemonize') as daemonize:
                with testtools.ExpectedException(SystemExit):
                    d.start()
                self.assertFalse(daemonize.called)
