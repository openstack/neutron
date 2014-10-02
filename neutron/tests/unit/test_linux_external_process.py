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

import mock

from neutron.agent.linux import external_process as ep
from neutron.tests import base


class TestProcessManager(base.BaseTestCase):
    def setUp(self):
        super(TestProcessManager, self).setUp()
        self.execute_p = mock.patch('neutron.agent.linux.utils.execute')
        self.execute = self.execute_p.start()
        self.conf = mock.Mock()
        self.conf.external_pids = '/var/path'

    def test_enable_no_namespace(self):
        callback = mock.Mock()
        callback.return_value = ['the', 'cmd']

        with mock.patch.object(ep.ProcessManager, 'get_pid_file_name') as name:
            name.return_value = 'pidfile'
            with mock.patch.object(ep.ProcessManager, 'active') as active:
                active.__get__ = mock.Mock(return_value=False)

                manager = ep.ProcessManager(self.conf, 'uuid')
                manager.enable(callback)
                callback.assert_called_once_with('pidfile')
                name.assert_called_once_with(ensure_pids_dir=True)
                self.execute.assert_called_once_with(['the', 'cmd'],
                                                     root_helper='sudo',
                                                     check_exit_code=True,
                                                     extra_ok_codes=None)

    def test_enable_with_namespace(self):
        callback = mock.Mock()
        callback.return_value = ['the', 'cmd']

        with mock.patch.object(ep.ProcessManager, 'get_pid_file_name') as name:
            name.return_value = 'pidfile'
            with mock.patch.object(ep.ProcessManager, 'active') as active:
                active.__get__ = mock.Mock(return_value=False)

                manager = ep.ProcessManager(self.conf, 'uuid', namespace='ns')
                with mock.patch.object(ep, 'ip_lib') as ip_lib:
                    manager.enable(callback)
                    callback.assert_called_once_with('pidfile')
                    name.assert_called_once_with(ensure_pids_dir=True)
                    ip_lib.assert_has_calls([
                        mock.call.IPWrapper('sudo', 'ns'),
                        mock.call.IPWrapper().netns.execute(['the', 'cmd'],
                                                            addl_env=None)])

    def test_enable_with_namespace_process_active(self):
        callback = mock.Mock()
        callback.return_value = ['the', 'cmd']

        with mock.patch.object(ep.ProcessManager, 'active') as active:
            active.__get__ = mock.Mock(return_value=True)

            manager = ep.ProcessManager(self.conf, 'uuid', namespace='ns')
            with mock.patch.object(ep, 'ip_lib'):
                manager.enable(callback)
                self.assertFalse(callback.called)

    def test_disable_no_namespace(self):
        with mock.patch.object(ep.ProcessManager, 'pid') as pid:
            pid.__get__ = mock.Mock(return_value=4)
            with mock.patch.object(ep.ProcessManager, 'active') as active:
                active.__get__ = mock.Mock(return_value=True)

                manager = ep.ProcessManager(self.conf, 'uuid')
                manager.disable()
                self.execute(['kill', '-9', 4], 'sudo')

    def test_disable_namespace(self):
        with mock.patch.object(ep.ProcessManager, 'pid') as pid:
            pid.__get__ = mock.Mock(return_value=4)
            with mock.patch.object(ep.ProcessManager, 'active') as active:
                active.__get__ = mock.Mock(return_value=True)

                manager = ep.ProcessManager(self.conf, 'uuid', namespace='ns')

                with mock.patch.object(ep, 'utils') as utils:
                    manager.disable()
                    utils.assert_has_calls(
                        mock.call.execute(['kill', '-9', 4], 'sudo'))

    def test_disable_not_active(self):
        with mock.patch.object(ep.ProcessManager, 'pid') as pid:
            pid.__get__ = mock.Mock(return_value=4)
            with mock.patch.object(ep.ProcessManager, 'active') as active:
                active.__get__ = mock.Mock(return_value=False)
                with mock.patch.object(ep.LOG, 'debug') as debug:
                    manager = ep.ProcessManager(self.conf, 'uuid')
                    manager.disable()
                    debug.assert_called_once_with(mock.ANY, mock.ANY)

    def test_disable_no_pid(self):
        with mock.patch.object(ep.ProcessManager, 'pid') as pid:
            pid.__get__ = mock.Mock(return_value=None)
            with mock.patch.object(ep.ProcessManager, 'active') as active:
                active.__get__ = mock.Mock(return_value=False)
                with mock.patch.object(ep.LOG, 'debug') as debug:
                    manager = ep.ProcessManager(self.conf, 'uuid')
                    manager.disable()
                    debug.assert_called_once_with(mock.ANY, mock.ANY)

    def test_get_pid_file_name_existing(self):
        with mock.patch.object(ep.utils.os.path, 'isdir') as isdir:
            isdir.return_value = True
            manager = ep.ProcessManager(self.conf, 'uuid')
            retval = manager.get_pid_file_name(ensure_pids_dir=True)
            self.assertEqual(retval, '/var/path/uuid.pid')

    def test_get_pid_file_name_not_existing(self):
        with mock.patch.object(ep.utils.os.path, 'isdir') as isdir:
            with mock.patch.object(ep.utils.os, 'makedirs') as makedirs:
                isdir.return_value = False
                manager = ep.ProcessManager(self.conf, 'uuid')
                retval = manager.get_pid_file_name(ensure_pids_dir=True)
                self.assertEqual(retval, '/var/path/uuid.pid')
                makedirs.assert_called_once_with('/var/path', 0o755)

    def test_get_pid_file_name_default(self):
        with mock.patch.object(ep.utils.os.path, 'isdir') as isdir:
            isdir.return_value = True
            manager = ep.ProcessManager(self.conf, 'uuid')
            retval = manager.get_pid_file_name(ensure_pids_dir=False)
            self.assertEqual(retval, '/var/path/uuid.pid')
            self.assertFalse(isdir.called)

    def test_pid(self):
        with mock.patch('__builtin__.open') as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = mock.Mock()
            mock_open.return_value.read.return_value = '5'
            manager = ep.ProcessManager(self.conf, 'uuid')
            self.assertEqual(manager.pid, 5)

    def test_pid_no_an_int(self):
        with mock.patch('__builtin__.open') as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = mock.Mock()
            mock_open.return_value.read.return_value = 'foo'
            manager = ep.ProcessManager(self.conf, 'uuid')
            self.assertIsNone(manager.pid, 5)

    def test_pid_invalid_file(self):
        with mock.patch.object(ep.ProcessManager, 'get_pid_file_name') as name:
            name.return_value = '.doesnotexist/pid'
            manager = ep.ProcessManager(self.conf, 'uuid')
            self.assertIsNone(manager.pid)

    def test_active(self):
        with mock.patch('__builtin__.open') as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = mock.Mock()
            mock_open.return_value.readline.return_value = \
                'python foo --router_id=uuid'
            with mock.patch.object(ep.ProcessManager, 'pid') as pid:
                pid.__get__ = mock.Mock(return_value=4)
                manager = ep.ProcessManager(self.conf, 'uuid')
                self.assertTrue(manager.active)

            mock_open.assert_called_once_with('/proc/4/cmdline', 'r')

    def test_active_none(self):
        dummy_cmd_line = 'python foo --router_id=uuid'
        self.execute.return_value = dummy_cmd_line
        with mock.patch.object(ep.ProcessManager, 'pid') as pid:
            pid.__get__ = mock.Mock(return_value=None)
            manager = ep.ProcessManager(self.conf, 'uuid')
            self.assertFalse(manager.active)

    def test_active_cmd_mismatch(self):
        with mock.patch('__builtin__.open') as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = mock.Mock()
            mock_open.return_value.readline.return_value = \
                'python foo --router_id=anotherid'
            with mock.patch.object(ep.ProcessManager, 'pid') as pid:
                pid.__get__ = mock.Mock(return_value=4)
                manager = ep.ProcessManager(self.conf, 'uuid')
                self.assertFalse(manager.active)

            mock_open.assert_called_once_with('/proc/4/cmdline', 'r')
