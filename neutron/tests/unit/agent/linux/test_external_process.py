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
import os.path

from neutron.agent.linux import external_process as ep
from neutron.agent.linux import utils
from neutron.tests import base


TEST_UUID = 'test-uuid'
TEST_SERVICE = 'testsvc'
TEST_PID = 1234


class BaseTestProcessMonitor(base.BaseTestCase):

    def setUp(self):
        super(BaseTestProcessMonitor, self).setUp()
        self.log_patch = mock.patch("neutron.agent.linux.external_process."
                                    "LOG.error")
        self.error_log = self.log_patch.start()

        self.spawn_patch = mock.patch("eventlet.spawn")
        self.eventlent_spawn = self.spawn_patch.start()

        # create a default process monitor
        self.create_child_process_monitor('respawn')

    def create_child_process_monitor(self, action):
        conf = mock.Mock()
        conf.AGENT.check_child_processes_action = action
        conf.AGENT.check_child_processes = True
        self.pmonitor = ep.ProcessMonitor(
            config=conf,
            resource_type='test')

    def get_monitored_process(self, uuid, service=None):
        monitored_process = mock.Mock()
        self.pmonitor.register(uuid=uuid,
                               service_name=service,
                               monitored_process=monitored_process)
        return monitored_process


class TestProcessMonitor(BaseTestProcessMonitor):

    def test_error_logged(self):
        pm = self.get_monitored_process(TEST_UUID)
        pm.active = False
        self.pmonitor._check_child_processes()
        self.assertTrue(self.error_log.called)

    def test_exit_handler(self):
        self.create_child_process_monitor('exit')
        pm = self.get_monitored_process(TEST_UUID)
        pm.active = False
        with mock.patch.object(ep.ProcessMonitor,
                               '_exit_handler') as exit_handler:
            self.pmonitor._check_child_processes()
            exit_handler.assert_called_once_with(TEST_UUID, None)

    def test_register(self):
        pm = self.get_monitored_process(TEST_UUID)
        self.assertEqual(len(self.pmonitor._monitored_processes), 1)
        self.assertIn(pm, self.pmonitor._monitored_processes.values())

    def test_register_same_service_twice(self):
        self.get_monitored_process(TEST_UUID)
        self.get_monitored_process(TEST_UUID)
        self.assertEqual(len(self.pmonitor._monitored_processes), 1)

    def test_register_different_service_types(self):
        self.get_monitored_process(TEST_UUID)
        self.get_monitored_process(TEST_UUID, TEST_SERVICE)
        self.assertEqual(len(self.pmonitor._monitored_processes), 2)

    def test_unregister(self):
        self.get_monitored_process(TEST_UUID)
        self.pmonitor.unregister(TEST_UUID, None)
        self.assertEqual(len(self.pmonitor._monitored_processes), 0)

    def test_unregister_unknown_process(self):
        self.pmonitor.unregister(TEST_UUID, None)
        self.assertEqual(len(self.pmonitor._monitored_processes), 0)


class TestProcessManager(base.BaseTestCase):
    def setUp(self):
        super(TestProcessManager, self).setUp()
        self.execute_p = mock.patch('neutron.agent.common.utils.execute')
        self.execute = self.execute_p.start()
        self.delete_if_exists = mock.patch(
            'neutron.openstack.common.fileutils.delete_if_exists').start()
        self.ensure_dir = mock.patch.object(
            utils, 'ensure_dir').start()

        self.conf = mock.Mock()
        self.conf.external_pids = '/var/path'

    def test_processmanager_ensures_pid_dir(self):
        pid_file = os.path.join(self.conf.external_pids, 'pid')
        ep.ProcessManager(self.conf, 'uuid', pid_file=pid_file)
        self.ensure_dir.assert_called_once_with(self.conf.external_pids)

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
                self.execute.assert_called_once_with(['the', 'cmd'],
                                                     check_exit_code=True,
                                                     extra_ok_codes=None,
                                                     run_as_root=False,
                                                     log_fail_as_error=True)

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
                    ip_lib.assert_has_calls([
                        mock.call.IPWrapper(namespace='ns'),
                        mock.call.IPWrapper().netns.execute(
                            ['the', 'cmd'], addl_env=None, run_as_root=False)])

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

                with mock.patch.object(ep, 'utils') as utils:
                    manager.disable()
                    utils.assert_has_calls([
                        mock.call.execute(['kill', '-9', 4],
                                          run_as_root=True)])

    def test_disable_namespace(self):
        with mock.patch.object(ep.ProcessManager, 'pid') as pid:
            pid.__get__ = mock.Mock(return_value=4)
            with mock.patch.object(ep.ProcessManager, 'active') as active:
                active.__get__ = mock.Mock(return_value=True)

                manager = ep.ProcessManager(self.conf, 'uuid', namespace='ns')

                with mock.patch.object(ep, 'utils') as utils:
                    manager.disable()
                    utils.assert_has_calls([
                        mock.call.execute(['kill', '-9', 4],
                                          run_as_root=True)])

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

    def test_get_pid_file_name_default(self):
        manager = ep.ProcessManager(self.conf, 'uuid')
        retval = manager.get_pid_file_name()
        self.assertEqual(retval, '/var/path/uuid.pid')

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
