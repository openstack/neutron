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

import os.path
import tempfile
from unittest import mock

from neutron_lib import fixture as lib_fixtures
from oslo_config import cfg
from oslo_utils import fileutils
from oslo_utils import uuidutils
import psutil

from neutron.agent.linux import external_process as ep
from neutron.common import utils as common_utils
from neutron.tests import base


TEST_UUID = 'test-uuid'
TEST_SERVICE = 'testsvc'
TEST_PID = 1234
TEST_CMDLINE = 'python foo --router_id=%s'
SCRIPT = """#!/bin/bash
output_file=$1
if [ -z "${PROCESS_TAG}" ] ; then
    echo "Variable PROCESS_TAG not set" > $output_file
else
    echo "Variable PROCESS_TAG set: $PROCESS_TAG" > $output_file
fi
"""
DEFAULT_ENVVAR = ep.PROCESS_TAG + '=' + ep.DEFAULT_SERVICE_NAME


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
            'oslo_utils.fileutils.delete_if_exists').start()
        self.ensure_dir = mock.patch.object(
            fileutils, 'ensure_tree').start()

        self.conf = mock.Mock()
        self.conf.external_pids = '/var/path'

    def test_processmanager_ensures_pid_dir(self):
        pid_file = os.path.join(self.conf.external_pids, 'pid')
        ep.ProcessManager(self.conf, 'uuid', pid_file=pid_file)
        self.ensure_dir.assert_called_once_with(self.conf.external_pids,
                                                mode=0o755)

    def test_enable_no_namespace(self):
        callback = mock.Mock()
        cmd = ['the', 'cmd']
        callback.return_value = cmd

        with mock.patch.object(ep.ProcessManager, 'get_pid_file_name') as name:
            name.return_value = 'pidfile'
            with mock.patch.object(ep.ProcessManager, 'active') as active:
                active.__get__ = mock.Mock(return_value=False)

                manager = ep.ProcessManager(self.conf, 'uuid')
                manager.enable(callback)
                callback.assert_called_once_with('pidfile')
                cmd = ['env', DEFAULT_ENVVAR + '-uuid'] + cmd
                self.execute.assert_called_once_with(cmd,
                                                     check_exit_code=True,
                                                     extra_ok_codes=None,
                                                     run_as_root=False,
                                                     log_fail_as_error=True,
                                                     privsep_exec=False)

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
                    env = {ep.PROCESS_TAG: ep.DEFAULT_SERVICE_NAME + '-uuid'}
                    ip_lib.assert_has_calls([
                        mock.call.IPWrapper(namespace='ns'),
                        mock.call.IPWrapper().netns.execute(
                            ['the', 'cmd'], addl_env=env, run_as_root=True)])

    def test_enable_with_namespace_process_active(self):
        callback = mock.Mock()
        callback.return_value = ['the', 'cmd']

        with mock.patch.object(ep.ProcessManager, 'active') as active:
            active.__get__ = mock.Mock(return_value=True)

            manager = ep.ProcessManager(self.conf, 'uuid', namespace='ns')
            with mock.patch.object(ep, 'ip_lib'):
                manager.enable(callback)
                self.assertFalse(callback.called)

    def test_enable_with_ensure_active(self):
        def _create_cmd(*args):
            return ['sleep', 0]

        pm = ep.ProcessManager(self.conf, 'uuid', pid_file='pid_file',
                               default_cmd_callback=_create_cmd)
        with mock.patch.object(psutil, 'Process') as mock_psutil_process, \
                mock.patch.object(ep.ProcessManager, 'pid',
                                  new_callable=mock.PropertyMock) as mock_pid:
            mock_pid.return_value = 'pid_value'
            mock_process = mock.Mock()
            mock_process.cmdline.side_effect = [[], ['the', 'cmd', 'uuid']]
            mock_psutil_process.return_value = mock_process
            try:
                pm.enable(ensure_active=True)
            except common_utils.WaitTimeout:
                self.fail('ProcessManager.enable() raised WaitTimeout')

    def _create_env_var_testing_environment(self, script_content, _create_cmd):
        with tempfile.NamedTemporaryFile('w+', dir='/tmp/',
                                         delete=False) as script:
            script.write(script_content)
        output = tempfile.NamedTemporaryFile('w+', dir='/tmp/', delete=False)
        os.chmod(script.name, 0o777)
        service_name = 'my_new_service'
        uuid = uuidutils.generate_uuid()
        pm = ep.ProcessManager(self.conf, uuid, service=service_name,
                               default_cmd_callback=_create_cmd)
        return script, output, service_name, uuid, pm

    def test_enable_check_process_id_env_var(self):
        def _create_cmd(*args):
            return [script.name, output.name]

        self.execute_p.stop()
        script, output, service_name, uuid, pm = (
            self._create_env_var_testing_environment(SCRIPT, _create_cmd))
        with mock.patch.object(ep.ProcessManager, 'active') as active:
            active.__get__ = mock.Mock(return_value=False)
            pm.enable()

        with open(output.name, 'r') as f:
            ret_value = f.readline().strip()
        expected_value = ('Variable PROCESS_TAG set: %s-%s' %
                          (service_name, uuid))
        self.assertEqual(expected_value, ret_value)

    def test_disable_check_process_id_env_var(self):
        def _create_cmd(*args):
            return [script.name, output.name]

        self.execute_p.stop()
        script, output, service_name, uuid, pm = (
            self._create_env_var_testing_environment(SCRIPT, _create_cmd))
        with mock.patch.object(ep.ProcessManager, 'active') as active, \
                mock.patch.object(pm, 'get_kill_cmd') as mock_kill_cmd:
            active.__get__ = mock.Mock(return_value=True)
            # NOTE(ralonsoh): the script we are using for testing does not
            # expect to receive the SIG number as the first argument.
            mock_kill_cmd.return_value = [script.name, output.name]
            pm.disable(sig='15')

        with open(output.name, 'r') as f:
            ret_value = f.readline().strip()
        expected_value = ('Variable PROCESS_TAG set: %s-%s' %
                          (service_name, uuid))
        self.assertEqual(expected_value, ret_value)

    def test_reload_cfg_without_custom_reload_callback(self):
        with mock.patch.object(ep.ProcessManager, 'disable') as disable:
            manager = ep.ProcessManager(self.conf, 'uuid', namespace='ns')
            manager.reload_cfg()
            disable.assert_called_once_with('HUP')

    def test_reload_cfg_with_custom_reload_callback(self):
        reload_callback = mock.sentinel.callback
        with mock.patch.object(ep.ProcessManager, 'disable') as disable:
            manager = ep.ProcessManager(
                self.conf, 'uuid', namespace='ns',
                custom_reload_callback=reload_callback)
            manager.reload_cfg()
            disable.assert_called_once_with(get_stop_command=reload_callback)

    def test_disable_get_stop_command(self):
        cmd = ['the', 'cmd']
        reload_callback = mock.Mock(return_value=cmd)
        with mock.patch.object(ep.ProcessManager, 'pid',
                               mock.PropertyMock(return_value=4)):
            with mock.patch.object(ep.ProcessManager, 'active',
                                   mock.PropertyMock(return_value=True)):
                manager = ep.ProcessManager(
                    self.conf, 'uuid',
                    custom_reload_callback=reload_callback)
                manager.disable(
                    get_stop_command=manager.custom_reload_callback)
                cmd = ['env', DEFAULT_ENVVAR + '-uuid'] + cmd
                self.assertIn(cmd, self.execute.call_args[0])

    def test_disable_no_namespace(self):
        with mock.patch.object(ep.ProcessManager, 'pid') as pid:
            pid.__get__ = mock.Mock(return_value=4)
            with mock.patch.object(ep.ProcessManager, 'active') as active:
                active.__get__ = mock.Mock(return_value=True)
                manager = ep.ProcessManager(self.conf, 'uuid')

                with mock.patch.object(ep, 'utils') as utils:
                    manager.disable()
                    env = {ep.PROCESS_TAG: ep.DEFAULT_SERVICE_NAME + '-uuid'}
                    utils.assert_has_calls([
                        mock.call.execute(['kill', '-9', 4],
                                          addl_env=env,
                                          run_as_root=False,
                                          privsep_exec=True)])

    def test_disable_namespace(self):
        with mock.patch.object(ep.ProcessManager, 'pid') as pid:
            pid.__get__ = mock.Mock(return_value=4)
            with mock.patch.object(ep.ProcessManager, 'active') as active:
                active.__get__ = mock.Mock(return_value=True)

                manager = ep.ProcessManager(self.conf, 'uuid', namespace='ns')

                with mock.patch.object(ep, 'utils') as utils:
                    manager.disable()
                    env = {ep.PROCESS_TAG: ep.DEFAULT_SERVICE_NAME + '-uuid'}
                    utils.assert_has_calls([
                        mock.call.execute(
                            ['kill', '-9', 4], addl_env=env, run_as_root=True,
                            privsep_exec=True)])

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

    def _test_disable_custom_kill_script(self, kill_script_exists, namespace,
                                         kill_scripts_path='test-path/'):
        cfg.CONF.set_override("kill_scripts_path", kill_scripts_path, "AGENT")
        if kill_script_exists:
            expected_cmd = [
                os.path.join(kill_scripts_path, 'test-service-kill'), '9', 4]
        else:
            expected_cmd = ['kill', '-9', 4]

        with mock.patch.object(ep.ProcessManager, 'pid') as pid:
            pid.__get__ = mock.Mock(return_value=4)
            with mock.patch.object(ep.ProcessManager, 'active') as active:
                active.__get__ = mock.Mock(return_value=True)
                service_name = 'test-service'
                manager = ep.ProcessManager(
                    self.conf, 'uuid', namespace=namespace,
                    service=service_name)
                with mock.patch.object(ep, 'utils') as utils, \
                        mock.patch.object(os.path, 'isfile',
                                          return_value=kill_script_exists):
                    manager.disable()
                    addl_env = {ep.PROCESS_TAG: service_name + '-uuid'}
                    utils.execute.assert_called_with(
                        expected_cmd, addl_env=addl_env,
                        run_as_root=bool(namespace), privsep_exec=True)

    def test_disable_custom_kill_script_no_namespace(self):
        self._test_disable_custom_kill_script(
            kill_script_exists=True, namespace=None)

    def test_disable_custom_kill_script_namespace(self):
        self._test_disable_custom_kill_script(
            kill_script_exists=True, namespace="ns")

    def test_disable_custom_kill_script_no_kill_script_no_namespace(self):
        self._test_disable_custom_kill_script(
            kill_script_exists=False, namespace=None)

    def test_disable_custom_kill_script_no_kill_script_namespace(self):
        self._test_disable_custom_kill_script(
            kill_script_exists=False, namespace="ns")

    def test_disable_custom_kill_script_namespace_no_path(self):
        self._test_disable_custom_kill_script(
            kill_script_exists=False, namespace="ns", kill_scripts_path=None)

    def test_get_pid_file_name_default(self):
        manager = ep.ProcessManager(self.conf, 'uuid')
        retval = manager.get_pid_file_name()
        self.assertEqual(retval, '/var/path/uuid.pid')

    def test_pid(self):
        self.useFixture(lib_fixtures.OpenFixture('/var/path/uuid.pid', '5'))
        manager = ep.ProcessManager(self.conf, 'uuid')
        self.assertEqual(manager.pid, 5)

    def test_pid_no_an_int(self):
        self.useFixture(lib_fixtures.OpenFixture('/var/path/uuid.pid', 'foo'))
        manager = ep.ProcessManager(self.conf, 'uuid')
        self.assertIsNone(manager.pid)

    def test_pid_invalid_file(self):
        with mock.patch.object(ep.ProcessManager, 'get_pid_file_name') as name:
            name.return_value = '.doesnotexist/pid'
            manager = ep.ProcessManager(self.conf, 'uuid')
            self.assertIsNone(manager.pid)

    def test_active(self):
        with mock.patch.object(ep.ProcessManager, 'cmdline') as cmdline:
            cmdline.__get__ = mock.Mock(
                return_value=TEST_CMDLINE % 'uuid')
            manager = ep.ProcessManager(self.conf, 'uuid')
            self.assertTrue(manager.active)

    def test_active_none(self):
        with mock.patch.object(ep.ProcessManager, 'cmdline') as cmdline:
            cmdline.__get__ = mock.Mock(return_value=None)
            manager = ep.ProcessManager(self.conf, 'uuid')
            self.assertFalse(manager.active)

    def test_active_cmd_mismatch(self):
        with mock.patch.object(ep.ProcessManager, 'cmdline') as cmdline:
            cmdline.__get__ = mock.Mock(
                return_value=TEST_CMDLINE % 'anotherid')
            manager = ep.ProcessManager(self.conf, 'uuid')
            self.assertFalse(manager.active)

    def test_cmdline(self):
        with mock.patch.object(psutil, 'Process') as proc:
            proc().cmdline.return_value = (TEST_CMDLINE % 'uuid').split(' ')
            with mock.patch.object(ep.ProcessManager, 'pid') as pid:
                pid.__get__ = mock.Mock(return_value=4)
                manager = ep.ProcessManager(self.conf, 'uuid')
                self.assertEqual(TEST_CMDLINE % 'uuid', manager.cmdline)
        proc().cmdline.assert_called_once_with()

    def test_cmdline_none(self):
        with mock.patch.object(psutil, 'Process') as proc:
            proc.side_effect = psutil.NoSuchProcess(4)
            with mock.patch.object(ep.ProcessManager, 'pid') as pid:
                pid.__get__ = mock.Mock(return_value=4)
                manager = ep.ProcessManager(self.conf, 'uuid')
                self.assertIsNone(manager.cmdline)
        proc.assert_called_once_with(4)
