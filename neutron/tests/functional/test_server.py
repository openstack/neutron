# Copyright 2015 Mirantis Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import abc
import multiprocessing
import os
import queue
import signal
import traceback
from unittest import mock

from neutron_lib import worker as neutron_worker
from oslo_config import cfg
from oslo_log import log
import psutil

from neutron.common import utils
from neutron import manager
from neutron import service
from neutron.tests import base as tests_base
from neutron.tests.functional import base

LOG = log.getLogger(__name__)
CONF = cfg.CONF

# Those messages will be written to temporary file each time
# start/reset methods are called.
FAKE_START_MSG = 'start'
FAKE_RESET_MSG = 'reset'

TARGET_PLUGIN = 'neutron.plugins.ml2.plugin.Ml2Plugin'


class TestNeutronServer(base.BaseLoggingTestCase,
                        metaclass=abc.ABCMeta):
    def setUp(self):
        super().setUp()
        self.service_pid = None
        self.workers = None
        self.num_workers = None
        self.num_start = 0
        self._mp_queue = multiprocessing.Queue()
        self._start_queue = multiprocessing.Queue()
        self.pipein, self.pipeout = os.pipe()
        self.addCleanup(self._destroy_workers)

    def _destroy_workers(self):
        if self.service_pid:
            # Make sure all processes are stopped
            os.kill(self.service_pid, signal.SIGKILL)

    def _start_server(self, callback, workers, processes_queue=None):
        """Run a given service.

        :param callback: callback that will start the required service
        :param workers: number of service workers
        :returns: list of spawned workers' pids
        """

        self.workers = workers

        # Fork a new process in which server will be started
        pid = os.fork()
        if pid == 0:
            status = 0
            try:
                callback(workers)
            except SystemExit as exc:
                status = exc.code
            except BaseException:
                traceback.print_exc()
                status = 2

            # Really exit
            os._exit(status)

        self.service_pid = pid

        # If number of workers is 1 it is assumed that we run
        # a service in the current process.
        if self.workers > 1:
            workers_pid = self._get_workers(
                10, processes_queue=processes_queue)
            self.assertEqual(len(workers_pid), self.workers)
        else:
            workers_pid = [self.service_pid]

        utils.wait_until_true(self._check_active, timeout=10, sleep=0.5,
                              exception=RuntimeError(
                                  "Failed to start service."))

        return workers_pid

    def _get_workers(self, timeout, processes_queue=None):
        """Get the list of processes in which WSGI server is running."""
        def safe_ppid(proc):
            try:
                return proc.ppid()
            except psutil.NoSuchProcess:
                return None

        def get_workers_pid():
            if self.workers > 1:
                return [proc.pid for proc in psutil.process_iter()
                        if safe_ppid(proc) == self.service_pid]
            return [proc.pid for proc in psutil.process_iter()
                    if proc.pid == self.service_pid]

        exception = RuntimeError('Failed to start %d workers.' % self.workers)

        if processes_queue:
            try:
                return processes_queue.get(timeout=timeout)
            except queue.Empty:
                raise exception

        # Wait at most 10 seconds to spawn workers
        def condition():
            return self.workers == len(get_workers_pid())
        utils.wait_until_true(condition, timeout=timeout, sleep=0.5,
                              exception=exception)
        return get_workers_pid()

    def _check_active(self):
        """Service activity check."""
        while not self._start_queue.empty():
            self._start_queue.get()
            self.num_start += 1
        return self.num_start == self.num_workers

    def _fake_start(self):
        self._mp_queue.put(FAKE_START_MSG)
        self._start_queue.put(True)

    def _fake_reset(self):
        self._mp_queue.put(FAKE_RESET_MSG)

    def _test_restart_service_on_sighup(self, service, workers=1,
                                        processes_queue=None):
        """Test that a service correctly (re)starts on receiving SIGHUP.

        1. Start a service with a given number of workers.
        2. Send SIGHUP to the service.
        3. Wait for workers (if any) to (re)start.
        """

        self._start_server(callback=service, workers=workers,
                           processes_queue=processes_queue)
        os.kill(self.service_pid, signal.SIGHUP)

        # After sending SIGHUP it is expected that there will be as many
        # FAKE_RESET_MSG as number of workers + one additional for main
        # process
        expected_msg = (
            FAKE_START_MSG * workers + FAKE_RESET_MSG * (workers + 1))

        # Wait for temp file to be created and its size reaching the expected
        # value
        expected_size = len(expected_msg)
        ret_msg = ''

        def is_ret_buffer_ok():
            nonlocal ret_msg
            LOG.debug('Checking returned buffer size')
            while not self._mp_queue.empty():
                ret_msg += self._mp_queue.get()
            LOG.debug('Size of buffer is %s. Expected size: %s',
                      len(ret_msg), expected_size)
            return len(ret_msg) == expected_size

        try:
            utils.wait_until_true(is_ret_buffer_ok, timeout=5, sleep=1)
        except utils.WaitTimeout:
            raise RuntimeError('Expected buffer size: %s, current size: %s' %
                               (expected_size, len(ret_msg)))

        # Verify that start has been called twice for each worker (one for
        # initial start, and the second one on SIGHUP after children were
        # terminated).
        self.assertEqual(expected_msg, ret_msg)


class TestRPCServer(TestNeutronServer):
    """Tests for neutron RPC server."""

    def setUp(self):
        super().setUp()
        self.setup_coreplugin('ml2', load_plugins=False)
        self._plugin_patcher = mock.patch(TARGET_PLUGIN, autospec=True)
        self.plugin = self._plugin_patcher.start()
        self.plugin.return_value.rpc_workers_supported = True
        self._processes_queue = multiprocessing.Queue()

    def _serve_rpc(self, workers=1):
        """Start RPC server with a given number of workers."""

        # Mock start method to check that children are started again on
        # receiving SIGHUP.
        with mock.patch("neutron.service.RpcWorker.start") as start_method,\
                mock.patch(
                    "neutron.service.RpcWorker.reset") as reset_method,\
                mock.patch(
                    "neutron_lib.plugins.directory.get_plugin") as get_plugin:
            start_method.side_effect = self._fake_start
            reset_method.side_effect = self._fake_reset
            get_plugin.return_value = self.plugin

            CONF.set_override("rpc_workers", workers)
            # not interested in state report workers specifically
            CONF.set_override("rpc_state_report_workers", 0)

            rpc_workers_launcher = service.start_rpc_workers()
            self._processes_queue.put(list(rpc_workers_launcher.children))
            rpc_workers_launcher.wait()

    @tests_base.unstable_test('LP bug 2100001')
    def test_restart_rpc_on_sighup_multiple_workers(self):
        self.num_workers = 2
        self._test_restart_service_on_sighup(
            service=self._serve_rpc, workers=self.num_workers,
            processes_queue=self._processes_queue)


class TestPluginWorker(TestNeutronServer):
    """Ensure that a plugin returning Workers spawns workers"""

    def setUp(self):
        super().setUp()
        self.setup_coreplugin('ml2', load_plugins=False)
        self._plugin_patcher = mock.patch(TARGET_PLUGIN, autospec=True)
        self.plugin = self._plugin_patcher.start()
        manager.init()

    def _start_plugin(self, workers=1):
        with mock.patch('neutron_lib.plugins.directory.get_plugin') as gp:
            gp.return_value = self.plugin
            plugin_workers_launcher = service.start_plugins_workers()
            plugin_workers_launcher.wait()

    @tests_base.unstable_test('LP bug 2100001')
    def test_start(self):
        class FakeWorker(neutron_worker.BaseWorker):
            def start(self):
                pass

            def wait(self):
                pass

            def stop(self):
                pass

            def reset(self):
                pass

        # Make both ABC happy and ensure 'self' is correct
        FakeWorker.start = self._fake_start
        FakeWorker.reset = self._fake_reset
        workers = [FakeWorker()]
        self.plugin.return_value.get_workers.return_value = workers
        self.num_workers = len(workers)
        self._test_restart_service_on_sighup(service=self._start_plugin,
                                             workers=self.num_workers)
