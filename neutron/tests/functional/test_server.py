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

import os
import signal
import socket
import time
import traceback

import httplib2
import mock
from neutron_lib import worker as neutron_worker
from oslo_config import cfg
import psutil

from neutron.common import utils
from neutron import manager
from neutron import service
from neutron.tests import base
from neutron import wsgi


CONF = cfg.CONF

# This message will be written to temporary file each time
# start method is called.
FAKE_START_MSG = b"start"

TARGET_PLUGIN = 'neutron.plugins.ml2.plugin.Ml2Plugin'


class TestNeutronServer(base.BaseTestCase):
    def setUp(self):
        super(TestNeutronServer, self).setUp()
        self.service_pid = None
        self.workers = None
        self.temp_file = self.get_temp_file_path("test_server.tmp")
        self.health_checker = self._check_active
        self.pipein, self.pipeout = os.pipe()
        self.addCleanup(self._destroy_workers)

    def _destroy_workers(self):
        if self.service_pid:
            # Make sure all processes are stopped
            os.kill(self.service_pid, signal.SIGKILL)

    def _start_server(self, callback, workers):
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
            # Wait at most 10 seconds to spawn workers
            condition = lambda: self.workers == len(self._get_workers())

            utils.wait_until_true(
                condition, timeout=10, sleep=0.1,
                exception=RuntimeError(
                    "Failed to start %d workers." % self.workers))

            workers = self._get_workers()
            self.assertEqual(len(workers), self.workers)
            return workers

        # Wait for a service to start.
        utils.wait_until_true(self.health_checker, timeout=10, sleep=0.1,
                              exception=RuntimeError(
                                  "Failed to start service."))

        return [self.service_pid]

    def _get_workers(self):
        """Get the list of processes in which WSGI server is running."""

        def safe_ppid(proc):
            try:
                return proc.ppid()
            except psutil.NoSuchProcess:
                return None

        if self.workers > 1:
            return [proc.pid for proc in psutil.process_iter()
                    if safe_ppid(proc) == self.service_pid]
        else:
            return [proc.pid for proc in psutil.process_iter()
                    if proc.pid == self.service_pid]

    def _check_active(self):
        """Dummy service activity check."""
        time.sleep(5)
        return True

    def _fake_start(self):
        with open(self.temp_file, 'ab') as f:
            f.write(FAKE_START_MSG)

    def _test_restart_service_on_sighup(self, service, workers=1):
        """Test that a service correctly (re)starts on receiving SIGHUP.

        1. Start a service with a given number of workers.
        2. Send SIGHUP to the service.
        3. Wait for workers (if any) to (re)start.
        """

        self._start_server(callback=service, workers=workers)
        os.kill(self.service_pid, signal.SIGHUP)

        expected_msg = FAKE_START_MSG * workers * 2

        # Wait for temp file to be created and its size reaching the expected
        # value
        expected_size = len(expected_msg)
        condition = lambda: (os.path.isfile(self.temp_file)
                             and os.stat(self.temp_file).st_size ==
                             expected_size)

        utils.wait_until_true(
            condition, timeout=5, sleep=0.1,
            exception=RuntimeError(
                "Timed out waiting for file %(filename)s to be created and "
                "its size become equal to %(size)s." %
                {'filename': self.temp_file,
                 'size': expected_size}))

        # Verify that start has been called twice for each worker (one for
        # initial start, and the second one on SIGHUP after children were
        # terminated).
        with open(self.temp_file, 'rb') as f:
            res = f.readline()
            self.assertEqual(expected_msg, res)


class TestWsgiServer(TestNeutronServer):
    """Tests for neutron.wsgi.Server."""

    def setUp(self):
        super(TestWsgiServer, self).setUp()
        self.health_checker = self._check_active
        self.port = None

    @staticmethod
    def application(environ, start_response):
        """A primitive test application."""

        response_body = 'Response'
        status = '200 OK'
        response_headers = [('Content-Type', 'text/plain'),
                            ('Content-Length', str(len(response_body)))]
        start_response(status, response_headers)
        return [response_body]

    def _check_active(self):
        """Check a wsgi service is active by making a GET request."""
        port = int(os.read(self.pipein, 5))
        conn = httplib2.HTTPConnectionWithTimeout("localhost", port)
        try:
            conn.request("GET", "/")
            resp = conn.getresponse()
            return resp.status == 200
        except socket.error:
            return False

    def _run_wsgi(self, workers=1):
        """Start WSGI server with a test application."""

        # Mock start method to check that children are started again on
        # receiving SIGHUP.
        with mock.patch("neutron.wsgi.WorkerService.start") as start_method:
            start_method.side_effect = self._fake_start

            server = wsgi.Server("Test")
            server.start(self.application, 0, "0.0.0.0",
                         workers=workers)

            # Memorize a port that was chosen for the service
            self.port = server.port
            os.write(self.pipeout, bytes(self.port))

            server.wait()

    def test_restart_wsgi_on_sighup_multiple_workers(self):
        self._test_restart_service_on_sighup(service=self._run_wsgi,
                                             workers=2)


class TestRPCServer(TestNeutronServer):
    """Tests for neutron RPC server."""

    def setUp(self):
        super(TestRPCServer, self).setUp()
        self.setup_coreplugin('ml2', load_plugins=False)
        self._plugin_patcher = mock.patch(TARGET_PLUGIN, autospec=True)
        self.plugin = self._plugin_patcher.start()
        self.plugin.return_value.rpc_workers_supported = True

    def _serve_rpc(self, workers=1):
        """Start RPC server with a given number of workers."""

        # Mock start method to check that children are started again on
        # receiving SIGHUP.
        with mock.patch("neutron.service.RpcWorker.start") as start_method:
            with mock.patch(
                    "neutron_lib.plugins.directory.get_plugin"
            ) as get_plugin:
                start_method.side_effect = self._fake_start
                get_plugin.return_value = self.plugin

                CONF.set_override("rpc_workers", workers)
                # not interested in state report workers specifically
                CONF.set_override("rpc_state_report_workers", 0)

                rpc_workers_launcher = service.start_rpc_workers()
                rpc_workers_launcher.wait()

    def test_restart_rpc_on_sighup_multiple_workers(self):
        self._test_restart_service_on_sighup(service=self._serve_rpc,
                                             workers=2)


class TestPluginWorker(TestNeutronServer):
    """Ensure that a plugin returning Workers spawns workers"""

    def setUp(self):
        super(TestPluginWorker, self).setUp()
        self.setup_coreplugin('ml2', load_plugins=False)
        self._plugin_patcher = mock.patch(TARGET_PLUGIN, autospec=True)
        self.plugin = self._plugin_patcher.start()
        manager.init()

    def _start_plugin(self, workers=1):
        with mock.patch('neutron_lib.plugins.directory.get_plugin') as gp:
            gp.return_value = self.plugin
            plugin_workers_launcher = service.start_plugins_workers()
            plugin_workers_launcher.wait()

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
        workers = [FakeWorker()]
        self.plugin.return_value.get_workers.return_value = workers
        self._test_restart_service_on_sighup(service=self._start_plugin,
                                             workers=len(workers))
