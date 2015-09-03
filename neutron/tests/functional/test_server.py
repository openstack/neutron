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

import httplib2
import mock
import os
import signal
import socket
import time
import traceback

from oslo_config import cfg
import psutil

from neutron.agent.linux import utils
from neutron import service
from neutron.tests import base
from neutron import wsgi


CONF = cfg.CONF

# This message will be written to temporary file each time
# reset method is called.
FAKE_RESET_MSG = "reset".encode("utf-8")

TARGET_PLUGIN = 'neutron.plugins.ml2.plugin.Ml2Plugin'


class TestNeutronServer(base.BaseTestCase):
    def setUp(self):
        super(TestNeutronServer, self).setUp()
        self.service_pid = None
        self.workers = None
        self.temp_file = self.get_temp_file_path("test_server.tmp")
        self.health_checker = None
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

        if self.workers > 0:
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

        if self.workers > 0:
            return [proc.pid for proc in psutil.process_iter()
                    if proc.ppid == self.service_pid]
        else:
            return [proc.pid for proc in psutil.process_iter()
                    if proc.pid == self.service_pid]

    def _fake_reset(self):
        """Writes FAKE_RESET_MSG to temporary file on each call."""

        with open(self.temp_file, 'a') as f:
            f.write(FAKE_RESET_MSG)

    def _test_restart_service_on_sighup(self, service, workers=0):
        """Test that a service correctly restarts on receiving SIGHUP.

        1. Start a service with a given number of workers.
        2. Send SIGHUP to the service.
        3. Wait for workers (if any) to restart.
        4. Assert that the pids of the workers didn't change after restart.
        """

        start_workers = self._start_server(callback=service, workers=workers)

        os.kill(self.service_pid, signal.SIGHUP)

        # Wait for temp file to be created and its size become equal
        # to size of FAKE_RESET_MSG repeated (workers + 1) times.
        expected_size = len(FAKE_RESET_MSG) * (workers + 1)
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

        # Verify that reset has been called for parent process in which
        # a service was started and for each worker by checking that
        # FAKE_RESET_MSG has been written to temp file workers + 1 times.
        with open(self.temp_file, 'r') as f:
            res = f.readline()
            self.assertEqual(FAKE_RESET_MSG * (workers + 1), res)

        # Make sure worker pids don't change
        end_workers = self._get_workers()
        self.assertEqual(start_workers, end_workers)


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

    def _run_wsgi(self, workers=0):
        """Start WSGI server with a test application."""

        # Mock reset method to check that it is being called
        # on receiving SIGHUP.
        with mock.patch("neutron.wsgi.WorkerService.reset") as reset_method:
            reset_method.side_effect = self._fake_reset

            server = wsgi.Server("Test")
            server.start(self.application, 0, "0.0.0.0",
                         workers=workers)

            # Memorize a port that was chosen for the service
            self.port = server.port
            os.write(self.pipeout, str(self.port))

            server.wait()

    def test_restart_wsgi_on_sighup_multiple_workers(self):
        self._test_restart_service_on_sighup(service=self._run_wsgi,
                                             workers=2)


class TestRPCServer(TestNeutronServer):
    """Tests for neutron RPC server."""

    def setUp(self):
        super(TestRPCServer, self).setUp()
        self.setup_coreplugin(TARGET_PLUGIN)
        self._plugin_patcher = mock.patch(TARGET_PLUGIN, autospec=True)
        self.plugin = self._plugin_patcher.start()
        self.plugin.return_value.rpc_workers_supported = True
        self.health_checker = self._check_active

    def _check_active(self):
        time.sleep(5)
        return True

    def _serve_rpc(self, workers=0):
        """Start RPC server with a given number of workers."""

        # Mock reset method to check that it is being called
        # on receiving SIGHUP.
        with mock.patch("neutron.service.RpcWorker.reset") as reset_method:
            with mock.patch(
                    "neutron.manager.NeutronManager.get_plugin"
            ) as get_plugin:
                reset_method.side_effect = self._fake_reset
                get_plugin.return_value = self.plugin

                CONF.set_override("rpc_workers", workers)

                launcher = service.serve_rpc()
                launcher.wait()

    def test_restart_rpc_on_sighup_multiple_workers(self):
        self._test_restart_service_on_sighup(service=self._serve_rpc,
                                             workers=2)
