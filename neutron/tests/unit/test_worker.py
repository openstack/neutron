#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import mock

from neutron.common import utils
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import worker as \
    ovn_worker
from neutron.tests import base
from neutron.tests.common import worker_lifecycle
from neutron import worker as neutron_worker


class PeriodicWorkerTestCase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.check_function = mock.Mock()
        self.desc = 'Periodic worker for "PeriodicWorkerTestCase"'
        self.worker = neutron_worker.PeriodicWorker(
            self.check_function, interval=1, initial_delay=1,
            desc=self.desc)
        self.addCleanup(self._stop_worker)

    def _stop_worker(self):
        self.worker.stop()
        completion, exc = worker_lifecycle.probe_worker_method(
            self.worker, 'wait', timeout=2)
        if exc is not None:
            raise RuntimeError(
                'worker.wait() raised during cleanup') from exc
        if completion is worker_lifecycle.MethodCompletion.BLOCKED:
            raise RuntimeError('worker.wait() did not return during cleanup')

    def test_periodic_worker_lifecycle(self):
        worker = self.worker
        check_function = self.check_function
        worker.wait()
        self.assertFalse(check_function.called)
        worker.start()
        utils.wait_until_true(
            lambda: check_function.called,
            timeout=5,
            exception=RuntimeError("check_function not called"))
        worker.stop()
        check_function.reset_mock()
        worker.wait()
        self.assertFalse(check_function.called)
        worker.reset()
        utils.wait_until_true(
            lambda: check_function.called,
            timeout=5,
            exception=RuntimeError("check_function not called"))

    def _probe(self, worker, method, **kwargs):
        return worker_lifecycle.probe_worker_method(
            worker, method, timeout=0.5, **kwargs)

    def _assert_returns(self, worker, method, **kwargs):
        completion, exc = self._probe(worker, method, **kwargs)
        self.assertIsNone(
            exc, '%s() raised %r' % (method, exc))
        self.assertEqual(
            worker_lifecycle.MethodCompletion.RETURNED, completion,
            '%s() blocked but was expected to return' % method)

    def _assert_blocks(self, worker, method, **kwargs):
        completion, _ = self._probe(worker, method, **kwargs)
        self.assertEqual(
            worker_lifecycle.MethodCompletion.BLOCKED, completion,
            '%s() returned but was expected to block' % method)

    def test_idle_lifecycle_methods_return(self):
        """Before start(), stop() and wait() are no-ops and return."""
        self._assert_returns(self.worker, 'wait')
        self._assert_returns(self.worker, 'stop')

    def test_stop_returns_while_running(self):
        self.worker.start()
        self._assert_returns(self.worker, 'stop')

    def test_wait_blocks_while_running(self):
        long_interval_worker = neutron_worker.PeriodicWorker(
            mock.Mock(), interval=60, initial_delay=60, desc=self.desc)
        self.addCleanup(long_interval_worker.stop)
        long_interval_worker.start()
        self._assert_blocks(long_interval_worker, 'wait')

    def test_wait_returns_after_stop(self):
        self.worker.start()
        self.worker.stop()
        self._assert_returns(self.worker, 'wait')

    def test_reset_returns_while_running(self):
        """reset() stops the loop, waits for it, then starts again."""
        long_interval_worker = neutron_worker.PeriodicWorker(
            mock.Mock(), interval=60, initial_delay=60, desc=self.desc)
        self.addCleanup(long_interval_worker.stop)
        long_interval_worker.start()
        self._assert_returns(long_interval_worker, 'reset')

    def test_periodic_worker_lifecycle_contract(self):
        """Verify PeriodicWorker return/block behavior across states."""

        def prepare_state(worker, state):
            worker.stop()
            completion, exc = worker_lifecycle.probe_worker_method(
                worker, 'wait', timeout=2)
            if exc is not None:
                raise RuntimeError(
                    'wait() raised while preparing state') from exc
            if completion is worker_lifecycle.MethodCompletion.BLOCKED:
                raise RuntimeError(
                    'wait() did not return while preparing state')
            if state == 'idle':
                return
            worker.start()
            if state == 'running':
                return
            if state == 'stopped':
                worker.stop()
                return
            raise ValueError('unknown state %r' % state)

        long_interval_worker = neutron_worker.PeriodicWorker(
            mock.Mock(), interval=60, initial_delay=60, desc=self.desc)
        self.addCleanup(long_interval_worker.stop)

        worker_lifecycle.assert_worker_expectations(
            self, long_interval_worker,
            worker_lifecycle.PERIODIC_WORKER_EXPECTATIONS,
            prepare_state=prepare_state)


class WorkerLifecycleProbeTestCase(base.BaseTestCase):
    """Generic lifecycle probes for built-in periodic-process workers."""

    def _assert_returns(self, worker, method, **kwargs):
        completion, exc = worker_lifecycle.probe_worker_method(
            worker, method, timeout=0.5, **kwargs)
        self.assertIsNone(
            exc, '%s() raised %r' % (method, exc))
        self.assertEqual(worker_lifecycle.MethodCompletion.RETURNED,
                         completion)

    def test_maintenance_worker_idle_methods_return(self):
        worker = ovn_worker.MaintenanceWorker()
        for method in worker_lifecycle.WORKER_LIFECYCLE_METHODS:
            self._assert_returns(worker, method)
