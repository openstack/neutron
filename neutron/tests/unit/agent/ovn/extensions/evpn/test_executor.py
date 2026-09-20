# Copyright 2026 Red Hat, LLC
# All Rights Reserved.
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

import threading
from unittest import mock

from neutron.agent.ovn.extensions.evpn import executor as evpn_executor
from neutron.agent.ovn.extensions.evpn import fsm
from neutron.common import utils
from neutron.tests import base

BR_MTU = 1500
MAC = 'aa:bb:cc:dd:ee:ff'


class TestEvpnExecutor(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.mock_svd = mock.Mock()
        self.mock_driver = mock.Mock()
        self.executor = evpn_executor.EvpnExecutor(
            self.mock_svd, BR_MTU, self.mock_driver,
            max_retries=5, initial_backoff=0, max_backoff=0)

    @staticmethod
    def _make_evpn(vrf='vrf1', vni=10, vid=1, mac=MAC):
        evpn = fsm.EVPNInstance(vrf)
        evpn.mac = mac
        evpn.vni = vni
        evpn.vid = vid
        return evpn

    def test_provision_supersedes_ready(self):
        """New provision() supersedes a pending provision for same evpn."""
        evpn = fsm.EVPNInstance('vrf1')
        evpn.mac = 'aa:bb:cc:dd:ee:ff'
        evpn.vni = 10
        evpn.vid = 1
        worker_blocked = threading.Event()
        gate = threading.Event()

        def blocking_add_vni(*args, **kwargs):
            worker_blocked.set()
            gate.wait(timeout=10)
            raise RuntimeError('interrupted')

        self.mock_svd.add_vni.side_effect = blocking_add_vni

        self.executor.provision(evpn)
        worker_blocked.wait(timeout=5)

        self.mock_svd.add_vni.side_effect = None
        evpn.vni = 20
        evpn.vid = 2
        self.executor.provision(evpn)
        gate.set()

        utils.wait_until_true(
            lambda: self.mock_svd.add_vni.call_args == mock.call(
                20, 2, 'vrf1', 'aa:bb:cc:dd:ee:ff', BR_MTU),
            timeout=5, sleep=0.01)
        self.mock_svd.add_vni.assert_called_with(
            20, 2, 'vrf1', 'aa:bb:cc:dd:ee:ff', BR_MTU)

    def test_rapid_fire_only_last_executes(self):
        """Many rapid provisions for same instance: only the last runs."""
        evpn = fsm.EVPNInstance('vrf1')
        evpn.mac = 'aa:bb:cc:dd:ee:ff'
        evpn.vni = 10
        evpn.vid = 1
        first_started = threading.Event()
        gate = threading.Event()

        def blocking_add_vni(*args, **kwargs):
            first_started.set()
            gate.wait(timeout=10)
            raise RuntimeError('interrupted')

        self.mock_svd.add_vni.side_effect = blocking_add_vni

        self.executor.provision(evpn)
        first_started.wait(timeout=5)

        self.mock_svd.add_vni.side_effect = None
        for vni in (20, 30, 40):
            evpn.vni = vni
            evpn.vid = vni
            self.executor.provision(evpn)

        evpn.vni = 50
        evpn.vid = 50
        self.executor.provision(evpn)

        gate.set()
        utils.wait_until_true(
            lambda: self.mock_svd.add_vni.call_args == mock.call(
                50, 50, 'vrf1', 'aa:bb:cc:dd:ee:ff', BR_MTU),
            timeout=5, sleep=0.01)
        self.mock_svd.add_vni.assert_called_with(
            50, 50, 'vrf1', 'aa:bb:cc:dd:ee:ff', BR_MTU)

    def test_different_instances_run_serially(self):
        """Commands for different EVPNInstances execute serially."""
        evpn1 = fsm.EVPNInstance('vrf1')
        evpn1.mac = 'aa:bb:cc:dd:ee:ff'
        evpn1.vni = 10
        evpn1.vid = 1
        evpn2 = fsm.EVPNInstance('vrf2')
        evpn2.mac = 'aa:bb:cc:dd:ee:ff'
        evpn2.vni = 20
        evpn2.vid = 2
        call_order = []

        def recording_add_vni(*args, **kwargs):
            call_order.append(args)

        self.mock_svd.add_vni.side_effect = recording_add_vni

        self.executor.provision(evpn1)
        self.executor.provision(evpn2)

        utils.wait_until_true(
            lambda: len(call_order) == 2, timeout=5, sleep=0.01)
        self.assertEqual(2, len(call_order))
        self.assertEqual(10, call_order[0][0])
        self.assertEqual(20, call_order[1][0])

    def test_requeue_after_failure(self):
        """Failed command is deferred, other items processed first."""
        evpn1 = fsm.EVPNInstance('vrf1')
        evpn1.mac = 'aa:bb:cc:dd:ee:ff'
        evpn1.vni = 10
        evpn1.vid = 1
        evpn2 = fsm.EVPNInstance('vrf2')
        evpn2.mac = 'aa:bb:cc:dd:ee:ff'
        evpn2.vni = 20
        evpn2.vid = 2
        call_order = []

        fail_count = [0]

        def flaky_add_vni(vni, *args, **kwargs):
            if vni == 10 and fail_count[0] < 2:
                fail_count[0] += 1
                raise RuntimeError('transient failure')
            call_order.append(vni)

        self.mock_svd.add_vni.side_effect = flaky_add_vni

        self.executor.provision(evpn1)
        self.executor.provision(evpn2)

        utils.wait_until_true(
            lambda: call_order == [20, 10], timeout=5, sleep=0.01)
        self.assertEqual([20, 10], call_order)

    def test_deprovision_supersedes_provision(self):
        """Deprovision overwrites a pending provision for the same evpn."""
        evpn = fsm.EVPNInstance('vrf1')
        evpn.mac = 'aa:bb:cc:dd:ee:ff'
        evpn.vni = 10
        evpn.vid = 1
        worker_blocked = threading.Event()
        gate = threading.Event()

        def blocking_add_vni(*args, **kwargs):
            worker_blocked.set()
            gate.wait(timeout=10)
            raise RuntimeError('interrupted')

        self.mock_svd.add_vni.side_effect = blocking_add_vni

        self.executor.provision(evpn)
        worker_blocked.wait(timeout=5)

        self.executor.deprovision(evpn)
        gate.set()

        utils.wait_until_true(
            lambda: self.mock_svd.del_vni.called, timeout=5, sleep=0.01)
        self.mock_svd.del_vni.assert_called_once_with(10, 1)
        self.mock_driver.delete_router.assert_called_once_with('vrf1', 10)

    def test_provision_then_deprovision_ordering(self):
        """Provision then deprovision for different instances: FIFO order."""
        evpn1 = fsm.EVPNInstance('vrf1')
        evpn1.mac = 'aa:bb:cc:dd:ee:ff'
        evpn1.vni = 10
        evpn1.vid = 1
        evpn2 = fsm.EVPNInstance('vrf2')
        evpn2.mac = 'aa:bb:cc:dd:ee:ff'
        evpn2.vni = 20
        evpn2.vid = 2
        call_order = []
        worker_blocked = threading.Event()
        gate = threading.Event()

        def blocking_add_vni(*args, **kwargs):
            worker_blocked.set()
            gate.wait(timeout=10)
            call_order.append('provision')

        def recording_del_vni(*args, **kwargs):
            call_order.append('deprovision')

        self.mock_svd.add_vni.side_effect = blocking_add_vni
        self.mock_svd.del_vni.side_effect = recording_del_vni

        self.executor.provision(evpn1)
        worker_blocked.wait(timeout=5)
        self.executor.deprovision(evpn2)
        gate.set()

        utils.wait_until_true(
            lambda: call_order == ['provision', 'deprovision'],
            timeout=5, sleep=0.01)
        self.assertEqual(['provision', 'deprovision'], call_order)

    def test_retries_exhausted(self):
        """Item dropped from both queues after max_retries failures."""
        evpn = fsm.EVPNInstance('vrf1')
        evpn.mac = 'aa:bb:cc:dd:ee:ff'
        evpn.vni = 10
        evpn.vid = 1
        self.mock_svd.add_vni.side_effect = RuntimeError('always fails')
        self.executor = evpn_executor.EvpnExecutor(
            self.mock_svd, BR_MTU, self.mock_driver,
            max_retries=3, initial_backoff=0, max_backoff=0)

        self.executor.provision(evpn)
        utils.wait_until_true(
            lambda: (self.mock_svd.add_vni.call_count == 3 and
                     not self.executor._ready and
                     not self.executor._deferred),
            timeout=5, sleep=0.01)
        self.assertEqual(0, len(self.executor._ready))
        self.assertEqual(0, len(self.executor._deferred))
        self.assertEqual(3, self.mock_svd.add_vni.call_count)

    def test_deprovision_cancels_deferred_provision(self):
        """Deprovision removes a provision sitting in _deferred."""
        evpn = self._make_evpn()
        # Keep the failed task deferred long enough to cancel it.
        self.executor = evpn_executor.EvpnExecutor(
            self.mock_svd, BR_MTU, self.mock_driver,
            max_retries=5, initial_backoff=60.0, max_backoff=60.0)
        mock_do_prov = mock.Mock(side_effect=RuntimeError('fail'))
        mock_do_deprov = mock.Mock()

        with mock.patch.object(self.executor, '_do_provision',
                               mock_do_prov), \
                mock.patch.object(self.executor, '_do_deprovision',
                                  mock_do_deprov):
            self.executor.provision(evpn)
            utils.wait_until_true(
                lambda: evpn.vrf in self.executor._deferred,
                timeout=5, sleep=0.01)
            prov_calls = mock_do_prov.call_count

            self.executor.deprovision(evpn)
            utils.wait_until_true(
                lambda: (mock_do_deprov.call_count == 1 and
                         not self.executor._ready and
                         not self.executor._deferred),
                timeout=5, sleep=0.01)

            self.assertEqual(prov_calls, mock_do_prov.call_count)
            mock_do_deprov.assert_called_once_with('vrf1', 10, 1)
            self.assertEqual(0, len(self.executor._ready))
            self.assertEqual(0, len(self.executor._deferred))

    def test_inflight_provision_not_deferred_when_deprovision_queued(self):
        """Failed in-flight provision is not re-deferred if deprovision waits.
        """
        evpn = self._make_evpn()
        worker_blocked = threading.Event()
        gate = threading.Event()

        def blocking_fail(*args):
            worker_blocked.set()
            gate.wait(timeout=10)
            raise RuntimeError('interrupted')

        mock_do_prov = mock.Mock(side_effect=blocking_fail)
        mock_do_deprov = mock.Mock()

        with mock.patch.object(self.executor, '_do_provision',
                               mock_do_prov), \
                mock.patch.object(self.executor, '_do_deprovision',
                                  mock_do_deprov):
            self.executor.provision(evpn)
            worker_blocked.wait(timeout=5)

            self.executor.deprovision(evpn)
            gate.set()
            utils.wait_until_true(
                lambda: (mock_do_deprov.call_count == 1 and
                         not self.executor._deferred),
                timeout=5, sleep=0.01)

            self.assertEqual(1, mock_do_prov.call_count)
            mock_do_deprov.assert_called_once_with('vrf1', 10, 1)
            self.assertEqual(0, len(self.executor._deferred))

    def test_inflight_provision_then_newer_provision_runs(self):
        """Newer provision supersedes in-flight; final _do_provision uses
        new args.
        """
        evpn = self._make_evpn(vni=10, vid=1)
        worker_blocked = threading.Event()
        gate = threading.Event()

        def blocking_fail(*args):
            worker_blocked.set()
            gate.wait(timeout=10)
            raise RuntimeError('interrupted')

        mock_do_prov = mock.Mock(side_effect=blocking_fail)

        with mock.patch.object(self.executor, '_do_provision',
                               mock_do_prov):
            self.executor.provision(evpn)
            worker_blocked.wait(timeout=5)

            mock_do_prov.side_effect = None
            evpn.vni = 20
            evpn.vid = 2
            self.executor.provision(evpn)
            gate.set()
            utils.wait_until_true(
                lambda: mock_do_prov.call_args == mock.call(
                    'vrf1', 20, 2, MAC),
                timeout=5, sleep=0.01)

            mock_do_prov.assert_called_with('vrf1', 20, 2, MAC)

    def test_inflight_success_then_queued_deprovision(self):
        """In-flight provision cannot be aborted; queued deprovision runs after
        .
        """
        evpn = self._make_evpn()
        worker_blocked = threading.Event()
        gate = threading.Event()
        call_order = []

        def blocking_success(*args):
            worker_blocked.set()
            gate.wait(timeout=10)
            call_order.append('provision')

        def recording_deprov(*args):
            call_order.append('deprovision')

        mock_do_prov = mock.Mock(side_effect=blocking_success)
        mock_do_deprov = mock.Mock(side_effect=recording_deprov)

        with mock.patch.object(self.executor, '_do_provision',
                               mock_do_prov), \
                mock.patch.object(self.executor, '_do_deprovision',
                                  mock_do_deprov):
            self.executor.provision(evpn)
            worker_blocked.wait(timeout=5)

            self.executor.deprovision(evpn)
            gate.set()
            utils.wait_until_true(
                lambda: call_order == ['provision', 'deprovision'],
                timeout=5, sleep=0.01)

            self.assertEqual(['provision', 'deprovision'], call_order)
            mock_do_prov.assert_called_once_with('vrf1', 10, 1, MAC)
            mock_do_deprov.assert_called_once_with('vrf1', 10, 1)
