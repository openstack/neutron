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

from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.services.bgp import events
from neutron.services.bgp import ovn
from neutron.services.bgp import reconciler
from neutron.tests import base


class BGPLockEventHandlerTestCase(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.reconciler = mock.Mock()
        self.handler = events.BGPLockEventHandler(self.reconciler)
        self.addCleanup(self.handler.shutdown)

    def _notify_lock(self, acquired):
        self.handler.notify_lock(ovn.OvnNbIdl.LOCK_NAME, acquired)
        # notify_lock only queues; wait for the notify_loop to dispatch it
        self.handler.notifications.join()

    def test_acquiring_the_lock_triggers_a_full_sync(self):
        self._notify_lock(True)
        self.reconciler.full_sync.assert_called_once_with()

    def test_losing_the_lock_does_not_trigger_a_full_sync(self):
        self._notify_lock(False)
        self.reconciler.full_sync.assert_not_called()

    def test_reacquiring_the_lock_triggers_another_full_sync(self):
        self._notify_lock(True)
        self._notify_lock(False)
        self._notify_lock(True)
        self.assertEqual(2, self.reconciler.full_sync.call_count)


class BGPTopologyReconcilerTestCase(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        ovn_conf.register_opts()
        self.nb_idl = mock.patch.object(reconciler.ovn, 'OvnNbIdl').start()
        mock.patch.object(reconciler.ovn, 'OvnSbIdl').start()
        self.full_sync_cmd = mock.patch.object(
            reconciler.commands, 'FullSyncBGPTopologyCommand').start()
        self.reconciler = reconciler.BGPTopologyReconciler()

    def test_start_hands_the_nb_idl_a_lock_event_handler(self):
        self.reconciler.start()

        handler = self.nb_idl.call_args.kwargs['notify_handler']
        self.addCleanup(handler.shutdown)
        self.assertIsInstance(handler, events.BGPLockEventHandler)
        self.assertIs(self.reconciler, handler.reconciler)

    def test_full_sync_does_not_depend_on_has_lock(self):
        # The lock_acquired hook only fires on the worker that holds the
        # lock, so full_sync must not second-guess it: re-reading has_lock
        # is the race this replaced.
        self.reconciler.start()
        self.reconciler.nb_api.has_lock = False

        self.reconciler.full_sync()

        self.assertTrue(self.full_sync_cmd.called)

    def test_full_sync_waits_for_start_to_finish(self):
        # lock_acquired can fire while start() is still assigning nb_api,
        # so a sync that arrives early has to block rather than blow up.
        finished = threading.Event()

        def sync():
            self.reconciler.full_sync()
            finished.set()

        syncer = threading.Thread(target=sync)
        syncer.daemon = True
        syncer.start()

        self.assertFalse(finished.wait(timeout=0.5))
        self.full_sync_cmd.assert_not_called()

        self.reconciler.start()

        self.assertTrue(finished.wait(timeout=10))
        self.assertTrue(self.full_sync_cmd.called)
