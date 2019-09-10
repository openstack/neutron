# Copyright (c) 2014 OpenStack Foundation.
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

import eventlet
import mock

from neutron.common import utils
from neutron.notifiers import batch_notifier
from neutron.tests import base


class TestBatchNotifier(base.BaseTestCase):
    def setUp(self):
        super(TestBatchNotifier, self).setUp()
        self._received_events = eventlet.Queue()
        self.notifier = batch_notifier.BatchNotifier(2, self._queue_events)
        self.spawn_n_p = mock.patch.object(eventlet, 'spawn_n')

    def _queue_events(self, events):
        for event in events:
            self._received_events.put(event)

    def test_queue_event_no_event(self):
        spawn_n = self.spawn_n_p.start()
        self.notifier.queue_event(None)
        self.assertEqual(0, len(self.notifier._pending_events.queue))
        self.assertEqual(0, spawn_n.call_count)

    def test_queue_event_first_event(self):
        spawn_n = self.spawn_n_p.start()
        self.notifier.queue_event(mock.Mock())
        self.assertEqual(1, len(self.notifier._pending_events.queue))
        self.assertEqual(1, spawn_n.call_count)

    def test_queue_event_multiple_events_notify_method(self):
        def _batch_notifier_dequeue():
            while not self.notifier._pending_events.empty():
                self.notifier._pending_events.get()

        c_mock = mock.patch.object(self.notifier, '_notify',
                                   side_effect=_batch_notifier_dequeue).start()
        events = 20
        for i in range(events):
            self.notifier.queue_event('Event %s' % i)
            eventlet.sleep(0)  # yield to let coro execute

        utils.wait_until_true(self.notifier._pending_events.empty,
                              timeout=5)
        # Called twice: when the first thread calls "synced_send" and then,
        # in the same loop, when self._pending_events is not empty(). All
        # self.notifier.queue_event calls are done in just one
        # "batch_interval" (2 secs).
        self.assertEqual(2, c_mock.call_count)

    def test_queue_event_multiple_events_callback_method(self):
        events = 20
        for i in range(events):
            self.notifier.queue_event('Event %s' % i)
            eventlet.sleep(0)  # yield to let coro execute

        utils.wait_until_true(self.notifier._pending_events.empty,
                              timeout=5)
        expected = ['Event %s' % i for i in range(events)]
        # Check the events have been handled in the same input order.
        self.assertEqual(expected, list(self._received_events.queue))
