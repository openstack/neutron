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

import mock

from neutron.notifiers import batch_notifier
from neutron.tests import base


class TestBatchNotifier(base.BaseTestCase):
    def setUp(self):
        super(TestBatchNotifier, self).setUp()
        self.notifier = batch_notifier.BatchNotifier(0.1, lambda x: x)
        self.spawn_n = mock.patch('eventlet.spawn_n').start()

    def test_queue_event_no_event(self):
        self.notifier.queue_event(None)
        self.assertEqual(0, len(self.notifier.pending_events))
        self.assertEqual(0, self.spawn_n.call_count)

    def test_queue_event_first_event(self):
        self.notifier.queue_event(mock.Mock())
        self.assertEqual(1, len(self.notifier.pending_events))
        self.assertEqual(1, self.spawn_n.call_count)

    def test_queue_event_multiple_events(self):
        events = 6
        for i in range(0, events):
            self.notifier.queue_event(mock.Mock())
        self.assertEqual(events, len(self.notifier.pending_events))
        self.assertEqual(1, self.spawn_n.call_count)

    def test_queue_event_call_send_events(self):
        with mock.patch.object(self.notifier,
                               'callback') as send_events:
            self.spawn_n.side_effect = lambda func: func()
            self.notifier.queue_event(mock.Mock())
            self.assertFalse(self.notifier._waiting_to_send)
            self.assertTrue(send_events.called)
