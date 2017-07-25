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
from neutron_lib.utils import runtime
from oslo_utils import uuidutils


class BatchNotifier(object):
    def __init__(self, batch_interval, callback):
        self.pending_events = []
        self.callback = callback
        self.batch_interval = batch_interval
        self._lock_identifier = 'notifier-%s' % uuidutils.generate_uuid()

    def queue_event(self, event):
        """Called to queue sending an event with the next batch of events.

        Sending events individually, as they occur, has been problematic as it
        can result in a flood of sends.  Previously, there was a loopingcall
        thread that would send batched events on a periodic interval.  However,
        maintaining a persistent thread in the loopingcall was also
        problematic.

        This replaces the loopingcall with a mechanism that creates a
        short-lived thread on demand whenever an event is queued. That thread
        will wait for a lock, send all queued events and then sleep for
        'batch_interval' seconds to allow other events to queue up.

        This effectively acts as a rate limiter to only allow 1 batch per
        'batch_interval' seconds.

        :param event: the event that occurred.
        """
        if not event:
            return

        self.pending_events.append(event)

        @runtime.synchronized(self._lock_identifier)
        def synced_send():
            self._notify()
            # sleeping after send while holding the lock allows subsequent
            # events to batch up
            eventlet.sleep(self.batch_interval)

        eventlet.spawn_n(synced_send)

    def _notify(self):
        if not self.pending_events:
            return

        batched_events = self.pending_events
        self.pending_events = []
        self.callback(batched_events)
