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


class BatchNotifier(object):
    def __init__(self, batch_interval, callback):
        self.pending_events = []
        self._waiting_to_send = False
        self.callback = callback
        self.batch_interval = batch_interval

    def queue_event(self, event):
        """Called to queue sending an event with the next batch of events.

        Sending events individually, as they occur, has been problematic as it
        can result in a flood of sends.  Previously, there was a loopingcall
        thread that would send batched events on a periodic interval.  However,
        maintaining a persistent thread in the loopingcall was also
        problematic.

        This replaces the loopingcall with a mechanism that creates a
        short-lived thread on demand when the first event is queued.  That
        thread will sleep once for the same batch_duration to allow other
        events to queue up in pending_events and then will send them when it
        wakes.

        If a thread is already alive and waiting, this call will simply queue
        the event and return leaving it up to the thread to send it.

        :param event: the event that occurred.
        """
        if not event:
            return

        self.pending_events.append(event)

        if self._waiting_to_send:
            return

        self._waiting_to_send = True

        def last_out_sends():
            eventlet.sleep(self.batch_interval)
            self._waiting_to_send = False
            self._notify()

        eventlet.spawn_n(last_out_sends)

    def _notify(self):
        if not self.pending_events:
            return

        batched_events = self.pending_events
        self.pending_events = []
        self.callback(batched_events)
