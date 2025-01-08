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

import queue
import threading
import time

from neutron.common import utils


class BatchNotifier:
    def __init__(self, batch_interval, callback):
        self._pending_events = queue.Queue()
        self.callback = callback
        self.batch_interval = batch_interval
        self._mutex = threading.Lock()

    def queue_event(self, event):
        """Called to queue sending an event with the next batch of events.

        Sending events individually, as they occur, has been problematic as it
        can result in a flood of sends.  Previously, there was a loopingcall
        thread that would send batched events on a periodic interval.  However,
        maintaining a persistent thread in the loopingcall was also
        problematic.

        This replaces the loopingcall with a mechanism that creates a
        short-lived thread on demand whenever an event is queued. That thread
        will check if the lock is released, send all queued events and then
        sleep for 'batch_interval' seconds. If at the end of this sleep time,
        other threads have added new events to the event queue, the same thread
        will process them.

        At the same time, other threads will be able to add new events to the
        queue and will spawn new "synced_send" threads to process them. But if
        the mutex is locked, the spawned thread will end immediately.

        :param event: the event that occurred.
        """
        if not event:
            return

        self._pending_events.put(event)

        def synced_send():
            if not self._mutex.locked():
                with self._mutex:
                    while not self._pending_events.empty():
                        self._notify()
                        # sleeping after send while holding the lock allows
                        # subsequent events to batch up
                        time.sleep(self.batch_interval)

        utils.spawn_n(synced_send)

    def _notify(self):
        batched_events = []
        while not self._pending_events.empty():
            batched_events.append(self._pending_events.get())
        self.callback(batched_events)
