# Copyright 2014 Hewlett-Packard Development Company, L.P.
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
#

import datetime
import Queue

from oslo_utils import timeutils

# Lower value is higher priority
PRIORITY_RPC = 0
PRIORITY_SYNC_ROUTERS_TASK = 1
DELETE_ROUTER = 1


class RouterUpdate(object):
    """Encapsulates a router update

    An instance of this object carries the information necessary to prioritize
    and process a request to update a router.
    """
    def __init__(self, router_id, priority,
                 action=None, router=None, timestamp=None):
        self.priority = priority
        self.timestamp = timestamp
        if not timestamp:
            self.timestamp = timeutils.utcnow()
        self.id = router_id
        self.action = action
        self.router = router

    def __lt__(self, other):
        """Implements priority among updates

        Lower numerical priority always gets precedence.  When comparing two
        updates of the same priority then the one with the earlier timestamp
        gets procedence.  In the unlikely event that the timestamps are also
        equal it falls back to a simple comparison of ids meaning the
        precedence is essentially random.
        """
        if self.priority != other.priority:
            return self.priority < other.priority
        if self.timestamp != other.timestamp:
            return self.timestamp < other.timestamp
        return self.id < other.id


class ExclusiveRouterProcessor(object):
    """Manager for access to a router for processing

    This class controls access to a router in a non-blocking way.  The first
    instance to be created for a given router_id is granted exclusive access to
    the router.

    Other instances may be created for the same router_id while the first
    instance has exclusive access.  If that happens then it doesn't block and
    wait for access.  Instead, it signals to the master instance that an update
    came in with the timestamp.

    This way, a thread will not block to wait for access to a router.  Instead
    it effectively signals to the thread that is working on the router that
    something has changed since it started working on it.  That thread will
    simply finish its current iteration and then repeat.

    This class keeps track of the last time that a router data was fetched and
    processed.  The timestamp that it keeps must be before when the data used
    to process the router last was fetched from the database.  But, as close as
    possible.  The timestamp should not be recorded, however, until the router
    has been processed using the fetch data.
    """
    _masters = {}
    _router_timestamps = {}

    def __init__(self, router_id):
        self._router_id = router_id

        if router_id not in self._masters:
            self._masters[router_id] = self
            self._queue = []

        self._master = self._masters[router_id]

    def _i_am_master(self):
        return self == self._master

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self._i_am_master():
            del self._masters[self._router_id]

    def _get_router_data_timestamp(self):
        return self._router_timestamps.get(self._router_id,
                                           datetime.datetime.min)

    def fetched_and_processed(self, timestamp):
        """Records the data timestamp after it is used to update the router"""
        new_timestamp = max(timestamp, self._get_router_data_timestamp())
        self._router_timestamps[self._router_id] = new_timestamp

    def queue_update(self, update):
        """Queues an update from a worker

        This is the queue used to keep new updates that come in while a router
        is being processed.  These updates have already bubbled to the front of
        the RouterProcessingQueue.
        """
        self._master._queue.append(update)

    def updates(self):
        """Processes the router until updates stop coming

        Only the master instance will process the router.  However, updates may
        come in from other workers while it is in progress.  This method loops
        until they stop coming.
        """
        if self._i_am_master():
            while self._queue:
                # Remove the update from the queue even if it is old.
                update = self._queue.pop(0)
                # Process the update only if it is fresh.
                if self._get_router_data_timestamp() < update.timestamp:
                    yield update


class RouterProcessingQueue(object):
    """Manager of the queue of routers to process."""
    def __init__(self):
        self._queue = Queue.PriorityQueue()

    def add(self, update):
        self._queue.put(update)

    def each_update_to_next_router(self):
        """Grabs the next router from the queue and processes

        This method uses a for loop to process the router repeatedly until
        updates stop bubbling to the front of the queue.
        """
        next_update = self._queue.get()

        with ExclusiveRouterProcessor(next_update.id) as rp:
            # Queue the update whether this worker is the master or not.
            rp.queue_update(next_update)

            # Here, if the current worker is not the master, the call to
            # rp.updates() will not yield and so this will essentially be a
            # noop.
            for update in rp.updates():
                yield (rp, update)
