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
import queue
import time

from oslo_utils import timeutils
from oslo_utils import uuidutils


class ResourceUpdate(object):
    """Encapsulates a resource update

    An instance of this object carries the information necessary to prioritize
    and process a request to update a resource.

    Priority values are ordered from higher (0) to lower (>0) by the caller,
    and are therefore not defined here, but must be done by the consumer.
    """
    def __init__(self, id, priority,
                 action=None, resource=None, timestamp=None, tries=5):
        self.priority = priority
        self.timestamp = timestamp
        if not timestamp:
            self.timestamp = timeutils.utcnow()
        self.id = id
        self.action = action
        self.resource = resource
        self.tries = tries
        # NOTE: Because one resource can be processed multiple times, this
        # update_id will be used for tracking one resource processing
        # procedure.
        self.update_id = uuidutils.generate_uuid()
        self.create_time = self.start_time = time.time()

    def set_start_time(self):
        # Set the start_time to 'now' - can be used by callers to help
        # track time spent in procedures.
        self.start_time = time.time()

    @property
    def time_elapsed_since_create(self):
        return time.time() - self.create_time

    @property
    def time_elapsed_since_start(self):
        # Time elapsed between processing start and end.
        return time.time() - self.start_time

    def __lt__(self, other):
        """Implements priority among updates

        Lower numerical priority always gets precedence.  When comparing two
        updates of the same priority then the one with the earlier timestamp
        gets precedence.  In the unlikely event that the timestamps are also
        equal it falls back to a simple comparison of ids meaning the
        precedence is essentially random.
        """
        if self.priority != other.priority:
            return self.priority < other.priority
        if self.timestamp != other.timestamp:
            return self.timestamp < other.timestamp
        return self.id < other.id

    def hit_retry_limit(self):
        return self.tries < 0


class ExclusiveResourceProcessor(object):
    """Manager for access to a resource for processing

    This class controls access to a resource in a non-blocking way.  The first
    instance to be created for a given ID is granted exclusive access to
    the resource.

    Other instances may be created for the same ID while the first
    instance has exclusive access.  If that happens then it doesn't block and
    wait for access.  Instead, it signals to the primary instance that an
    update came in with the timestamp.

    This way, a thread will not block to wait for access to a resource.
    Instead it effectively signals to the thread that is working on the
    resource that something has changed since it started working on it.
    That thread will simply finish its current iteration and then repeat.

    This class keeps track of the last time that resource data was fetched and
    processed.  The timestamp that it keeps must be before when the data used
    to process the resource last was fetched from the database.  But, as close
    as possible.  The timestamp should not be recorded, however, until the
    resource has been processed using the fetch data.
    """
    _primaries = {}
    _resource_timestamps = {}

    def __init__(self, id):
        self._id = id

        if id not in self._primaries:
            self._primaries[id] = self
            self._queue = queue.PriorityQueue(-1)

        self._primary = self._primaries[id]

    def _i_am_primary(self):
        return self == self._primary

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self._i_am_primary():
            del self._primaries[self._id]

    def _get_resource_data_timestamp(self):
        return self._resource_timestamps.get(self._id,
                                             datetime.datetime.min)

    def fetched_and_processed(self, timestamp):
        """Records the timestamp after it is used to update the resource"""
        new_timestamp = max(timestamp, self._get_resource_data_timestamp())
        self._resource_timestamps[self._id] = new_timestamp

    def queue_update(self, update):
        """Queues an update from a worker

        This is the queue used to keep new updates that come in while a
        resource is being processed.  These updates have already bubbled to
        the front of the ResourceProcessingQueue.
        """
        self._primary._queue.put(update)

    def updates(self):
        """Processes the resource until updates stop coming

        Only the primary instance will process the resource.  However, updates
        may come in from other workers while it is in progress.  This method
        loops until they stop coming.
        """
        while self._i_am_primary():
            if self._queue.empty():
                return
            # Get the update from the queue even if it is old.
            update = self._queue.get()
            # Process the update only if it is fresh.
            if self._get_resource_data_timestamp() < update.timestamp:
                yield update


class ResourceProcessingQueue(object):
    """Manager of the queue of resources to process."""
    def __init__(self):
        self._queue = queue.PriorityQueue()

    def add(self, update):
        update.tries -= 1
        self._queue.put(update)

    def each_update_to_next_resource(self):
        """Grabs the next resource from the queue and processes

        This method uses a for loop to process the resource repeatedly until
        updates stop bubbling to the front of the queue.
        """
        next_update = self._queue.get()

        with ExclusiveResourceProcessor(next_update.id) as rp:
            # Queue the update whether this worker is the primary or not.
            rp.queue_update(next_update)

            # Here, if the current worker is not the primary, the call to
            # rp.updates() will not yield and so this will essentially be a
            # noop.
            for update in rp.updates():
                update.set_start_time()
                yield (rp, update)
