#! /usr/bin/env python

# Copyright (c) 2019 Red Hat, Inc.
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

import signal
import sys

import eventlet
from eventlet import queue
from oslo_serialization import jsonutils

from neutron.agent.linux import ip_lib


EVENT_STOP = eventlet.Event()
EVENT_STARTED = eventlet.Event()
POOL = eventlet.GreenPool(2)


def sigterm_handler(_signo, _stack_frame):
    global EVENT_STOP
    global POOL
    EVENT_STOP.send()
    POOL.waitall()
    exit(0)


signal.signal(signal.SIGTERM, sigterm_handler)


def read_queue(temp_file, _queue, event_stop, event_started):
    event_started.wait()
    with open(temp_file, 'w') as f:
        f.write('')
    while not event_stop.ready():
        eventlet.sleep(0)
        try:
            retval = _queue.get(timeout=2)
        except eventlet.queue.Empty:
            retval = None
        if retval:
            with open(temp_file, 'a+') as f:
                f.write(jsonutils.dumps(retval) + '\n')


def main(temp_file, namespace):
    global POOL
    namespace = None if namespace == 'None' else namespace
    _queue = queue.Queue()
    POOL.spawn(ip_lib.ip_monitor, namespace, _queue, EVENT_STOP, EVENT_STARTED)
    POOL.spawn(read_queue, temp_file, _queue, EVENT_STOP, EVENT_STARTED)
    POOL.waitall()


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
