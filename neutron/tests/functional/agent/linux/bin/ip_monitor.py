#!/usr/bin/env python3

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

import queue
import signal
import sys
import threading

from oslo_serialization import jsonutils

from neutron.agent.linux import ip_lib


EVENT_STOP = threading.Event()
EVENT_STARTED = threading.Event()
IP_MONITOR = None
READ_QUEUE = None


def sigterm_handler(_signo, _stack_frame):
    EVENT_STOP.set()
    # These might not be initialized if SIGTERM before assignment below
    if IP_MONITOR:
        IP_MONITOR.join()
    if READ_QUEUE:
        READ_QUEUE.join()
    sys.exit(0)


signal.signal(signal.SIGTERM, sigterm_handler)


def read_queue(temp_file, _queue, event_stop, event_started):
    event_started.wait()
    with open(temp_file, 'w') as f:
        f.write('')
    while not event_stop.is_set():
        try:
            retval = _queue.get(timeout=1)
        except queue.Empty:
            retval = None
        if retval:
            with open(temp_file, 'a+') as f:
                f.write(jsonutils.dumps(retval) + '\n')


def main(temp_file, namespace):
    global IP_MONITOR
    global READ_QUEUE
    namespace = None if namespace == 'None' else namespace
    _queue = queue.Queue()
    IP_MONITOR = threading.Thread(
        target=ip_lib.ip_monitor,
        args=(namespace, _queue, EVENT_STOP, EVENT_STARTED))
    IP_MONITOR.start()
    READ_QUEUE = threading.Thread(
        target=read_queue,
        args=(temp_file, _queue, EVENT_STOP, EVENT_STARTED))
    READ_QUEUE.start()
    READ_QUEUE.join()


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
