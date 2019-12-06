# Copyright 2019 Red Hat, Inc.
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

import re

import eventlet

from neutron.agent.common import async_process


class OFEvent(object):

    def __init__(self, event_type, flow):
        self.event_type = event_type
        self.flow = flow


class OFMonitor(async_process.AsyncProcess):
    """Wrapper over 'ovs-ofctl monitor'.

    This is an interactive OpenFlow monitor. By default, when the object is
    instantiated, the monitor process is started. To retrieve the pending
    events, the property "of_events" can be retrieved.

    NOTE(ralonsoh): 'ovs-ofctl monitor' command is sending existing flows to
    stdout pipe (startup first messages) and next incoming messages to stderr
    pipe. That's why this     class joins both outputs in one single queue
    (self._queue).
    """

    EVENT_RE = re.compile(
        r"event=(?P<action>ADDED|DELETED|MODIFIED) (?P<flow>.*)")

    def __init__(self, bridge_name, namespace=None, respawn_interval=None,
                 start=True):
        cmd = ['ovs-ofctl', 'monitor', bridge_name, 'watch:', '--monitor']
        super(OFMonitor, self).__init__(cmd, run_as_root=True,
                                        respawn_interval=respawn_interval,
                                        namespace=namespace)
        if start:
            self.start()

        self._queue = eventlet.queue.Queue()
        eventlet.spawn(self._read_and_enqueue, self.iter_stdout)
        eventlet.spawn(self._read_and_enqueue, self.iter_stderr)

    def _read_and_enqueue(self, iter):
        for event_line in iter(block=True):
            event = self._parse_event_line(event_line)
            if event:
                self._queue.put(event)

    @property
    def of_events(self):
        events = []
        while not self._queue.empty():
            events.append(self._queue.get())
        return events

    def _parse_event_line(self, event_line):
        match = self.EVENT_RE.match(event_line)
        if match is None:
            return
        return OFEvent(match.group('action'), match.group('flow'))

    def start(self, **kwargs):
        if not self._is_running:
            super(OFMonitor, self).start(block=True)

    def stop(self, **kwargs):
        if self._is_running:
            super(OFMonitor, self).stop(block=True)
