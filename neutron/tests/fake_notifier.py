# Copyright 2014 Red Hat, Inc.
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

import collections
import functools


NOTIFICATIONS = []


def reset():
    del NOTIFICATIONS[:]


FakeMessage = collections.namedtuple('Message',
                                     ['publisher_id', 'priority',
                                      'event_type', 'payload'])


class FakeNotifier(object):

    def __init__(self, transport, publisher_id=None,
                 driver=None, topics=None,
                 serializer=None, retry=None):
        self.transport = transport
        self.publisher_id = publisher_id
        for priority in ('debug', 'info', 'warn', 'error', 'critical'):
            setattr(self, priority,
                    functools.partial(self._notify, priority=priority.upper()))

    def prepare(self, publisher_id=None):
        if publisher_id is None:
            publisher_id = self.publisher_id
        return self.__class__(self.transport, publisher_id)

    def _notify(self, ctxt, event_type, payload, priority):
        msg = dict(publisher_id=self.publisher_id,
                   priority=priority,
                   event_type=event_type,
                   payload=payload)
        NOTIFICATIONS.append(msg)
