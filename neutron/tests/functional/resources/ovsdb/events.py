# Copyright 2019 Red Hat, Inc.
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
import threading

from ovsdbapp.backend.ovs_idl import event
from ovsdbapp.tests.functional.schema.ovn_southbound import event as test_event

from neutron.common.ovn import constants as ovn_const


class WaitForCrLrpPortBindingEvent(event.RowEvent):
    event_name = 'WaitForCrLrpPortBindingEvent'
    PREFIX = 'cr-lrp-'
    TABLE = 'Port_Binding'

    def __init__(self, timeout=5):
        self.logical_port_events = collections.defaultdict(threading.Event)
        self.timeout = timeout
        super(WaitForCrLrpPortBindingEvent, self).__init__(
            (self.ROW_CREATE, self.ROW_UPDATE), 'Port_Binding', None)

    def match_fn(self, event, row, old=None):
        return row.logical_port.startswith(self.PREFIX)

    def run(self, event, row, old):
        self.logical_port_events[row.logical_port].set()

    def wait(self, logical_port_name):
        wait_val = self.logical_port_events[logical_port_name].wait(
            self.timeout)
        del self.logical_port_events[logical_port_name]
        return wait_val


class WaitForCreatePortBindingEvent(test_event.WaitForPortBindingEvent):
    event_name = 'WaitForCreatePortBindingEvent'

    def run(self, event, row, old):
        self.row = row
        super(WaitForCreatePortBindingEvent, self).run(event, row, old)


class WaitForUpdatePortBindingEvent(test_event.WaitForPortBindingEvent):
    event_name = 'WaitForUpdatePortBindingEvent'

    def __init__(self, port, mac, timeout=5):
        # Call the super of the superclass to avoid passing CREATE event type
        # to the superclass.
        super(test_event.WaitForPortBindingEvent, self).__init__(
            (self.ROW_UPDATE,),
            'Port_Binding',
            (('logical_port', '=', port),
             ('mac', '=', mac)),
            timeout=timeout)


class WaitForCreatePortBindingEventPerType(event.WaitEvent):
    event_name = 'WaitForCreatePortBindingEventPerType'

    def __init__(self, port_type=ovn_const.OVN_CHASSIS_REDIRECT,
                 timeout=5):
        super().__init__((self.ROW_CREATE,), 'Port_Binding',
                         (('type', '=', port_type),), timeout=timeout)
