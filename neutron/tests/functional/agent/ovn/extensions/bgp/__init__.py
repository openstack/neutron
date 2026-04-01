# Copyright 2025 Red Hat, LLC
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

from ovsdbapp.backend.ovs_idl import event


class WaitForPortBindingCreatedEvent(event.WaitEvent):
    event_name = 'WaitForPortBindingCreatedEvent'

    def __init__(self, port_name):
        table = 'Port_Binding'
        events = (self.ROW_CREATE,)
        conditions = (('logical_port', '=', port_name),)
        super().__init__(events, table, conditions, timeout=10)


class WaitForPortBindingUpdatedEvent(event.WaitEvent):
    event_name = 'WaitForPortBindingUpdatedEvent'

    def __init__(self, port_name, chassis_id):
        table = 'Port_Binding'
        events = (self.ROW_UPDATE,)
        conditions = (('logical_port', '=', port_name),)
        self.chassis_id = chassis_id
        super().__init__(events, table, conditions, timeout=10)

    def match_fn(self, event, row, old=None):
        if not hasattr(old, 'chassis'):
            return False

        try:
            if row.chassis[0].uuid != self.chassis_id:
                return False
        except IndexError:
            return False

        return True
