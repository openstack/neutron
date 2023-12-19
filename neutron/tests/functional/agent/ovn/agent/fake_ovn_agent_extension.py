# Copyright (c) 2023 Red Hat, Inc.
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

from ovsdbapp.backend.ovs_idl import event as row_event

from neutron.agent.ovn.extensions import extension_manager as ext_mgr


class OVSInterfaceEvent(row_event.RowEvent):

    def __init__(self, ovn_agent):
        self.ovn_agent = ovn_agent
        events = (self.ROW_CREATE, self.ROW_UPDATE)
        table = 'Interface'
        super().__init__(events, table, None)

    def run(self, event, row, old):
        self.ovn_agent.test_ovs_idl.append(row.name)


class OVNSBChassisEvent(row_event.RowEvent):
    def __init__(self, ovn_agent):
        self.ovn_agent = ovn_agent
        events = (self.ROW_CREATE, self.ROW_UPDATE)
        table = 'Chassis'
        super().__init__(events, table, None)

    def run(self, event, row, old):
        self.ovn_agent.test_ovn_sb_idl.append(row.name)


class OVNNBLogicalSwitchEvent(row_event.RowEvent):
    def __init__(self, ovn_agent):
        self.ovn_agent = ovn_agent
        events = (self.ROW_CREATE, self.ROW_UPDATE)
        table = 'Logical_Switch'
        super().__init__(events, table, None)

    def run(self, event, row, old):
        self.ovn_agent.test_ovn_nb_idl.append(row.name)


class FakeOVNAgentExtension(ext_mgr.OVNAgentExtension):

    @property
    def name(self):
        return 'Fake OVN agent extension'

    @property
    def ovs_idl_events(self):
        return [OVSInterfaceEvent]

    @property
    def nb_idl_tables(self):
        return ['Logical_Switch']

    @property
    def nb_idl_events(self):
        return [OVNNBLogicalSwitchEvent]

    @property
    def sb_idl_tables(self):
        return ['Chassis', 'Chassis_Private']

    @property
    def sb_idl_events(self):
        return [OVNSBChassisEvent]

    def start(self):
        self._is_started = True
