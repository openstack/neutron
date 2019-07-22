# Copyright (c) 2018 Red Hat, Inc.
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

import threading

from ovsdbapp import event

from neutron.agent.common import ovs_lib
from neutron.tests.functional import base


class WaitForBridgesEvent(event.RowEvent):
    event_name = 'WaitForBridgesEvent'
    ONETIME = True

    def __init__(self, bridges, timeout=5):
        self.bridges_not_seen = set(bridges)
        self.timeout = timeout
        self.event = threading.Event()
        super(WaitForBridgesEvent, self).__init__(
            (self.ROW_CREATE,), 'Bridge', None)

    def matches(self, event, row, old=None):
        if event not in self.events or row._table.name != self.table:
            return False
        self.bridges_not_seen.discard(row.name)
        return not self.bridges_not_seen

    def run(self, event, row, old):
        self.event.set()

    def wait(self):
        return self.event.wait(self.timeout)


class BridgeMonitorTestCase(base.BaseSudoTestCase):

    def _delete_bridges(self, bridges):
        for bridge in bridges:
            self.ovs.delete_bridge(bridge)

    def test_create_bridges(self):
        bridges_to_monitor = ['br01', 'br02', 'br03']
        bridges_to_create = ['br01', 'br02', 'br03', 'br04', 'br05']
        self.ovs = ovs_lib.BaseOVS()
        self.ovs.ovsdb.idl_monitor.start_bridge_monitor(bridges_to_monitor)
        self.addCleanup(self._delete_bridges, bridges_to_create)
        event = WaitForBridgesEvent(bridges_to_monitor)
        self.ovs.ovsdb.idl_monitor.notify_handler.watch_event(event)
        for bridge in bridges_to_create:
            self.ovs.add_bridge(bridge)
        self.assertTrue(event.wait())
        self.assertEqual(bridges_to_monitor,
                         self.ovs.ovsdb.idl_monitor.bridges_added)
        self.assertEqual([], self.ovs.ovsdb.idl_monitor.bridges_added)
