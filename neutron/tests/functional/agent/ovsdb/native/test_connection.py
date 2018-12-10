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

from neutron.agent.common import ovs_lib
from neutron.common import utils as common_utils
from neutron.tests.functional import base


class BridgeMonitorTestCase(base.BaseLoggingTestCase):

    def _delete_bridges(self, bridges):
        for bridge in bridges:
            self.ovs.delete_bridge(bridge)

    def test_create_bridges(self):
        bridges_added = []
        bridges_to_monitor = ['br01', 'br02', 'br03']
        bridges_to_create = ['br01', 'br02', 'br03', 'br04', 'br05']
        self.ovs = ovs_lib.BaseOVS()
        self.ovs.ovsdb.idl_monitor.start_bridge_monitor(bridges_to_monitor)
        self.addCleanup(self._delete_bridges, bridges_to_create)

        for bridge in bridges_to_create:
            self.ovs.add_bridge(bridge)

        def retrieve_bridges(bridges_added):
            bridges_added += self.ovs.ovsdb.idl_monitor.bridges_added
            return len(bridges_added)

        common_utils.wait_until_true(
            lambda: retrieve_bridges(bridges_added) == len(bridges_to_monitor),
            timeout=5)
        bridges_added.sort()
        self.assertEqual(bridges_to_monitor, bridges_added)
        self.assertEqual([], self.ovs.ovsdb.idl_monitor.bridges_added)
