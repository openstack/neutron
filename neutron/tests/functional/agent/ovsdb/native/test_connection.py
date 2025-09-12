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

from oslo_utils import uuidutils

from neutron.agent.common import ovs_lib
from neutron.common import utils as common_utils
from neutron.tests.functional import base


class BridgeMonitorTestCase(base.BaseSudoTestCase):

    def _delete_bridges(self, bridges):
        for bridge in bridges:
            self.ovs.delete_bridge(bridge)

    def test_create_bridges(self):
        bridges_to_create = [
            'br_' + uuidutils.generate_uuid()[:12],
            'br_' + uuidutils.generate_uuid()[:12],
            'br_' + uuidutils.generate_uuid()[:12],
            'br_' + uuidutils.generate_uuid()[:12],
            'br_' + uuidutils.generate_uuid()[:12],
        ]
        bridges_to_monitor = bridges_to_create[:3]
        self.ovs = ovs_lib.BaseOVS()
        self._delete_bridges(bridges_to_create)

        self.ovs.ovsdb.idl_monitor.start_bridge_monitor(bridges_to_monitor)
        self.addCleanup(self._delete_bridges, bridges_to_create)
        for bridge in bridges_to_create:
            self.ovs.add_bridge(bridge)

        _idl_mon = self.ovs.ovsdb.idl_monitor
        common_utils.wait_until_true(
            lambda: set(bridges_to_monitor) ==
                    set(_idl_mon._bridges_added_list),
            timeout=20)
        self.assertEqual(bridges_to_monitor, _idl_mon.bridges_added)
        self.assertEqual([], _idl_mon.bridges_added)
