# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack, LLC.
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

import mock
from oslo.config import cfg
import testtools

from quantum.plugins.linuxbridge.agent import linuxbridge_quantum_agent
from quantum.plugins.linuxbridge.common import constants as lconst


class TestLinuxBridge(testtools.TestCase):

    def setUp(self):
        super(TestLinuxBridge, self).setUp()
        self.addCleanup(cfg.CONF.reset)
        interface_mappings = {'physnet1': 'eth1'}
        root_helper = cfg.CONF.AGENT.root_helper

        self.linux_bridge = linuxbridge_quantum_agent.LinuxBridgeManager(
            interface_mappings, root_helper)

    def test_ensure_physical_in_bridge_invalid(self):
        result = self.linux_bridge.ensure_physical_in_bridge('network_id',
                                                             'physnetx',
                                                             7)
        self.assertFalse(result)

    def test_ensure_physical_in_bridge_flat(self):
        with mock.patch.object(self.linux_bridge,
                               'ensure_flat_bridge') as flat_bridge_func:
            result = self.linux_bridge.ensure_physical_in_bridge(
                'network_id', 'physnet1', lconst.FLAT_VLAN_ID)
        self.assertTrue(flat_bridge_func.called)

    def test_ensure_physical_in_bridge_vlan(self):
        with mock.patch.object(self.linux_bridge,
                               'ensure_vlan_bridge') as vlan_bridge_func:
            result = self.linux_bridge.ensure_physical_in_bridge(
                'network_id', 'physnet1', 7)
        self.assertTrue(vlan_bridge_func.called)
