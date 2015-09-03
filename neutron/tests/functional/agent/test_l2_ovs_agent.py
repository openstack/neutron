# Copyright (c) 2015 Red Hat, Inc.
# Copyright (c) 2015 SUSE Linux Products GmbH
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

import time

from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.l2 import base


class TestOVSAgent(base.OVSAgentTestFramework):

    def test_port_creation_and_deletion(self):
        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports())
        self.wait_until_ports_state(self.ports, up=True)

        for port in self.ports:
            self.agent.int_br.delete_port(port['vif_name'])

        self.wait_until_ports_state(self.ports, up=False)

    def _check_datapath_type_netdev(self, expected, default=False):
        if not default:
            self.config.set_override('datapath_type',
                                     expected,
                                     "OVS")
        agent = self.create_agent()
        self.start_agent(agent)
        actual = self.ovs.db_get_val('Bridge',
                                     agent.int_br.br_name,
                                     'datapath_type')
        self.assertEqual(expected, actual)
        actual = self.ovs.db_get_val('Bridge',
                                     agent.tun_br.br_name,
                                     'datapath_type')
        self.assertEqual(expected, actual)

    def test_datapath_type_netdev(self):
        self._check_datapath_type_netdev(
            constants.OVS_DATAPATH_NETDEV)

    def test_datapath_type_system(self):
        self._check_datapath_type_netdev(
            constants.OVS_DATAPATH_SYSTEM)

    def test_datapath_type_default(self):
        self._check_datapath_type_netdev(
            constants.OVS_DATAPATH_SYSTEM, default=True)

    def test_resync_devices_set_up_after_exception(self):
        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports(),
            trigger_resync=True)
        self.wait_until_ports_state(self.ports, up=True)

    def test_port_vlan_tags(self):
        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports(),
            trigger_resync=True)
        self.wait_until_ports_state(self.ports, up=True)
        self.assert_vlan_tags(self.ports, self.agent)

    def test_assert_bridges_ports_vxlan(self):
        agent = self.create_agent()
        self.assertTrue(self.ovs.bridge_exists(self.br_int))
        self.assertTrue(self.ovs.bridge_exists(self.br_tun))
        self.assert_bridge_ports()
        self.assert_patch_ports(agent)

    def test_assert_bridges_ports_no_tunnel(self):
        self.create_agent(create_tunnels=False)
        self.assertTrue(self.ovs.bridge_exists(self.br_int))
        self.assertFalse(self.ovs.bridge_exists(self.br_tun))

    def test_assert_pings_during_br_int_setup_not_lost(self):
        self.setup_agent_and_ports(port_dicts=self.create_test_ports(),
                                   create_tunnels=False)
        self.wait_until_ports_state(self.ports, up=True)
        ips = [port['fixed_ips'][0]['ip_address'] for port in self.ports]
        with net_helpers.async_ping(self.namespace, ips) as running:
            while running():
                self.agent.setup_integration_br()
                time.sleep(0.25)
