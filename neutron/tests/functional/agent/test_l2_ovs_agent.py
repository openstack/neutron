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

from eventlet.timeout import Timeout

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
        for br_name in (getattr(self, br) for br in
                        ('br_int', 'br_tun', 'br_phys')):
            actual = self.ovs.db_get_val('Bridge', br_name, 'datapath_type')
            self.assertEqual(expected, actual)

    def test_datapath_type_change(self):
        self._check_datapath_type_netdev('system')
        self._check_datapath_type_netdev('netdev')

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

    def test_reprocess_port_when_ovs_restarts(self):
        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports())
        self.wait_until_ports_state(self.ports, up=True)
        self.agent.check_ovs_status.return_value = constants.OVS_RESTARTED
        # OVS restarted, the agent should reprocess all the ports
        self.agent.plugin_rpc.update_device_list.reset_mock()
        self.wait_until_ports_state(self.ports, up=True)

    def test_resync_dev_up_after_failure(self):
        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports(),
            failed_dev_up=True)
        # in the RPC mock the first port fails and should
        # be re-synced
        expected_ports = self.ports + [self.ports[0]]
        self.wait_until_ports_state(expected_ports, up=True)

    def test_resync_dev_down_after_failure(self):
        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports(),
            failed_dev_down=True)
        self.wait_until_ports_state(self.ports, up=True)
        for port in self.ports:
            self.agent.int_br.delete_port(port['vif_name'])

        # in the RPC mock the first port fails and should
        # be re-synced
        expected_ports = self.ports + [self.ports[0]]
        self.wait_until_ports_state(expected_ports, up=False)

    def test_ancillary_port_creation_and_deletion(self):
        external_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture()).bridge
        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports(),
            ancillary_bridge=external_bridge)
        self.wait_until_ports_state(self.ports, up=True)

        for port in self.ports:
            external_bridge.delete_port(port['vif_name'])

        self.wait_until_ports_state(self.ports, up=False)

    def test_resync_ancillary_devices(self):
        external_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture()).bridge
        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports(),
            ancillary_bridge=external_bridge,
            trigger_resync=True)
        self.wait_until_ports_state(self.ports, up=True)

    def test_resync_ancillary_dev_up_after_failure(self):
        external_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture()).bridge
        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports(),
            ancillary_bridge=external_bridge,
            failed_dev_up=True)
        # in the RPC mock the first port fails and should
        # be re-synced
        expected_ports = self.ports + [self.ports[0]]
        self.wait_until_ports_state(expected_ports, up=True)

    def test_resync_ancillary_dev_down_after_failure(self):
        external_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture()).bridge
        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports(),
            ancillary_bridge=external_bridge,
            failed_dev_down=True)
        self.wait_until_ports_state(self.ports, up=True)

        for port in self.ports:
            external_bridge.delete_port(port['vif_name'])

        # in the RPC mock the first port fails and should
        # be re-synced
        expected_ports = self.ports + [self.ports[0]]
        self.wait_until_ports_state(expected_ports, up=False)

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
        with net_helpers.async_ping(self.namespace, ips) as done:
            while not done():
                self.agent.setup_integration_br()
                time.sleep(0.25)

    def test_noresync_after_port_gone(self):
        '''This will test the scenario where a port is removed after listing
        it but before getting vif info about it.
        '''
        self.ports = self.create_test_ports(amount=2)
        self.agent = self.create_agent(create_tunnels=False)
        self.network = self._create_test_network_dict()
        self._plug_ports(self.network, self.ports, self.agent)
        self.start_agent(self.agent, ports=self.ports,
                         unplug_ports=[self.ports[1]])
        self.wait_until_ports_state([self.ports[0]], up=True)
        self.assertRaises(
            Timeout, self.wait_until_ports_state, [self.ports[1]], up=True,
            timeout=10)


class TestOVSAgentExtensionConfig(base.OVSAgentTestFramework):
    def setUp(self):
        super(TestOVSAgentExtensionConfig, self).setUp()
        self.config.set_override('extensions', ['qos'], 'agent')
        self.agent = self.create_agent(create_tunnels=False)

    def test_report_loaded_extension(self):
        self.agent._report_state()
        agent_state = self.agent.state_rpc.report_state.call_args[0][1]
        self.assertEqual(['qos'], agent_state['configurations']['extensions'])
