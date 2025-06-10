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
from unittest import mock

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.plugins.ml2 import ovs_constants

from neutron.common import utils
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

    def test_no_stale_flows_after_port_delete(self):
        def find_drop_flow(ofport, flows):
            for flow in flows:
                # flow.instruction == [] means actions=drop
                if (not flow.instructions and
                        ('in_port', ofport) in flow.match.items()):
                    return True
            return False

        def num_ports_with_drop_flows(ofports, flows):
            count = 0
            for ofport in ofports:
                if find_drop_flow(ofport, flows):
                    count = count + 1
            return count
        # setup
        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports())
        self.wait_until_ports_state(self.ports, up=True)

        # call port_delete first
        for port in self.ports:
            self.agent.port_delete([], port_id=port['id'])
        portnames = [port["vif_name"] for port in self.ports]
        ofports = [port.ofport for port in self.agent.int_br.get_vif_ports()
                   if port.port_name in portnames]

        # wait until ports are marked dead, with drop flow
        utils.wait_until_true(
            lambda: num_ports_with_drop_flows(
                ofports,
                self.agent.int_br.dump_flows(
                    ovs_constants.LOCAL_SWITCHING
                )) == len(ofports))

        # delete the ports on bridge
        for port in self.ports:
            self.agent.int_br.delete_port(port['vif_name'])
        self.wait_until_ports_state(self.ports, up=False)

        # verify no stale drop flows
        self.assertEqual(0,
            num_ports_with_drop_flows(
                ofports,
                self.agent.int_br.dump_flows(
                    ovs_constants.LOCAL_SWITCHING
                )
            ))

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
        self.stop_agent(agent, self.agent_thread)

    def test_datapath_type_change(self):
        self._check_datapath_type_netdev('system')
        self._check_datapath_type_netdev('netdev')

    def test_datapath_type_netdev(self):
        self._check_datapath_type_netdev(
            ovs_constants.OVS_DATAPATH_NETDEV)

    def test_datapath_type_system(self):
        self._check_datapath_type_netdev(
            ovs_constants.OVS_DATAPATH_SYSTEM)

    def test_datapath_type_default(self):
        self._check_datapath_type_netdev(
            ovs_constants.OVS_DATAPATH_SYSTEM, default=True)

    def test_resync_devices_set_up_after_exception(self):
        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports(),
            trigger_resync=True)
        self.wait_until_ports_state(self.ports, up=True)

    def test_reprocess_port_when_ovs_restarts(self):
        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports())
        self.wait_until_ports_state(self.ports, up=True)
        self.agent.check_ovs_status.return_value = ovs_constants.OVS_RESTARTED
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

    def _test_assert_bridges_ports_vxlan(self, local_ip=None):
        agent = self.create_agent(local_ip=local_ip)
        self.assertTrue(self.ovs.bridge_exists(self.br_int))
        self.assertTrue(self.ovs.bridge_exists(self.br_tun))
        self.assert_bridge_ports()
        self.assert_patch_ports(agent)

    def test_assert_bridges_ports_vxlan_ipv4(self):
        self._test_assert_bridges_ports_vxlan()

    def test_assert_bridges_ports_vxlan_ipv6(self):
        self._test_assert_bridges_ports_vxlan(local_ip='2001:db8:100::1')

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

    def test_assert_br_int_patch_port_ofports_dont_change(self):
        # When the integration bridge is setup, it should reuse the existing
        # patch ports between br-int and br-tun.
        self.setup_agent_and_ports(port_dicts=[], create_tunnels=True)
        patch_int_ofport_before = self.agent.patch_int_ofport
        patch_tun_ofport_before = self.agent.patch_tun_ofport

        self.stop_agent(self.agent, self.agent_thread)
        self.setup_agent_and_ports(port_dicts=[], create_tunnels=True)
        self.assertEqual(patch_int_ofport_before, self.agent.patch_int_ofport)
        self.assertEqual(patch_tun_ofport_before, self.agent.patch_tun_ofport)

    def test_assert_br_phys_patch_port_ofports_dont_change(self):
        # When the integration bridge is setup, it should reuse the existing
        # patch ports between br-int and br-phys.
        self.setup_agent_and_ports(port_dicts=[])
        patch_int_ofport_before = self.agent.int_ofports['physnet']
        patch_phys_ofport_before = self.agent.phys_ofports['physnet']

        self.stop_agent(self.agent, self.agent_thread)
        self.setup_agent_and_ports(port_dicts=[])
        self.assertEqual(patch_int_ofport_before,
                         self.agent.int_ofports['physnet'])
        self.assertEqual(patch_phys_ofport_before,
                         self.agent.phys_ofports['physnet'])

    def test_assert_pings_during_br_phys_setup_not_lost_in_vlan_to_flat(self):
        provider_net = self._create_test_network_dict()
        provider_net['network_type'] = 'flat'

        self._test_assert_pings_during_br_phys_setup_not_lost(provider_net)

    def test_assert_pings_during_br_phys_setup_not_lost_in_vlan_to_vlan(self):
        provider_net = self._create_test_network_dict()
        provider_net['network_type'] = 'vlan'
        provider_net['segmentation_id'] = 876

        self._test_assert_pings_during_br_phys_setup_not_lost(provider_net)

    def _test_assert_pings_during_br_phys_setup_not_lost(self, provider_net):
        # Separate namespace is needed when pinging from one port to another,
        # otherwise Linux ping uses loopback instead for sending and receiving
        # ping, hence ignoring flow setup.
        ns_phys = self.useFixture(net_helpers.NamespaceFixture()).name

        ports = self.create_test_ports(amount=2)
        port_int = ports[0]
        port_phys = ports[1]
        ip_int = port_int['fixed_ips'][0]['ip_address']
        ip_phys = port_phys['fixed_ips'][0]['ip_address']

        self.setup_agent_and_ports(port_dicts=[port_int], create_tunnels=False,
                                   network=provider_net)

        self.plug_ports_to_phys_br(provider_net, [port_phys],
                                   namespace=ns_phys)

        # The OVS agent doesn't monitor the physical bridges, no notification
        # is sent when a port is up on a physical bridge, hence waiting only
        # for the ports connected to br-int
        self.wait_until_ports_state([port_int], up=True)
        # sanity pings before we start
        net_helpers.assert_ping(ns_phys, ip_int)
        net_helpers.assert_ping(self.namespace, ip_phys)

        with net_helpers.async_ping(ns_phys, [ip_int, ip_phys]) as done:
            self.agent.setup_physical_bridges(self.agent.bridge_mappings)
            while not done():
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
            utils.WaitTimeout, self.wait_until_ports_state, [self.ports[1]],
            up=True, timeout=10)

    def test_ovs_restarted_event(self):
        callback = mock.Mock()

        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports())

        registry.subscribe(callback,
                           resources.AGENT,
                           events.OVS_RESTARTED)

        self.agent.check_ovs_status.return_value = ovs_constants.OVS_RESTARTED

        utils.wait_until_true(lambda: callback.call_count, timeout=10)

        callback.assert_called_with(resources.AGENT,
                                    events.OVS_RESTARTED,
                                    mock.ANY, payload=None)


class TestOVSAgentExtensionConfig(base.OVSAgentTestFramework):
    def setUp(self):
        super(TestOVSAgentExtensionConfig, self).setUp()
        self.config.set_override('extensions', ['qos'], 'agent')
        self.agent = self.create_agent(create_tunnels=False)

    def test_report_loaded_extension(self):
        self.agent._report_state()
        agent_state = self.agent.state_rpc.report_state.call_args[0][1]
        self.assertEqual(['qos'], agent_state['configurations']['extensions'])
