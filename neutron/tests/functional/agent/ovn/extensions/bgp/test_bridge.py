# Copyright 2025 Red Hat, Inc.
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

import netaddr

from neutron.agent.ovn.extensions.bgp import bridge
from neutron.agent.ovsdb import impl_idl
from neutron.common import utils
from neutron.services.bgp import constants
from neutron.services.bgp import ovn as bgp_ovn
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.ovn.extensions import bgp as test_bgp
from neutron.tests.functional.services import bgp as base


class FakeAgentApi:
    def __init__(self, sb_idl):
        self.sb_idl = sb_idl
        self.ovs_idl = impl_idl.api_factory()


class FakeBgpAgentApi:
    def __init__(self, sb_idl):
        self.agent_api = FakeAgentApi(sb_idl)


class BgpTestCaseWithIdls(base.BaseBgpIDLTestCase):
    schemas = ['OVN_Northbound', 'OVN_Southbound']

    def setUp(self):
        bgp_ovn.OvnSbIdl.tables = (
            'Port_Binding', 'Chassis', 'Chassis_Private', 'Encap')
        try:
            super().setUp()
        finally:
            bgp_ovn.OvnSbIdl.tables = bgp_ovn.OVN_SB_TABLES


class BGPChassisBridgeTestCase(BgpTestCaseWithIdls):
    def setUp(self):
        super().setUp()
        self.ovs_api = impl_idl.api_factory()
        self.test_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture()).bridge

        patch_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture()).bridge

        self.fake_nic = self.useFixture(net_helpers.VethFixture()).ports[0]

        with self.ovs_api.transaction(check_error=True) as txn:
            txn.add(self.ovs_api.add_port(
                self.test_bridge.br_name,
                'bgp-patch-port', type='patch',
                options={'peer': 'peer-patch-port'}))
            txn.add(self.ovs_api.add_port(
                patch_bridge.br_name,
                'peer-patch-port', type='patch',
                options={'peer': 'bgp-patch-port'}))
            txn.add(self.ovs_api.add_port(
                self.test_bridge.br_name, self.fake_nic.name))

        self.bgp_bridge = bridge.BGPChassisBridge(
            FakeBgpAgentApi(self.sb_api),
            self.test_bridge.br_name)

        # Wait for OVS to assign the patch port an ofport
        utils.wait_until_true(
            lambda: (self.bgp_bridge.patch_port_ofport
                     is not None),
            sleep=0.1,
            timeout=5,
            exception=Exception("Patch port ofport not found"))

    @staticmethod
    def _dump_flows(bridge):
        flows_str = bridge.ovs_bridge.dump_flows_for()
        return flows_str.splitlines() if flows_str else []

    def test_patch_port_ofport(self):
        ofport = self.bgp_bridge.patch_port_ofport
        self.assertIn(ofport, [1, 2])

    def test_configure_flows_complete_has_all_expected_flows(self):
        self.bgp_bridge.bgp_agent_api.host_ips = [
            netaddr.IPNetwork('172.16.1.1/30'),
            netaddr.IPNetwork('2001:db8::1/64'),
            netaddr.IPNetwork('192.168.1.10/32'),
            netaddr.IPNetwork('10.0.0.1/32'),
            netaddr.IPNetwork('2001:db8:eee::1/128'),
        ]

        chassis_name = 'chassis-test'
        chassis = self.sb_api.chassis_add(
            chassis_name,
            ['geneve'],
            '172.24.4.10',
            hostname=chassis_name,
        ).execute(check_error=True)
        self.sb_api.db_create(
            'Chassis_Private', name=chassis_name,
            chassis=chassis.uuid,
        ).execute(check_error=True)

        port_name = 'lrp-test'

        pb_wait_event = test_bgp.WaitForPortBindingEvent(port_name)
        self.sb_api.idl.notify_handler.watch_event(pb_wait_event)

        lrp_ext_ids = {
            constants.LRP_NETWORK_NAME_EXT_ID_KEY: self.test_bridge.br_name}
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lr_add(router='lr-test',
                                       options={'chassis': chassis.name}))
            txn.add(self.nb_api.lrp_add(router='lr-test',
                                        port=port_name,
                                        mac='aa:bb:cc:dd:ee:ff',
                                        networks=['192.168.1.10/32'],
                                        external_ids=lrp_ext_ids))

        self.assertTrue(pb_wait_event.wait())

        self.bgp_bridge.configure_flows()

        flows = self._dump_flows(self.bgp_bridge)
        flow_strings = ' '.join(flows)

        # 1. ARP and ICMPv6 flows
        self.assertIn('arp actions=NORMAL', flow_strings)
        self.assertIn('icmp6,icmp_type=133 actions=NORMAL',
                        flow_strings)
        self.assertIn('icmp6,icmp_type=134 actions=NORMAL',
                        flow_strings)
        self.assertIn('icmp6,icmp_type=135 actions=NORMAL',
                        flow_strings)
        self.assertIn('icmp6,icmp_type=136 actions=NORMAL',
                        flow_strings)

        # 2. Host IP flows (IPv4)
        self.assertIn('nw_dst=192.168.1.10 actions=NORMAL', flow_strings)
        self.assertIn('nw_dst=10.0.0.1 actions=NORMAL', flow_strings)

        # 3. Host IP flows (IPv6)
        self.assertIn('ipv6_dst=2001:db8:eee::1 actions=NORMAL', flow_strings)
        self.assertIn('ipv6_dst=2001:db8::1 actions=NORMAL', flow_strings)

        # 4. IPv6 link-local traffic
        self.assertIn('ipv6_dst=fe80::/64 actions=NORMAL', flow_strings)

        # 5. Default flow
        self.assertIn('priority=0 actions=NORMAL', flow_strings)

        # 6. LRP MAC rewrite flow
        self.assertIn(
            f"in_port={self.bgp_bridge.nic_ofport} actions="
            f"mod_dl_dst:aa:bb:cc:dd:ee:ff,"
            f"output:{self.bgp_bridge.patch_port_ofport}",
            flow_strings)
