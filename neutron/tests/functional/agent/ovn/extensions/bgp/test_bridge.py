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

from oslo_utils import uuidutils

from neutron.agent.ovn.extensions.bgp import bridge
from neutron.agent.ovn.extensions.bgp import commands
from neutron.agent.ovsdb import impl_idl
from neutron.common.ovn import constants as ovn_const
from neutron.common import utils
from neutron.conf.services import bgp as bgp_config
from neutron.services.bgp import constants
from neutron.services.bgp import helpers
from neutron.services.bgp import ovn as bgp_ovn
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.ovn.extensions import bgp as test_bgp
from neutron.tests.functional.services import bgp as base


class FakeAgentApi:
    def __init__(self, nb_idl, sb_idl):
        self.nb_idl = nb_idl
        self.sb_idl = sb_idl
        self.ovs_idl = impl_idl.api_factory()


class FakeBgpAgentApi:
    # TODO(jlibosva): Use the real agent extension here
    def __init__(self, nb_idl, sb_idl):
        self.agent_api = FakeAgentApi(nb_idl, sb_idl)

    def get_interconnect_lrp_mac(self, localnet_port_name):
        return commands.GetInterconnectLrpMacCommand(
            self.agent_api.nb_idl, localnet_port_name
        ).execute(check_error=True)


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

        bgp_patch_port_name = utils.get_rand_name(max_length=14,
                                                  prefix='bgp-pp')
        peer_patch_port_name = utils.get_rand_name(max_length=14,
                                                   prefix='peer-pp')
        with self.ovs_api.transaction(check_error=True) as txn:
            txn.add(self.ovs_api.add_port(
                self.test_bridge.br_name,
                bgp_patch_port_name, type='patch',
                options={'peer': peer_patch_port_name}))
            txn.add(self.ovs_api.add_port(
                patch_bridge.br_name,
                peer_patch_port_name, type='patch',
                options={'peer': bgp_patch_port_name}))
            txn.add(self.ovs_api.add_port(
                self.test_bridge.br_name, self.fake_nic.name))

        self.bgp_bridge = bridge.BGPChassisBridge(
            FakeBgpAgentApi(self.nb_api, self.sb_api),
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
        self.bgp_bridge.bgp_agent_api.hostdev_ips = [
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
        self.bgp_bridge.bgp_agent_api.chassis_id = chassis.uuid
        # Set the chassis_name just in case logger is called
        self.bgp_bridge.bgp_agent_api.chassis_name = chassis_name
        self.sb_api.db_create(
            'Chassis_Private', name=chassis_name,
            chassis=chassis.uuid,
        ).execute(check_error=True)

        port_name = 'lrp-test'
        pb_created_wait_event = test_bgp.WaitForPortBindingCreatedEvent(
            port_name)
        pb_updated_wait_event = test_bgp.WaitForPortBindingUpdatedEvent(
            port_name, chassis.uuid)
        self.sb_api.idl.notify_handler.watch_event(pb_created_wait_event)

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

        self.assertTrue(pb_created_wait_event.wait())
        self.sb_api.idl.notify_handler.watch_event(pb_updated_wait_event)

        self.sb_api.lsp_bind(port_name, chassis.name).execute(check_error=True)

        self.assertTrue(pb_updated_wait_event.wait())

        self.bgp_bridge.configure_flows()

        flows = self._dump_flows(self.bgp_bridge)
        flow_strings = ' '.join(flows)

        # 1. ARP and ICMPv6 flows
        self.assertIn('arp actions=NORMAL', flow_strings)
        self.assertIn(f'icmp6,in_port={self.bgp_bridge.nic_ofport},'
                      'icmp_type=133 actions=NORMAL,'
                      'mod_dl_dst:aa:bb:cc:dd:ee:ff,'
                      f'output:{self.bgp_bridge.patch_port_ofport}',
                      flow_strings)
        self.assertIn(f'icmp6,in_port={self.bgp_bridge.nic_ofport},'
                      'icmp_type=134 actions=NORMAL,'
                      'mod_dl_dst:aa:bb:cc:dd:ee:ff,'
                      f'output:{self.bgp_bridge.patch_port_ofport}',
                      flow_strings)
        self.assertIn(f'icmp6,in_port={self.bgp_bridge.nic_ofport},'
                      'icmp_type=135 actions=NORMAL,'
                      'mod_dl_dst:aa:bb:cc:dd:ee:ff,'
                      f'output:{self.bgp_bridge.patch_port_ofport}',
                      flow_strings)
        self.assertIn(f'icmp6,in_port={self.bgp_bridge.nic_ofport},'
                      'icmp_type=136 actions=NORMAL,'
                      'mod_dl_dst:aa:bb:cc:dd:ee:ff,'
                      f'output:{self.bgp_bridge.patch_port_ofport}',
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


class BGPInterconnectBridgeTestCase(BgpTestCaseWithIdls):

    def setUp(self):
        super().setUp()
        self.ovs_api = impl_idl.api_factory()
        self.test_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture()).bridge
        self.peer_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture()).bridge

        self.ic_bridge = bridge.BGPInterconnectBridge(
            FakeBgpAgentApi(self.nb_api, self.sb_api),
            self.test_bridge.br_name)

    def _add_patch_port(self, provider=False, localnet_port_name=None):
        if provider:
            uuid = uuidutils.generate_uuid()
            port_name = f'patch-provnet-{uuid}-to-br-int'
        else:
            port_name = utils.get_rand_name(max_length=14, prefix='patch-bgp')
        peer_name = utils.get_rand_name(max_length=14, prefix='peer')
        with self.ovs_api.transaction(check_error=True) as txn:
            txn.add(self.ovs_api.add_port(
                self.test_bridge.br_name, port_name, type='patch',
                options={'peer': peer_name}))
            txn.add(self.ovs_api.add_port(
                self.peer_bridge.br_name, peer_name, type='patch',
                options={'peer': port_name}))
            if localnet_port_name:
                ext_ids = {
                    ovn_const.OVN_LOCALNET_PORT_EXT_ID_KEY: localnet_port_name}
                txn.add(self.ovs_api.db_set(
                    'Port', port_name, external_ids=ext_ids))
        return port_name

    def _get_iface_row(self, iface_name):
        return self.ovs_api.lookup('Interface', iface_name)

    def _create_nb_interconnect(self, ic_switch_name, lrp_mac):
        lr_name = bgp_config.get_main_router_name()
        lrp_name = helpers.get_lrp_name(lr_name, ic_switch_name)
        localnet_lsp_name = helpers.get_lsp_localnet_name(ic_switch_name)
        ls_name = utils.get_rand_name(max_length=14, prefix='ls')
        lsp_rtr_name = utils.get_rand_name(max_length=14, prefix='rtr')
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lr_add(lr_name))
            txn.add(self.nb_api.ls_add(ls_name))
            txn.add(self.nb_api.lrp_add(
                lr_name, lrp_name, mac=lrp_mac, networks=[]))
            txn.add(self.nb_api.lsp_add(
                ls_name, lsp_rtr_name,
                type=ovn_const.LSP_TYPE_ROUTER,
                addresses=['router'],
                options={'router-port': lrp_name}))
            txn.add(self.nb_api.lsp_add(
                ls_name, localnet_lsp_name,
                type=ovn_const.LSP_TYPE_LOCALNET,
                addresses=['unknown'],
                options={'network_name': 'test-net'}))

    def test_initial_state(self):
        self.assertIsNone(self.ic_bridge.provider_patch_port)
        self.assertIsNone(self.ic_bridge.bgp_patch_port)
        self.assertFalse(self.ic_bridge.check_requirements_for_flows_met())

    def test_add_provider_patch_port(self):
        port_name = self._add_patch_port(provider=True)
        iface_row = self._get_iface_row(port_name)
        self.ic_bridge.add_patch_port(iface_row)
        self.assertEqual(port_name, self.ic_bridge.provider_patch_port)
        self.assertIsNone(self.ic_bridge.bgp_patch_port)

    def test_add_bgp_patch_port(self):
        port_name = self._add_patch_port()
        iface_row = self._get_iface_row(port_name)
        self.ic_bridge.add_patch_port(iface_row)
        self.assertEqual(port_name, self.ic_bridge.bgp_patch_port)
        self.assertIsNone(self.ic_bridge.provider_patch_port)

    def test_requirements_met_when_everything_set(self):
        ic_switch_name = 'test'
        localnet_lsp = helpers.get_lsp_localnet_name(ic_switch_name)
        prov_name = self._add_patch_port(provider=True)
        self._create_nb_interconnect(ic_switch_name, 'aa:bb:cc:dd:ee:ff')
        bgp_name = self._add_patch_port(localnet_port_name=localnet_lsp)

        self.ic_bridge.add_patch_port(self._get_iface_row(prov_name))
        self.assertFalse(self.ic_bridge.check_requirements_for_flows_met())

        self.ic_bridge.add_patch_port(self._get_iface_row(bgp_name))
        self.assertTrue(self.ic_bridge.check_requirements_for_flows_met())

    def test_provider_patch_ofport(self):
        port_name = self._add_patch_port(provider=True)
        iface_row = self._get_iface_row(port_name)
        self.ic_bridge.add_patch_port(iface_row)
        self.assertGreater(self.ic_bridge.provider_patch_ofport, 0)

    def test_bgp_patch_ofport(self):
        port_name = self._add_patch_port()
        iface_row = self._get_iface_row(port_name)
        self.ic_bridge.add_patch_port(iface_row)
        self.assertGreater(self.ic_bridge.bgp_patch_ofport, 0)

    def test_remove_provider_patch_port(self):
        port_name = self._add_patch_port(provider=True)
        iface_row = self._get_iface_row(port_name)
        self.ic_bridge.add_patch_port(iface_row)

        self.ic_bridge.remove_patch_port(iface_row)
        self.assertIsNone(self.ic_bridge.provider_patch_port)

    def test_remove_bgp_patch_port(self):
        port_name = self._add_patch_port()
        iface_row = self._get_iface_row(port_name)
        self.ic_bridge.add_patch_port(iface_row)

        self.ic_bridge.remove_patch_port(iface_row)
        self.assertIsNone(self.ic_bridge.bgp_patch_port)

    def test_has_patch_port(self):
        port_name = self._add_patch_port()
        iface_row = self._get_iface_row(port_name)
        self.ic_bridge.add_patch_port(iface_row)

        self.assertTrue(self.ic_bridge.has_patch_port(port_name))
        self.assertFalse(self.ic_bridge.has_patch_port('unknown-port'))

    def test_scan_existing_patch_ports(self):
        ic_switch_name = 'test'
        localnet_lsp = helpers.get_lsp_localnet_name(ic_switch_name)
        prov_name = self._add_patch_port(provider=True)
        self._create_nb_interconnect(ic_switch_name, 'aa:bb:cc:dd:ee:ff')
        bgp_name = self._add_patch_port(localnet_port_name=localnet_lsp)

        self.ic_bridge.scan_existing_patch_ports()

        self.assertEqual(prov_name, self.ic_bridge.provider_patch_port)
        self.assertEqual(bgp_name, self.ic_bridge.bgp_patch_port)
        self.assertTrue(self.ic_bridge.check_requirements_for_flows_met())

    def test_configure_flows(self):
        lrp_mac = 'aa:bb:cc:dd:ee:ff'
        ic_switch_name = 'test'
        localnet_lsp = helpers.get_lsp_localnet_name(ic_switch_name)
        prov_name = self._add_patch_port(provider=True)
        self._create_nb_interconnect(ic_switch_name, lrp_mac)
        bgp_name = self._add_patch_port(localnet_port_name=localnet_lsp)

        self.ic_bridge.add_patch_port(self._get_iface_row(prov_name))
        self.ic_bridge.add_patch_port(self._get_iface_row(bgp_name))

        self.ic_bridge.configure_flows()

        prov_ofport = self.ic_bridge.provider_patch_ofport
        bgp_ofport = self.ic_bridge.bgp_patch_ofport
        flows_str = self.ic_bridge.ovs_bridge.dump_flows_for()

        self.assertIn(
            f'in_port={prov_ofport} '
            f'actions=mod_dl_dst:{lrp_mac},output:{bgp_ofport}',
            flows_str)
        self.assertIn(
            f'in_port={bgp_ofport} '
            f'actions=output:{prov_ofport}',
            flows_str)

    def test_localnet_port_name_from_ovs_port_external_ids(self):
        localnet_lsp = helpers.get_lsp_localnet_name('test')
        bgp_name = self._add_patch_port(localnet_port_name=localnet_lsp)

        self.ic_bridge.add_patch_port(self._get_iface_row(bgp_name))

        self.assertEqual(localnet_lsp, self.ic_bridge.localnet_port_name)

    def test_localnet_port_name_none_when_no_bgp_patch_port(self):
        self.assertIsNone(self.ic_bridge.localnet_port_name)

    def test_localnet_port_name_none_when_ext_id_missing(self):
        bgp_name = self._add_patch_port()

        self.ic_bridge.add_patch_port(self._get_iface_row(bgp_name))

        self.assertIsNone(self.ic_bridge.localnet_port_name)

    def test_ic_lrp_mac_returns_mac_from_nb_topology(self):
        lrp_mac = 'aa:bb:cc:dd:ee:ff'
        ic_switch_name = 'test'
        localnet_lsp = helpers.get_lsp_localnet_name(ic_switch_name)
        self._create_nb_interconnect(ic_switch_name, lrp_mac)
        bgp_name = self._add_patch_port(localnet_port_name=localnet_lsp)

        self.ic_bridge.add_patch_port(self._get_iface_row(bgp_name))

        self.assertEqual(lrp_mac, self.ic_bridge.ic_lrp_mac)

    def test_ic_lrp_mac_none_when_no_bgp_patch_port(self):
        self.assertIsNone(self.ic_bridge.ic_lrp_mac)

    def test_ic_lrp_mac_none_when_localnet_ext_id_missing(self):
        bgp_name = self._add_patch_port()

        self.ic_bridge.add_patch_port(self._get_iface_row(bgp_name))

        self.assertIsNone(self.ic_bridge.ic_lrp_mac)

    def test_ic_lrp_mac_none_when_localnet_port_not_in_ovn(self):
        localnet_lsp = 'bogus-lsp-not-in-ovn'
        bgp_name = self._add_patch_port(localnet_port_name=localnet_lsp)

        self.ic_bridge.add_patch_port(self._get_iface_row(bgp_name))

        self.assertIsNone(self.ic_bridge.ic_lrp_mac)

    def test_configure_flows_skipped_without_requirements(self):
        self.ic_bridge.configure_flows()

        flows_str = self.ic_bridge.ovs_bridge.dump_flows_for()
        self.assertIn('actions=NORMAL', flows_str)
