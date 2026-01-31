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

import tempfile
from unittest import mock
import weakref

import netaddr
from oslo_config import cfg
from ovsdbapp import venv

from neutron.agent.linux import ip_lib
from neutron.agent.ovsdb import impl_idl
from neutron.common import utils
from neutron.services.bgp import constants
from neutron.tests.common.exclusive_resources import ip_address
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.ovn.agent import test_ovn_neutron_agent
from neutron.tests.functional.agent.ovn.extensions import bgp as test_bgp


class FakeLoopbackContext:
    """Context manager that creates a fake loopback device and mocks constants.

    This creates a veth pair to use as a fake loopback device and patches
    the ip_lib.LOOPBACK_DEVNAME and bgp.LOCALHOST_ADDRESSES constants.
    """

    def __init__(self, test_case):
        """Initialize the fake loopback context.

        :param test_case: The test case instance, used to register fixtures.
        """
        self.test_case = test_case
        self.device = None
        self._patches = []

    def __enter__(self):
        # Create a fake loopback device using a veth pair
        self.device = self.test_case.useFixture(
            net_helpers.VethFixture()).ports[0]
        self.device.link.set_up()

        # Get an exclusive IP for the fake localhost address
        fake_localhost = self.test_case.useFixture(
            ip_address.ExclusiveIPAddress('169.254.0.1', '169.254.0.254'))

        # Add the fake localhost IP to the device
        self.device.addr.add(f'{fake_localhost.address}/8',
                             add_broadcast=False)

        @property
        def is_loopback_mock(ip_network):
            return lambda: str(ip_network) == f"{fake_localhost.address}/8"

        # Start the patches
        self._patches = [
            mock.patch.object(
                self.test_case.bgp_ext, 'hostdev_name', self.device.name),
            mock.patch.object(netaddr.IPNetwork, 'is_loopback',
                              is_loopback_mock),
        ]
        for p in self._patches:
            p.start()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for p in self._patches:
            p.stop()
        return False

    def add_ips(self, cidrs):
        """Add IP addresses to the fake loopback device.

        :param cidrs: List of CIDR strings to add to the device.
        """
        for cidr in cidrs:
            self.device.addr.add(cidr, add_broadcast=False)


class BGPExtensionBaseTestCase(test_ovn_neutron_agent.TestOVNNeutronAgentBase):
    def setUp(self, **kwargs):
        test_ovn_neutron_agent.EXTENSION_NAMES[
            constants.AGENT_BGP_EXT_NAME] = 'BGP agent extension'
        try:
            super().setUp(extensions=[constants.AGENT_BGP_EXT_NAME], **kwargs)
        finally:
            self.addCleanup(self._reset_class_attributes)

    def _reset_class_attributes(self):
        # EXTENSION_NAMES is a class attribute so we need to reset it for other
        # tests running in the same process
        try:
            del test_ovn_neutron_agent.EXTENSION_NAMES[
                constants.AGENT_BGP_EXT_NAME]
        except KeyError:
            pass

    @property
    def bgp_ext(self):
        return self.ovn_agent[constants.AGENT_BGP_EXT_NAME]


class BGPExtensionTestCase(BGPExtensionBaseTestCase):
    def setUp(self, **kwargs):
        self.ovs_venv = self.useFixture(venv.OvsVenvFixture(
            tempfile.mkdtemp(),
            remove=True,
        ))
        _orig_ovsdb_connection = cfg.CONF.OVS.ovsdb_connection
        cfg.CONF.set_override(
            'ovsdb_connection', self.ovs_venv.ovs_connection, group='OVS')
        self.addCleanup(
            cfg.CONF.set_override,
            'ovsdb_connection',
            _orig_ovsdb_connection,
            group='OVS')
        # Cleanup after tests that did not cleanup after themselves
        self._reset_class_attributes()
        super().setUp(**kwargs)

    def _reset_class_attributes(self):
        # The connection is a class attribute so we need to reset it in order
        # to connect to the newly spawned per-test ovsdb server
        impl_idl.NeutronOvsdbIdl._klass._ovsdb_connection = None

        # We spawn a different ovsdb server for each test
        # let's make sure the connection is always a new one
        impl_idl._connection = None

        # We also need to reset the SingletonDecorator
        utils.SingletonDecorator._singleton_instances = (
            weakref.WeakValueDictionary())

        super()._reset_class_attributes()

    def _add_bgp_bridge(self, bridge_name):
        # Get current BGP bridges and append the new one
        ext_ids = self.ovn_agent.ovs_idl.db_get(
            'Open_vSwitch', '.', 'external_ids').execute(check_error=True)
        current_bridges = ext_ids.get(constants.AGENT_BGP_PEER_BRIDGES, '')
        if current_bridges:
            new_bridges = f'{current_bridges},{bridge_name}'
        else:
            new_bridges = bridge_name

        with self.ovn_agent.ovs_idl.transaction(check_error=True) as txn:
            txn.add(self.ovn_agent.ovs_idl.add_br(bridge_name))
            txn.add(self.ovn_agent.ovs_idl.db_set(
                'Open_vSwitch', '.',
                external_ids={constants.AGENT_BGP_PEER_BRIDGES: new_bridges}))
            txn.add(self.ovn_agent.ovs_idl.add_port(
                bridge_name, f'fake-nic-{bridge_name}', type=''))

        # Wait until the agent picks up the bridge name
        utils.wait_until_true(
            lambda: bridge_name in self.bgp_ext.bgp_bridges,
            timeout=10, exception=Exception(
                'Bridge %s not added or not detected by '
                'BGPChassisBridge' % bridge_name))

        bgp_bridge = self.bgp_ext.bgp_bridges[bridge_name]

        return bgp_bridge

    def _get_bridge_mappings(self):
        return self.ovn_agent.ovs_idl.db_get(
            'Open_vSwitch', '.',
            'external_ids').execute(
                check_error=True).get('ovn-bridge-mappings', '')

    def _check_bridge_mappings(self, expected_bms):
        def wait_for_bms():
            bms = self._get_bridge_mappings()
            return sorted(bms.split(',')) == sorted(expected_bms.split(','))

        utils.wait_until_true(
            wait_for_bms,
            sleep=0.1,
            timeout=5,
            exception=Exception(
                "Expected bridge mappings %s were not configured" %
                expected_bms)
        )

    def _verify_chassis_bgp_bridges(self, expected_bridge_names):
        def wait_for_chassis_bgp_bridges():
            ext_ids = self.ovn_agent.sb_idl.db_get(
                'Chassis_Private', self.chassis_name, 'external_ids').execute(
                    check_error=True)
            try:
                observed_bridges = ext_ids[
                    constants.CHASSIS_BGP_BRIDGES_EXT_ID_KEY]
            except KeyError:
                observed_bridges = ''
            return observed_bridges == expected_bridge_names

        utils.wait_until_true(
            wait_for_chassis_bgp_bridges,
            sleep=0.1,
            timeout=5,
            exception=Exception(
                "Expected chassis BGP bridges %s were not configured" %
                expected_bridge_names))

    def test_bgp_extension_configures_bridges(self):
        self.ovn_agent.ovs_idl.db_set(
            'Open_vSwitch', '.',
            external_ids={
                'ovn-bridge-mappings': 'physnet:bridge',
                constants.AGENT_BGP_PEER_BRIDGES: 'bgp-br-1,bgp-br-2'}
        ).execute(check_error=True)

        self.ovn_agent.ovs_idl.restart_connection()

        expected_bms = 'physnet:bridge,bgp-br-1:bgp-br-1,bgp-br-2:bgp-br-2'
        self._check_bridge_mappings(expected_bms)
        self._verify_chassis_bgp_bridges('bgp-br-1,bgp-br-2')

    def test_bgp_extension_configures_bridge_with_empty_bms(self):
        self.ovn_agent.ovs_idl.db_set(
            'Open_vSwitch', '.',
            external_ids={
                constants.AGENT_BGP_PEER_BRIDGES: 'bgp-br-1,bgp-br-2'}
            ).execute(check_error=True)
        self.ovn_agent.ovs_idl.restart_connection()

        expected_bms = 'bgp-br-1:bgp-br-1,bgp-br-2:bgp-br-2'
        self._check_bridge_mappings(expected_bms)
        self._verify_chassis_bgp_bridges('bgp-br-1,bgp-br-2')

    def test_bgp_extension_missing_bgp_peer_bridges(self):
        self.ovn_agent.ovs_idl.db_set(
            'Open_vSwitch', '.',
            external_ids={'ovn-bridge-mappings': 'physnet:bridge'}).execute(
                check_error=True)
        self.ovn_agent.ovs_idl.restart_connection()

        expected_bms = 'physnet:bridge'
        self._check_bridge_mappings(expected_bms)
        self._verify_chassis_bgp_bridges('')

    def _test_lrp_with_mac_helper(self, bridge_name):
        port_name = 'ovn-port-bgp'
        lrp_mac = '02:00:00:00:00:00'
        pb_wait_event = test_bgp.WaitForPortBindingEvent(port_name)
        self.ovn_agent.sb_idl.idl.notify_handler.watch_event(pb_wait_event)

        lrp_ext_ids = {constants.LRP_NETWORK_NAME_EXT_ID_KEY: bridge_name}

        bgp_bridge = self._add_bgp_bridge(bridge_name)

        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lr_add('lr-bgp',
                                  options={'chassis': self.chassis_name}))
            txn.add(self.nb_api.lrp_add(
                'lr-bgp',
                port_name,
                mac=lrp_mac,
                networks=['192.168.1.2/30'],
                external_ids=lrp_ext_ids))

        self.assertTrue(pb_wait_event.wait())

        try:
            pb = self.ovn_agent.sb_idl.db_find_rows(
                'Port_Binding', ('logical_port', '=', port_name)).execute(
                    check_error=True)[0]
        except IndexError:
            self.fail('Port binding for port %s not found' % port_name)

        return (bgp_bridge, pb.mac[0].split(' ', 1)[0])

    def test_new_lrp_with_mac(self):
        bridge_name = 'ovn-br-bgp'
        bgp_bridge, mac = self._test_lrp_with_mac_helper(bridge_name)
        utils.wait_until_true(
            lambda: mac == bgp_bridge.lrp_mac,
            sleep=0.1,
            timeout=5,
            exception=Exception(
                "Expected LRP MAC %s was not configured, is %s" %
                (mac, bgp_bridge.lrp_mac)))

    def test_existing_lrp_with_mac(self):
        bridge_name = 'ovn-br-bgp'
        bgp_bridge, mac = self._test_lrp_with_mac_helper(bridge_name)

        del self.bgp_ext.bgp_bridges[bridge_name]

        bgp_bridge = self.bgp_ext.create_bgp_bridge(bridge_name)

        self.assertEqual(mac, bgp_bridge.lrp_mac)

    def test_watch_patch_port_created_event(self):
        bgp_bridge = self._add_bgp_bridge('ovn-br-bgp')
        self.bgp_ext.watch_port_created_event(bgp_bridge, 'patch')

        self.ovn_agent.ovs_idl.add_port(
            'ovn-br-bgp', 'ovn-port-bgp', type='patch').execute(
                check_error=True)

        utils.wait_until_true(
            lambda: bgp_bridge.patch_port_ofport is not None,
            timeout=5,
            exception=Exception(
                "Patch port ofport was not configured"))

    def test_creating_bgp_bridge_with_existing_patch_port(self):
        bridge_name = 'ovn-br-bgp'
        bgp_bridge = self._add_bgp_bridge(bridge_name)
        self.ovn_agent.ovs_idl.add_port(
            bridge_name, 'ovn-port-bgp', type='patch').execute(
                check_error=True)

        del self.bgp_ext.bgp_bridges[bridge_name]

        bgp_bridge = self.bgp_ext.create_bgp_bridge(bridge_name)

        self.assertIsNotNone(bgp_bridge.patch_port_ofport)


class BGPExtensionHostIpsTestCase(BGPExtensionBaseTestCase):
    def _add_bgp_bridge(self, ips):
        bridge = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        nic = self.useFixture(net_helpers.VethFixture()).ports[0]

        self.ovn_agent.ovs_idl.add_port(
            bridge.br_name, nic.name, type='').execute(check_error=True)

        for ip in ips:
            ip_lib.add_ip_address(ip, bridge.br_name, namespace=None,
                                  add_broadcast=False)

        # Avoid using the local OVS Open_vSwitch table to define the BGP
        # bridges
        self.bgp_ext.create_bgp_bridge(bridge.br_name)

    def _check_host_ips(self, loopback_ips, bridge1_ips, bridge2_ips):
        """Helper to test host_ips with given IP configurations.

        Creates a fake loopback device and two BGP bridges with the specified
        IPs, then verifies that host_ips returns all expected IPs.

        :param loopback_ips: List of CIDRs to add to the fake loopback device.
        :param bridge1_ips: List of CIDRs to add to the first bridge.
        :param bridge2_ips: List of CIDRs to add to the second bridge.
        """
        with FakeLoopbackContext(self) as fake_lo:
            fake_lo.add_ips(loopback_ips)
            self._add_bgp_bridge(bridge1_ips)
            self._add_bgp_bridge(bridge2_ips)

            host_ips = self.bgp_ext.host_ips
            host_ip_cidrs = [str(ip) for ip in host_ips]

            expected_cidrs = loopback_ips + bridge1_ips + bridge2_ips

            self.assertCountEqual(expected_cidrs, host_ip_cidrs)

    def _get_exclusive_ip(self, test_net_number):
        """Get an exclusive IP address from a TEST-NET range.

        :param test_net_number: 1, 2, or 3 for different TEST-NET ranges.
        :returns: CIDR string with /32 prefix.
        """
        exclusive_ip = self.useFixture(
            ip_address.get_test_net_address_fixture(test_net_number))
        return f'{exclusive_ip.address}/32'

    def test_host_ips_combines_loopback_and_bridge_ips(self):
        loopback_ips = [
            self._get_exclusive_ip(1),
            self._get_exclusive_ip(1),
        ]
        bridge1_ips = [self._get_exclusive_ip(2), self._get_exclusive_ip(3)]
        bridge2_ips = [self._get_exclusive_ip(3), self._get_exclusive_ip(2)]

        self._check_host_ips(loopback_ips, bridge1_ips, bridge2_ips)

    def test_host_ips_with_bridge_having_no_ips(self):
        loopback_ips = [self._get_exclusive_ip(1)]
        bridge1_ips = [self._get_exclusive_ip(2)]
        bridge2_ips = []

        self._check_host_ips(loopback_ips, bridge1_ips, bridge2_ips)

    def test_host_ips_with_loopback_having_no_ips(self):
        loopback_ips = []
        bridge1_ips = [self._get_exclusive_ip(2)]
        bridge2_ips = [self._get_exclusive_ip(3)]

        self._check_host_ips(loopback_ips, bridge1_ips, bridge2_ips)
