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
import weakref

from oslo_config import cfg
from ovsdbapp.backend.ovs_idl import event
from ovsdbapp import venv

from neutron.agent.ovsdb import impl_idl
from neutron.common import utils
from neutron.services.bgp import constants
from neutron.tests.functional.agent.ovn.agent import test_ovn_neutron_agent


class WaitForPortBindingEvent(event.WaitEvent):
    event_name = 'WaitForPortBindingEvent'

    def __init__(self, port_name):
        table = 'Port_Binding'
        events = (self.ROW_CREATE,)
        conditions = (('logical_port', '=', port_name),)
        super().__init__(events, table, conditions, timeout=10)


class BGPExtensionTestCase(test_ovn_neutron_agent.TestOVNNeutronAgentBase):
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
        test_ovn_neutron_agent.EXTENSION_NAMES[
            constants.AGENT_BGP_EXT_NAME] = 'BGP agent extension'
        try:
            super().setUp(extensions=[constants.AGENT_BGP_EXT_NAME], **kwargs)
        finally:
            self.addCleanup(self._reset_class_attributes)

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

    def _add_bgp_bridge(self, bridge_name):
        with self.ovn_agent.ovs_idl.transaction(check_error=True) as txn:
            txn.add(self.ovn_agent.ovs_idl.add_br(bridge_name))
            txn.add(self.ovn_agent.ovs_idl.db_set(
                'Open_vSwitch', '.',
                external_ids={constants.AGENT_BGP_PEER_BRIDGES: bridge_name}))
            txn.add(self.ovn_agent.ovs_idl.add_port(
                bridge_name, 'fake-nic', type=''))

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

    def test_bgp_extension_configures_bridge_mappings(self):
        self.ovn_agent.ovs_idl.db_set(
            'Open_vSwitch', '.',
            external_ids={
                'ovn-bridge-mappings': 'physnet:bridge',
                constants.AGENT_BGP_PEER_BRIDGES: 'bgp-br-1,bgp-br-2'}
        ).execute(check_error=True)

        self.ovn_agent.ovs_idl.restart_connection()

        expected_bms = 'physnet:bridge,bgp-br-1:bgp-br-1,bgp-br-2:bgp-br-2'
        self._check_bridge_mappings(expected_bms)

    def test_bgp_extension_configures_bridge_mappings_with_empty_bms(self):
        self.ovn_agent.ovs_idl.db_set(
            'Open_vSwitch', '.',
            external_ids={
                constants.AGENT_BGP_PEER_BRIDGES: 'bgp-br-1,bgp-br-2'}
            ).execute(check_error=True)
        self.ovn_agent.ovs_idl.restart_connection()

        expected_bms = 'bgp-br-1:bgp-br-1,bgp-br-2:bgp-br-2'
        self._check_bridge_mappings(expected_bms)

    def test_bgp_extension_missing_bgp_peer_bridges(self):
        self.ovn_agent.ovs_idl.db_set(
            'Open_vSwitch', '.',
            external_ids={'ovn-bridge-mappings': 'physnet:bridge'}).execute(
                check_error=True)
        self.ovn_agent.ovs_idl.restart_connection()

        expected_bms = 'physnet:bridge'
        self._check_bridge_mappings(expected_bms)

    def _test_lrp_with_mac_helper(self, bridge_name):
        port_name = 'ovn-port-bgp'
        lrp_mac = '02:00:00:00:00:00'
        pb_wait_event = WaitForPortBindingEvent(port_name)
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
