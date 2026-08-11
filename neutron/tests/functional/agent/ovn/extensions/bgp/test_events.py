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

import threading
from unittest import mock

from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import event
import testtools

from neutron.agent.ovn.extensions import bgp as bgp_ext_module
from neutron.agent.ovn.extensions.bgp import bridge
from neutron.agent.ovn.extensions.bgp import events
from neutron.agent.ovn.extensions import extension_manager as ovn_ext_mgr
from neutron.common.ovn import constants as ovn_const
from neutron.common import utils
from neutron.services.bgp import constants
from neutron.services.bgp import ovn as bgp_ovn
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.ovn.extensions import bgp as test_bgp
from neutron.tests.functional.services import bgp as bgp_base


class WaitForChassisBGPBridgesEvent(event.WaitEvent):
    event_name = 'WaitForChassisBGPBridgesEvent'

    def __init__(self, chassis_name, expected_bridges):
        table = 'Chassis_Private'
        events = (self.ROW_UPDATE,)
        conditions = (('name', '=', chassis_name),)
        self.expected = sorted(expected_bridges)
        super().__init__(events, table, conditions, timeout=10)

    def match_fn(self, event, row, old=None):
        if not hasattr(old, 'external_ids'):
            return False
        value = row.external_ids.get(
            constants.CHASSIS_BGP_BRIDGES_EXT_ID_KEY, '')
        actual = sorted(value.split(',')) if value else []
        return actual == self.expected


class WaitForOVSExtIdEvent(event.WaitEvent):
    event_name = 'WaitForOVSExtIdEvent'

    def __init__(self, key, expected_mappings):
        table = 'Open_vSwitch'
        events = (self.ROW_CREATE, self.ROW_UPDATE,)
        self.ext_id_key = key
        self.expected = sorted(expected_mappings)
        super().__init__(events, table, (), timeout=10)

    # RowEvent.key is (class, table, events) which makes all instances
    # of this class equal in the notify handler's set.  Include the
    # ext_id_key so we can watch multiple keys simultaneously.
    @property
    def key(self):
        return super().key + (self.ext_id_key,)

    def __hash__(self):
        return hash(self.key)

    def match_fn(self, event, row, old=None):
        if event == self.ROW_UPDATE:
            if not hasattr(old, 'external_ids'):
                return False
            old_value = old.external_ids.get(self.ext_id_key, '')
            new_value = row.external_ids.get(self.ext_id_key, '')
            if old_value == new_value:
                return False
        value = row.external_ids.get(self.ext_id_key, '')
        actual = sorted(value.split(',')) if value else []
        return actual == self.expected


class BridgeNotMatchedException(Exception):
    def __init__(self):
        super().__init__("BGP bridge event was not matched")


class EventNotExpected(Exception):
    pass


class TestOVNAgentExtensionAPI(ovn_ext_mgr.OVNAgentExtensionAPI):
    """OVNAgentExtensionAPI with extension lookup for tests.

    In production, extension lookup (``__getitem__``) lives on the
    ``OVNNeutronAgent`` which delegates to the extension manager.
    This subclass adds that capability directly so tests can pass the
    API object to events without needing the full agent.
    """

    def __init__(self):
        super().__init__()
        self._extensions = {}
        self.chassis = None

    def register_extension(self, name, ext):
        ext.consume_api(self)
        self._extensions[name] = ext

    def __getitem__(self, key):
        return self._extensions[key]


class TestBGPAgentExtension(bgp_ext_module.BGPAgentExtension):
    """BGPAgentExtension with no default events for tests.

    Tests register only the specific events they want to exercise.
    The bridge objects created by this extension have their ``ovsdb``
    attribute wired to the test's OVS IDL so that OVS queries go to
    the sandboxed database instead of the system one.
    """

    @property
    def ovs_idl_events(self):
        return []

    @property
    def nb_idl_events(self):
        return []

    @property
    def sb_idl_events(self):
        return []

    def _wire_bridge_ovsdb(self, br):
        # Bridge.__init__ creates an ovs_lib.OVSBridge whose ovsdb
        # connects to the system OVS via api_factory().  Replace it
        # with the test's sandboxed OVS IDL.
        br.ovs_bridge.ovsdb = self.agent_api.ovs_idl

    def create_bgp_bridge(self, bridge_name):
        bgp_bridge = super().create_bgp_bridge(bridge_name)
        self._wire_bridge_ovsdb(bgp_bridge)
        return bgp_bridge

    def set_interconnect_bridge(self, name):
        super().set_interconnect_bridge(name)
        if self.interconnect_bridge:
            self._wire_bridge_ovsdb(self.interconnect_bridge)


class BaseBgpEventsTestCase(bgp_base.BaseBgpIDLTestCase):
    schemas = ['Open_vSwitch', 'OVN_Northbound', 'OVN_Southbound']
    CHASSIS_NAME = 'test-chassis'

    def setUp(self):
        bgp_ovn.OvnSbIdl.tables = (
            'Chassis', 'Encap', 'Chassis_Private',
            'Port_Binding')
        try:
            super().setUp()
        finally:
            bgp_ovn.OvnSbIdl.tables = bgp_ovn.OVN_SB_TABLES

        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids={'system-id': self.CHASSIS_NAME}
        ).execute(check_error=True)

        self.agent_api = TestOVNAgentExtensionAPI()
        self.agent_api.ovs_idl = self.ovs_api
        self.agent_api.sb_idl = self.sb_api
        self.agent_api.nb_idl = self.nb_api
        self.agent_api.chassis = self.CHASSIS_NAME
        self.bgp_ext = TestBGPAgentExtension()
        self.agent_api.register_extension(
            constants.AGENT_BGP_EXT_NAME, self.bgp_ext)

        mock.patch.object(
            bridge.BGPChassisBridge, 'configure_flows').start()
        mock.patch.object(
            bridge.BGPInterconnectBridge, 'configure_flows').start()

        self._create_initial_resources()

    def _create_initial_resources(self):
        self.chassis = self.sb_api.chassis_add(
            self.CHASSIS_NAME, ['geneve'], '10.0.0.1'
        ).execute(check_error=True)
        self.sb_api.db_create(
            'Chassis_Private', name=self.CHASSIS_NAME,
            chassis=self.chassis.uuid,
        ).execute(check_error=True)


class NewBgpBridgeEventTestCase(BaseBgpEventsTestCase):
    def _register_event(self):
        self.ovs_api.idl.notify_handler.watch_event(
            events.NewBgpBridgeEvent(self.agent_api))

    def _set_bgp_bridges(self, bgp_bridges):
        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids={constants.AGENT_BGP_PEER_BRIDGES: bgp_bridges}
        ).execute(check_error=True)

    def _create_fake_nic(self):
        return self.useFixture(net_helpers.VethFixture()).ports[0]

    def _check_event_not_triggered(self):
        with testtools.ExpectedException(BridgeNotMatchedException):
            utils.wait_until_true(
                lambda: self.bgp_ext.bgp_bridges,
                sleep=0.5,
                timeout=2,
                exception=BridgeNotMatchedException())

    def test_new_bgp_bridge_event(self):
        self._register_event()
        bgp_bridge_name = 'br-bgp'
        self._set_bgp_bridges(bgp_bridge_name)
        fake_nic = self._create_fake_nic()

        with self.ovs_api.transaction(check_error=True) as txn:
            txn.add(self.ovs_api.add_br(bgp_bridge_name))
            txn.add(self.ovs_api.add_port(bgp_bridge_name, fake_nic.name))
        utils.wait_until_true(
            lambda: bgp_bridge_name in self.bgp_ext.bgp_bridges,
            sleep=0.5,
            timeout=5,
            exception=BridgeNotMatchedException())

    def test_new_bgp_bridge_event_interface_added(self):
        bgp_bridge_name = 'br-bgp'
        self._set_bgp_bridges(bgp_bridge_name)
        self.ovs_api.add_br(bgp_bridge_name).execute(check_error=True)
        # let's make sure the event hasn't been triggered
        self._register_event()

        fake_nic = self._create_fake_nic()
        self.ovs_api.add_port(bgp_bridge_name, fake_nic.name).execute(
            check_error=True)
        utils.wait_until_true(
            lambda: bgp_bridge_name in self.bgp_ext.bgp_bridges,
            sleep=0.5,
            timeout=5,
            exception=Exception("BGP bridge %s not matched" % bgp_bridge_name))

    def test_adding_bridge_without_nic_does_not_trigger_event(self):
        self._register_event()
        bgp_bridge_name = 'br-bgp'
        self._set_bgp_bridges(bgp_bridge_name)
        self.ovs_api.add_br(bgp_bridge_name).execute(check_error=True)
        self._check_event_not_triggered()

    def test_modifying_bridge_does_not_trigger_event(self):
        self._register_event()
        bgp_bridge_name = 'br-bgp'
        self._set_bgp_bridges(bgp_bridge_name)
        self.ovs_api.add_br(bgp_bridge_name).execute(check_error=True)

        self.ovs_api.db_set(
            'Bridge', bgp_bridge_name, other_config={'foo': 'bar'}
        ).execute(check_error=True)
        self._check_event_not_triggered()

    def test_removing_nic_does_not_trigger_event(self):
        bgp_bridge_name = 'br-bgp'
        self._set_bgp_bridges(bgp_bridge_name)
        with self.ovs_api.transaction(check_error=True) as txn:
            txn.add(self.ovs_api.add_br(bgp_bridge_name))
            fake_nic = self._create_fake_nic()
            txn.add(self.ovs_api.add_port(bgp_bridge_name, fake_nic.name))
            fake_nic = self._create_fake_nic()
            txn.add(self.ovs_api.add_port(bgp_bridge_name, fake_nic.name))
        self._register_event()

        self.ovs_api.del_port(fake_nic.name).execute(check_error=True)
        self._check_event_not_triggered()

    def test_new_non_bgp_bridge_does_not_trigger_event(self):
        self._register_event()
        bgp_bridge_name = 'br-bgp'
        fake_nic = self._create_fake_nic()

        with self.ovs_api.transaction(check_error=True) as txn:
            txn.add(self.ovs_api.add_br(bgp_bridge_name))
            txn.add(self.ovs_api.add_port(bgp_bridge_name, fake_nic.name))
        self._check_event_not_triggered()

    def test_adding_patch_port_does_not_trigger_event(self):
        bgp_bridge_name = 'br-bgp'
        patch_port_bridge = 'br-patch'
        self._set_bgp_bridges(bgp_bridge_name)
        fake_nic = self._create_fake_nic()

        with self.ovs_api.transaction(check_error=True) as txn:
            txn.add(self.ovs_api.add_br(bgp_bridge_name))
            txn.add(self.ovs_api.add_br(patch_port_bridge))
            txn.add(self.ovs_api.add_port(bgp_bridge_name, fake_nic.name))

        self._register_event()

        with self.ovs_api.transaction(check_error=True) as txn:
            txn.add(self.ovs_api.add_port(bgp_bridge_name, 'bgp-patch-port'))
            txn.add(self.ovs_api.add_port(
                patch_port_bridge, 'patch-patch-port'))
            txn.add(self.ovs_api.db_set(
                'Interface', 'bgp-patch-port', type='patch',
                options={'peer': 'patch-patch-port'}))
            txn.add(self.ovs_api.db_set(
                'Interface', 'patch-patch-port', type='patch',
                options={'peer': 'bgp-patch-port'}))
        self._check_event_not_triggered()


class BGPBridgePortCreatedEventTestCase(BaseBgpEventsTestCase):
    LRP_MAC = 'aa:bb:cc:dd:ee:ff'

    def setUp(self):
        super().setUp()
        self.bgp_bridge_name = 'br-bgp'

        self.int_bridge_name = 'br-int-%s' % uuidutils.generate_uuid()[:8]
        for br in (self.bgp_bridge_name, self.int_bridge_name):
            self.ovs_api.add_br(br).execute(check_error=True)

        self.bgp_bridge = self.bgp_ext.create_bgp_bridge(self.bgp_bridge_name)

        lrp_name = 'lrp-test'
        lrp_ext_ids = {
            constants.LRP_NETWORK_NAME_EXT_ID_KEY:
                self.bgp_bridge_name}
        pb_created_ev = test_bgp.WaitForPortBindingCreatedEvent(lrp_name)
        self.sb_api.idl.notify_handler.watch_event(pb_created_ev)
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lr_add(
                router='lr-test',
                options={'chassis': self.CHASSIS_NAME}))
            txn.add(self.nb_api.lrp_add(
                router='lr-test',
                port=lrp_name,
                mac=self.LRP_MAC,
                networks=['192.168.1.1/32'],
                external_ids=lrp_ext_ids))
        self.assertTrue(pb_created_ev.wait())
        self.sb_api.lsp_bind(
            lrp_name, self.CHASSIS_NAME
        ).execute(check_error=True)
        utils.wait_until_true(
            lambda: self.bgp_bridge.lrp_mac is not None,
            sleep=0.1, timeout=10,
            exception=Exception("LRP MAC not visible in SB IDL"))

    def _register_event(self, *port_types):
        ev = events.BGPBridgePortCreatedEvent(
            self.agent_api, self.bgp_bridge_name, *port_types)
        self.ovs_api.idl.notify_handler.watch_event(ev)
        return ev

    def _add_patch_ports(self):
        suffix = uuidutils.generate_uuid()[:8]
        port_name = 'bgp-patch-%s' % suffix
        peer_name = 'int-patch-%s' % suffix
        with self.ovs_api.transaction(check_error=True) as txn:
            txn.add(self.ovs_api.add_port(
                self.bgp_bridge_name, port_name))
            txn.add(self.ovs_api.add_port(self.int_bridge_name, peer_name))
            txn.add(self.ovs_api.db_set(
                'Interface', port_name, type='patch',
                options={'peer': peer_name}))
            txn.add(self.ovs_api.db_set(
                'Interface', peer_name, type='patch',
                options={'peer': port_name}))

    def _check_flows_applied(self):
        utils.wait_until_true(
            lambda: self.bgp_bridge.configure_flows.called,
            timeout=5,
            exception=Exception("configure_flows was not called"))

    def _check_flows_not_applied(self):
        with testtools.ExpectedException(Exception):
            utils.wait_until_true(
                lambda: self.bgp_bridge.configure_flows.called,
                sleep=0.5,
                timeout=2,
                exception=Exception("configure_flows was unexpectedly called"))

    def test_patch_port_created_configures_flows(self):
        fake_nic = self.useFixture(net_helpers.VethFixture()).ports[0]
        self.ovs_api.add_port(
            self.bgp_bridge_name, fake_nic.name
        ).execute(check_error=True)
        utils.wait_until_true(
            lambda: self.bgp_bridge.nic_ofport is not None,
            sleep=0.1, timeout=5)
        self._register_event('patch')
        self._add_patch_ports()
        self._check_flows_applied()

    def test_nic_port_created_configures_flows(self):
        self._add_patch_ports()
        utils.wait_until_true(
            lambda: self.bgp_bridge.patch_port_ofport is not None,
            sleep=0.1, timeout=5)
        self._register_event(*constants.BGP_BRIDGE_NIC_TYPES)
        fake_nic = self.useFixture(net_helpers.VethFixture()).ports[0]
        self.ovs_api.add_port(
            self.bgp_bridge_name, fake_nic.name).execute(check_error=True)
        self._check_flows_applied()

    def test_wrong_port_type_does_not_trigger_event(self):
        self._register_event('patch')
        fake_nic = self.useFixture(net_helpers.VethFixture()).ports[0]
        self.ovs_api.add_port(
            self.bgp_bridge_name, fake_nic.name).execute(check_error=True)
        self._check_flows_not_applied()

    def test_wrong_bridge_does_not_trigger_event(self):
        self._register_event('patch')
        other_bridge = 'br-other-%s' % uuidutils.generate_uuid()[:8]
        self.ovs_api.add_br(other_bridge).execute(check_error=True)
        suffix = uuidutils.generate_uuid()[:8]
        port_name = 'bgp-patch-%s' % suffix
        peer_name = 'int-patch-%s' % suffix
        with self.ovs_api.transaction(check_error=True) as txn:
            txn.add(self.ovs_api.add_port(other_bridge, port_name))
            txn.add(self.ovs_api.add_port(
                self.int_bridge_name, peer_name))
            txn.add(self.ovs_api.db_set(
                'Interface', port_name, type='patch',
                options={'peer': peer_name}))
            txn.add(self.ovs_api.db_set(
                'Interface', peer_name, type='patch',
                options={'peer': port_name}))
        self._check_flows_not_applied()


class BgpBridgeMappingsBase(BaseBgpEventsTestCase):
    def _watch_chassis_bgp_bridges(self, expected_bridges):
        wait_ev = WaitForChassisBGPBridgesEvent(
            self.CHASSIS_NAME, expected_bridges)
        self.sb_api.idl.notify_handler.watch_event(wait_ev)
        return wait_ev

    def _verify_chassis_bgp_bridges(self, wait_ev):
        if not wait_ev.wait():
            cp = self.sb_api.db_list_rows(
                'Chassis_Private', [self.CHASSIS_NAME]
            ).execute(check_error=True)[0]
            actual = cp.external_ids.get(
                constants.CHASSIS_BGP_BRIDGES_EXT_ID_KEY, '')
            self.fail(
                "Expected Chassis_Private bgp bridges %s, got %r"
                % (wait_ev.expected, actual))

    def _watch_mappings(self, key, expected_mappings):
        wait_ev = WaitForOVSExtIdEvent(key, expected_mappings)
        self.ovs_api.idl.notify_handler.watch_event(wait_ev)
        return wait_ev

    def _verify_mappings(self, wait_ev):
        if not wait_ev.wait():
            actual = self.ovs_api.db_get(
                'Open_vSwitch', '.', 'external_ids'
            ).execute(check_error=True).get(wait_ev.ext_id_key, '')
            self.fail(
                "Expected OVS external_ids[%s] = %s, got %r"
                % (wait_ev.ext_id_key, wait_ev.expected, actual))

    def _watch_bridge_mappings(self, expected):
        return self._watch_mappings('ovn-bridge-mappings', expected)

    def _watch_port_mappings(self, expected):
        return self._watch_mappings(
            constants.OVN_DYNAMIC_ROUTING_PORT_MAPPING, expected)


class CreateLocalOVSEventTestCase(BgpBridgeMappingsBase):
    def setUp(self):
        super().setUp()
        self.ovs_api.idl.notify_handler.watch_event(
            events.CreateLocalOVSEvent(self.agent_api))

    def trigger_event(self):
        self.ovs_api.restart_connection()

    def test_create_local_ovs_event(self):
        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids={
                constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp-1,br-bgp-2'}
        ).execute(check_error=True)
        expected_mappings = ['br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2']
        bm_ev = self._watch_bridge_mappings(expected_mappings)
        pm_ev = self._watch_port_mappings(expected_mappings)
        cp_ev = self._watch_chassis_bgp_bridges(['br-bgp-1', 'br-bgp-2'])

        self.trigger_event()

        self._verify_mappings(bm_ev)
        self._verify_mappings(pm_ev)
        self._verify_chassis_bgp_bridges(cp_ev)

    def test_create_local_ovs_event_existing_bridge_mappings(self):
        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids={
                'ovn-bridge-mappings': 'physnet:bridge',
                constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp-1,br-bgp-2'}
        ).execute(check_error=True)
        expected_bridge_mappings = [
            'physnet:bridge', 'br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2']
        expected_port_mappings = [
            'br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2']
        bm_ev = self._watch_bridge_mappings(expected_bridge_mappings)
        pm_ev = self._watch_port_mappings(expected_port_mappings)
        cp_ev = self._watch_chassis_bgp_bridges(['br-bgp-1', 'br-bgp-2'])

        self.trigger_event()

        self._verify_mappings(bm_ev)
        self._verify_mappings(pm_ev)
        self._verify_chassis_bgp_bridges(cp_ev)

    def test_create_local_ovs_no_chassis_private(self):
        """OVS reconnect while ovn-controller is stopped."""
        with self.sb_api.transaction(check_error=True) as txn:
            txn.add(self.sb_api.db_destroy(
                'Chassis_Private', self.CHASSIS_NAME))
            txn.add(self.sb_api.chassis_del(self.CHASSIS_NAME))

        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids={
                constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp-1,br-bgp-2'}
        ).execute(check_error=True)
        expected_mappings = ['br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2']
        bm_ev = self._watch_bridge_mappings(expected_mappings)
        pm_ev = self._watch_port_mappings(expected_mappings)

        self.trigger_event()

        self._verify_mappings(bm_ev)
        self._verify_mappings(pm_ev)

    def test_create_local_ovs_event_existing_bgp_in_bridge_mappings(self):
        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids={
                'ovn-bridge-mappings': 'physnet:bridge,br-bgp-1:br-bgp-1',
                constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp-1,br-bgp-2'}
        ).execute(check_error=True)
        expected_bridge_mappings = [
            'physnet:bridge', 'br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2']
        expected_port_mappings = [
            'br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2']
        bm_ev = self._watch_bridge_mappings(expected_bridge_mappings)
        pm_ev = self._watch_port_mappings(expected_port_mappings)
        cp_ev = self._watch_chassis_bgp_bridges(
            ['br-bgp-1', 'br-bgp-2'])

        self.trigger_event()

        self._verify_mappings(bm_ev)
        self._verify_mappings(pm_ev)
        self._verify_chassis_bgp_bridges(cp_ev)


class UpdateLocalOVSEventTestCase(BgpBridgeMappingsBase):
    def _test_helper(
            self, initial_ext_ids,
            new_ext_ids,
            expected_bridge_mappings,
            expected_port_mappings,
            expected_chassis_bgp_bridges):
        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids=initial_ext_ids
        ).execute(check_error=True)
        bm_ev = self._watch_bridge_mappings(expected_bridge_mappings)
        pm_ev = self._watch_port_mappings(expected_port_mappings)
        cp_ev = self._watch_chassis_bgp_bridges(
            expected_chassis_bgp_bridges)
        self.ovs_api.idl.notify_handler.watch_event(
            events.UpdateLocalOVSEvent(self.agent_api))

        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids=new_ext_ids
        ).execute(check_error=True)

        self._verify_mappings(bm_ev)
        self._verify_mappings(pm_ev)
        self._verify_chassis_bgp_bridges(cp_ev)

    def test_adding_bgp_bridge(self):
        self._test_helper(
            initial_ext_ids={
                'ovn-bridge-mappings': 'physnet:bridge',
            },
            new_ext_ids={
                constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp-1,br-bgp-2'},
            expected_bridge_mappings=[
                'physnet:bridge', 'br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2'],
            expected_port_mappings=[
                'br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2'],
            expected_chassis_bgp_bridges=['br-bgp-1', 'br-bgp-2'],
        )

    def test_removing_bgp_bridge(self):
        self._test_helper(
            initial_ext_ids={
                'ovn-bridge-mappings':
                    'physnet:bridge,br-bgp-1:br-bgp-1,br-bgp-2:br-bgp-2',
                constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp-1,br-bgp-2',
            },
            new_ext_ids={constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp-2'},
            expected_bridge_mappings=['physnet:bridge', 'br-bgp-2:br-bgp-2'],
            expected_port_mappings=['br-bgp-2:br-bgp-2'],
            expected_chassis_bgp_bridges=['br-bgp-2'],
        )

    def test_modifying_bgp_bridge(self):
        self._test_helper(
            initial_ext_ids={
                'ovn-bridge-mappings':
                    'physnet:bridge,br-bgp-1:br-bgp-1,br-bgp-2:br-bgp-2',
                constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp-1,br-bgp-2',
            },
            new_ext_ids={
                constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp-2,br-bgp-3'},
            expected_bridge_mappings=[
                'physnet:bridge', 'br-bgp-2:br-bgp-2', 'br-bgp-3:br-bgp-3'],
            expected_port_mappings=[
                'br-bgp-2:br-bgp-2', 'br-bgp-3:br-bgp-3'],
            expected_chassis_bgp_bridges=['br-bgp-2', 'br-bgp-3'],
        )

    def test_modifying_bridge_mappings(self):
        self._test_helper(
            initial_ext_ids={
                'ovn-bridge-mappings':
                    'physnet:bridge,br-bgp-1:br-bgp-1,br-bgp-2:br-bgp-2',
                constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp-1,br-bgp-2',
            },
            new_ext_ids={
                'ovn-bridge-mappings': 'physnet:bridge,br-bgp-2:br-bgp-2',
            },
            expected_bridge_mappings=[
                'physnet:bridge', 'br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2'],
            expected_port_mappings=[
                'br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2'],
            expected_chassis_bgp_bridges=['br-bgp-1', 'br-bgp-2'],
        )

    def test_unrelated_change_does_not_trigger_event(self):
        th_event = threading.Event()

        def event_run(event, row, old):
            th_event.set()

        with mock.patch.object(
                events.UpdateLocalOVSEvent, 'run', side_effect=event_run):
            self.ovs_api.idl.notify_handler.watch_event(
                events.UpdateLocalOVSEvent(self.agent_api))
            self.ovs_api.add_br('br-bgp-test').execute(check_error=True)
            self.assertFalse(th_event.wait(5))


class GetInterconnectBridgeNameTestCase(bgp_base.BaseBgpIDLTestCase):
    schemas = ['Open_vSwitch']

    def _set_ext_id(self, key, value):
        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids={key: value}
        ).execute(check_error=True)

    def _clear_ext_id(self, key):
        self.ovs_api.db_remove(
            'Open_vSwitch', '.', 'external_ids', key
        ).execute(check_error=True)

    def test_returns_bridge_name(self):
        self._set_ext_id(
            constants.AGENT_BGP_INTERCONNECT_BRIDGE, 'br-ic')
        result = events._get_interconnect_bridge_name(self.ovs_api.idl)
        self.assertEqual('br-ic', result)

    def test_strips_whitespace(self):
        self._set_ext_id(
            constants.AGENT_BGP_INTERCONNECT_BRIDGE, '  br-ic  ')
        result = events._get_interconnect_bridge_name(self.ovs_api.idl)
        self.assertEqual('br-ic', result)

    def test_missing_key_returns_none(self):
        self.assertIsNone(
            events._get_interconnect_bridge_name(self.ovs_api.idl))

    def test_empty_string_returns_none(self):
        self._set_ext_id(
            constants.AGENT_BGP_INTERCONNECT_BRIDGE, '')
        self.assertIsNone(
            events._get_interconnect_bridge_name(self.ovs_api.idl))

    def test_whitespace_only_returns_none(self):
        self._set_ext_id(
            constants.AGENT_BGP_INTERCONNECT_BRIDGE, '   ')
        self.assertIsNone(
            events._get_interconnect_bridge_name(self.ovs_api.idl))

    def test_value_updated(self):
        self._set_ext_id(
            constants.AGENT_BGP_INTERCONNECT_BRIDGE, 'br-old')
        self.assertEqual(
            'br-old',
            events._get_interconnect_bridge_name(self.ovs_api.idl))

        self._set_ext_id(
            constants.AGENT_BGP_INTERCONNECT_BRIDGE, 'br-new')
        self.assertEqual(
            'br-new',
            events._get_interconnect_bridge_name(self.ovs_api.idl))

    def test_value_cleared(self):
        self._set_ext_id(
            constants.AGENT_BGP_INTERCONNECT_BRIDGE, 'br-ic')
        self.assertEqual(
            'br-ic',
            events._get_interconnect_bridge_name(self.ovs_api.idl))

        self._clear_ext_id(constants.AGENT_BGP_INTERCONNECT_BRIDGE)
        self.assertIsNone(
            events._get_interconnect_bridge_name(self.ovs_api.idl))


class InterconnectBridgeEventBase(BaseBgpEventsTestCase):
    EVENT_CLASS = None

    def setUp(self):
        super().setUp()
        self.ovs_api.idl.notify_handler.watch_event(
            self.EVENT_CLASS(self.agent_api))


class InterconnectBridgeOVSEventTestCase(InterconnectBridgeEventBase):
    EVENT_CLASS = events.InterconnectBridgeOVSEvent

    def _set_interconnect_bridge(self, name):
        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids={constants.AGENT_BGP_INTERCONNECT_BRIDGE: name}
        ).execute(check_error=True)

    def _clear_interconnect_bridge(self):
        self.ovs_api.db_remove(
            'Open_vSwitch', '.', 'external_ids',
            constants.AGENT_BGP_INTERCONNECT_BRIDGE
        ).execute(check_error=True)

    def test_ext_id_set_bridge_exists(self):
        br_name = test_bgp.unique_bridge_name()
        self.ovs_api.add_br(br_name).execute(check_error=True)
        self._set_interconnect_bridge(br_name)
        utils.wait_until_true(
            lambda: (self.bgp_ext.interconnect_bridge is not None and
                     self.bgp_ext.interconnect_bridge.name == br_name),
            sleep=0.5, timeout=5,
            exception=Exception("InterconnectBridgeOVSEvent not triggered"))

    def test_ext_id_set_bridge_does_not_exist(self):
        sentinel_br = test_bgp.unique_bridge_name()
        self.ovs_api.add_br(sentinel_br).execute(check_error=True)
        self.bgp_ext.interconnect_bridge = bridge.BGPInterconnectBridge(
            self.bgp_ext, sentinel_br)

        br_name = test_bgp.unique_bridge_name()
        self._set_interconnect_bridge(br_name)
        utils.wait_until_true(
            lambda: self.bgp_ext.interconnect_bridge is None,
            sleep=0.5, timeout=5,
            exception=Exception("InterconnectBridgeOVSEvent not triggered"))

    def test_ext_id_cleared(self):
        br_name = test_bgp.unique_bridge_name()
        self.ovs_api.add_br(br_name).execute(check_error=True)
        self._set_interconnect_bridge(br_name)
        utils.wait_until_true(
            lambda: (self.bgp_ext.interconnect_bridge is not None and
                     self.bgp_ext.interconnect_bridge.name == br_name),
            sleep=0.5, timeout=5)

        self._clear_interconnect_bridge()
        utils.wait_until_true(
            lambda: self.bgp_ext.interconnect_bridge is None,
            sleep=0.5, timeout=5,
            exception=Exception("InterconnectBridgeOVSEvent not triggered "
                                "on clear"))

    def test_ext_id_changed(self):
        br_old = test_bgp.unique_bridge_name()
        br_new = test_bgp.unique_bridge_name()
        self.ovs_api.add_br(br_old).execute(check_error=True)
        self.ovs_api.add_br(br_new).execute(check_error=True)
        self._set_interconnect_bridge(br_old)
        utils.wait_until_true(
            lambda: (self.bgp_ext.interconnect_bridge is not None and
                     self.bgp_ext.interconnect_bridge.name == br_old),
            sleep=0.5, timeout=5)

        self._set_interconnect_bridge(br_new)
        utils.wait_until_true(
            lambda: (self.bgp_ext.interconnect_bridge is not None and
                     self.bgp_ext.interconnect_bridge.name == br_new),
            sleep=0.5, timeout=5,
            exception=Exception("InterconnectBridgeOVSEvent not triggered "
                                "on change"))

    def test_whitespace_only_change_does_not_trigger(self):
        br_name = test_bgp.unique_bridge_name()
        self.ovs_api.add_br(br_name).execute(check_error=True)
        self._set_interconnect_bridge(br_name)
        utils.wait_until_true(
            lambda: (self.bgp_ext.interconnect_bridge is not None and
                     self.bgp_ext.interconnect_bridge.name == br_name),
            sleep=0.5, timeout=5)

        self._set_interconnect_bridge(br_name + ' ')
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: (self.bgp_ext.interconnect_bridge is None or
                         self.bgp_ext.interconnect_bridge.name != br_name),
                sleep=0.5, timeout=5,
                exception=EventNotExpected())

    def test_next_cfg_update_does_not_trigger(self):
        init_br = test_bgp.unique_bridge_name()
        self.ovs_api.add_br(init_br).execute(check_error=True)
        self.bgp_ext.interconnect_bridge = bridge.BGPInterconnectBridge(
            self.bgp_ext, init_br)

        self._set_interconnect_bridge('br-ic')
        utils.wait_until_true(
            lambda: self.bgp_ext.interconnect_bridge is None,
            sleep=0.5, timeout=5)

        self.ovs_api.db_set(
            'Open_vSwitch', '.', next_cfg=2018).execute(check_error=True)
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: self.bgp_ext.interconnect_bridge is not None,
                sleep=0.5, timeout=5,
                exception=EventNotExpected())

    def test_unrelated_ext_id_change_does_not_trigger(self):
        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids={'some-other-key': 'value'}
        ).execute(check_error=True)
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: self.bgp_ext.interconnect_bridge is not None,
                sleep=0.5, timeout=5,
                exception=EventNotExpected())


class InterconnectBridgeCreatedEventTestCase(InterconnectBridgeEventBase):
    EVENT_CLASS = events.InterconnectBridgeCreatedEvent

    def test_bridge_created_matching_ext_id(self):
        br_name = test_bgp.unique_bridge_name()
        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids={constants.AGENT_BGP_INTERCONNECT_BRIDGE: br_name}
        ).execute(check_error=True)

        self.ovs_api.add_br(br_name).execute(check_error=True)
        utils.wait_until_true(
            lambda: (self.bgp_ext.interconnect_bridge is not None and
                     self.bgp_ext.interconnect_bridge.name == br_name),
            sleep=0.5, timeout=5,
            exception=Exception(
                "InterconnectBridgeCreatedEvent not triggered"))

    def test_bridge_created_not_matching_ext_id(self):
        br_name = test_bgp.unique_bridge_name()
        br_other = test_bgp.unique_bridge_name()
        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids={
                constants.AGENT_BGP_INTERCONNECT_BRIDGE: br_name}
        ).execute(check_error=True)

        self.ovs_api.add_br(br_other).execute(check_error=True)
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: self.bgp_ext.interconnect_bridge is not None,
                sleep=0.5, timeout=5,
                exception=EventNotExpected())

    def test_bridge_created_no_ext_id_set(self):
        br_name = test_bgp.unique_bridge_name()
        self.ovs_api.add_br(br_name).execute(check_error=True)
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: self.bgp_ext.interconnect_bridge is not None,
                sleep=0.5, timeout=5,
                exception=EventNotExpected())


class InterconnectBridgeDeletedEventTestCase(InterconnectBridgeEventBase):
    EVENT_CLASS = events.InterconnectBridgeDeletedEvent

    def test_interconnect_bridge_deleted(self):
        br_name = test_bgp.unique_bridge_name()
        self.ovs_api.add_br(br_name).execute(check_error=True)
        self.bgp_ext.interconnect_bridge = bridge.BGPInterconnectBridge(
            self.bgp_ext, br_name)

        self.ovs_api.del_br(br_name).execute(check_error=True)
        utils.wait_until_true(
            lambda: self.bgp_ext.interconnect_bridge is None,
            sleep=0.5, timeout=5,
            exception=Exception(
                "InterconnectBridgeDeletedEvent not triggered"))

    def test_non_interconnect_bridge_deleted(self):
        ic_name = test_bgp.unique_bridge_name()
        self.ovs_api.add_br(ic_name).execute(check_error=True)
        self.bgp_ext.interconnect_bridge = bridge.BGPInterconnectBridge(
            self.bgp_ext, ic_name)

        br_other = test_bgp.unique_bridge_name()
        self.ovs_api.add_br(br_other).execute(check_error=True)

        self.ovs_api.del_br(br_other).execute(check_error=True)
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: self.bgp_ext.interconnect_bridge is None,
                sleep=0.5, timeout=5,
                exception=EventNotExpected())

    def test_no_interconnect_bridge_set(self):
        br_name = test_bgp.unique_bridge_name()
        self.ovs_api.add_br(br_name).execute(check_error=True)

        self.ovs_api.del_br(br_name).execute(check_error=True)
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: self.bgp_ext.interconnect_bridge is not None,
                sleep=0.5, timeout=5,
                exception=EventNotExpected())


class InterconnectPatchPortEventBase(BaseBgpEventsTestCase):

    def setUp(self):
        super().setUp()
        self.ic_bridge_name = test_bgp.unique_bridge_name('ic')
        self.peer_bridge_name = test_bgp.unique_bridge_name('peer')

        self.ovs_api.add_br(self.ic_bridge_name).execute(check_error=True)
        self.ovs_api.add_br(self.peer_bridge_name).execute(check_error=True)

        self.bgp_ext.set_interconnect_bridge(self.ic_bridge_name)
        self.ic_bridge = self.bgp_ext.interconnect_bridge

        self.ovs_api.idl.notify_handler.watch_event(
            events.InterconnectPatchPortCreatedEvent(self.agent_api))
        self.ovs_api.idl.notify_handler.watch_event(
            events.InterconnectPatchPortDeletedEvent(self.agent_api))

    def _add_patch_port_pair(self, on_bridge, port_name, peer_name):
        with self.ovs_api.transaction(check_error=True) as txn:
            txn.add(self.ovs_api.add_port(on_bridge, port_name))
            txn.add(self.ovs_api.add_port(self.peer_bridge_name, peer_name))
            txn.add(self.ovs_api.db_set(
                'Interface', port_name, type='patch',
                options={'peer': peer_name},
                external_ids={
                    ovn_const.OVN_PHYSNET_EXT_ID_KEY: 'physnet',
                })
            )
            txn.add(self.ovs_api.db_set(
                'Interface', peer_name, type='patch',
                options={'peer': port_name}))


class InterconnectPatchPortCreatedEventTestCase(
        InterconnectPatchPortEventBase):

    def test_provider_patch_port_created(self):
        port_name = utils.get_rand_name(prefix='patch-provnet-')
        peer_name = utils.get_rand_name(max_length=14, prefix='peer')
        self._add_patch_port_pair(
            self.ic_bridge_name, port_name, peer_name)
        utils.wait_until_true(
            lambda: self.ic_bridge.provider_patch_port == port_name,
            sleep=0.5, timeout=5,
            exception=Exception(
                "Provider patch port not detected on IC bridge"))
        self.assertGreater(self.ic_bridge.provider_patch_ofport, 0)

    def test_bgp_patch_port_created(self):
        port_name = utils.get_rand_name(max_length=14, prefix='bgp')
        peer_name = utils.get_rand_name(max_length=14, prefix='peer')
        self._add_patch_port_pair(
            self.ic_bridge_name, port_name, peer_name)
        utils.wait_until_true(
            lambda: self.ic_bridge.bgp_patch_port == port_name,
            sleep=0.5, timeout=5,
            exception=Exception(
                "BGP patch port not detected on IC bridge"))
        self.assertGreater(self.ic_bridge.bgp_patch_ofport, 0)

    def test_both_patch_ports_meet_requirements(self):
        prov_name = utils.get_rand_name(prefix='patch-provnet-')
        prov_peer = utils.get_rand_name(max_length=14, prefix='peer')
        bgp_name = utils.get_rand_name(max_length=14, prefix='bgp')
        bgp_peer = utils.get_rand_name(max_length=14, prefix='peer')
        self._add_patch_port_pair(
            self.ic_bridge_name, prov_name, prov_peer)
        self._add_patch_port_pair(
            self.ic_bridge_name, bgp_name, bgp_peer)
        utils.wait_until_true(
            lambda: (self.ic_bridge.provider_patch_port == prov_name and
                     self.ic_bridge.bgp_patch_port == bgp_name),
            sleep=0.5, timeout=5,
            exception=Exception(
                "Both patch ports not detected on IC bridge"))
        self.assertGreater(self.ic_bridge.provider_patch_ofport, 0)
        self.assertGreater(self.ic_bridge.bgp_patch_ofport, 0)

    def test_patch_port_on_other_bridge_does_not_trigger(self):
        other_bridge = test_bgp.unique_bridge_name('other')
        self.ovs_api.add_br(other_bridge).execute(check_error=True)
        port_name = utils.get_rand_name(max_length=14, prefix='oth')
        peer_name = utils.get_rand_name(max_length=14, prefix='peer')
        self._add_patch_port_pair(other_bridge, port_name, peer_name)
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: (self.ic_bridge.provider_patch_port is not None or
                         self.ic_bridge.bgp_patch_port is not None),
                sleep=0.5, timeout=5,
                exception=EventNotExpected())

    def test_non_patch_port_does_not_trigger(self):
        fake_nic = self.useFixture(net_helpers.VethFixture()).ports[0]
        self.ovs_api.add_port(
            self.ic_bridge_name, fake_nic.name
        ).execute(check_error=True)
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: (self.ic_bridge.provider_patch_port is not None or
                         self.ic_bridge.bgp_patch_port is not None),
                sleep=0.5, timeout=5,
                exception=EventNotExpected())

    def test_no_ic_bridge_set_does_not_trigger(self):
        self.bgp_ext.interconnect_bridge = None
        port_name = utils.get_rand_name(max_length=14, prefix='bgp')
        peer_name = utils.get_rand_name(max_length=14, prefix='peer')
        self._add_patch_port_pair(
            self.ic_bridge_name, port_name, peer_name)
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: (self.ic_bridge.provider_patch_port is not None or
                         self.ic_bridge.bgp_patch_port is not None),
                sleep=0.5, timeout=5,
                exception=EventNotExpected())

    def test_external_ids_change_does_not_retrigger(self):
        port_name = utils.get_rand_name(max_length=14, prefix='bgp')
        peer_name = utils.get_rand_name(max_length=14, prefix='peer')
        self._add_patch_port_pair(
            self.ic_bridge_name, port_name, peer_name)
        utils.wait_until_true(
            lambda: self.ic_bridge.bgp_patch_port == port_name,
            sleep=0.5, timeout=5)

        with mock.patch.object(self.ic_bridge, 'add_patch_port') as m:
            self.ovs_api.db_set(
                'Interface', port_name,
                external_ids={'foo': 'bar'}
            ).execute(check_error=True)
            with testtools.ExpectedException(EventNotExpected):
                utils.wait_until_true(
                    lambda: m.called,
                    sleep=0.5, timeout=5,
                    exception=EventNotExpected())

    def test_statistics_change_does_not_retrigger(self):
        port_name = utils.get_rand_name(max_length=14, prefix='bgp')
        peer_name = utils.get_rand_name(max_length=14, prefix='peer')
        self._add_patch_port_pair(
            self.ic_bridge_name, port_name, peer_name)
        utils.wait_until_true(
            lambda: self.ic_bridge.bgp_patch_port == port_name,
            sleep=0.5, timeout=5)

        with mock.patch.object(self.ic_bridge, 'add_patch_port') as m:
            self.ovs_api.db_set(
                'Interface', port_name,
                mtu_request=1500
            ).execute(check_error=True)
            with testtools.ExpectedException(EventNotExpected):
                utils.wait_until_true(
                    lambda: m.called,
                    sleep=0.5, timeout=5,
                    exception=EventNotExpected())


class InterconnectPatchPortDeletedEventTestCase(
        InterconnectPatchPortEventBase):

    def test_provider_patch_port_deleted(self):
        port_name = utils.get_rand_name(prefix='patch-provnet-')
        peer_name = utils.get_rand_name(max_length=14, prefix='peer')
        self._add_patch_port_pair(
            self.ic_bridge_name, port_name, peer_name)
        utils.wait_until_true(
            lambda: self.ic_bridge.provider_patch_port == port_name,
            sleep=0.5, timeout=5)

        self.ovs_api.del_port(port_name).execute(check_error=True)
        utils.wait_until_true(
            lambda: self.ic_bridge.provider_patch_port is None,
            sleep=0.5, timeout=5,
            exception=Exception(
                "Provider patch port not removed from IC bridge"))
        self.assertFalse(self.ic_bridge.check_requirements_for_flows_met())

    def test_bgp_patch_port_deleted(self):
        port_name = utils.get_rand_name(max_length=14, prefix='bgp')
        peer_name = utils.get_rand_name(max_length=14, prefix='peer')
        self._add_patch_port_pair(
            self.ic_bridge_name, port_name, peer_name)
        utils.wait_until_true(
            lambda: self.ic_bridge.bgp_patch_port == port_name,
            sleep=0.5, timeout=5)

        self.ovs_api.del_port(port_name).execute(check_error=True)
        utils.wait_until_true(
            lambda: self.ic_bridge.bgp_patch_port is None,
            sleep=0.5, timeout=5,
            exception=Exception(
                "BGP patch port not removed from IC bridge"))
        self.assertFalse(self.ic_bridge.check_requirements_for_flows_met())

    def test_untracked_port_deleted_does_not_affect_bridge(self):
        other_bridge = test_bgp.unique_bridge_name('other')
        self.ovs_api.add_br(other_bridge).execute(check_error=True)
        other_port = utils.get_rand_name(max_length=14, prefix='oth')
        other_peer = utils.get_rand_name(max_length=14, prefix='peer')
        self._add_patch_port_pair(other_bridge, other_port, other_peer)

        bgp_port = utils.get_rand_name(max_length=14, prefix='bgp')
        bgp_peer = utils.get_rand_name(max_length=14, prefix='peer')
        self._add_patch_port_pair(
            self.ic_bridge_name, bgp_port, bgp_peer)
        utils.wait_until_true(
            lambda: self.ic_bridge.bgp_patch_port == bgp_port,
            sleep=0.5, timeout=5)

        self.ovs_api.del_port(other_port).execute(check_error=True)
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: self.ic_bridge.bgp_patch_port is None,
                sleep=0.5, timeout=5,
                exception=EventNotExpected())


class ChassisPrivateCreateEventTestCase(BaseBgpEventsTestCase):

    def _create_initial_resources(self):
        """Skip chassis creation; tests trigger it explicitly.

        Set BGP peer bridges in OVS external_ids — this is the
        operator-configured source that persists across
        ovn-controller restarts.
        """
        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids={
                constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp-1,br-bgp-2'}
        ).execute(check_error=True)

    def _register_event(self):
        ev = events.ChassisPrivateCreateEvent(self.agent_api)
        self.sb_api.idl.notify_handler.watch_event(ev)
        return ev

    def _create_chassis(self, name):
        self.add_fake_chassis(name, '192.168.1.100')

    def _wait_for_bgp_bridges(self, expected_bridges_str, timeout=10):
        wait_ev = test_bgp.WaitForChassisBgpBridgesEvent(
            self.CHASSIS_NAME, expected_bridges_str, timeout=timeout)
        self.sb_api.idl.notify_handler.watch_event(wait_ev)
        return wait_ev

    def test_chassis_private_create_sets_bgp_bridges(self):
        self._register_event()

        wait_ev = self._wait_for_bgp_bridges('br-bgp-1,br-bgp-2')
        self._create_chassis(self.CHASSIS_NAME)
        self.assertTrue(
            wait_ev.wait(),
            "Chassis_Private was not updated with BGP bridges")

    def test_chassis_private_create_no_bridges_does_not_trigger(self):
        self._register_event()
        self.ovs_api.db_remove(
            'Open_vSwitch', '.',
            'external_ids', constants.AGENT_BGP_PEER_BRIDGES
        ).execute(check_error=True)

        wait_ev = self._wait_for_bgp_bridges('', timeout=2)
        self._create_chassis(self.CHASSIS_NAME)
        self.assertFalse(
            wait_ev.wait(),
            "Chassis_Private should not be updated when no bridges exist")

    def test_other_chassis_does_not_trigger(self):
        self._register_event()

        wait_ev = self._wait_for_bgp_bridges('br-bgp-1,br-bgp-2', timeout=2)
        self._create_chassis('other-chassis')
        self.assertFalse(
            wait_ev.wait(),
            "Chassis_Private for a different chassis should not be updated")

    def test_chassis_private_recreate_resets_bgp_bridges(self):
        """Simulate ovn-controller restart: delete + create."""
        self._register_event()

        wait_ev = self._wait_for_bgp_bridges('br-bgp-1,br-bgp-2')
        self._create_chassis(self.CHASSIS_NAME)
        self.assertTrue(
            wait_ev.wait(),
            "Chassis_Private was not updated on first create")

        # Delete the old Chassis + Chassis_Private (simulating
        # ovn-controller shutdown)
        with self.sb_api.transaction(check_error=True) as txn:
            txn.add(self.sb_api.db_destroy(
                'Chassis_Private', self.CHASSIS_NAME))
            txn.add(self.sb_api.chassis_del(self.CHASSIS_NAME))

        # Re-create (simulating ovn-controller restart)
        wait_ev = self._wait_for_bgp_bridges('br-bgp-1,br-bgp-2')
        self._create_chassis(self.CHASSIS_NAME)
        self.assertTrue(
            wait_ev.wait(),
            "Chassis_Private was not updated after re-create")
