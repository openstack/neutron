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
import testtools

from neutron.agent.ovn.extensions.bgp import bridge
from neutron.agent.ovn.extensions.bgp import events
from neutron.common.ovn import constants as ovn_const
from neutron.common import utils
from neutron.services.bgp import constants
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.ovn.extensions import bgp as test_bgp
from neutron.tests.functional.services import bgp as bgp_base


class BridgeNotMatchedException(Exception):
    def __init__(self):
        super().__init__("BGP bridge event was not matched")


class EventNotExpected(Exception):
    pass


class BaseBgpEventsTestCase(bgp_base.BaseBgpIDLTestCase):
    schemas = ['Open_vSwitch']


class FakeAgentAPI:
    def __init__(self, ovs_idl):
        self.ovs_idl = ovs_idl
        self.bgp_extension = mock.Mock(interconnect_bridge=None)

    def __getitem__(self, key):
        if key == constants.AGENT_BGP_EXT_NAME:
            return self.bgp_extension
        raise KeyError(key)


class NewBgpBridgeEventTestCase(BaseBgpEventsTestCase):
    def setUp(self):
        super().setUp()
        self.bgp_ext = mock.Mock()
        self.agent_api = {constants.AGENT_BGP_EXT_NAME: self.bgp_ext}

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
                lambda: self.bgp_ext.create_bgp_bridge.called,
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
            lambda: self.bgp_ext.create_bgp_bridge.called,
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
            lambda: self.bgp_ext.create_bgp_bridge.called,
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
    def setUp(self):
        super().setUp()
        self.bgp_ext = mock.Mock()
        self.agent_api = {constants.AGENT_BGP_EXT_NAME: self.bgp_ext}
        self.bgp_bridge_name = 'br-bgp'

        self.bridge_mock = mock.Mock()
        self.bridge_mock.check_requirements_for_flows_met.return_value = True
        self.bgp_ext.bgp_bridges = {self.bgp_bridge_name: self.bridge_mock}

        self.int_bridge_name = 'br-int-%s' % uuidutils.generate_uuid()[:8]
        for br in (self.bgp_bridge_name, self.int_bridge_name):
            self.ovs_api.add_br(br).execute(check_error=True)

    def _register_event(self, *port_types):
        ev = events.BGPBridgePortCreatedEvent(
            self.agent_api, self.bgp_bridge_name, *port_types)
        ev._get_port_bridge = mock.Mock(return_value=self.bgp_bridge_name)
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
            lambda: self.bridge_mock.configure_flows.called,
            timeout=5,
            exception=Exception("configure_flows was not called"))

    def _check_flows_not_applied(self):
        with testtools.ExpectedException(Exception):
            utils.wait_until_true(
                lambda: self.bridge_mock.configure_flows.called,
                sleep=0.5,
                timeout=2,
                exception=Exception("configure_flows was unexpectedly called"))

    def test_patch_port_created_configures_flows(self):
        self._register_event('patch')
        self._add_patch_ports()
        self._check_flows_applied()

    def test_nic_port_created_configures_flows(self):
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
        ev = self._register_event('patch')
        ev._get_port_bridge = mock.Mock(return_value='other-bridge')
        self._add_patch_ports()
        self._check_flows_not_applied()


class BgpBridgeMappingsBase(BaseBgpEventsTestCase):
    def setUp(self):
        super().setUp()
        self.agent_api = FakeAgentAPI(self.ovs_api)

    def _verify_mappings(self, key, expected_mappings):
        def wait_for_mappings():
            try:
                mappings = self.ovs_api.db_get(
                    'Open_vSwitch', '.', 'external_ids'
                ).execute(check_error=True)[key]
            except KeyError:
                mappings = ''
            if mappings:
                mappings = sorted(mappings.split(','))
            return mappings == sorted(expected_mappings)

        utils.wait_until_true(
            wait_for_mappings,
            sleep=0.1,
            timeout=5,
            exception=Exception(
                f"Expected {key} {expected_mappings} were not configured",
            ))

    def _verify_bridge_mappings(self, expected_bridge_mappings):
        self._verify_mappings('ovn-bridge-mappings', expected_bridge_mappings)

    def _verify_port_mappings(self, expected_port_mappings):
        self._verify_mappings(
            constants.OVN_DYNAMIC_ROUTING_PORT_MAPPING, expected_port_mappings)


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
        self.trigger_event()
        expected_mappings = ['br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2']
        self._verify_bridge_mappings(expected_mappings)
        self._verify_port_mappings(expected_mappings)

    def test_create_local_ovs_event_existing_bridge_mappings(self):
        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids={
                'ovn-bridge-mappings': 'physnet:bridge',
                constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp-1,br-bgp-2'}
        ).execute(check_error=True)
        self.trigger_event()
        expected_bridge_mappings = [
            'physnet:bridge', 'br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2']
        expected_port_mappings = [
            'br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2']
        self._verify_bridge_mappings(expected_bridge_mappings)
        self._verify_port_mappings(expected_port_mappings)

    def test_create_local_ovs_event_existing_bgp_in_bridge_mappings(self):
        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids={
                'ovn-bridge-mappings': 'physnet:bridge,br-bgp-1:br-bgp-1',
                constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp-1,br-bgp-2'}
        ).execute(check_error=True)
        self.trigger_event()
        expected_bridge_mappings = [
            'physnet:bridge', 'br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2']
        expected_port_mappings = [
            'br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2']
        self._verify_bridge_mappings(expected_bridge_mappings)
        self._verify_port_mappings(expected_port_mappings)


class UpdateLocalOVSEventTestCase(BgpBridgeMappingsBase):
    def _test_helper(
            self, initial_ext_ids,
            new_ext_ids,
            expected_bridge_mappings,
            expected_port_mappings):
        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids=initial_ext_ids
        ).execute(check_error=True)
        self.ovs_api.idl.notify_handler.watch_event(
            events.UpdateLocalOVSEvent(self.agent_api))

        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids=new_ext_ids
        ).execute(check_error=True)

        self._verify_bridge_mappings(expected_bridge_mappings)
        self._verify_port_mappings(expected_port_mappings)

    def test_adding_bgp_bridge(self):
        self._test_helper(
            initial_ext_ids={
                'ovn-bridge-mappings': 'physnet:bridge',
            },
            new_ext_ids={
                constants.AGENT_BGP_PEER_BRIDGES: 'br-bgp-1,br-bgp-2'},
            expected_bridge_mappings=[
                'physnet:bridge', 'br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2'],
            expected_port_mappings=['br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2']
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
            expected_port_mappings=['br-bgp-2:br-bgp-2']
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
            expected_port_mappings=['br-bgp-2:br-bgp-2', 'br-bgp-3:br-bgp-3']
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
            expected_port_mappings=['br-bgp-1:br-bgp-1', 'br-bgp-2:br-bgp-2']
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


class InterconnectBridgeEventBase(BaseBgpEventsTestCase):
    EVENT_CLASS = None

    def setUp(self):
        super().setUp()
        self.agent_api = FakeAgentAPI(self.ovs_api)
        self.bgp_ext = self.agent_api.bgp_extension
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
            lambda: self.bgp_ext.set_interconnect_bridge.called,
            sleep=0.5, timeout=5,
            exception=Exception("InterconnectBridgeOVSEvent not triggered"))

    def test_ext_id_set_bridge_does_not_exist(self):
        br_name = test_bgp.unique_bridge_name()
        self._set_interconnect_bridge(br_name)
        utils.wait_until_true(
            lambda: self.bgp_ext.clear_interconnect_bridge.called,
            sleep=0.5, timeout=5,
            exception=Exception("InterconnectBridgeOVSEvent not triggered"))

    def test_ext_id_cleared(self):
        br_name = test_bgp.unique_bridge_name()
        self.ovs_api.add_br(br_name).execute(check_error=True)
        self._set_interconnect_bridge(br_name)
        utils.wait_until_true(
            lambda: self.bgp_ext.set_interconnect_bridge.called,
            sleep=0.5, timeout=5)

        self._clear_interconnect_bridge()
        utils.wait_until_true(
            lambda: self.bgp_ext.clear_interconnect_bridge.called,
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
            lambda: self.bgp_ext.set_interconnect_bridge.called,
            sleep=0.5, timeout=5)
        self.bgp_ext.set_interconnect_bridge.reset_mock()

        self._set_interconnect_bridge(br_new)
        utils.wait_until_true(
            lambda: self.bgp_ext.set_interconnect_bridge.called,
            sleep=0.5, timeout=5,
            exception=Exception("InterconnectBridgeOVSEvent not triggered "
                                "on change"))
        self.bgp_ext.set_interconnect_bridge.assert_called_with(br_new)

    def test_whitespace_only_change_does_not_trigger(self):
        br_name = test_bgp.unique_bridge_name()
        self.ovs_api.add_br(br_name).execute(check_error=True)
        self._set_interconnect_bridge(br_name)
        utils.wait_until_true(
            lambda: self.bgp_ext.set_interconnect_bridge.called,
            sleep=0.5, timeout=5)
        self.bgp_ext.set_interconnect_bridge.reset_mock()
        self.bgp_ext.clear_interconnect_bridge.reset_mock()

        self._set_interconnect_bridge(br_name + ' ')
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: (self.bgp_ext.set_interconnect_bridge.called or
                         self.bgp_ext.clear_interconnect_bridge.called),
                sleep=0.5, timeout=5,
                exception=EventNotExpected())

    def test_next_cfg_update_does_not_trigger(self):
        self._set_interconnect_bridge('br-ic')
        utils.wait_until_true(
            lambda: self.bgp_ext.clear_interconnect_bridge.called,
            sleep=0.5, timeout=5)
        self.bgp_ext.reset_mock()

        self.ovs_api.db_set(
            'Open_vSwitch', '.', next_cfg=2018).execute(check_error=True)
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: (self.bgp_ext.set_interconnect_bridge.called or
                         self.bgp_ext.clear_interconnect_bridge.called),
                sleep=0.5, timeout=5,
                exception=EventNotExpected())

    def test_unrelated_ext_id_change_does_not_trigger(self):
        self.ovs_api.db_set(
            'Open_vSwitch', '.',
            external_ids={'some-other-key': 'value'}
        ).execute(check_error=True)
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: self.bgp_ext.set_interconnect_bridge.called,
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
            lambda: self.bgp_ext.set_interconnect_bridge.called,
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
                lambda: self.bgp_ext.set_interconnect_bridge.called,
                sleep=0.5, timeout=5,
                exception=EventNotExpected())

    def test_bridge_created_no_ext_id_set(self):
        br_name = test_bgp.unique_bridge_name()
        self.ovs_api.add_br(br_name).execute(check_error=True)
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: self.bgp_ext.set_interconnect_bridge.called,
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
            lambda: self.bgp_ext.clear_interconnect_bridge.called,
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
                lambda: self.bgp_ext.clear_interconnect_bridge.called,
                sleep=0.5, timeout=5,
                exception=EventNotExpected())

    def test_no_interconnect_bridge_set(self):
        br_name = test_bgp.unique_bridge_name()
        self.ovs_api.add_br(br_name).execute(check_error=True)

        self.ovs_api.del_br(br_name).execute(check_error=True)
        with testtools.ExpectedException(EventNotExpected):
            utils.wait_until_true(
                lambda: self.bgp_ext.clear_interconnect_bridge.called,
                sleep=0.5, timeout=5,
                exception=EventNotExpected())


class InterconnectPatchPortEventBase(BaseBgpEventsTestCase):

    def setUp(self):
        super().setUp()
        self.agent_api = FakeAgentAPI(self.ovs_api)
        self.bgp_ext = self.agent_api.bgp_extension
        self.ic_bridge_name = test_bgp.unique_bridge_name('ic')
        self.peer_bridge_name = test_bgp.unique_bridge_name('peer')

        self.ovs_api.add_br(self.ic_bridge_name).execute(check_error=True)
        self.ovs_api.add_br(self.peer_bridge_name).execute(check_error=True)

        self.ic_bridge = bridge.BGPInterconnectBridge(
            self.bgp_ext, self.ic_bridge_name)
        self.ic_bridge.ovs_bridge.ovsdb = self.ovs_api
        self.bgp_ext.interconnect_bridge = self.ic_bridge

        self.ovs_api.idl.notify_handler.watch_event(
            events.InterconnectPatchPortCreatedEvent(self.agent_api))
        self.ovs_api.idl.notify_handler.watch_event(
            events.InterconnectPatchPortDeletedEvent(self.agent_api))

    def _add_patch_port_pair(self, on_bridge, port_name, peer_name,
                             port_external_ids=None):
        with self.ovs_api.transaction(check_error=True) as txn:
            txn.add(self.ovs_api.add_port(on_bridge, port_name))
            txn.add(self.ovs_api.add_port(self.peer_bridge_name, peer_name))
            txn.add(self.ovs_api.db_set(
                'Interface', port_name, type='patch',
                options={'peer': peer_name}))
            txn.add(self.ovs_api.db_set(
                'Interface', peer_name, type='patch',
                options={'peer': port_name}))
            if port_external_ids:
                txn.add(self.ovs_api.db_set(
                    'Port', port_name,
                    external_ids=port_external_ids))


class InterconnectPatchPortCreatedEventTestCase(
        InterconnectPatchPortEventBase):

    def test_provider_patch_port_created(self):
        port_name = utils.get_rand_name(max_length=14, prefix='prov')
        peer_name = utils.get_rand_name(max_length=14, prefix='peer')
        self._add_patch_port_pair(
            self.ic_bridge_name, port_name, peer_name,
            port_external_ids={
                ovn_const.OVN_PHYSNET_EXT_ID_KEY: 'public'})
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
        prov_name = utils.get_rand_name(max_length=14, prefix='prov')
        prov_peer = utils.get_rand_name(max_length=14, prefix='peer')
        bgp_name = utils.get_rand_name(max_length=14, prefix='bgp')
        bgp_peer = utils.get_rand_name(max_length=14, prefix='peer')
        self._add_patch_port_pair(
            self.ic_bridge_name, prov_name, prov_peer,
            port_external_ids={
                ovn_const.OVN_PHYSNET_EXT_ID_KEY: 'public'})
        self._add_patch_port_pair(
            self.ic_bridge_name, bgp_name, bgp_peer)
        utils.wait_until_true(
            lambda: (self.ic_bridge.provider_patch_port == prov_name and
                     self.ic_bridge.bgp_patch_port == bgp_name),
            sleep=0.5, timeout=5,
            exception=Exception(
                "Both patch ports not detected on IC bridge"))
        self.assertTrue(self.ic_bridge.check_requirements_for_flows_met())
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
        port_name = utils.get_rand_name(max_length=14, prefix='prov')
        peer_name = utils.get_rand_name(max_length=14, prefix='peer')
        self._add_patch_port_pair(
            self.ic_bridge_name, port_name, peer_name,
            port_external_ids={
                ovn_const.OVN_PHYSNET_EXT_ID_KEY: 'public'})
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
