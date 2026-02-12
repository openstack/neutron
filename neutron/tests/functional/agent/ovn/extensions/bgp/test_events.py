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

from unittest import mock

import testtools

from neutron.agent.ovn.extensions.bgp import events
from neutron.common import utils
from neutron.services.bgp import constants
from neutron.tests.common import net_helpers
from neutron.tests.functional.services import bgp as bgp_base


class BridgeNotMatchedException(Exception):
    def __init__(self):
        super().__init__("BGP bridge event was not matched")


class BaseBgpEventsTestCase(bgp_base.BaseBgpIDLTestCase):
    schemas = ['Open_vSwitch']


class FakeAgentAPI:
    def __init__(self, ovs_idl):
        self.ovs_idl = ovs_idl

    def set_chassis_bgp_bridges(self, bridge_names):
        pass


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
