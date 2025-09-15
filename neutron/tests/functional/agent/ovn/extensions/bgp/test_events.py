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
