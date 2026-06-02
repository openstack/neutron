# Copyright 2026 Red Hat, LLC
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

from neutron.agent.ovn.extensions.evpn import fsm
from neutron.agent.ovn.extensions.evpn import netlink_monitor
from neutron.tests import base

BR_MTU = 1500


class TestEvpnFSM(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.mock_svd = mock.Mock()
        self.mock_config = mock.Mock()
        self.evpn_fsm = fsm.EvpnFSM(self.mock_svd, self.mock_config)
        self.mock_config.br_mtu = BR_MTU

    def test_vrf_then_port_binding_create(self):
        vrf = 'vr0a1b2c3d-fff'
        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_VRF_CREATE, vrf)
        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_PORT_BINDING_CREATE,
            vrf, mac='aa:bb:cc:dd:ee:ff', vni=10, vid=1)
        evpn = self.evpn_fsm.instances[vrf]
        self.assertEqual(fsm.Evpn.ADVERTISING, evpn.state)
        self.assertEqual('aa:bb:cc:dd:ee:ff', evpn.mac)
        self.assertEqual(10, evpn.vni)
        self.assertEqual(1, evpn.vid)
        self.assertTrue(evpn.vrf_up)
        self.mock_svd.add_vni.assert_called_once_with(
            10, 1, vrf, 'aa:bb:cc:dd:ee:ff', BR_MTU)

    def test_port_binding_then_vrf_create(self):
        vrf = 'vr0a1b2c3d-fff'
        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_PORT_BINDING_CREATE,
            vrf, mac='aa:bb:cc:dd:ee:ff', vni=10, vid=1)
        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_VRF_CREATE, vrf)
        evpn = self.evpn_fsm.instances[vrf]
        self.assertEqual(fsm.Evpn.ADVERTISING, evpn.state)
        self.assertEqual('aa:bb:cc:dd:ee:ff', evpn.mac)
        self.assertEqual(10, evpn.vni)
        self.assertEqual(1, evpn.vid)
        self.assertTrue(evpn.vrf_up)
        self.mock_svd.add_vni.assert_called_once_with(
            10, 1, vrf, 'aa:bb:cc:dd:ee:ff', BR_MTU)

    def test_advertise_then_port_binding_delete(self):
        vrf = 'vr0a1b2c3d-fff'
        evpn = fsm.Evpn(vrf)
        evpn.mac = 'aa:bb:cc:dd:ee:ff'
        evpn.vni = 10
        evpn.vid = 1
        evpn.vrf_up = True
        evpn.state = fsm.Evpn.ADVERTISING
        self.evpn_fsm.instances[vrf] = evpn

        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_VRF_DELETE, vrf)
        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_PORT_BINDING_DELETE, vrf)
        self.assertNotIn(vrf, self.evpn_fsm.instances)
        self.mock_svd.del_vni.assert_called_once_with(10, 1)

    def test_advertise_then_vrf_delete(self):
        vrf = 'vr0a1b2c3d-fff'
        evpn = fsm.Evpn(vrf)
        evpn.mac = 'aa:bb:cc:dd:ee:ff'
        evpn.vni = 10
        evpn.vid = 1
        evpn.vrf_up = True
        evpn.state = fsm.Evpn.ADVERTISING
        self.evpn_fsm.instances[vrf] = evpn

        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_PORT_BINDING_DELETE, vrf)
        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_VRF_DELETE, vrf)
        self.assertNotIn(vrf, self.evpn_fsm.instances)
        self.mock_svd.del_vni.assert_called_once_with(10, 1)

    def test_simultaneous_vrf_and_port_binding_create(self):
        """Netlink and SB IDL threads both create for the same VRF."""
        vrf = 'vr0a1b2c3d-fff'
        barrier = threading.Barrier(2)

        def netlink_thread():
            barrier.wait()
            self.evpn_fsm.advance(
                fsm.EvpnFSM.FSM_EVENT_VRF_CREATE, vrf)

        def idl_thread():
            barrier.wait()
            self.evpn_fsm.advance(
                fsm.EvpnFSM.FSM_EVENT_PORT_BINDING_CREATE,
                vrf, mac='aa:bb:cc:dd:ee:ff', vni=10, vid=1)

        threads = [threading.Thread(target=netlink_thread),
                   threading.Thread(target=idl_thread)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        evpn = self.evpn_fsm.instances[vrf]
        self.assertEqual(fsm.Evpn.ADVERTISING, evpn.state)
        self.assertEqual('aa:bb:cc:dd:ee:ff', evpn.mac)
        self.assertEqual(10, evpn.vni)
        self.assertEqual(1, evpn.vid)
        self.assertTrue(evpn.vrf_up)

    def test_simultaneous_vrf_and_port_binding_delete(self):
        """Netlink and SB IDL threads both delete for the same VRF."""
        vrf = 'vr0a1b2c3d-fff'
        evpn = fsm.Evpn(vrf)
        evpn.mac = 'aa:bb:cc:dd:ee:ff'
        evpn.vni = 10
        evpn.vid = 1
        evpn.vrf_up = True
        evpn.state = fsm.Evpn.ADVERTISING
        self.evpn_fsm.instances[vrf] = evpn

        barrier = threading.Barrier(2)

        def netlink_thread():
            barrier.wait()
            self.evpn_fsm.advance(
                fsm.EvpnFSM.FSM_EVENT_VRF_DELETE, vrf)

        def idl_thread():
            barrier.wait()
            self.evpn_fsm.advance(
                fsm.EvpnFSM.FSM_EVENT_PORT_BINDING_DELETE, vrf)

        threads = [threading.Thread(target=netlink_thread),
                   threading.Thread(target=idl_thread)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertNotIn(vrf, self.evpn_fsm.instances)

    def test_advertise_then_vrf_delete_then_vrf_create(self):
        vrf = 'vr0a1b2c3d-fff'
        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_VRF_CREATE, vrf)
        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_PORT_BINDING_CREATE,
            vrf, mac='aa:bb:cc:dd:ee:ff', vni=10, vid=1)
        evpn = self.evpn_fsm.instances[vrf]
        self.assertEqual(fsm.Evpn.ADVERTISING, evpn.state)

        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_VRF_DELETE, vrf)
        self.assertEqual(fsm.Evpn.WAITING_FOR_ROUTER, evpn.state)
        self.mock_svd.del_vni.assert_called_once_with(10, 1)

        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_VRF_CREATE, vrf)
        self.assertEqual(fsm.Evpn.ADVERTISING, evpn.state)
        self.assertEqual(2, self.mock_svd.add_vni.call_count)

    def test_advertise_then_port_binding_delete_then_port_binding_create(self):
        vrf = 'vr0a1b2c3d-fff'
        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_PORT_BINDING_CREATE,
            vrf, mac='aa:bb:cc:dd:ee:ff', vni=10, vid=1)
        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_VRF_CREATE, vrf)
        evpn = self.evpn_fsm.instances[vrf]
        self.assertEqual(fsm.Evpn.ADVERTISING, evpn.state)

        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_PORT_BINDING_DELETE, vrf)
        self.assertEqual(fsm.Evpn.WAITING_FOR_BRIDGE, evpn.state)
        self.assertIsNone(evpn.mac)
        self.assertIsNone(evpn.vni)
        self.assertIsNone(evpn.vid)
        self.mock_svd.del_vni.assert_called_once_with(10, 1)

        self.evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_PORT_BINDING_CREATE,
            vrf, mac='11:22:33:44:55:66', vni=20, vid=2)
        self.assertEqual(fsm.Evpn.ADVERTISING, evpn.state)
        self.assertEqual('11:22:33:44:55:66', evpn.mac)
        self.assertEqual(20, evpn.vni)
        self.assertEqual(2, evpn.vid)
        self.assertEqual(2, self.mock_svd.add_vni.call_count)

    def test_replay_end_deletes_stale_fsm_instance(self):
        vrf1, vrf2 = 'vr0a1b2c3d-eee', 'vr1a2b3c3d-fff'
        evpn = fsm.Evpn(vrf1)
        evpn.vrf_up = True
        evpn.state = fsm.Evpn.WAITING_FOR_BRIDGE
        self.evpn_fsm.instances[vrf1] = evpn
        handler = netlink_monitor.VrfHandler(self.evpn_fsm)
        handler._known_vrfs = {vrf1, vrf2}
        handler._replay_vrfs = {vrf2}
        handler.replay_end()
        self.assertNotIn(vrf1, self.evpn_fsm.instances)
        self.assertEqual({vrf2}, handler._known_vrfs)

    def test_replay_end_transitions_advertising_to_waiting(self):
        vrf = 'vr0a1b2c3d-fff'
        evpn = fsm.Evpn(vrf)
        evpn.mac = 'aa:bb:cc:dd:ee:ff'
        evpn.vni = 10
        evpn.vid = 1
        evpn.vrf_up = True
        evpn.state = fsm.Evpn.ADVERTISING
        self.evpn_fsm.instances[vrf] = evpn
        handler = netlink_monitor.VrfHandler(self.evpn_fsm)
        handler._known_vrfs = {vrf}
        handler._replay_vrfs = set()
        handler.replay_end()
        self.assertEqual(fsm.Evpn.WAITING_FOR_ROUTER, evpn.state)
        self.assertIn(vrf, self.evpn_fsm.instances)

    def test_replay_end_no_stale_vrfs(self):
        vrf = 'vr0a1b2c3d-fff'
        evpn = fsm.Evpn(vrf)
        evpn.vrf_up = True
        evpn.state = fsm.Evpn.WAITING_FOR_BRIDGE
        self.evpn_fsm.instances[vrf] = evpn
        handler = netlink_monitor.VrfHandler(self.evpn_fsm)
        handler._known_vrfs = {vrf}
        handler._replay_vrfs = {vrf}
        handler.replay_end()
        self.assertIn(vrf, self.evpn_fsm.instances)
        self.assertEqual({vrf}, handler._known_vrfs)
