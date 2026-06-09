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

from oslo_utils import uuidutils
from pyroute2.netlink import rtnl

from neutron.agent.linux import ip_lib
from neutron.agent.linux import nl_constants as nl_const
from neutron.agent.linux import nl_dispatcher
from neutron.agent.linux import utils as agent_utils
from neutron.agent.ovn.extensions import evpn
from neutron.agent.ovn.extensions.evpn import constants as evpn_const
from neutron.agent.ovn.extensions.evpn import fsm
from neutron.agent.ovn.extensions.evpn import netlink_monitor
from neutron.agent.ovn.extensions.evpn import svd
from neutron.agent.ovn.extensions.evpn import utils as evpn_utils
from neutron.common import utils
from neutron.privileged.agent.linux import ip_lib as privileged
from neutron.tests.functional.agent.linux import base
from neutron.tests.functional import base as functional_base


class TestVrfHandlerLifecycle(functional_base.BaseSudoTestCase):

    @staticmethod
    def _safe_delete(name):
        try:
            ip_lib.IPDevice(name).link.delete()
        except Exception:
            pass

    def test_vrf_handler_lifecycle(self):
        vrf_handler = netlink_monitor.VrfHandler(
            fsm.EvpnFSM(svd=None, config=None))

        dispatcher = nl_dispatcher.NetlinkDispatcher(rtnl.RTMGRP_LINK)
        dispatcher.register_handler(
            nl_const.RTM_NEWLINK, vrf_handler.handle_newlink)
        dispatcher.register_handler(
            nl_const.RTM_DELLINK, vrf_handler.handle_dellink)
        dispatcher.register_replay_callbacks(
            on_start=vrf_handler.replay_start,
            on_end=vrf_handler.replay_end)

        # Create a VRF before starting the dispatcher so replay discovers it.
        preexisting_vrf = evpn_utils.evpn_vrf_name(uuidutils.generate_uuid())
        privileged.create_interface(preexisting_vrf, None, 'vrf',
                                    vrf_table=100)
        self.addCleanup(self._safe_delete, preexisting_vrf)

        dispatcher.start()
        utils.wait_until_true(
            lambda: preexisting_vrf in vrf_handler._known_vrfs,
            timeout=10, sleep=0.1)

        # Create a VRF after start — live newlink detection.
        live_vrf = evpn_utils.evpn_vrf_name(uuidutils.generate_uuid())
        privileged.create_interface(live_vrf, None, 'vrf', vrf_table=200)
        self.addCleanup(self._safe_delete, live_vrf)
        utils.wait_until_true(
            lambda: live_vrf in vrf_handler._known_vrfs,
            timeout=10, sleep=0.1)

        # Delete the live VRF — dellink detection.
        ip_lib.IPDevice(live_vrf).link.delete()
        utils.wait_until_true(
            lambda: live_vrf not in vrf_handler._known_vrfs,
            timeout=10, sleep=0.1)

        # Remember the baseline _known_vrfs which should not change after the
        # next two interface creations
        baseline = set(vrf_handler._known_vrfs)

        # Non-VRF interface is ignored.
        ip_lib.IPWrapper().add_dummy('testdummy')
        self.addCleanup(self._safe_delete, 'testdummy')
        utils.wait_until_true(
            lambda: ip_lib.device_exists('testdummy'),
            timeout=10, sleep=0.1)
        utils.wait_until_true(
            lambda: vrf_handler._known_vrfs.issubset(baseline),
            timeout=10, sleep=0.1)

        # VRF with non-EVPN name is ignored.
        non_evpn_vrf = 'myvrf-300'
        privileged.create_interface(non_evpn_vrf, None, 'vrf', vrf_table=300)
        self.addCleanup(self._safe_delete, non_evpn_vrf)
        utils.wait_until_true(
            lambda: ip_lib.device_exists(non_evpn_vrf),
            timeout=10, sleep=0.1)
        self.assertEqual(baseline, vrf_handler._known_vrfs)


class TestFsmSvdIntegration(base.BaseNetlinkTestCase):

    DSTPORT = 15000
    LOCAL_IP = '10.10.10.10'
    SVD_MAC = 'aa:bb:cc:dd:ee:ff'
    SVI_MAC = '00:11:22:33:44:55'

    @staticmethod
    def _safe_delete(name):
        try:
            ip_lib.IPDevice(name).link.delete()
        except Exception:
            pass

    @staticmethod
    def _set_link_up(name):
        agent_utils.execute(
            ['ip', 'link', 'set', name, 'up'],
            run_as_root=True, privsep_exec=True)

    def setUp(self):
        super().setUp()
        self._parent = utils.get_rand_device_name(prefix='evpnp-')
        privileged.create_interface(self._parent, None, 'dummy')
        self._set_link_up(self._parent)
        ip_lib.IPDevice(self._parent).addr.add(self.LOCAL_IP + '/32')
        self.addCleanup(self._safe_delete, self._parent)
        self.cfg = evpn.EvpnConfig(local_ip=self.LOCAL_IP,
                                   dstport=self.DSTPORT,
                                   vxlan_parent=self._parent,
                                   mac=self.SVD_MAC,
                                   br_mtu=evpn_const.EVPN_BR_MTU)

        self._vrf = utils.get_rand_device_name(prefix='evpnvrf-')
        privileged.create_interface(self._vrf, None, 'vrf', vrf_table=9999)
        self._set_link_up(self._vrf)
        self.addCleanup(self._safe_delete, self._vrf)

        self._br = utils.get_rand_device_name(prefix='evpnbr-')
        self._vx = utils.get_rand_device_name(prefix='evpnvx-')
        self.svd = svd.EvpnSvd(br_evpn=self._br, vxlan_evpn=self._vx)
        self.svd.create(local_ip=self.LOCAL_IP, mac=self.SVD_MAC,
                        vxlan_parent=self._parent, dstport=self.DSTPORT,
                        br_mtu=evpn_const.EVPN_BR_MTU)
        self.addCleanup(self._safe_delete, self._vx)
        self.addCleanup(self._safe_delete, self._br)

        self._evpn_fsm = fsm.EvpnFSM(self.svd, config=self.cfg)

    def _advance_to_advertising(self, vni, vid):
        self._evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_VRF_CREATE, self._vrf)
        self._evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_PORT_BINDING_CREATE,
            self._vrf, mac=self.SVI_MAC, vni=vni, vid=vid)

    def test_fsm_advertise_creates_svi(self):
        index = 0
        vni = 1000
        vid = 10
        svi_name = evpn_const.EVPN_VLAN_IFNAME_PATTERN % {
            'index': index, 'vid': vid}
        self._advance_to_advertising(vni, vid)

        evpn = self._evpn_fsm.instances[self._vrf]
        self.assertEqual(fsm.Evpn.ADVERTISING, evpn.state)
        self.assertTrue(ip_lib.device_exists(svi_name))

    def test_fsm_port_binding_delete_deletes_svi(self):
        index = 0
        vni = 2000
        vid = 20
        svi_name = evpn_const.EVPN_VLAN_IFNAME_PATTERN % {
            'index': index, 'vid': vid}
        self._advance_to_advertising(vni, vid)
        self.assertTrue(ip_lib.device_exists(svi_name))

        self._evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_PORT_BINDING_DELETE, self._vrf)

        evpn = self._evpn_fsm.instances[self._vrf]
        self.assertEqual(fsm.Evpn.WAITING_FOR_BRIDGE, evpn.state)
        self.assertFalse(ip_lib.device_exists(svi_name))

    def test_fsm_vrf_delete_deletes_svi(self):
        index = 0
        vni = 3000
        vid = 30
        svi_name = evpn_const.EVPN_VLAN_IFNAME_PATTERN % {
            'index': index, 'vid': vid}
        self._advance_to_advertising(vni, vid)
        self.assertTrue(ip_lib.device_exists(svi_name))

        self._evpn_fsm.advance(
            fsm.EvpnFSM.FSM_EVENT_VRF_DELETE, self._vrf)

        evpn = self._evpn_fsm.instances[self._vrf]
        self.assertEqual(fsm.Evpn.WAITING_FOR_ROUTER, evpn.state)
        self.assertFalse(ip_lib.device_exists(svi_name))
