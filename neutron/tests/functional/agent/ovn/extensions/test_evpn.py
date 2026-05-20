# Copyright 2026 Red Hat, Inc.
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

from pyroute2.netlink import rtnl

from neutron.agent.linux import ip_lib
from neutron.agent.linux import nl_dispatcher
from neutron.agent.ovn.extensions.evpn import constants as evpn_const
from neutron.agent.ovn.extensions.evpn import netlink_monitor
from neutron.common import utils
from neutron.privileged.agent.linux import ip_lib as privileged
from neutron.tests.functional import base as functional_base


class TestVrfHandlerLifecycle(functional_base.BaseSudoTestCase):

    @staticmethod
    def _safe_delete(name):
        try:
            ip_lib.IPDevice(name).link.delete()
        except Exception:
            pass

    def test_vrf_handler_lifecycle(self):
        vrf_handler = netlink_monitor.VrfHandler()

        dispatcher = nl_dispatcher.NetlinkDispatcher(rtnl.RTMGRP_LINK)
        dispatcher.register_handler(
            evpn_const.EVPN_RTM_NEWLINK, vrf_handler.handle_newlink)
        dispatcher.register_handler(
            evpn_const.EVPN_RTM_DELLINK, vrf_handler.handle_dellink)
        dispatcher.register_replay_callbacks(
            on_start=vrf_handler.replay_start,
            on_end=vrf_handler.replay_end)

        # Create a VRF before starting the dispatcher so replay discovers it.
        preexisting_vrf = 'vr0a1b2c3d-fff'
        privileged.create_interface(preexisting_vrf, None, 'vrf',
                                    vrf_table=100)
        self.addCleanup(self._safe_delete, preexisting_vrf)

        dispatcher.start()
        utils.wait_until_true(
            lambda: preexisting_vrf in vrf_handler._known_vrfs,
            timeout=10, sleep=0.1)

        # Create a VRF after start — live newlink detection.
        live_vrf = 'vr1a2b3c3d-eee'
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
        self.assertEqual(baseline, vrf_handler._known_vrfs)

        # VRF with non-EVPN name is ignored.
        non_evpn_vrf = 'myvrf-300'
        privileged.create_interface(non_evpn_vrf, None, 'vrf', vrf_table=300)
        self.addCleanup(self._safe_delete, non_evpn_vrf)
        utils.wait_until_true(
            lambda: ip_lib.device_exists(non_evpn_vrf),
            timeout=10, sleep=0.1)
        self.assertEqual(baseline, vrf_handler._known_vrfs)
