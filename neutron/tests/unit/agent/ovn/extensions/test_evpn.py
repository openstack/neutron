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

from pyroute2.iproute import ipmock
from pyroute2.netlink.rtnl import ifinfmsg

from neutron.agent.ovn.extensions.evpn import exceptions as evpn_exc
from neutron.agent.ovn.extensions.evpn import netlink_monitor
from neutron.tests import base


def _make_nlmsg(ifname, kind=None):
    data = ipmock.MockLink(index=3, ifname=ifname, kind=kind).export()
    msg = ifinfmsg.ifinfmsg()
    msg.load(data)
    msg.encode()
    decoded = ifinfmsg.ifinfmsg(msg.data)
    decoded.decode()
    return decoded


def _make_vrf_msg(ifname, kind='vrf'):
    return _make_nlmsg(ifname, kind=kind)


class TestVrfHandler(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.handler = netlink_monitor.VrfHandler()

    def test_handle_newlink_evpn_vrf(self):
        vrf = 'vr0a1b2c3d-fff'
        msg = _make_vrf_msg(vrf)
        self.handler.handle_newlink(msg)
        self.assertIn(vrf, self.handler._known_vrfs)

    def test_handle_newlink_deduplicates(self):
        vrf = 'vr0a1b2c3d-fff'
        msg = _make_vrf_msg(vrf)
        self.handler.handle_newlink(msg)
        self.handler.handle_newlink(msg)
        self.assertEqual({vrf}, self.handler._known_vrfs)

    def test_handle_dellink_evpn_vrf(self):
        vrf = 'vr0a1b2c3d-fff'
        self.handler._known_vrfs.add(vrf)
        msg = _make_vrf_msg(vrf)
        self.handler.handle_dellink(msg)
        self.assertNotIn(vrf, self.handler._known_vrfs)

    def test_handle_dellink_unknown_vrf(self):
        vrf = 'vr0a1b2c3d-fff'
        self.handler._known_vrfs.add(vrf)
        msg = _make_vrf_msg('vr0a1b2c3d-eee')
        self.handler.handle_dellink(msg)
        self.assertEqual({vrf}, self.handler._known_vrfs)

    def test_ignores_non_vrf_kind(self):
        msg = _make_vrf_msg('vr0a1b2c3d-fff', kind='bridge')
        self.handler.handle_newlink(msg)
        self.assertEqual(set(), self.handler._known_vrfs)

    def test_ignores_non_evpn_vrf_prefix(self):
        msg = _make_vrf_msg('myvrf-10')
        self.handler.handle_newlink(msg)
        self.assertEqual(set(), self.handler._known_vrfs)

    def test_ignores_wrong_length(self):
        msg = _make_vrf_msg('vr0a1b')
        self.handler.handle_newlink(msg)
        self.assertEqual(set(), self.handler._known_vrfs)

    def test_ignores_no_linkinfo(self):
        no_linkinfo_msg = _make_nlmsg('vr0a1b2c3d-fff')
        self.handler.handle_newlink(no_linkinfo_msg)
        self.assertEqual(set(), self.handler._known_vrfs)

    def test_parse_evpn_vrf_raises_unknown_message_for_non_vrf(self):
        msg = _make_vrf_msg('eth0', kind='dummy')
        self.assertRaises(evpn_exc.UnknownMessage,
                          self.handler._parse_evpn_vrf, msg)

    def test_parse_evpn_vrf_raises_unknown_vrf_for_wrong_prefix(self):
        msg = _make_vrf_msg('myvrf-10')
        self.assertRaises(evpn_exc.UnknownVrfMessage,
                          self.handler._parse_evpn_vrf, msg)

    def test_parse_evpn_vrf_raises_unknown_vrf_for_wrong_length(self):
        msg = _make_vrf_msg('vr0a1b')
        self.assertRaises(evpn_exc.UnknownVrfMessage,
                          self.handler._parse_evpn_vrf, msg)

    def test_multiple_vrfs(self):
        vrf1, vrf2, vrf3 = 'vr0a1b2c3d-ddd', 'vr0a1b2c3d-eee', 'vr0a1b2c3d-fff'
        self.handler.handle_newlink(_make_vrf_msg(vrf1))
        self.handler.handle_newlink(_make_vrf_msg(vrf2))
        self.handler.handle_newlink(_make_vrf_msg(vrf3))
        self.assertEqual({vrf1, vrf2, vrf3}, self.handler._known_vrfs)
        self.handler.handle_dellink(_make_vrf_msg(vrf2))
        self.assertEqual({vrf1, vrf3}, self.handler._known_vrfs)

    def test_replay_removes_stale_vrfs(self):
        vrf1, vrf2, vrf3 = 'vr0a1b2c3d-ddd', 'vr0a1b2c3d-eee', 'vr0a1b2c3d-fff'
        self.handler._known_vrfs = {vrf1, vrf2, vrf3}
        self.handler.replay_start()
        self.handler.handle_newlink(_make_vrf_msg(vrf1))
        self.handler.handle_newlink(_make_vrf_msg(vrf3))
        self.handler.replay_end()
        self.assertEqual({vrf1, vrf3}, self.handler._known_vrfs)

    def test_replay_adds_new_vrfs(self):
        vrf1, vrf2 = 'vr0a1b2c3d-ddd', 'vr0a1b2c3d-eee'
        self.handler._known_vrfs = {vrf1}
        self.handler.replay_start()
        self.handler.handle_newlink(_make_vrf_msg(vrf1))
        self.handler.handle_newlink(_make_vrf_msg(vrf2))
        self.handler.replay_end()
        self.assertEqual({vrf1, vrf2}, self.handler._known_vrfs)

    def test_replay_empty_dump_clears_all(self):
        self.handler._known_vrfs = {'vr0a1b2c3d-ddd', 'vr0a1b2c3d-eee'}
        self.handler.replay_start()
        self.handler.replay_end()
        self.assertEqual(set(), self.handler._known_vrfs)
