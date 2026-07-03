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

from unittest import mock

from pyroute2.iproute import ipmock
from pyroute2.netlink.rtnl import ifinfmsg

from neutron.agent.linux import svd as linux_svd
from neutron.agent.ovn.extensions import evpn as evpn_ext
from neutron.agent.ovn.extensions.evpn import exceptions as evpn_exc
from neutron.agent.ovn.extensions.evpn import fsm
from neutron.agent.ovn.extensions.evpn import netlink_monitor
from neutron.agent.ovn.extensions.evpn import svd
from neutron.conf.agent.ovn.evpn import config as evpn_conf
from neutron.privileged.agent.linux import svd as privileged_svd
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


class TestEVPNAgentExtension(base.BaseTestCase):

    LOCAL_IP = '10.10.10.10'
    VXLAN_PORT = '4789'
    DSTPORT = 49152
    MAC = 'fa:16:3e:aa:bb:cc'

    def setUp(self):
        super().setUp()
        evpn_conf.register_opts()
        self.ext = evpn_ext.EVPNAgentExtension()
        self.ext.agent_api = mock.Mock()
        self.ext.agent_api.ovs_idl.db_get.return_value.execute.return_value = {
            'ovn-evpn-local-ip': self.LOCAL_IP,
            'ovn-evpn-vxlan-ports': self.VXLAN_PORT,
        }
        mock.patch.object(privileged_svd,
                          'register_vxlan_vnifilter').start()
        self.mock_svd_cls = mock.patch.object(svd, 'EvpnSvd').start()
        self.mock_nl = mock.patch('neutron.agent.ovn.extensions'
                                  '.evpn.nl_dispatcher'
                                  '.NetlinkDispatcher').start()
        mock.patch.object(evpn_ext.net_lib, 'get_random_mac',
                          return_value=self.MAC).start()
        mock.patch.object(evpn_ext.EVPNAgentExtension,
                          '_get_free_udp_port',
                          return_value=self.DSTPORT).start()
        self.addCleanup(mock.patch.stopall)


class TestCreateSvdWithFreePort(base.BaseTestCase):

    LOCAL_IP = '10.10.10.10'
    VXLAN_PORT = '4789'
    MAC = 'fa:16:3e:aa:bb:cc'

    def setUp(self):
        super().setUp()
        evpn_conf.register_opts()
        self.ext = evpn_ext.EVPNAgentExtension()
        self.ext.agent_api = mock.Mock()
        self.ext.agent_api.ovs_idl.db_get.return_value.execute.return_value = {
            'ovn-evpn-local-ip': self.LOCAL_IP,
            'ovn-evpn-vxlan-ports': self.VXLAN_PORT,
        }
        mock.patch.object(evpn_ext.net_lib, 'get_random_mac',
                          return_value=self.MAC).start()
        self.ext._get_evpn_config()
        self.ext.svd = mock.Mock()
        self.addCleanup(mock.patch.stopall)

    def test_creates_svd_on_first_try(self):
        mock.patch.object(
            evpn_ext.EVPNAgentExtension, '_get_free_udp_port',
            return_value=49152).start()
        self.ext._create_svd_with_free_port()
        self.ext.svd.create.assert_called_once()

    def test_retries_on_port_in_use(self):
        mock.patch.object(
            evpn_ext.EVPNAgentExtension, '_get_free_udp_port',
            side_effect=[49152, 49153, 49154]).start()
        self.ext.svd.create.side_effect = [
            linux_svd.SvdPortInUse("port 49152 in use"),
            linux_svd.SvdPortInUse("port 49153 in use"),
            None,
        ]
        self.ext._create_svd_with_free_port()
        self.assertEqual(3, self.ext.svd.create.call_count)

    def test_reuses_existing_svd(self):
        mock.patch.object(
            evpn_ext.EVPNAgentExtension, '_get_free_udp_port',
            return_value=49152).start()
        self.ext.svd.create.side_effect = linux_svd.SvdDeviceAlreadyExists(
            "already exists")
        self.ext._create_svd_with_free_port()
        self.ext.svd.create.assert_called_once()

    def test_raises_after_max_attempts(self):
        mock.patch.object(
            evpn_ext.EVPNAgentExtension, '_get_free_udp_port',
            side_effect=list(range(49152, 49162))).start()
        self.ext.svd.create.side_effect = linux_svd.SvdPortInUse("in use")
        self.assertRaises(
            RuntimeError, self.ext._create_svd_with_free_port)
        self.assertEqual(10, self.ext.svd.create.call_count)


class TestVrfHandler(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self._evpn_fsm = fsm.EvpnFSM()
        self._evpn_fsm.setup(mock.Mock(), mock.Mock(), mock.Mock())
        self.handler = netlink_monitor.VrfHandler(self._evpn_fsm)

    def test_handle_newlink_evpn_vrf(self):
        vrf = 'vr0a1b2c3d-ffff'
        msg = _make_vrf_msg(vrf)
        self.handler.handle_newlink(msg)
        self.assertIn(vrf, self.handler._known_vrfs)

    def test_handle_newlink_deduplicates(self):
        vrf = 'vr0a1b2c3d-ffff'
        msg = _make_vrf_msg(vrf)
        self.handler.handle_newlink(msg)
        self.handler.handle_newlink(msg)
        self.assertEqual({vrf}, self.handler._known_vrfs)

    def test_handle_dellink_evpn_vrf(self):
        vrf = 'vr0a1b2c3d-ffff'
        self.handler._known_vrfs.add(vrf)
        evpn = fsm.Evpn(vrf)
        evpn.vrf_up = True
        evpn.state = fsm.Evpn.WAITING_FOR_BRIDGE
        self._evpn_fsm.instances[vrf] = evpn
        msg = _make_vrf_msg(vrf)
        self.handler.handle_dellink(msg)
        self.assertNotIn(vrf, self.handler._known_vrfs)
        self.assertNotIn(vrf, self._evpn_fsm.instances)

    def test_handle_dellink_unknown_vrf(self):
        vrf = 'vr0a1b2c3d-ffff'
        self.handler._known_vrfs.add(vrf)
        evpn = fsm.Evpn(vrf)
        evpn.vrf_up = True
        evpn.state = fsm.Evpn.WAITING_FOR_BRIDGE
        self._evpn_fsm.instances[vrf] = evpn
        msg = _make_vrf_msg('vr0a1b2c3d-eeee')
        self.handler.handle_dellink(msg)
        self.assertEqual({vrf}, self.handler._known_vrfs)

    def test_ignores_non_vrf_kind(self):
        msg = _make_vrf_msg('vr0a1b2c3d-ffff', kind='bridge')
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
        no_linkinfo_msg = _make_nlmsg('vr0a1b2c3d-ffff')
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
        vrf1 = 'vr0a1b2c3d-dddd'
        vrf2 = 'vr0a1b2c3d-eeee'
        vrf3 = 'vr0a1b2c3d-ffff'
        self.handler.handle_newlink(_make_vrf_msg(vrf1))
        self.handler.handle_newlink(_make_vrf_msg(vrf2))
        self.handler.handle_newlink(_make_vrf_msg(vrf3))
        self.assertEqual({vrf1, vrf2, vrf3}, self.handler._known_vrfs)
        self.handler.handle_dellink(_make_vrf_msg(vrf2))
        self.assertEqual({vrf1, vrf3}, self.handler._known_vrfs)

    def test_replay_removes_stale_vrfs(self):
        vrf1 = 'vr0a1b2c3d-dddd'
        vrf2 = 'vr0a1b2c3d-eeee'
        vrf3 = 'vr0a1b2c3d-ffff'
        self.handler.handle_newlink(_make_vrf_msg(vrf1))
        self.handler.handle_newlink(_make_vrf_msg(vrf2))
        self.handler.handle_newlink(_make_vrf_msg(vrf3))
        self.handler.replay_start()
        self.handler.handle_newlink(_make_vrf_msg(vrf1))
        self.handler.handle_newlink(_make_vrf_msg(vrf3))
        self.handler.replay_end()
        self.assertEqual({vrf1, vrf3}, self.handler._known_vrfs)

    def test_replay_adds_new_vrfs(self):
        vrf1, vrf2 = 'vr0a1b2c3d-dddd', 'vr0a1b2c3d-eeee'
        self.handler._known_vrfs = {vrf1}
        self.handler.replay_start()
        self.handler.handle_newlink(_make_vrf_msg(vrf1))
        self.handler.handle_newlink(_make_vrf_msg(vrf2))
        self.handler.replay_end()
        self.assertEqual({vrf1, vrf2}, self.handler._known_vrfs)
