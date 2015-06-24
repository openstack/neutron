# Copyright (C) 2014 VA Linux Systems Japan K.K.
# Copyright (C) 2014 Fumihiko Kakuma <kakuma at valinux co jp>
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

import mock

from neutron.common import constants as n_const
from neutron.tests.unit.plugins.ml2.drivers.l2pop.rpc_manager \
    import l2population_rpc_base


class TestL2populationRpcCallBackTunnelMixin(
    l2population_rpc_base.TestL2populationRpcCallBackTunnelMixinBase):

    def test_get_agent_ports_no_data(self):
        self.assertFalse(
            list(self.fakeagent.get_agent_ports(self.fdb_entries1, {})))

    def test_get_agent_ports_non_existence_key_in_lvm(self):
        results = {}
        del self.local_vlan_map1[self.lvms[1].net]
        for lvm, agent_ports in self.fakeagent.get_agent_ports(
            self.fdb_entries1, self.local_vlan_map1):
            results[lvm] = agent_ports
        expected = {
            self.lvm1: {
                self.ports[0].ip: [(self.lvms[0].mac, self.lvms[0].ip)],
                self.local_ip: []},
            self.lvm3: {
                self.ports[2].ip: [(self.lvms[2].mac, self.lvms[2].ip)],
                self.local_ip: []},
        }
        self.assertEqual(expected, results)

    def test_get_agent_ports_no_agent_ports(self):
        results = {}
        self.fdb_entries1[self.lvms[1].net]['ports'] = {}
        for lvm, agent_ports in self.fakeagent.get_agent_ports(
            self.fdb_entries1, self.local_vlan_map1):
            results[lvm] = agent_ports
        expected = {
            self.lvm1: {
                self.ports[0].ip: [(self.lvms[0].mac, self.lvms[0].ip)],
                self.local_ip: []},
            self.lvm2: {},
            self.lvm3: {
                self.ports[2].ip: [(self.lvms[2].mac, self.lvms[2].ip)],
                self.local_ip: []},
        }
        self.assertEqual(expected, results)

    def test_fdb_add_tun(self):
        with mock.patch.object(self.fakeagent, 'setup_tunnel_port'),\
                mock.patch.object(self.fakeagent, 'add_fdb_flow'
                                  ) as mock_add_fdb_flow:
            self.fakeagent.fdb_add_tun('context', self.fakebr, self.lvm1,
                                       self.agent_ports,
                                       self._tunnel_port_lookup)
        expected = [
            mock.call(self.fakebr, (self.lvms[0].mac, self.lvms[0].ip),
                      self.ports[0].ip, self.lvm1, self.ports[0].ofport),
            mock.call(self.fakebr, (self.lvms[1].mac, self.lvms[1].ip),
                      self.ports[1].ip, self.lvm1, self.ports[1].ofport),
            mock.call(self.fakebr, (self.lvms[2].mac, self.lvms[2].ip),
                      self.ports[2].ip, self.lvm1, self.ports[2].ofport),
        ]
        self.assertEqual(sorted(expected),
                         sorted(mock_add_fdb_flow.call_args_list))

    def test_fdb_add_tun_non_existence_key_in_ofports(self):
        ofport = self.lvm1.network_type + '0a0a0a0a'
        del self.ofports[self.type_gre][self.ports[1].ip]
        with mock.patch.object(self.fakeagent, 'setup_tunnel_port',
                               return_value=ofport
                               ) as mock_setup_tunnel_port,\
                mock.patch.object(self.fakeagent, 'add_fdb_flow'
                                  ) as mock_add_fdb_flow:
            self.fakeagent.fdb_add_tun('context', self.fakebr, self.lvm1,
                                       self.agent_ports,
                                       self._tunnel_port_lookup)
        mock_setup_tunnel_port.assert_called_once_with(
            self.fakebr, self.ports[1].ip, self.lvm1.network_type)
        expected = [
            mock.call(self.fakebr, (self.lvms[0].mac, self.lvms[0].ip),
                      self.ports[0].ip, self.lvm1, self.ports[0].ofport),
            mock.call(self.fakebr, (self.lvms[1].mac, self.lvms[1].ip),
                      self.ports[1].ip, self.lvm1, ofport),
            mock.call(self.fakebr, (self.lvms[2].mac, self.lvms[2].ip),
                      self.ports[2].ip, self.lvm1, self.ports[2].ofport),
        ]
        self.assertEqual(sorted(expected),
                         sorted(mock_add_fdb_flow.call_args_list))

    def test_fdb_add_tun_unavailable_ofport(self):
        del self.ofports[self.type_gre][self.ports[1].ip]
        with mock.patch.object(self.fakeagent, 'setup_tunnel_port',
                               return_value=0
                               ) as mock_setup_tunnel_port,\
                mock.patch.object(self.fakeagent, 'add_fdb_flow'
                                  ) as mock_add_fdb_flow:
            self.fakeagent.fdb_add_tun('context', self.fakebr, self.lvm1,
                                       self.agent_ports,
                                       self._tunnel_port_lookup)
        mock_setup_tunnel_port.assert_called_once_with(
            self.fakebr, self.ports[1].ip, self.lvm1.network_type)
        expected = [
            mock.call(self.fakebr, (self.lvms[0].mac, self.lvms[0].ip),
                      self.ports[0].ip, self.lvm1, self.ports[0].ofport),
            mock.call(self.fakebr, (self.lvms[2].mac, self.lvms[2].ip),
                      self.ports[2].ip, self.lvm1, self.ports[2].ofport),
        ]
        self.assertEqual(sorted(expected),
                         sorted(mock_add_fdb_flow.call_args_list))

    def test_fdb_remove_tun(self):
        with mock.patch.object(
            self.fakeagent, 'del_fdb_flow') as mock_del_fdb_flow:
            self.fakeagent.fdb_remove_tun('context', self.fakebr, self.lvm1,
                                          self.agent_ports,
                                          self._tunnel_port_lookup)
        expected = [
            mock.call(self.fakebr, (self.lvms[0].mac, self.lvms[0].ip),
                      self.ports[0].ip, self.lvm1, self.ports[0].ofport),
            mock.call(self.fakebr, (self.lvms[1].mac, self.lvms[1].ip),
                      self.ports[1].ip, self.lvm1, self.ports[1].ofport),
            mock.call(self.fakebr, (self.lvms[2].mac, self.lvms[2].ip),
                      self.ports[2].ip, self.lvm1, self.ports[2].ofport),
        ]
        self.assertEqual(sorted(expected),
                         sorted(mock_del_fdb_flow.call_args_list))

    def test_fdb_remove_tun_flooding_entry(self):
        self.agent_ports[self.ports[1].ip] = [n_const.FLOODING_ENTRY]
        with mock.patch.object(self.fakeagent, 'del_fdb_flow'
                               ) as mock_del_fdb_flow,\
                mock.patch.object(self.fakeagent, 'cleanup_tunnel_port'
                                  ) as mock_cleanup_tunnel_port:
            self.fakeagent.fdb_remove_tun('context', self.fakebr, self.lvm1,
                                          self.agent_ports,
                                          self._tunnel_port_lookup)
        expected = [
            mock.call(self.fakebr, (self.lvms[0].mac, self.lvms[0].ip),
                      self.ports[0].ip, self.lvm1, self.ports[0].ofport),
            mock.call(self.fakebr,
                      (n_const.FLOODING_ENTRY[0], n_const.FLOODING_ENTRY[1]),
                      self.ports[1].ip, self.lvm1, self.ports[1].ofport),
            mock.call(self.fakebr, (self.lvms[2].mac, self.lvms[2].ip),
                      self.ports[2].ip, self.lvm1, self.ports[2].ofport),
        ]
        self.assertEqual(sorted(expected),
                         sorted(mock_del_fdb_flow.call_args_list))
        mock_cleanup_tunnel_port.assert_called_once_with(
            self.fakebr, self.ports[1].ofport, self.lvm1.network_type)

    def test_fdb_remove_tun_non_existence_key_in_ofports(self):
        del self.ofports[self.type_gre][self.ports[1].ip]
        with mock.patch.object(
            self.fakeagent, 'del_fdb_flow') as mock_del_fdb_flow:
            self.fakeagent.fdb_remove_tun('context', self.fakebr, self.lvm1,
                                          self.agent_ports,
                                          self._tunnel_port_lookup)
        expected = [
            mock.call(self.fakebr, (self.lvms[0].mac, self.lvms[0].ip),
                      self.ports[0].ip, self.lvm1, self.ports[0].ofport),
            mock.call(self.fakebr, (self.lvms[2].mac, self.lvms[2].ip),
                      self.ports[2].ip, self.lvm1, self.ports[2].ofport),
        ]
        self.assertEqual(sorted(expected),
                         sorted(mock_del_fdb_flow.call_args_list))

    def test_fdb_update(self):
        fake__fdb_chg_ip = mock.Mock()
        self.fakeagent._fdb_chg_ip = fake__fdb_chg_ip
        self.fakeagent.fdb_update('context', self.upd_fdb_entry1)
        fake__fdb_chg_ip.assert_called_once_with(
            'context', self.upd_fdb_entry1_val)

    def test_fdb_update_non_existence_method(self):
        self.assertRaises(NotImplementedError,
                          self.fakeagent.fdb_update,
                          'context', self.upd_fdb_entry1)

    def test__fdb_chg_ip(self):
        m_setup_entry_for_arp_reply = mock.Mock()
        self.fakeagent.setup_entry_for_arp_reply = m_setup_entry_for_arp_reply
        self.fakeagent.fdb_chg_ip_tun('context', self.fakebr,
                                      self.upd_fdb_entry1_val, self.local_ip,
                                      self.local_vlan_map1)
        expected = [
            mock.call(self.fakebr, 'remove', self.lvm1.vlan, self.lvms[0].mac,
                      self.lvms[0].ip),
            mock.call(self.fakebr, 'add', self.lvm1.vlan, self.lvms[1].mac,
                      self.lvms[1].ip),
            mock.call(self.fakebr, 'remove', self.lvm1.vlan, self.lvms[0].mac,
                      self.lvms[0].ip),
            mock.call(self.fakebr, 'add', self.lvm1.vlan, self.lvms[1].mac,
                      self.lvms[1].ip),
            mock.call(self.fakebr, 'remove', self.lvm2.vlan, self.lvms[0].mac,
                      self.lvms[0].ip),
            mock.call(self.fakebr, 'add', self.lvm2.vlan, self.lvms[2].mac,
                      self.lvms[2].ip),
        ]
        m_setup_entry_for_arp_reply.assert_has_calls(expected, any_order=True)

    def test__fdb_chg_ip_no_lvm(self):
        m_setup_entry_for_arp_reply = mock.Mock()
        self.fakeagent.setup_entry_for_arp_reply = m_setup_entry_for_arp_reply
        self.fakeagent.fdb_chg_ip_tun(
            'context', self.fakebr, self.upd_fdb_entry1, self.local_ip, {})
        self.assertFalse(m_setup_entry_for_arp_reply.call_count)

    def test__fdb_chg_ip_ip_is_local_ip(self):
        upd_fdb_entry_val = {
            self.lvms[0].net: {
                self.local_ip: {
                    'before': [(self.lvms[0].mac, self.lvms[0].ip)],
                    'after': [(self.lvms[1].mac, self.lvms[1].ip)],
                },
            },
        }
        m_setup_entry_for_arp_reply = mock.Mock()
        self.fakeagent.setup_entry_for_arp_reply = m_setup_entry_for_arp_reply
        self.fakeagent.fdb_chg_ip_tun('context', self.fakebr,
                                      upd_fdb_entry_val, self.local_ip,
                                      self.local_vlan_map1)
        self.assertFalse(m_setup_entry_for_arp_reply.call_count)

    def test_fdb_chg_ip_tun_empty_before_after(self):
        upd_fdb_entry_val = {
            self.lvms[0].net: {
                self.local_ip: {},
            },
        }
        m_setup_entry_for_arp_reply = mock.Mock()
        self.fakeagent.setup_entry_for_arp_reply = m_setup_entry_for_arp_reply
        # passing non-local ip
        self.fakeagent.fdb_chg_ip_tun('context', self.fakebr,
                                      upd_fdb_entry_val, "8.8.8.8",
                                      self.local_vlan_map1)
        self.assertFalse(m_setup_entry_for_arp_reply.call_count)
