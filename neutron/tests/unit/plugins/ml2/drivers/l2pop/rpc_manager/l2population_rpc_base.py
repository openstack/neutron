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

import collections
from unittest import mock

from neutron.plugins.ml2.drivers.l2pop import rpc as l2pop_rpc
from neutron.plugins.ml2.drivers.l2pop.rpc_manager import l2population_rpc
from neutron.tests import base
from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent import \
    test_vlanmanager


class FakeNeutronAgent(l2population_rpc.L2populationRpcCallBackTunnelMixin):

    def fdb_add(self, context, fdb_entries):
        pass

    def fdb_remove(self, context, fdb_entries):
        pass

    def add_fdb_flow(self, br, port_info, remote_ip, lvm, ofport):
        pass

    def del_fdb_flow(self, br, port_info, remote_ip, lvm, ofport):
        pass

    def setup_tunnel_port(self, br, remote_ip, network_type):
        pass

    def cleanup_tunnel_port(self, br, tun_ofport, tunnel_type):
        pass

    def setup_entry_for_arp_reply(self, br, action, local_vid, mac_address,
                                  ip_address):
        pass


class TestL2populationRpcCallBackTunnelMixinBase(base.BaseTestCase):

    def setUp(self):
        super(TestL2populationRpcCallBackTunnelMixinBase, self).setUp()
        self.vlan_manager = self.useFixture(
            test_vlanmanager.LocalVlanManagerFixture()).manager
        self.fakeagent = FakeNeutronAgent()
        self.fakebr = mock.Mock()
        Port = collections.namedtuple('Port', 'ip, ofport')
        LVM = collections.namedtuple(
            'LVM', 'net, vlan, phys, segid, mac, ip, vif, port')

        self.local_ip = '127.0.0.1'
        self.type_gre = 'gre'
        self.ports = [Port(ip='10.1.0.1', ofport='ofport1'),
                      Port(ip='10.1.0.2', ofport='ofport2'),
                      Port(ip='10.1.0.3', ofport='ofport3')]
        self.ofports = {
            self.type_gre: {
                self.ports[0].ip: self.ports[0].ofport,
                self.ports[1].ip: self.ports[1].ofport,
                self.ports[2].ip: self.ports[2].ofport,
            }
        }

        self.lvms = [LVM(net='net1', vlan=1, phys='phys1', segid='tun1',
                         mac='mac1', ip='1.1.1.1', vif='vifid1',
                         port='port1'),
                     LVM(net='net2', vlan=2, phys='phys2', segid='tun2',
                         mac='mac2', ip='2.2.2.2', vif='vifid2',
                         port='port2'),
                     LVM(net='net3', vlan=3, phys='phys3', segid='tun3',
                         mac='mac3', ip='3.3.3.3', vif='vifid3',
                         port='port3')]

        self.agent_ports = {
            self.ports[0].ip: [(self.lvms[0].mac, self.lvms[0].ip)],
            self.ports[1].ip: [(self.lvms[1].mac, self.lvms[1].ip)],
            self.ports[2].ip: [(self.lvms[2].mac, self.lvms[2].ip)],
        }

        self.fdb_entries1 = {
            self.lvms[0].net: {
                'network_type': self.type_gre,
                'segment_id': self.lvms[0].segid,
                'ports': {
                    self.local_ip: [],
                    self.ports[0].ip: [(self.lvms[0].mac, self.lvms[0].ip)]},
            },
            self.lvms[1].net: {
                'network_type': self.type_gre,
                'segment_id': self.lvms[1].segid,
                'ports': {
                    self.local_ip: [],
                    self.ports[1].ip: [(self.lvms[1].mac, self.lvms[1].ip)]},
            },
            self.lvms[2].net: {
                'network_type': self.type_gre,
                'segment_id': self.lvms[2].segid,
                'ports': {
                    self.local_ip: [],
                    self.ports[2].ip: [(self.lvms[2].mac, self.lvms[2].ip)]},
            },
        }

        for i in range(3):
            self.vlan_manager.add(
                self.lvms[i].net,
                self.lvms[i].vlan, self.type_gre, self.lvms[i].phys,
                self.lvms[i].segid, {self.lvms[i].vif: self.lvms[i].port})
            setattr(self, 'lvm%d' % i,
                    self.vlan_manager.get(self.lvms[i].net))

        self.upd_fdb_entry1_val = {
            self.lvms[0].net: {
                self.ports[0].ip: {
                    'before': [l2pop_rpc.PortInfo(self.lvms[0].mac,
                               self.lvms[0].ip)],
                    'after': [l2pop_rpc.PortInfo(self.lvms[1].mac,
                              self.lvms[1].ip)],
                },
                self.ports[1].ip: {
                    'before': [l2pop_rpc.PortInfo(self.lvms[0].mac,
                               self.lvms[0].ip)],
                    'after': [l2pop_rpc.PortInfo(self.lvms[1].mac,
                              self.lvms[1].ip)],
                },
            },
            self.lvms[1].net: {
                self.ports[2].ip: {
                    'before': [l2pop_rpc.PortInfo(self.lvms[0].mac,
                               self.lvms[0].ip)],
                    'after': [l2pop_rpc.PortInfo(self.lvms[2].mac,
                              self.lvms[2].ip)],
                },
            },
        }
        self.upd_fdb_entry1 = {'chg_ip': self.upd_fdb_entry1_val}

    def _tunnel_port_lookup(self, network_type, remote_ip):
        return self.ofports[network_type].get(remote_ip)
