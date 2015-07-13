# Copyright (C) 2014,2015 VA Linux Systems Japan K.K.
# Copyright (C) 2014,2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

from neutron.common import constants

from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent \
    import ovs_test_base


call = mock.call  # short hand


class OVSBridgeTestBase(ovs_test_base.OVSOFCtlTestBase):
    def setup_bridge_mock(self, name, cls):
        self.br = cls(name)
        mock_add_flow = mock.patch.object(self.br, 'add_flow').start()
        mock_mod_flow = mock.patch.object(self.br, 'mod_flow').start()
        mock_delete_flows = mock.patch.object(self.br, 'delete_flows').start()
        self.mock = mock.Mock()
        self.mock.attach_mock(mock_add_flow, 'add_flow')
        self.mock.attach_mock(mock_mod_flow, 'mod_flow')
        self.mock.attach_mock(mock_delete_flows, 'delete_flows')

    def test_drop_port(self):
        in_port = 2345
        self.br.drop_port(in_port=in_port)
        expected = [
            call.add_flow(priority=2, table=0, actions='drop',
                          in_port=in_port),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_goto(self):
        dest_table_id = 123
        priority = 99
        in_port = 666
        self.br.install_goto(dest_table_id=dest_table_id,
                             priority=priority, in_port=in_port)
        expected = [
            call.add_flow(priority=priority, table=0,
                          actions='resubmit(,%s)' % dest_table_id,
                          in_port=in_port),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_drop(self):
        priority = 99
        in_port = 666
        self.br.install_drop(priority=priority, in_port=in_port)
        expected = [
            call.add_flow(priority=priority, table=0,
                          actions='drop',
                          in_port=in_port),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_normal(self):
        priority = 99
        in_port = 666
        self.br.install_normal(priority=priority, in_port=in_port)
        expected = [
            call.add_flow(priority=priority, table=0,
                          actions='normal',
                          in_port=in_port),
        ]
        self.assertEqual(expected, self.mock.mock_calls)


class OVSDVRProcessTestMixin(object):
    def test_install_dvr_process_ipv4(self):
        vlan_tag = 999
        gateway_ip = '192.0.2.1'
        self.br.install_dvr_process_ipv4(vlan_tag=vlan_tag,
                                         gateway_ip=gateway_ip)
        expected = [
            call.add_flow(table=self.dvr_process_table_id,
                          proto='arp', nw_dst=gateway_ip, actions='drop',
                          priority=3, dl_vlan=vlan_tag),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_dvr_process_ipv4(self):
        vlan_tag = 999
        gateway_ip = '192.0.2.1'
        self.br.delete_dvr_process_ipv4(vlan_tag=vlan_tag,
                                        gateway_ip=gateway_ip)
        expected = [
            call.delete_flows(table=self.dvr_process_table_id,
                              dl_vlan=vlan_tag, proto='arp',
                              nw_dst=gateway_ip),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_dvr_process_ipv6(self):
        vlan_tag = 999
        gateway_mac = '08:60:6e:7f:74:e7'
        self.br.install_dvr_process_ipv6(vlan_tag=vlan_tag,
                                         gateway_mac=gateway_mac)
        expected = [
            call.add_flow(table=self.dvr_process_table_id,
                          proto='icmp6', dl_src=gateway_mac, actions='drop',
                          priority=3, dl_vlan=vlan_tag,
                          icmp_type=constants.ICMPV6_TYPE_RA),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_dvr_process_ipv6(self):
        vlan_tag = 999
        gateway_mac = '08:60:6e:7f:74:e7'
        self.br.delete_dvr_process_ipv6(vlan_tag=vlan_tag,
                                        gateway_mac=gateway_mac)
        expected = [
            call.delete_flows(table=self.dvr_process_table_id,
                              dl_vlan=vlan_tag, dl_src=gateway_mac,
                              proto='icmp6',
                              icmp_type=constants.ICMPV6_TYPE_RA),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_install_dvr_process(self):
        vlan_tag = 999
        vif_mac = '00:0e:0c:5e:95:d0'
        dvr_mac_address = 'f2:0b:a4:5b:b2:ab'
        self.br.install_dvr_process(vlan_tag=vlan_tag,
                                    vif_mac=vif_mac,
                                    dvr_mac_address=dvr_mac_address)
        expected = [
            call.add_flow(priority=2, table=self.dvr_process_table_id,
                          dl_dst=vif_mac, dl_vlan=vlan_tag, actions='drop'),
            call.add_flow(priority=1, table=self.dvr_process_table_id,
                          dl_vlan=vlan_tag, dl_src=vif_mac,
                          actions='mod_dl_src:%(mac)s,resubmit(,%(next)s)' % {
                              'mac': dvr_mac_address,
                              'next': self.dvr_process_next_table_id,
                          }),
        ]
        self.assertEqual(expected, self.mock.mock_calls)

    def test_delete_dvr_process(self):
        vlan_tag = 999
        vif_mac = '00:0e:0c:5e:95:d0'
        self.br.delete_dvr_process(vlan_tag=vlan_tag,
                                   vif_mac=vif_mac)
        expected = [
            call.delete_flows(table=self.dvr_process_table_id,
                              dl_dst=vif_mac, dl_vlan=vlan_tag),
            call.delete_flows(table=self.dvr_process_table_id,
                              dl_vlan=vlan_tag, dl_src=vif_mac),
        ]
        self.assertEqual(expected, self.mock.mock_calls)
