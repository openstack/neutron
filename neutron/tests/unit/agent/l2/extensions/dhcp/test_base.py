# Copyright (c) 2021 China Unicom Cloud Data Co.,Ltd.
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

import netaddr
from neutron_lib import constants
from neutron_lib.utils import net as net_utils
from os_ken.lib import addrconv
from os_ken.lib.packet import dhcp
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import in_proto as inet
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import packet
from os_ken.lib.packet import udp

from neutron.agent.common import ovs_lib
from neutron.agent.l2.extensions.dhcp import base as dhcp_resp_base
from neutron.objects import subnet as subnet_obj
from neutron.plugins.ml2.drivers.openvswitch.agent \
    import ovs_agent_extension_api as ovs_ext_api
from neutron.tests import base


class FakeOF(object):
    OFPR_NO_MATCH = 0
    OFPR_ACTION = 1
    FPR_INVALID_TTL = 2
    OFP_NO_BUFFER = 3
    OFPP_CONTROLLER = 4


class FakeDatapath(object):
    ofproto = FakeOF()


class FakeMsg(object):
    datapath = FakeDatapath()
    reason = datapath.ofproto.OFPR_ACTION
    match = {'in_port': 1}
    data = ""
    buffer_id = 1
    total_len = 1
    table_id = 77
    cookie = 1

    def set_data(self, packet):
        packet.serialize()
        self.data = packet.data


PORT_INFO = {
    'device_owner': 'compute:nova',
    'admin_state_up': True,
    'network_id': 'd666ccb3-69e9-46cb-b157-bb3741d87d5a',
    'fixed_ips': [
        {'version': 4,
         'host_routes': [
             subnet_obj.Route(
                 destination=netaddr.IPNetwork('1.1.1.0/24'),
                 nexthop='192.168.1.100',
                 subnet_id='daed3c3d-d95a-48a8-a8b1-17d408cd760f'),
             subnet_obj.Route(
                 destination=netaddr.IPNetwork('2.2.2.2/32'),
                 nexthop='192.168.1.101',
                 subnet_id='daed3c3d-d95a-48a8-a8b1-17d408cd760f')],
         'subnet_id': 'daed3c3d-d95a-48a8-a8b1-17d408cd760f',
         'dns_nameservers': [
             subnet_obj.DNSNameServer(
                 address='8.8.8.8',
                 order=0,
                 subnet_id='daed3c3d-d95a-48a8-a8b1-17d408cd760f'),
             subnet_obj.DNSNameServer(
                 address='8.8.4.4',
                 order=1,
                 subnet_id='daed3c3d-d95a-48a8-a8b1-17d408cd760f')],
         'cidr': net_utils.AuthenticIPNetwork('192.168.111.0/24'),
         'ip_address': '192.168.111.45',
         'gateway_ip': netaddr.IPAddress('192.168.111.1')},
        {'version': 6,
         'host_routes': [],
         'subnet_id': 'bd013460-b05f-4927-a4c6-5127584b2487',
         'dns_nameservers': [],
         'cidr': net_utils.AuthenticIPNetwork('fda7:a5cc:3460:1::/64'),
         'ip_address': 'fda7:a5cc:3460:1::bf',
         'gateway_ip': netaddr.IPAddress('fda7:a5cc:3460:1::1')}
    ],
    'mac_address': '00:01:02:03:04:05',
    'port_id': '9a0e1889-f05f-43c7-a319-e1a723ed1587',
    'mtu': 1450
}


class DHCPResponderBaseTestCase(base.BaseTestCase):

    def setUp(self):
        super(DHCPResponderBaseTestCase, self).setUp()
        self.int_br = mock.Mock()
        self.tun_br = mock.Mock()
        self.plugin_rpc = mock.Mock()
        self.remote_resource_cache = mock.Mock()
        self.plugin_rpc.remote_resource_cache = self.remote_resource_cache
        self.agent_api = ovs_ext_api.OVSAgentExtensionAPI(
            self.int_br,
            self.tun_br,
            phys_brs=None,
            plugin_rpc=self.plugin_rpc)
        self.ext_api = mock.Mock()
        self.base_responer = dhcp_resp_base.DHCPResponderBase(self.agent_api,
                                                              self.ext_api)
        self.base_responer.int_br = self.int_br

        self.base_responer.get_dhcp_options = mock.Mock()
        self.base_responer.get_ret_packet = mock.Mock()
        self.base_responer.get_state = mock.Mock()
        self.base_responer.handle_dhcp = mock.Mock()

        self.port_info = PORT_INFO

    def _create_test_dhcp_request_packet(self):
        option_list = []
        bin_server = addrconv.ipv4.text_to_bin('192.168.1.1')
        option_list.append(
            dhcp.option(tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT,
                        value=bin_server))
        option_list.append(
                dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT,
                            value=b'\x03'))
        options = dhcp.options(option_list=option_list)
        ret_pkt = packet.Packet()
        ret_pkt.add_protocol(ethernet.ethernet(
            dst="ff:ff:ff:ff:ff:ff",
            src=self.port_info['mac_address']))
        ret_pkt.add_protocol(
            ipv4.ipv4(dst="255.255.255.255",
                      src="0.0.0.0",
                      proto=inet.IPPROTO_UDP))
        ret_pkt.add_protocol(udp.udp(
            src_port=constants.DHCP_CLIENT_PORT,
            dst_port=constants.DHCP_RESPONSE_PORT))
        ret_pkt.add_protocol(dhcp.dhcp(op=dhcp.DHCP_BOOT_REQUEST,
                                       chaddr=self.port_info['mac_address'],
                                       siaddr='0.0.0.0',
                                       xid=3454038351,
                                       options=options))
        return ret_pkt

    def test__packet_in_handler(self):
        ev = mock.Mock()
        ev.msg = FakeMsg()
        dhcp_req = self._create_test_dhcp_request_packet()
        ev.msg.set_data(dhcp_req)

        self.base_responer.get_port_id_from_br = mock.Mock()
        self.base_responer.get_port_id_from_br.return_value = (
            PORT_INFO['port_id'])
        self.ext_api.get_port_info = mock.Mock()
        self.ext_api.get_port_info.return_value = PORT_INFO
        self.base_responer._packet_in_handler(ev)
        self.base_responer.handle_dhcp.assert_called_once_with(
            ev.msg.datapath, 1, mock.ANY, self.port_info)

    def test_get_bin_dns(self):
        except_value = b'\x08\x08\x08\x08\x08\x08\x04\x04'
        bin_dns = self.base_responer.get_bin_dns(
            self.port_info['fixed_ips'][0]['dns_nameservers'])
        self.assertEqual(except_value, bin_dns)

    def test_get_bin_route(self):
        expect_bin_route = b' \x08\x08\x08\x08\xc0\xa8\x01\x01'
        bin_route = self.base_responer.get_bin_route('8.8.8.8', '192.168.1.1')
        self.assertEqual(expect_bin_route, bin_route)

    def test_get_port_id_from_br(self):
        self.int_br.get_vif_ports = mock.Mock()
        self.int_br.get_vif_ports.return_value = [
            ovs_lib.VifPort(port_name="tap-1", ofport=1,
                            vif_id=PORT_INFO['port_id'],
                            vif_mac=PORT_INFO['mac_address'],
                            switch='br-int')]
        pid = self.base_responer.get_port_id_from_br(
            1, PORT_INFO['mac_address'])
        self.assertEqual(PORT_INFO['port_id'], pid)

    def test_get_port_ip(self):
        ip_v4 = self.base_responer.get_port_ip(self.port_info, 4)
        self.assertEqual(self.port_info['fixed_ips'][0],
                         ip_v4)
        ip_v6 = self.base_responer.get_port_ip(self.port_info, 6)
        self.assertEqual(self.port_info['fixed_ips'][1],
                         ip_v6)

    def test_packet_out(self):
        datapath = mock.Mock()
        ofport = 1
        dhcp_req = self._create_test_dhcp_request_packet()
        self.base_responer.packet_out(datapath, ofport, dhcp_req)
        datapath.send_msg.assert_called_once_with(mock.ANY)
