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

import time
from unittest import mock

from neutron_lib import constants
from os_ken.lib.packet import dhcp6
from os_ken.lib.packet import ether_types
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import in_proto as inet
from os_ken.lib.packet import ipv6
from os_ken.lib.packet import packet
from os_ken.lib.packet import udp

from neutron.agent.l2.extensions.dhcp import ipv6 as dhcp_ipv6
from neutron.tests.unit.agent.l2.extensions.dhcp \
    import test_base as dhcp_test_base

ONE_SEC_AFTER_2000 = dhcp_ipv6.TIME_FIRST_DAY_2000 + 1


class DHCPIPv6ResponderTestCase(dhcp_test_base.DHCPResponderBaseTestCase):

    def setUp(self):
        super(DHCPIPv6ResponderTestCase, self).setUp()
        self.dhcp6_responer = dhcp_ipv6.DHCPIPv6Responder(self.agent_api,
                                                          self.ext_api)
        self.dhcp6_responer.int_br = self.int_br

    def _compare_option_values(self, expect_options, test_options):
        # os_ken dhcp.option class does not have __eq__ method so
        # compare one by one
        expected = [(option.code, option.length, option.data)
                    for option in expect_options]
        test = [(option.code, option.length, option.data)
                for option in test_options]
        for i in test:
            self.assertIn(i, expected)

    def _create_test_dhcp6_packet(self, zero_time=False):
        ret_pkt = packet.Packet()
        ret_pkt.add_protocol(
            ethernet.ethernet(
                ethertype=ether_types.ETH_TYPE_IPV6,
                dst='33:33:00:01:00:02',
                src=self.port_info['mac_address']))
        ret_pkt.add_protocol(
            ipv6.ipv6(
                src='fe80::f816:3eff:fe60:714b',
                dst='ff02::1:2',
                nxt=inet.IPPROTO_UDP))
        ret_pkt.add_protocol(
            udp.udp(
                src_port=constants.DHCPV6_RESPONSE_PORT,
                dst_port=constants.DHCPV6_CLIENT_PORT))

        options = [dhcp6.option(
            code=1,
            data=b"\x00\x01\x00\x01",
            length=4)]
        if zero_time:
            options.append(dhcp6.option(
                code=3,
                data=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                length=12))
        else:
            options.append(dhcp6.option(
                code=3,
                data=b"\x01\x02\x03\x04\x05\x06\x07\x08\x0a\x0b\x0c\x0d",
                length=12))
        ret_pkt.add_protocol(dhcp6.dhcp6(
            dhcp6.DHCPV6_REQUEST, dhcp6.options(option_list=options)))
        return ret_pkt

    def test_get_dhcpv6_client_ident(self):
        packet_in = self._create_test_dhcp6_packet()
        header_dhcp = packet_in.get_protocol(dhcp6.dhcp6)
        client_ident = self.dhcp6_responer.get_dhcpv6_client_ident(
            self.port_info['mac_address'], header_dhcp.options.option_list)
        self.assertEqual(header_dhcp.options.option_list[0].data,
                         client_ident)

        expect_ident = (
            b'\x00\x01\x00\x01\x00\x00\x00\x01\x00\x01\x02\x03\x04\x05')
        time_p = mock.patch.object(time, 'time',
                                   return_value=ONE_SEC_AFTER_2000)
        time_p.start()
        self.addCleanup(time_p.stop)
        client_ident = client_ident = (
            self.dhcp6_responer.get_dhcpv6_client_ident(
                self.port_info['mac_address'], []))
        self.assertEqual(expect_ident, client_ident)

    def test_get_dhcpv6_server_ident(self):
        self.dhcp6_responer.get_dhcpv6_server_ident()

    def test_get_dhcpv6_status_code(self):
        expect_status_code = b'\x00\x00success'
        status_code = self.dhcp6_responer.get_dhcpv6_status_code(
            "success", code=0)
        self.assertEqual(expect_status_code, status_code)

    def test_get_dhcp_options(self):
        self._test_get_dhcp_options()

    def test_get_dhcp_options_zero_time(self):
        self._test_get_dhcp_options(zero_time=True)

    def _test_get_dhcp_options(self, zero_time=False):
        ip_info = self.dhcp6_responer.get_port_ip(self.port_info, ip_version=6)
        mac = self.port_info['mac_address']

        option_list = [
            dhcp6.option(
                code=1,
                data=b"\x00\x01\x00\x01",
                length=4),
            dhcp6.option(
                code=2,
                data=b'\x00\x01\x00\x01\x00\x00\x00\x01\xfa\x16>\x00\x00\x00',
                length=14),
            dhcp6.option(code=13,
                data=b'\x00\x00success',
                length=9),
            dhcp6.option(
                code=23,
                data=(b'\xfd\xa7\xa5\xcc4`\x00\x01\x00'
                      b'\x00\x00\x00\x00\x00\x00\x01'),
                length=16),
            dhcp6.option(
                code=24,
                data=b'\x0eopenstacklocal\x00',
                length=16),
            dhcp6.option(
                code=39,
                data=b'\x03(host-fda7-a5cc-3460-1--bf.openstacklocal',
                length=42)]
        if zero_time:
            option_list.append(dhcp6.option(code=3,
                data=(b'\x00\x00\x00\x01\x00\x01Q\x80\x00\x01Q'
                      b'\x80\x00\x05\x00\x18\xfd\xa7\xa5\xcc4`'
                      b'\x00\x01\x00\x00\x00\x00\x00\x00\x00'
                      b'\xbf\x00\x01Q\x80\x00\x01Q\x80'),
                length=40))
        else:
            option_list.append(dhcp6.option(code=3,
                data=(b'\x01\x02\x03\x04\x05\x06\x07\x08\n\x0b\x0c\r'
                      b'\x00\x05\x00\x18\xfd\xa7\xa5\xcc4`'
                      b'\x00\x01\x00\x00\x00\x00\x00\x00\x00'
                      b'\xbf\x05\x06\x07\x08\n\x0b\x0c\r'),
                length=40))

        test_options = dhcp6.options(
            option_list=option_list,
            options_len=0)

        time_p = mock.patch.object(time, 'time',
                                   return_value=ONE_SEC_AFTER_2000)
        time_p.start()
        self.addCleanup(time_p.stop)
        packet_in = self._create_test_dhcp6_packet(zero_time=zero_time)
        pkt_dhcp = packet_in.get_protocol(dhcp6.dhcp6)
        dhcp_req_state = dhcp_ipv6.DHCPV6_TYPE_MAP.get(pkt_dhcp.msg_type)
        dhcp_options = self.dhcp6_responer.get_dhcp_options(
            mac, ip_info, pkt_dhcp.options.option_list, dhcp_req_state)
        self._compare_option_values(test_options.option_list,
                                    dhcp_options.option_list)

    def test_get_ret_packet(self):
        packet_in = self._create_test_dhcp6_packet()
        pkt_dhcp = packet_in.get_protocol(dhcp6.dhcp6)
        dhcp_req_state = dhcp_ipv6.DHCPV6_TYPE_MAP.get(pkt_dhcp.msg_type)
        ret_packet = self.dhcp6_responer.get_ret_packet(
            packet_in, self.port_info, dhcp_req_state)

        header_eth = ret_packet.get_protocol(ethernet.ethernet)
        header_ipv6 = ret_packet.get_protocol(ipv6.ipv6)
        header_dhcp = ret_packet.get_protocol(dhcp6.dhcp6)

        self.assertIsNotNone(header_eth)
        self.assertIsNotNone(header_ipv6)
        self.assertIsNotNone(header_dhcp)

    def test_get_reply_dhcp_options(self):
        mac = '00:01:02:03:04:05'
        packet_in = self._create_test_dhcp6_packet()
        header_dhcp = packet_in.get_protocol(dhcp6.dhcp6)
        time_p = mock.patch.object(time, 'time',
                                   return_value=ONE_SEC_AFTER_2000)
        time_p.start()
        self.addCleanup(time_p.stop)
        dhcp_options = self.dhcp6_responer.get_reply_dhcp_options(
            mac, message="all addresses still on link",
            req_options=header_dhcp.options.option_list)

        test_options = dhcp6.options(option_list=[
            dhcp6.option(code=1, data=b'\x00\x01\x00\x01', length=4),
            dhcp6.option(
                code=2,
                data=b'\x00\x01\x00\x01\x00\x00\x00\x01\xfa\x16>\x00\x00\x00',
                length=14),
            dhcp6.option(code=13, data=b'\x00\x00all addresses still on link',
                         length=29)],
            options_len=0)

        self._compare_option_values(test_options.option_list,
                                    dhcp_options.option_list)

    def test_handle_dhcp(self):
        self.dhcp6_responer.packet_out = mock.Mock()
        datapath = mock.Mock()
        ofport = 1
        packet_in = self._create_test_dhcp6_packet()
        self.dhcp6_responer.handle_dhcp(
            datapath, ofport, packet_in, self.port_info)
        self.dhcp6_responer.packet_out.assert_called_once_with(
            datapath, ofport, mock.ANY)
