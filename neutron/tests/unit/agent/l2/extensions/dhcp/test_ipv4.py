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

from os_ken.lib.packet import dhcp
from os_ken.lib.packet import ipv4

from neutron.agent.l2.extensions.dhcp import ipv4 as dhcp_ipv4
from neutron.tests.unit.agent.l2.extensions.dhcp \
    import test_base as dhcp_test_base


class DHCPIPv4ResponderTestCase(dhcp_test_base.DHCPResponderBaseTestCase):

    def setUp(self):
        super(DHCPIPv4ResponderTestCase, self).setUp()
        self.dhcp4_responer = dhcp_ipv4.DHCPIPv4Responder(self.agent_api,
                                                          self.ext_api)
        self.dhcp4_responer.int_br = self.int_br

    def _compare_option_values(self, expect_options, test_options):
        # os_ken dhcp.option class does not have __eq__ method so compare
        # one by one
        expected = [(option.tag, option.length, option.value)
                    for option in expect_options]
        test = [(option.tag, option.length, option.value)
                for option in test_options]
        for i in test:
            self.assertIn(i, expected)

    def test_handle_dhcp(self):
        self.dhcp4_responer.packet_out = mock.Mock()
        datapath = mock.Mock()
        ofport = 1
        packet_in = self._create_test_dhcp_request_packet()
        self.dhcp4_responer.handle_dhcp(
            datapath, ofport, packet_in, self.port_info)
        self.dhcp4_responer.packet_out.assert_called_once_with(
            datapath, ofport, mock.ANY)

    def test_get_state(self):
        packet_in = self._create_test_dhcp_request_packet()
        dhcp_pkt = packet_in.get_protocol(dhcp.dhcp)
        state = self.dhcp4_responer.get_state(dhcp_pkt)
        self.assertEqual('DHCPREQUEST', state)

    def test_get_ret_packet(self):
        packet_in = self._create_test_dhcp_request_packet()
        ret_pkt = self.dhcp4_responer.get_ret_packet(
            packet_in, self.port_info, is_ack=False)

        ip_header = ret_pkt.get_protocol(ipv4.ipv4)
        self.assertIsNotNone(ip_header)
        dhcp_pkt = ret_pkt.get_protocols(dhcp.dhcp)
        self.assertIsNotNone(dhcp_pkt)

    def test_get_dhcp_options(self):
        expect_bin_routes = (b'\x00\xc0\xa8o\x01 \xa9\xfe\xa9\xfe\xc0\xa8o\x01'
                             b'\x18\x01\x01\x01\xc0\xa8\x01d '
                             b'\x02\x02\x02\x02\xc0\xa8\x01e')
        expect_offer_options = dhcp.options(
            magic_cookie='99.130.83.99',
            option_list=[
                dhcp.option(length=0, tag=53, value=b'\x02'),
                dhcp.option(length=0, tag=54, value=b'\xc0\xa8o\x01'),
                dhcp.option(length=0, tag=51, value=b'\x00\x01Q\x80'),
                dhcp.option(length=0, tag=1, value=b'\xff\xff\xff\x00'),
                dhcp.option(length=0, tag=28, value=b'\xc0\xa8o\xff'),
                dhcp.option(length=0, tag=6,
                            value=b'\x08\x08\x08\x08\x08\x08\x04\x04'),
                dhcp.option(length=0, tag=15, value=b'openstacklocal'),
                dhcp.option(length=0, tag=3, value=b'\xc0\xa8o\x01'),
                dhcp.option(
                    length=0, tag=121,
                    value=expect_bin_routes),
                dhcp.option(length=0, tag=26, value=b'\x05\xaa')],
            options_len=0)
        offer_options = self.dhcp4_responer.get_dhcp_options(self.port_info)
        self._compare_option_values(expect_offer_options.option_list,
                                    offer_options.option_list)

        expect_ack_options = dhcp.options(
            magic_cookie='99.130.83.99',
            option_list=[
                dhcp.option(length=0, tag=53, value=b'\x05'),
                dhcp.option(length=0, tag=54, value=b'\xc0\xa8o\x01'),
                dhcp.option(length=0, tag=51, value=b'\x00\x01Q\x80'),
                dhcp.option(length=0, tag=1, value=b'\xff\xff\xff\x00'),
                dhcp.option(length=0, tag=28, value=b'\xc0\xa8o\xff'),
                dhcp.option(length=0, tag=6,
                            value=b'\x08\x08\x08\x08\x08\x08\x04\x04'),
                dhcp.option(length=0, tag=15, value=b'openstacklocal'),
                dhcp.option(length=0, tag=3, value=b'\xc0\xa8o\x01'),
                dhcp.option(
                    length=0, tag=121,
                    value=expect_bin_routes),
                dhcp.option(length=0, tag=26, value=b'\x05\xaa')],
            options_len=0)
        ack_options = self.dhcp4_responer.get_dhcp_options(
            self.port_info, is_ack=True)
        self._compare_option_values(expect_ack_options.option_list,
                                    ack_options.option_list)

    def test_get_bin_routes(self):
        expect_bin_routes = (b'\x00\xc0\xa8o\x01 \xa9\xfe\xa9\xfe\xc0\xa8o\x01'
                             b'\x18\x01\x01\x01\xc0\xa8\x01d '
                             b'\x02\x02\x02\x02\xc0\xa8\x01e')
        bin_routes = self.dhcp4_responer.get_bin_routes(
            self.port_info['fixed_ips'][0]['gateway_ip'],
            self.port_info['fixed_ips'][0]['host_routes'])
        self.assertEqual(expect_bin_routes, bin_routes)
