# Copyright (c) 2025 OMZ Cloud
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
import socket
from unittest import mock

from os_ken.lib.packet import ether_types
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import in_proto as inet
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import ipv6
from os_ken.lib.packet import packet
from os_ken.lib.packet import udp
from oslo_config import cfg

from neutron.agent.l2.extensions.dns_forwarder import DNSResponder
from neutron.plugins.ml2.drivers.openvswitch.agent \
    import ovs_agent_extension_api as ovs_ext_api
from neutron.tests import base


class FakeOF:
    OFPR_NO_MATCH = 0
    OFPR_ACTION = 1
    FPR_INVALID_TTL = 2
    OFP_NO_BUFFER = 3
    OFPP_CONTROLLER = 4


class FakeDatapath:
    ofproto = FakeOF()


class FakeMsg:
    datapath = mock.Mock()
    reason = datapath.ofproto.OFPR_ACTION
    match = {'in_port': 1}
    data = ""
    buffer_id = 1
    total_len = 1
    table_id = 60
    cookie = 1

    def set_data(self, packet):
        packet.serialize()
        self.data = packet.data


class DNSForwarderResponderTestCase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
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
        self.dns_forwarder = DNSResponder(self.agent_api)
        self.dns_question_data = (
            b'\x124\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\nopenstack\x03org\x00\x00\x01\x00\x01'
        )

    def _build_dns_question_packet(self, for_ipv6=False):
        """Build a DNS question packet to ask about openstack.org"""
        ret_pkt = packet.Packet()
        if for_ipv6:
            ret_pkt.add_protocol(ethernet.ethernet(
                dst="11:22:33:44:55:66",
                src="aa:bb:cc:dd:ee:ff",
                ethertype=ether_types.ETH_TYPE_IPV6
            ))
            ret_pkt.add_protocol(
                ipv6.ipv6(dst="fd00::254",
                          src="2001:db8::1",
                          nxt=inet.IPPROTO_UDP))
        else:
            ret_pkt.add_protocol(ethernet.ethernet(
                dst="11:22:33:44:55:66",
                src="aa:bb:cc:dd:ee:ff",
                ethertype=ether_types.ETH_TYPE_IP
            ))
            ret_pkt.add_protocol(
                ipv4.ipv4(dst="169.254.169.254",
                          src="192.168.100.122",
                          proto=inet.IPPROTO_UDP))
        ret_pkt.add_protocol(udp.udp(
                      src_port=35678,
                      dst_port=53,
                      total_length=8 + len(self.dns_question_data)))
        ret_pkt.add_protocol(self.dns_question_data)
        return ret_pkt

    @mock.patch('neutron.agent.l2.extensions.dns_forwarder.socket.socket')
    def test_forward_to_upstream_valid_ipv4(self, mock_socket_class):
        cfg.CONF.set_override(
            'upstream_dns_server_ports', ['8.8.8.8:53'],
            group='DNS_FORWARDER'
        )
        self.dns_forwarder = DNSResponder(self.agent_api)

        mock_socket = mock.MagicMock()
        mock_socket.recvfrom.return_value = (
            b'response_bytes', ('8.8.8.8', 53)
        )
        mock_socket_class.return_value.__enter__.return_value = mock_socket

        self.dns_forwarder.forward_to_upstream(self.dns_question_data)

        mock_socket_class.assert_called_with(socket.AF_INET, socket.SOCK_DGRAM)
        mock_socket.settimeout.assert_called_once()
        mock_socket.sendto.assert_called_once_with(
            self.dns_question_data, ('8.8.8.8', 53)
        )
        mock_socket.recvfrom.assert_called_once_with(4096)

    @mock.patch('neutron.agent.l2.extensions.dns_forwarder.socket.socket')
    def test_forward_to_upstream_valid_ipv6(self, mock_socket_class):
        cfg.CONF.set_override(
            'upstream_dns_server_ports', ['[2001:4860:4860::8888]:53'],
            group='DNS_FORWARDER'
        )
        self.dns_forwarder = DNSResponder(self.agent_api)

        mock_socket = mock.MagicMock()
        mock_socket.recvfrom.return_value = (
            b'response_bytes', ('2001:4860:4860::8888', 53)
        )
        mock_socket_class.return_value.__enter__.return_value = mock_socket

        self.dns_forwarder.forward_to_upstream(self.dns_question_data)

        mock_socket_class.assert_called_with(
            socket.AF_INET6, socket.SOCK_DGRAM
        )
        mock_socket.settimeout.assert_called_once()
        mock_socket.sendto.assert_called_once_with(
            self.dns_question_data, ('2001:4860:4860::8888', 53)
        )
        mock_socket.recvfrom.assert_called_once_with(4096)

    @mock.patch('neutron.agent.l2.extensions.dns_forwarder.sys.exit')
    def test_forward_to_upstream_sys_exit(self, mock_exit):
        cfg.CONF.set_override(
            'upstream_dns_server_ports',
            ['8.8.8.999:53', '[2001:4860:4860::8888]:53'],
            group='DNS_FORWARDER'
        )

        with self.assertLogs(
            'neutron.agent.l2.extensions.dns_forwarder', level='ERROR'
        ) as cm:
            self.dns_forwarder = DNSResponder(self.agent_api)
            self.assertIn(
                "Invalid upstream_dns_server_ports config",
                cm.output[0]
            )
            self.assertEqual(len(cm.output), 1)
            mock_exit.assert_called_once_with(1)

    def test_forward_to_upstream_value_error(self):
        self.assertRaises(
            ValueError,
            cfg.CONF.set_override,
            'upstream_dns_server_ports',
            ['8.8.8.999', '[2001:4860:4860::8888]:53'],
            group='DNS_FORWARDER'
        )

    def test__get_dns_payload(self):
        ret_pkt = self._build_dns_question_packet()
        payload, _ip_version = self.dns_forwarder._get_dns_payload(ret_pkt)
        self.assertEqual(self.dns_question_data, payload)

    def test__build_dns_response_packet_ipv4(self):
        original_ipv4_pkt = self._build_dns_question_packet()
        fake_dns_response = b'response_bytes'

        response_pkt = self.dns_forwarder._build_dns_response_packet(
            original_ipv4_pkt,
            dns_response=fake_dns_response,
            ip_version=4
        )

        protocols = {type(p): p for p in response_pkt.protocols}

        # MAC Address swapped
        eth = protocols[ethernet.ethernet]
        self.assertEqual(eth.src, '11:22:33:44:55:66')
        self.assertEqual(eth.dst, 'aa:bb:cc:dd:ee:ff')

        # IPs swapped
        ip = protocols[ipv4.ipv4]
        self.assertEqual(ip.src, '169.254.169.254')
        self.assertEqual(ip.dst, '192.168.100.122')

        # UDP ports swapped
        udp_hdr = protocols[udp.udp]
        self.assertEqual(udp_hdr.src_port, 53)
        self.assertEqual(udp_hdr.dst_port, 35678)

        # Payload match
        self.assertIn(fake_dns_response, response_pkt.data)

    def test__build_dns_response_packet_ipv6(self):
        original_ipv6_pkt = self._build_dns_question_packet(for_ipv6=True)
        fake_dns_response = b'response_bytes'

        response_pkt = self.dns_forwarder._build_dns_response_packet(
            original_ipv6_pkt,
            dns_response=fake_dns_response,
            ip_version=6
        )

        protocols = {type(p): p for p in response_pkt.protocols}

        # MAC Address swapped
        eth = protocols[ethernet.ethernet]
        self.assertEqual(eth.src, '11:22:33:44:55:66')
        self.assertEqual(eth.dst, 'aa:bb:cc:dd:ee:ff')

        # IPs swapped
        ip = protocols[ipv6.ipv6]
        self.assertEqual(ip.src, 'fd00::254')
        self.assertEqual(ip.dst, '2001:db8::1')

        # UDP ports swapped
        udp_hdr = protocols[udp.udp]
        self.assertEqual(udp_hdr.src_port, 53)
        self.assertEqual(udp_hdr.dst_port, 35678)

        # Payload match
        self.assertIn(fake_dns_response, response_pkt.data)

    def _test__packet_in_handler(self, for_ipv6=False):
        pkt = self._build_dns_question_packet()
        ev = mock.Mock()
        ev.msg = FakeMsg()
        ev.msg.set_data(pkt)

        with self.assertLogs(
            'neutron.agent.l2.extensions.dns_forwarder', level='DEBUG'
        ) as cm:
            self.dns_forwarder._packet_in_handler(ev)
            self.assertIn(
                "DNS Controller packet out to OF port", cm.output[-1]
            )

    @mock.patch('neutron.agent.l2.extensions'
                '.dns_forwarder.DNSResponder.forward_to_upstream')
    def test__packet_in_handler_ipv4(self, mock_forward_to_upstream):
        mock_forward_to_upstream.return_value = b'response_bytes'
        self._test__packet_in_handler(for_ipv6=False)

    @mock.patch('neutron.agent.l2.extensions'
                '.dns_forwarder.DNSResponder.forward_to_upstream')
    def test__packet_in_handler_ipv6(self, mock_forward_to_upstream):
        mock_forward_to_upstream.return_value = b'response_bytes'
        self._test__packet_in_handler(for_ipv6=True)
