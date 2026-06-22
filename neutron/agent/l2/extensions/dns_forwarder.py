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
import sys

import netaddr
from neutron_lib.agent import l2_extension as l2_agent_extension
from neutron_lib import constants as lib_consts
from os_ken.base import app_manager
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import ipv6
from os_ken.lib.packet import packet
from os_ken.lib.packet import udp
from oslo_config import cfg
from oslo_log import log as logging

from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import base_oskenapp

LOG = logging.getLogger(__name__)


class DNSResponder(base_oskenapp.BaseNeutronAgentOSKenApp):

    def __init__(self, agent_api, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.agent_api = agent_api
        self.int_br = self.agent_api.request_int_br()
        self.name = "DNSResponder"
        self.upstream_dns_server_ports = []

        for ip_port in cfg.CONF.DNS_FORWARDER.upstream_dns_server_ports:
            try:
                ip_part, port_part = ip_port.rsplit(':', 1)
                ip = ip_part.replace('[', '').replace(']', '')
                self.upstream_dns_server_ports.append({
                    'ip_port': ip_port,
                    'ip': ip,
                    'netaddr_ip': netaddr.IPAddress(ip),
                    'port': int(port_part)
                })
            except (ValueError, netaddr.AddrFormatError):
                LOG.error(
                    "Invalid upstream_dns_server_ports config: %s",
                    ip_port
                )
                sys.exit(1)

        self.register_packet_in_handler(self._packet_in_handler)

    def forward_to_upstream(self, query_data):
        """Forward DNS query to upstream servers"""
        for dns_server in self.upstream_dns_server_ports:
            LOG.debug(
                "Connect to DNS upstream server: %s",
                dns_server["ip_port"]
            )
            try:
                socket_family = (
                    socket.AF_INET6
                    if dns_server[
                        'netaddr_ip'
                    ].version == lib_consts.IP_VERSION_6 else socket.AF_INET
                )

                with socket.socket(
                    socket_family, socket.SOCK_DGRAM
                ) as upstream_socket:
                    upstream_socket.settimeout(
                        cfg.CONF.DNS_FORWARDER.upstream_dns_query_timeout
                    )
                    upstream_socket.sendto(
                        query_data,
                        (dns_server['ip'], dns_server['port'])
                    )
                    response, _address = upstream_socket.recvfrom(4096)
                    return response

            except Exception as e:
                LOG.debug(
                    "Failed to query upstream server %s: %s",
                    dns_server["ip_port"], e
                )

    def _packet_in_handler(self, event):
        msg = event.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        if msg.reason != ofproto.OFPR_ACTION:
            LOG.debug("DNS Controller only handle the packet which "
                      "match the rules and the action is send to the "
                      "controller.")
            return

        of_in_port = msg.match['in_port']
        LOG.debug("DNS Controller packet in OF port: %s", of_in_port)
        pkt = packet.Packet(data=msg.data)

        LOG.debug('DNS Controller packet received: '
                  'buffer_id=%x total_len=%d reason=ACTION '
                  'table_id=%d cookie=%d match=%s pkt=%s',
                  msg.buffer_id, msg.total_len,
                  msg.table_id, msg.cookie, msg.match,
                  pkt)

        # Check for UDP packet protocol
        udp_header = pkt.get_protocol(udp.udp)
        if not udp_header:
            LOG.debug("DNS Controller received packet is not a UDP packet")
            return

        # DNS Forwarding
        dns_payload, ip_version = self._get_dns_payload(pkt)
        if not dns_payload:
            return

        dns_result = self.forward_to_upstream(dns_payload)
        if dns_result:
            # Build complete response packet
            response_pkt = self._build_dns_response_packet(
                pkt, dns_result, ip_version
            )

            parser = datapath.ofproto_parser
            actions = [parser.OFPActionOutput(port=of_in_port)]
            out = parser.OFPPacketOut(datapath=datapath,
                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                    in_port=ofproto.OFPP_CONTROLLER,
                                    actions=actions,
                                    data=response_pkt.data)
            LOG.debug(
                "DNS Controller packet out to OF port %s, %s", of_in_port, out
            )
            datapath.send_msg(out)

    def _get_dns_payload(self, pkt):
        """Extract DNS payload from the packet."""
        try:
            # Get the raw packet data
            pkt.serialize()
            data = pkt.data

            # Parse Ethernet header (14 bytes)
            eth_header_len = 14

            # Parse IP header to get its length
            ip_version = (data[eth_header_len] >> 4) & 0xF

            if ip_version == 4:
                # IPv4 header length is in the lower 4 bits of the first byte
                # multiplied by 4
                ip_header_len = (data[eth_header_len] & 0xF) * 4
            elif ip_version == 6:
                # IPv6 header is fixed at 40 bytes
                ip_header_len = 40
            else:
                return None, None

            # UDP header is 8 bytes
            udp_header_len = 8

            # DNS payload starts after Ethernet + IP + UDP headers
            dns_start = eth_header_len + ip_header_len + udp_header_len

            if len(data) <= dns_start:
                return None, None

            return data[dns_start:], ip_version
        except Exception as e:
            LOG.error("Error extracting DNS payload: %s", e)
            return None, None

    def _build_dns_response_packet(
        self, original_pkt, dns_response, ip_version=4
    ):
        """Build complete DNS response packet"""
        eth_header = original_pkt.get_protocol(ethernet.ethernet)
        udp_header = original_pkt.get_protocol(udp.udp)

        # Create response packet
        response_pkt = packet.Packet()

        # Add Ethernet header (swap src/dst)
        response_pkt.add_protocol(ethernet.ethernet(
            ethertype=eth_header.ethertype,
            dst=eth_header.src,
            src=eth_header.dst
        ))

        if ip_version == 6:
            # IPv6 header
            ip_header = original_pkt.get_protocol(ipv6.ipv6)
            response_pkt.add_protocol(ipv6.ipv6(
                dst=ip_header.src,
                src=ip_header.dst,
                nxt=ip_header.nxt
            ))
        else:
            # IPv4 header
            ip_header = original_pkt.get_protocol(ipv4.ipv4)
            response_pkt.add_protocol(ipv4.ipv4(
                dst=ip_header.src,
                src=ip_header.dst,
                proto=ip_header.proto
            ))

        # Add UDP header (swap ports)
        response_pkt.add_protocol(udp.udp(
            dst_port=udp_header.src_port,
            src_port=udp_header.dst_port
        ))

        # Add DNS response as raw payload
        response_pkt.add_protocol(dns_response)
        response_pkt.serialize()

        return response_pkt


class DNSForwarderAgentExtension(l2_agent_extension.L2AgentExtension):

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def initialize(self, connection, driver_type):
        self.app_mgr = app_manager.AppManager.get_instance()
        app = self.app_mgr.instantiate(DNSResponder, self.agent_api)
        app.start()

    def handle_port(self, context, data):
        """DNSForwarder do nothing when port is updated/created"""

    def delete_port(self, context, data):
        """DNSForwarder do nothing when port is deleted"""
