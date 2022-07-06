# Copyright (c) 2021 China Unicom Cloud Data Co.,Ltd.
# Copyright (c) 2019 - 2020 China Telecom Corporation
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

import struct

import netaddr
from neutron_lib import constants
from os_ken.lib import addrconv
from os_ken.lib.packet import dhcp
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import packet
from os_ken.lib.packet import udp
from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.l2.extensions.dhcp import base as dhcp_base

LOG = logging.getLogger(__name__)

DHCPV4_TYPE_MAP = {dhcp.DHCP_DISCOVER: 'DHCPDISCOVER',
                   dhcp.DHCP_OFFER: 'DHCPOFFER',
                   dhcp.DHCP_REQUEST: 'DHCPREQUEST',
                   dhcp.DHCP_ACK: 'DHCPACK'}
DHCPV4_MSG_TYPE_BYTES_ACK = b'\x05'
DHCPV4_MSG_TYPE_BYTES_OFFER = b'\x02'

# TODO(liuyulong): Move to os-ken(ryu) someday.
# Align the name prefix with the definitions in
# os_ken.lib.packet.dhcp.
DHCP_BROADCAST_ADDRESS_OPT = 28


class DHCPIPv4Responder(dhcp_base.DHCPResponderBase):

    def get_bin_routes(self, gateway=None, routes=None):
        bin_routes = b''

        # Default routes
        default_route = self.get_bin_route(constants.IPv4_ANY, gateway)
        bin_routes += default_route

        # For some VMs they may need the metadata IP's route, we move
        # the destination to gateway IP.
        if gateway:
            meta_route = self.get_bin_route(
                constants.METADATA_V4_CIDR, gateway)
            bin_routes += meta_route

        # Subnet routes
        for route in routes or []:
            bin_routes += self.get_bin_route(route['destination'],
                                             route['nexthop'])
        return bin_routes

    def get_dhcp_options(self, port_info, is_ack=False):
        fixed_ips = port_info['fixed_ips']
        net = netaddr.IPNetwork(fixed_ips[0]['cidr'])
        dns_nameservers = fixed_ips[0]['dns_nameservers']
        host_routes = fixed_ips[0]['host_routes']
        gateway_ip = fixed_ips[0]['gateway_ip']
        bin_server = addrconv.ipv4.text_to_bin(gateway_ip)

        option_list = []

        if is_ack:
            option_list.append(
                dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT,
                            value=DHCPV4_MSG_TYPE_BYTES_ACK))
        else:
            option_list.append(
                dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT,
                            value=DHCPV4_MSG_TYPE_BYTES_OFFER))

        option_list.append(
            dhcp.option(tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT,
                        value=bin_server))
        option_list.append(
            dhcp.option(tag=dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT,
                        value=struct.pack(
                            '!i', cfg.CONF.dhcp_lease_duration)))

        if cfg.CONF.DHCP.dhcp_renewal_time > 0:
            option_list.append(
                dhcp.option(tag=dhcp.DHCP_RENEWAL_TIME_OPT,
                            value=struct.pack(
                                '!I', cfg.CONF.DHCP.dhcp_renewal_time)))
        if cfg.CONF.DHCP.dhcp_rebinding_time > 0:
            option_list.append(
                dhcp.option(tag=dhcp.DHCP_REBINDING_TIME_OPT,
                            value=struct.pack(
                                '!I', cfg.CONF.DHCP.dhcp_rebinding_time)))

        option_list.append(
            dhcp.option(tag=dhcp.DHCP_SUBNET_MASK_OPT,
                        value=addrconv.ipv4.text_to_bin(str(net.netmask))))
        # Option: (28) Broadcast Address
        option_list.append(
            dhcp.option(tag=DHCP_BROADCAST_ADDRESS_OPT,
                        value=addrconv.ipv4.text_to_bin(str(net.broadcast))))
        # DNS
        if dns_nameservers:
            option_list.append(
                dhcp.option(tag=dhcp.DHCP_DNS_SERVER_ADDR_OPT,
                value=self.get_bin_dns(dns_nameservers)))
        if cfg.CONF.dns_domain:
            option_list.append(
                dhcp.option(tag=dhcp.DHCP_DOMAIN_NAME_OPT,
                            value=struct.pack(
                                '!%ds' % len(cfg.CONF.dns_domain),
                                str.encode(cfg.CONF.dns_domain))))
        option_list.append(
            dhcp.option(tag=dhcp.DHCP_GATEWAY_ADDR_OPT,
                        value=bin_server))
        # Static routes
        option_list.append(
            dhcp.option(tag=dhcp.DHCP_CLASSLESS_ROUTE_OPT,
                        value=self.get_bin_routes(gateway_ip,
                                                  host_routes)))
        # MTU
        mtu = int(port_info.get('mtu', 0))
        if mtu > 0:
            mtu_bin = struct.pack('!H', mtu)
            option_list.append(
                dhcp.option(tag=dhcp.DHCP_INTERFACE_MTU_OPT,
                            value=mtu_bin))
        options = dhcp.options(option_list=option_list)
        return options

    def get_ret_packet(self, packet_in, port_info, is_ack=False):
        ip_info = self.get_port_ip(port_info,
                                   ip_version=constants.IP_VERSION_4)
        if not ip_info:
            return
        ip_addr = ip_info['ip_address']
        gateway_ip = ip_info['gateway_ip']

        options = self.get_dhcp_options(port_info, is_ack)
        if is_ack:
            fqdn = 'host-%s' % ip_addr.replace('.', '-').replace(':', '-')
            if cfg.CONF.dns_domain:
                fqdn = '%s.%s' % (fqdn, cfg.CONF.dns_domain)
            domain_name_bin = struct.pack('!%ds' % len(fqdn),
                                          bytes(str(fqdn).encode()))
            options.option_list.append(
                dhcp.option(tag=dhcp.DHCP_HOST_NAME_OPT,
                            value=domain_name_bin))

        header_eth = packet_in.get_protocol(ethernet.ethernet)
        header_ipv4 = packet_in.get_protocol(ipv4.ipv4)
        header_dhcp = packet_in.get_protocol(dhcp.dhcp)

        ret_pkt = packet.Packet()
        ret_pkt.add_protocol(ethernet.ethernet(
            ethertype=header_eth.ethertype,
            dst=header_eth.src,
            src=self.hw_addr))
        ret_pkt.add_protocol(
            ipv4.ipv4(dst=header_ipv4.dst,
                      src=gateway_ip,
                      proto=header_ipv4.proto))
        ret_pkt.add_protocol(udp.udp(src_port=constants.DHCP_RESPONSE_PORT,
                                     dst_port=constants.DHCP_CLIENT_PORT))
        ret_pkt.add_protocol(dhcp.dhcp(op=dhcp.DHCP_BOOT_REPLY,
                                       chaddr=header_eth.src,
                                       siaddr=gateway_ip,
                                       boot_file=header_dhcp.boot_file,
                                       yiaddr=ip_addr,
                                       xid=header_dhcp.xid,
                                       options=options))
        return ret_pkt

    def assemble_ack(self, pkt, port_info):
        ack = self.get_ret_packet(pkt, port_info, is_ack=True)
        LOG.debug("DHCP controller DHCPv4 ACK assembled: %s", ack)
        return ack

    def assemble_offer(self, pkt, port_info):
        offer = self.get_ret_packet(pkt, port_info)
        LOG.debug("DHCP controller DHCPv4 offer assemble: %s", offer)
        return offer

    def get_state(self, pkt_dhcp):
        dhcp_state = ord(
            [opt for opt in pkt_dhcp.options.option_list
             if opt.tag == dhcp.DHCP_MESSAGE_TYPE_OPT][0].value)
        return DHCPV4_TYPE_MAP.get(dhcp_state)

    def handle_dhcp(self, datapath, ofport, pkt, port_info):
        pkt_dhcp = pkt.get_protocol(dhcp.dhcp)
        dhcp_state = self.get_state(pkt_dhcp)
        LOG.debug("DHCP controller DHCPv4 packet received, "
                  "state: %s, data: %s",
                  dhcp_state, pkt_dhcp)
        if dhcp_state == 'DHCPDISCOVER':
            self.packet_out(datapath, ofport,
                            self.assemble_offer(pkt, port_info))
        elif dhcp_state == 'DHCPREQUEST':
            self.packet_out(datapath, ofport,
                            self.assemble_ack(pkt, port_info))
