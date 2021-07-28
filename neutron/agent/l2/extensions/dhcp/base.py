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

import math
import struct

import netaddr
from neutron_lib.api import converters
from os_ken.lib import addrconv
from os_ken.lib.packet import dhcp
from os_ken.lib.packet import dhcp6
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import ipv6
from os_ken.lib.packet import packet
from oslo_config import cfg
from oslo_log import log as logging

from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import base_oskenapp

LOG = logging.getLogger(__name__)

IPV4_STR = "v4"
IPV6_STR = "v6"


class DHCPResponderBase(base_oskenapp.BaseNeutronAgentOSKenApp):

    def __init__(self, agent_api, ext_api, version=IPV4_STR, *args, **kwargs):
        super(DHCPResponderBase, self).__init__(*args, **kwargs)
        self.agent_api = agent_api
        self.int_br = self.agent_api.request_int_br()
        self.ext_api = ext_api
        self.version = version
        self.name = "DHCP%sResponder" % version

        self.hw_addr = converters.convert_to_sanitized_mac_address(
            cfg.CONF.base_mac)
        self.register_packet_in_handler(self._packet_in_handler)

    def _packet_in_handler(self, event):
        msg = event.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        if msg.reason != ofproto.OFPR_ACTION:
            LOG.debug("DHCP Controller only handle the packet which "
                      "match the rules and the action is send to the "
                      "controller.")
            return

        of_in_port = msg.match['in_port']
        LOG.info("DHCP Controller packet in OF port: %s", of_in_port)
        pkt = packet.Packet(data=msg.data)

        LOG.debug('DHCP Controller packet received: '
                  'buffer_id=%x total_len=%d reason=ACTION '
                  'table_id=%d cookie=%d match=%s pkt=%s',
                  msg.buffer_id, msg.total_len,
                  msg.table_id, msg.cookie, msg.match,
                  pkt)

        if self.version == IPV4_STR:
            ip_protocol = ipv4.ipv4
            dhcp_protocol = dhcp.dhcp
        else:
            ip_protocol = ipv6.ipv6
            dhcp_protocol = dhcp6.dhcp6
        ip_header = pkt.get_protocol(ip_protocol)
        if not ip_header:
            LOG.warning("DHCP Controller received packet "
                        "is not an IP%s packet",
                        self.version)
            return

        dhcp_pkt = pkt.get_protocol(dhcp_protocol)
        if not dhcp_pkt:
            LOG.warning("DHCP Controller received packet "
                        "is not a DHCP%s packet",
                        self.version)
            return

        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        port_id = self.get_port_id_from_br(of_in_port, eth_pkt.src)
        LOG.debug("DHCP Controller received DHCP%s packet's neutron port "
                  "id: %s", self.version, port_id)

        port_info = self.ext_api.get_port_info(port_id)
        LOG.debug("DHCP Controller received DHCP%s packet's neutron port "
                  "info: %s", self.version, port_info)
        if not port_info:
            return

        self.handle_dhcp(datapath, of_in_port, pkt, port_info)

    def get_bin_dns(self, dns_nameservers):
        if self.version == IPV4_STR:
            text_protocol = addrconv.ipv4
        else:
            text_protocol = addrconv.ipv6

        dns_bin = b''
        for dns in dns_nameservers:
            dns_bin += text_protocol.text_to_bin(dns['address'])
        return dns_bin

    def get_bin_route(self, destination, nexthop):
        if self.version == IPV4_STR:
            text_protocol = addrconv.ipv4
        else:
            text_protocol = addrconv.ipv6

        bin_route = b''
        net = netaddr.IPNetwork(str(destination))
        dest = str(net.ip)
        mask = net.prefixlen
        bin_route += struct.pack('B', mask)
        bin_addr = text_protocol.text_to_bin(dest)
        dest_len = int(math.ceil(mask / 8.0))
        bin_route += bin_addr[:dest_len]
        bin_route += text_protocol.text_to_bin(nexthop)
        return bin_route

    def get_port_id_from_br(self, ofport, vif_mac):
        vifs = self.int_br.get_vif_ports()
        for vif in vifs:
            if vif.ofport == ofport and vif.vif_mac == vif_mac:
                return vif.vif_id

    def get_port_ip(self, port_info, ip_version):
        fixed_ips = port_info['fixed_ips']
        for ip in fixed_ips:
            ipaddr = netaddr.IPNetwork(ip['ip_address'])
            # For the first IP only, secondary IPs will not be returned.
            if ipaddr.version == ip_version:
                return ip

    def get_dhcp_options(self, port_info, is_ack):
        raise NotImplementedError()

    def get_ret_packet(self, packet_in, port_info, is_ack=False):
        raise NotImplementedError()

    def get_state(self, pkt_dhcp):
        raise NotImplementedError()

    def handle_dhcp(self, datapath, ofport, pkt, port_info):
        raise NotImplementedError()

    def packet_out(self, datapath, ofport, pkt):
        if not pkt:
            LOG.debug("DHCP Controller no packet assembled for DHCP%s.",
                      self.version)
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        LOG.debug("DHCP Controller packet assembled for DHCP%s %s",
                  self.version, (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=ofport)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        LOG.info("DHCP Controller assembled DHCP%s packet out to OF port %s",
                 self.version, ofport)
        datapath.send_msg(out)
