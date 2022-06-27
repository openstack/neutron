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
import time

from neutron_lib import constants
from os_ken.lib import addrconv
from os_ken.lib.packet import dhcp6
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import in_proto as inet
from os_ken.lib.packet import ipv6
from os_ken.lib.packet import packet
from os_ken.lib.packet import udp
from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.l2.extensions.dhcp import base as dhcp_base

LOG = logging.getLogger(__name__)

DHCPV6_TYPE_MAP = {dhcp6.DHCPV6_SOLICIT: 'SOLICIT',
                   dhcp6.DHCPV6_REQUEST: 'REQUEST',
                   dhcp6.DHCPV6_CONFIRM: 'CONFIRM',
                   dhcp6.DHCPV6_RELEASE: 'RELEASE',
                   dhcp6.DHCPV6_RENEW: 'RENEW',
                   dhcp6.DHCPV6_REBIND: 'REBIND'}
REQ_TYPES_FOR_REPLY = ['REQUEST', 'CONFIRM', 'RELEASE', 'RENEW', 'REBIND']
REQ_TYPE_UNKNOWN = -1
# DUID Type: link-layer address plus time (1)
DUID_TYPE_LINK_LAYER_ADDRESS_PLUS_TIME = 1
# Hardware type: Ethernet (1)
HARDWARE_TYPE_ETHERNET = 1
# Status Code: Success (0)
DHCPV6_STATUS_CODE_SUCCESS = 0
# 1/1/2000 in integer style
TIME_FIRST_DAY_2000 = 946684800

# TODO(liuyulong): move to os-ken someday
DHCPV6_OPTION_DNS_RECURSIVE_NS = 23
DHCPV6_OPTION_DOMAIN_SEARCH_LIST = 24
DHCPV6_OPTION_FQDN = 39


class DHCPIPv6Responder(dhcp_base.DHCPResponderBase):

    def __init__(self, agent_api, ext_api, *args, **kwargs):
        super(DHCPIPv6Responder, self).__init__(agent_api, ext_api,
                                                version=dhcp_base.IPV6_STR,
                                                *args, **kwargs)

    def _create_duid(self, mac):
        """Create a DUID based on the mac address and time.

        For details see RFC 8415:
        11.2.  DUID Based on Link-Layer Address Plus Time (DUID-LLT)
        https://datatracker.ietf.org/doc/html/rfc8415#section-11.2
        """
        duid_type = struct.pack('!H', DUID_TYPE_LINK_LAYER_ADDRESS_PLUS_TIME)
        hardware_type = struct.pack('!H', HARDWARE_TYPE_ETHERNET)
        # DUID Time: time now
        # Rebase epoch to 1/1/2000.
        duid_time = struct.pack('!I', int(time.time() - TIME_FIRST_DAY_2000))
        # Link-layer address
        mac_bin = addrconv.mac.text_to_bin(str(mac))
        return duid_type + hardware_type + duid_time + mac_bin

    def get_dhcpv6_client_ident(self, mac, req_options):
        # DHCPV6_OPTION_CLIENTID = 1
        for opt in req_options:
            if opt.code == dhcp6.DHCPV6_OPTION_CLIENTID:
                return opt.data
        return self._create_duid(mac)

    def get_dhcpv6_server_ident(self):
        # DHCPV6_OPTION_SERVERID = 2
        return self._create_duid(self.hw_addr)

    def get_dhcpv6_status_code(self, message, code=DHCPV6_STATUS_CODE_SUCCESS):
        # DHCPV6_OPTION_STATUS_CODE = 13
        status_code = struct.pack('!H', code)
        message_bin = struct.pack('!%ds' % len(message),
                                  bytes(str(message).encode()))
        return status_code + message_bin

    def _get_ia_na_attrs(self, options):
        """Get IA_NA options."""
        attrs = {}
        default_value = struct.pack('!i', cfg.CONF.dhcp_lease_duration)

        def _check_and_get_value(opt, start, end, iaid=False):
            data = struct.unpack('!i', opt.data[start:end])
            if data and data[0] != 0:
                # Get request time interval T1 option for IA_NA.
                # Get request time interval T2 option for IA_NA.
                # Get request Preferred Lifetime for IA_NA.
                # Get request Valid Lifetime for IA_NA.
                # Get request IAID for IA_NA.
                return opt.data[start:end]
            elif iaid:
                # default IAID
                return struct.pack('!I', 1)
            # default time or interval
            return default_value

        for opt in options:
            if opt.code == dhcp6.DHCPV6_OPTION_IA_NA:
                attrs['t1'] = _check_and_get_value(opt, 4, 8)
                attrs['t2'] = _check_and_get_value(opt, 8, 12)
                attrs['preferred_lifetime'] = _check_and_get_value(
                    opt, -8, -4)
                attrs['valid_lifetime'] = _check_and_get_value(
                    opt, -4, len(opt.data))
                attrs['ia_id'] = _check_and_get_value(
                    opt, 0, 4, iaid=True)
        return attrs

    def _get_ia_na_opt(self, options, ip_addr):
        # DHCPV6_OPTION_IA_NA = 3
        attrs = self._get_ia_na_attrs(options)
        # IA Address
        # Option: IA Address (5)
        ia_addr_opt = struct.pack('!H', dhcp6.DHCPV6_OPTION_IAADDR)
        # IPv6 address: client IPv6 Address
        ia_addr_bin = addrconv.ipv6.text_to_bin(str(ip_addr))

        ia = (ia_addr_bin + attrs['preferred_lifetime'] +
              attrs['valid_lifetime'])
        # Length: 24
        ia_addr_len = struct.pack('!H', len(ia))
        ia_addr = ia_addr_opt + ia_addr_len + ia
        ia_na_data = attrs['ia_id'] + attrs['t1'] + attrs['t2'] + ia_addr
        return ia_na_data

    def get_dhcp_options(self, mac, ip_info, req_options, req_type):
        ip_addr = ip_info['ip_address']
        gateway_ip = ip_info['gateway_ip']
        dns_nameservers = ip_info['dns_nameservers']

        option_list = []
        client_ident = self.get_dhcpv6_client_ident(mac, req_options)
        option_list.append(
            dhcp6.option(
                code=dhcp6.DHCPV6_OPTION_CLIENTID,
                data=client_ident,
                length=len(client_ident)))

        server_id_bin = self.get_dhcpv6_server_ident()
        option_list.append(
            dhcp6.option(
                code=dhcp6.DHCPV6_OPTION_SERVERID,
                data=server_id_bin,
                length=len(server_id_bin)))

        ia_na_data = self._get_ia_na_opt(req_options, ip_addr)
        option_list.append(
            dhcp6.option(
                code=dhcp6.DHCPV6_OPTION_IA_NA,
                data=ia_na_data, length=len(ia_na_data)))

        # Status Message: success
        status_bin = self.get_dhcpv6_status_code("success")
        option_list.append(
            dhcp6.option(
                code=dhcp6.DHCPV6_OPTION_STATUS_CODE,
                data=status_bin, length=len(status_bin)))

        if req_type == 'SOLICIT':  # for DHCP6 advertise packet
            # DHCPV6_OPTION_PREFERENCE = 7
            # Pref-value: 0
            perference = struct.pack('!b', 0)
            option_list.append(
                dhcp6.option(
                    code=dhcp6.DHCPV6_OPTION_PREFERENCE,
                    data=perference,
                    length=len(perference)))

        # 24: Domain Search List
        if req_type == 'REQUEST' and cfg.CONF.dns_domain:
            # Domain Search List FQDN: default openstacklocal
            dns_domain = struct.pack(
                '!%ds' % len(str(cfg.CONF.dns_domain)),
                bytes(str(cfg.CONF.dns_domain).encode()))
            dns_str_len = struct.pack('!b', len(dns_domain))
            dns_str_end = struct.pack('!b', 0)
            dns_domain_data = dns_str_len + dns_domain + dns_str_end
            option_list.append(
                dhcp6.option(
                    code=DHCPV6_OPTION_DOMAIN_SEARCH_LIST,
                    data=dns_domain_data,
                    length=len(dns_domain_data)))

        # 23: DNS recursive name server
        if dns_nameservers:
            domain_serach = self.get_bin_dns(dns_nameservers)
            option_list.append(
                dhcp6.option(
                    code=DHCPV6_OPTION_DNS_RECURSIVE_NS,
                    data=domain_serach, length=len(domain_serach)))
        else:
            # use gateway as the default DNS server address
            domain_serach = addrconv.ipv6.text_to_bin(str(gateway_ip))
            option_list.append(
                dhcp6.option(
                    code=DHCPV6_OPTION_DNS_RECURSIVE_NS,
                    data=domain_serach, length=len(domain_serach)))

        # 39: Fully Qualified Domain Name
        fqdn = 'host-%s' % ip_addr.replace('.', '-').replace(':', '-')
        if req_type == 'REQUEST' and cfg.CONF.dns_domain:
            fqdn = '%s.%s' % (fqdn, cfg.CONF.dns_domain)

        # 0000 0... = Reserved: 0x00
        # .... .0.. = N bit: Server should perform DNS updates
        # .... ..1. = O bit: Server has overridden client's S bit preference
        # .... ...1 = S bit: Server should perform forward DNS updates
        dns_tag = struct.pack('!b', 3)
        # Client FQDN: host-<ip-v6-address>
        fqdn_bin = struct.pack('!%ds' % len(fqdn), bytes(str(fqdn).encode()))
        fqdn_str_len = struct.pack('!b', len(fqdn_bin))
        dns_data = (dns_tag + fqdn_str_len + fqdn_bin)
        option_list.append(
            dhcp6.option(code=DHCPV6_OPTION_FQDN,
                         data=dns_data, length=len(dns_data)))

        # Final option list
        options = dhcp6.options(option_list=option_list)
        return options

    def get_ret_type(self, req_type):
        if req_type == 'SOLICIT':
            return dhcp6.DHCPV6_ADVERTISE
        elif req_type in REQ_TYPES_FOR_REPLY:
            return dhcp6.DHCPV6_REPLY
        return REQ_TYPE_UNKNOWN

    def get_ret_packet(self, packet_in, port_info, req_type):
        ip_info = self.get_port_ip(port_info,
                                   ip_version=constants.IP_VERSION_6)
        if not ip_info:
            return
        gateway_ip = ip_info['gateway_ip']
        mac = port_info['mac_address']

        header_eth = packet_in.get_protocol(ethernet.ethernet)
        header_ipv6 = packet_in.get_protocol(ipv6.ipv6)
        header_dhcp = packet_in.get_protocol(dhcp6.dhcp6)

        if req_type == 'CONFIRM':
            options = self.get_reply_dhcp_options(
                mac, message="all addresses still on link",
                req_options=header_dhcp.options.option_list)
        if req_type == 'RELEASE':
            options = self.get_reply_dhcp_options(
                mac, message="release received",
                req_options=header_dhcp.options.option_list)
        else:
            options = self.get_dhcp_options(
                mac, ip_info,
                header_dhcp.options.option_list,
                req_type)

        ret_pkt = packet.Packet()
        ret_pkt.add_protocol(ethernet.ethernet(
            ethertype=header_eth.ethertype,
            dst=header_eth.src,
            src=self.hw_addr))
        ret_pkt.add_protocol(
            ipv6.ipv6(
                src=gateway_ip,
                dst=header_ipv6.src,
                nxt=inet.IPPROTO_UDP))
        ret_pkt.add_protocol(udp.udp(src_port=constants.DHCPV6_RESPONSE_PORT,
                                     dst_port=constants.DHCPV6_CLIENT_PORT))

        ret_type = self.get_ret_type(req_type)

        ret_pkt.add_protocol(dhcp6.dhcp6(
            ret_type, options,
            transaction_id=header_dhcp.transaction_id))

        return ret_pkt

    def get_reply_dhcp_options(self, mac, message, req_options):
        option_list = []
        client_ident = self.get_dhcpv6_client_ident(mac, req_options)
        option_list.append(
            dhcp6.option(
                code=dhcp6.DHCPV6_OPTION_CLIENTID,
                data=client_ident,
                length=len(client_ident)))

        server_id_bin = self.get_dhcpv6_server_ident()
        option_list.append(
            dhcp6.option(
                code=dhcp6.DHCPV6_OPTION_SERVERID,
                data=server_id_bin,
                length=len(server_id_bin)))

        # Status Message: "<message>"
        status_bin = self.get_dhcpv6_status_code(
            message, code=DHCPV6_STATUS_CODE_SUCCESS)
        option_list.append(
            dhcp6.option(
                code=dhcp6.DHCPV6_OPTION_STATUS_CODE,
                data=status_bin, length=len(status_bin)))

        # Final option list
        options = dhcp6.options(option_list=option_list)
        return options

    def handle_dhcp(self, datapath, ofport, pkt, port_info):
        pkt_dhcp = pkt.get_protocol(dhcp6.dhcp6)
        dhcp_req_state = DHCPV6_TYPE_MAP.get(pkt_dhcp.msg_type)
        if not dhcp_req_state:
            LOG.warning("DHCP controller received DHCPv6 with unknown "
                        "type: %s from port: %s",
                        pkt_dhcp.msg_type, ofport)
            return
        LOG.info("DHCP controller DHCPv6 packet received, "
                 "state: %s, data: %s", dhcp_req_state, pkt_dhcp)
        self.packet_out(datapath, ofport,
                        self.get_ret_packet(pkt, port_info, dhcp_req_state))
