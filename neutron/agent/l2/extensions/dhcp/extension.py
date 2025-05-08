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

import netaddr
from neutron_lib.agent import l2_extension as l2_agent_extension
from neutron_lib import constants
from os_ken.base import app_manager
from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.l2.extensions.dhcp import ipv4
from neutron.agent.l2.extensions.dhcp import ipv6
from neutron.api.rpc.callbacks import resources

LOG = logging.getLogger(__name__)
LINK_LOCAL_GATEWAY = {
    constants.IP_VERSION_4: constants.METADATA_V4_IP,
    constants.IP_VERSION_6: constants.METADATA_V6_IP
}


class DHCPExtensionPortInfoAPI:

    def __init__(self, cache_api):
        self.cache_api = cache_api

    def get_port_info(self, port_id):
        port_obj = self.cache_api.get_resource_by_id(
            resources.PORT, port_id)
        if not port_obj or not port_obj.device_owner.startswith(
                constants.DEVICE_OWNER_COMPUTE_PREFIX):
            return

        mac_addr = str(netaddr.EUI(str(port_obj.mac_address),
                                   dialect=netaddr.mac_unix_expanded))

        entry = {
            'network_id': port_obj.network_id,
            'port_id': port_obj.id,
            'mac_address': mac_addr,
            'admin_state_up': port_obj.admin_state_up,
            'device_owner': port_obj.device_owner
        }

        # fixed_ips info for DHCP
        fixed_ips = []
        for ip in port_obj.fixed_ips:
            subnet = self.cache_api.get_resource_by_id(
                resources.SUBNET, ip.subnet_id)
            if not subnet.enable_dhcp:
                continue
            info = {'subnet_id': ip.subnet_id,
                    'ip_address': str(ip.ip_address),
                    'version': subnet.ip_version,
                    'cidr': subnet.cidr,
                    'host_routes': subnet.host_routes,
                    'dns_nameservers': subnet.dns_nameservers,
                    'gateway_ip': subnet.gateway_ip or LINK_LOCAL_GATEWAY[
                        subnet.ip_version
                    ]}
            fixed_ips.append(info)
        net = self.cache_api.get_resource_by_id(
            resources.NETWORK, port_obj.network_id)
        extra_info = {'fixed_ips': fixed_ips,
                      'mtu': net.mtu}
        entry.update(extra_info)

        LOG.debug("DHCP extension API return port info: %s", entry)
        return entry


class DHCPAgentExtension(l2_agent_extension.L2AgentExtension):

    VIF_PORT_CACHE = {}

    def consume_api(self, agent_api):
        """Allows an extension to gain access to resources internal to the
           neutron agent and otherwise unavailable to the extension.
        """
        self.agent_api = agent_api
        self.rcache_api = agent_api.plugin_rpc.remote_resource_cache

    def initialize(self, connection, driver_type):
        """Initialize agent extension."""
        self.ext_api = DHCPExtensionPortInfoAPI(self.rcache_api)
        self.int_br = self.agent_api.request_int_br()
        self.app_mgr = app_manager.AppManager.get_instance()
        self.start_dhcp()

        if cfg.CONF.DHCP.enable_ipv6:
            self.start_dhcp(version=constants.IP_VERSION_6)

    def start_dhcp(self, version=constants.IP_VERSION_4):
        responder = (
            ipv4.DHCPIPv4Responder if version == constants.IP_VERSION_4 else (
                ipv6.DHCPIPv6Responder))

        app = self.app_mgr.instantiate(
            responder,
            self.agent_api,
            self.ext_api)
        app.start()
        if version == constants.IP_VERSION_4:
            self.dhcp4_app = app
        else:
            self.dhcp6_app = app

    def handle_port(self, context, port_detail):
        fixed_ips = port_detail.get('fixed_ips')
        port = port_detail['vif_port']
        # TODO(liuyulong): DHCP for baremetal
        if (not port_detail['device_owner'].startswith(
                constants.DEVICE_OWNER_COMPUTE_PREFIX) or (
                    not fixed_ips)):
            return
        LOG.info("DHCP extension add DHCP related flows for port %s",
                 port_detail['port_id'])
        self.int_br.add_dhcp_ipv4_flow(port_detail['port_id'],
                                       port.ofport,
                                       port.vif_mac)
        if cfg.CONF.DHCP.enable_ipv6:
            self.int_br.add_dhcp_ipv6_flow(port_detail['port_id'],
                                           port.ofport,
                                           port.vif_mac)
        self.VIF_PORT_CACHE[port_detail['port_id']] = port

    def get_ofport(self, port_id):
        vifs = self.int_br.get_vif_ports()
        for vif in vifs:
            if vif.vif_id == port_id:
                return vif

    def delete_port(self, context, port_detail):
        port_id = port_detail['port_id']
        port = port_detail.get('vif_port')
        cached_port = self.VIF_PORT_CACHE.pop(port_id, None)
        if not port or port.ofport <= 0:
            port = cached_port
        if not port:
            port = self.get_ofport(port_id)
        if not port:
            LOG.warning("DHCP extension skipping delete DHCP related flow, "
                        "failed to get port %s ofport and MAC.",
                        port_id)
            return
        LOG.info("DHCP extension remove DHCP related flows for port %s",
                 port_id)
        self.int_br.del_dhcp_flow(port.ofport, port.vif_mac)
