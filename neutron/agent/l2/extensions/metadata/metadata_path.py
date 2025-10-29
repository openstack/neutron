# Copyright (c) 2023 China Unicom Cloud Data Co.,Ltd.
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

import collections
import os
import secrets
import time

import netaddr
from neutron_lib.agent import l2_extension as l2_agent_extension
from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins.ml2 import ovs_constants as p_const
from neutron_lib.plugins import utils as p_utils
from neutron_lib.utils import net as net_lib
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging

from neutron._i18n import _
from neutron.agent.common import ip_lib
from neutron.agent.l2.extensions.metadata import host_metadata_proxy
from neutron.agent.l2.extensions.metadata import metadata_flows_process
from neutron.agent.linux import external_process
from neutron.api.rpc.callbacks import resources
from neutron.common import coordination

LOG = logging.getLogger(__name__)

DEFAULT_META_GATEWAY_MAC = "fa:16:ee:00:00:01"
METADATA_DEFAULT_MAC = 'fa:16:ee:ff:ff:ff'


class InvalidProviderCIDR(n_exc.NeutronException):
    message = _("Not enough Metadata IPs in /32 CIDR")


class NoMoreProviderRes(n_exc.NeutronException):
    message = _("No more %(res)s")


class FailedToInitMetadataPathExtension(n_exc.NeutronException):
    message = _("Could not initialize agent extension "
                "metadata path, error: %(msg)s")


class MetadataPathExtensionPortInfoAPI:

    def __init__(self, cache_api):
        self.cache_api = cache_api
        self.allocated_ips = netaddr.IPSet()
        self.allocated_macs = set()

    def get_port_fixed_ip(self, port):
        for ip in port.fixed_ips:
            ip_addr = netaddr.IPAddress(str(ip.ip_address))
            if ip_addr.version == constants.IP_VERSION_4:
                return str(ip.ip_address)

    def remove_allocated_ip(self, ip):
        self.allocated_ips.remove(ip)

    def remove_allocated_mac(self, mac):
        self.allocated_macs.remove(mac)

    def _get_one_ip(self):

        def generate_local_ip(cidr):
            network = netaddr.IPNetwork(cidr)
            if network.prefixlen == 32:
                raise InvalidProviderCIDR()
            # https://docs.python.org/3/library/secrets.html#module-secrets
            # secrets.randbelow(exclusive_upper_bound)
            # Return a random int in the range [0, exclusive_upper_bound).
            # Here we remove the first and last IPs here.
            index = secrets.randbelow(network.size - 1)
            return str(network[index + 1])

        for _i in range(1, 100):
            ip = generate_local_ip(cfg.CONF.METADATA.provider_cidr)
            if ip not in self.allocated_ips:
                return ip
        raise NoMoreProviderRes(res="provider IP addresses")

    def _get_one_mac(self):
        for _i in range(1, 1000):
            base_mac = cfg.CONF.METADATA.provider_base_mac
            mac = net_lib.get_random_mac(base_mac.split(':'))
            if mac not in self.allocated_macs:
                return mac
        raise NoMoreProviderRes(res="provider MAC addresses")

    def get_provider_ip_info(self, port_id,
                             provider_ip=None,
                             provider_mac=None):
        port_obj = self.cache_api.get_resource_by_id(
            resources.PORT, port_id)
        if not port_obj or not port_obj.device_id:
            return

        info = {"instance_id": port_obj.device_id,
                "project_id": port_obj.project_id}

        if (not provider_ip or netaddr.IPNetwork(provider_ip) not in
                netaddr.IPNetwork(cfg.CONF.METADATA.provider_cidr)):
            provider_ip = self._get_one_ip()
        self.allocated_ips.add(provider_ip)
        info["provider_ip"] = provider_ip

        if not provider_mac:
            provider_mac = self._get_one_mac()
        self.allocated_macs.add(provider_mac)
        info["provider_port_mac"] = provider_mac

        return info


class MetadataPathAgentExtension(
        l2_agent_extension.L2AgentExtension,
        metadata_flows_process.MetadataDataPathFlows):

    PORT_INFO_CACHE = {}
    META_DEV_NAME = "tap-meta"

    NETWORK_DHCP_PORTS = {}
    NETWORK_PORTS = collections.defaultdict(set)

    @lockutils.synchronized('networking-path-ofport-cache')
    def set_port_info_cache(self, port_id, port_info):
        self.PORT_INFO_CACHE[port_id] = port_info

    @lockutils.synchronized('networking-path-ofport-cache')
    def get_port_info_from_cache(self, port_id):
        return self.PORT_INFO_CACHE.pop(port_id, None)

    def consume_api(self, agent_api):
        if not all([agent_api.br_phys.get('meta'), agent_api.phys_ofports,
                    agent_api.bridge_mappings.get('meta')]):
            raise FailedToInitMetadataPathExtension(
                msg="The metadata bridge device may not exist.")

        self.agent_api = agent_api
        self.rcache_api = agent_api.plugin_rpc.remote_resource_cache

    def initialize(self, connection, driver_type):
        """Initialize agent extension."""
        self.ext_api = MetadataPathExtensionPortInfoAPI(self.rcache_api)
        self.int_br = self.agent_api.request_int_br()
        self.meta_br = self.agent_api.request_physical_br('meta')
        self.instance_infos = {}

        bridge = self.agent_api.bridge_mappings.get('meta')
        port_name = p_utils.get_interface_name(
            bridge, prefix=p_const.PEER_INTEGRATION_PREFIX)
        self.ofport_int_to_meta = self.int_br.get_port_ofport(port_name)
        self.ofport_meta_to_int = self.agent_api.phys_ofports['meta']

        if (not cfg.CONF.METADATA.nova_metadata_host or
                not cfg.CONF.METADATA.nova_metadata_port):
            LOG.warning("Nova metadata API related options are not set. "
                        "Host metadata haproxy will not start. "
                        "Please check the config option of "
                        "'nova_metadata_*' in [METADATA] section.")
            return
        self.process_monitor = external_process.ProcessMonitor(
            config=cfg.CONF,
            resource_type='MetadataPath')
        self.meta_daemon = host_metadata_proxy.HostMedataHAProxyDaemonMonitor(
            self.process_monitor,
            user=str(os.geteuid()),
            group=str(os.getegid()))

        self.provider_vlan_id = cfg.CONF.METADATA.provider_vlan_id
        self.provider_cidr = cfg.CONF.METADATA.provider_cidr

        self.provider_gateway_ip = str(netaddr.IPAddress(
            netaddr.IPNetwork(cfg.CONF.METADATA.provider_cidr).first + 1))

        self._create_internal_port()

        # In order to cover the situation that the VM has a link reachable
        # route to 169.254.169.254.
        self.install_arp_responder(
            bridge=self.int_br,
            ip=metadata_flows_process.METADATA_V4_IP,
            mac=METADATA_DEFAULT_MAC,
            table=p_const.TRANSIENT_TABLE)

        self.set_path_br(self.meta_br)
        self.metadata_ofport = self.meta_br.get_port_ofport(self.META_DEV_NAME)
        self.init_br_snat_metadata_path()

    def _set_port_vlan(self):
        ovsdb = self.meta_br.ovsdb
        with self.meta_br.ovsdb.transaction() as txn:
            # When adding the port's tag,
            # also clear port's vlan_mode and trunks,
            # which were set to make sure all packets are dropped.
            txn.add(ovsdb.db_set('Port', self.META_DEV_NAME,
                                 ('tag', self.provider_vlan_id)))
            txn.add(ovsdb.db_clear('Port', self.META_DEV_NAME, 'vlan_mode'))
            txn.add(ovsdb.db_clear('Port', self.META_DEV_NAME, 'trunks'))

    def _create_internal_port(self):
        attrs = [('type', 'internal'),
                 ('external_ids', {'iface-status': 'active',
                                   'attached-mac': DEFAULT_META_GATEWAY_MAC})]
        self.meta_br.replace_port(self.META_DEV_NAME, *attrs)

        ns_dev = ip_lib.IPDevice(self.META_DEV_NAME)

        for _i in range(9):
            try:
                ns_dev.link.set_address(DEFAULT_META_GATEWAY_MAC)
                break
            except RuntimeError as e:
                LOG.warning("Got error trying to set mac, retrying: %s", e)
                time.sleep(1)

        try:
            ns_dev.link.set_address(DEFAULT_META_GATEWAY_MAC)
        except RuntimeError as e:
            raise RuntimeError(
                _("Failed to set mac address "
                  "for dev %(dev)s, error: %(error)s") %
                  {'dev': self.META_DEV_NAME, 'error': e})

        cidr = "{}/{}".format(
            self.provider_gateway_ip,
            netaddr.IPNetwork(self.provider_cidr).prefixlen)
        ns_dev.addr.add(cidr)
        ns_dev.link.set_up()

        self.meta_br.set_value_to_other_config(
            self.META_DEV_NAME,
            "tag",
            self.provider_vlan_id)
        self._set_port_vlan()

    def _reload_host_metadata_proxy(self, force_reload=False):
        if (not cfg.CONF.METADATA.nova_metadata_host or
                not cfg.CONF.METADATA.nova_metadata_port):
            LOG.warning("Nova metadata API related options are not set. "
                        "Host metadata haproxy will not start.")
            return
        if not force_reload and not self.instance_infos:
            return
        # Haproxy does not suport 'kill -HUP' to reload config file,
        # so just kill it and then re-spawn.
        self.meta_daemon.disable()
        self.meta_daemon.config(list(self.instance_infos.values()))
        if self.instance_infos:
            self.meta_daemon.enable()

    def _get_port_info(self, port_detail):
        device_owner = port_detail['device_owner']
        if not device_owner.startswith(constants.DEVICE_OWNER_COMPUTE_PREFIX):
            return

        port = port_detail['vif_port']
        provider_ip = self.int_br.get_value_from_other_config(
            port.port_name, 'provider_ip')
        provider_mac = self.int_br.get_value_from_other_config(
            port.port_name, 'provider_mac')

        ins_info = self.ext_api.get_provider_ip_info(port_detail['port_id'],
                                                     provider_ip,
                                                     provider_mac)
        if not ins_info:
            LOG.info("Failed to get port %s instance provider IP info.",
                     port_detail['port_id'])
            return
        self.instance_infos[port_detail['port_id']] = ins_info
        if not provider_ip or provider_ip != ins_info['provider_ip']:
            self.int_br.set_value_to_other_config(
                port.port_name,
                'provider_ip',
                ins_info['provider_ip'])
        if not provider_mac:
            self.int_br.set_value_to_other_config(
                port.port_name,
                'provider_mac',
                ins_info['provider_port_mac'])

        vlan = self.int_br.get_value_from_other_config(
            port.port_name, 'tag', int)

        port_info = {"port_id": port_detail['port_id'],
                     "device_owner": device_owner,
                     "port_name": port.port_name,
                     "vlan": vlan,
                     "mac_address": port_detail["mac_address"],
                     "fixed_ips": port_detail["fixed_ips"],
                     "ofport": port.ofport,
                     "network_id": port_detail['network_id']}

        LOG.debug("Metadata path got the port information: %s ",
                  port_info)
        return port_info

    def handle_port(self, context, port_detail):
        try:
            port_info = self._get_port_info(port_detail)
            if not port_info:
                return
            self.set_port_info_cache(port_detail['port_id'], port_info)
        except Exception as err:
            LOG.info("Failed to get or set port %s info, error: %s",
                     port_detail['port_id'], err)
        else:
            self.process_install_metadata_path_flows(port_info)
            self.install_dhcp_ports_arp_responder(port_info)
            self._reload_host_metadata_proxy()

    def _get_fixed_ip(self, port_info):
        for ip in port_info['fixed_ips']:
            ip_addr = netaddr.IPAddress(ip['ip_address'])
            if ip_addr.version == constants.IP_VERSION_4:
                return ip['ip_address']

    def delete_port(self, context, port_detail):
        ins_info = self.instance_infos.pop(port_detail['port_id'], None)
        self._reload_host_metadata_proxy(force_reload=True)
        port_info = self.get_port_info_from_cache(port_detail['port_id'])
        if not port_info:
            LOG.info("No port_info cache found for %s, "
                     "skipping remove networking path related flows.",
                     port_detail['port_id'])
            return

        self.remove_port_metadata_direct_flow(port_info["ofport"],
                                              port_info["vlan"],
                                              port_info['mac_address'],
                                              self.ofport_int_to_meta)
        self.remove_dhcp_ports_arp_responder(port_info)

        if not ins_info:
            return
        self.ext_api.remove_allocated_ip(ins_info['provider_ip'])
        self.ext_api.remove_allocated_mac(ins_info['provider_port_mac'])

        port_fixed_ip = self._get_fixed_ip(port_info)
        if not port_fixed_ip:
            return

        self.remove_port_metadata_path_nat_and_arp_flow(
            port_info['vlan'], port_info['mac_address'], port_fixed_ip,
            self.provider_vlan_id, ins_info["provider_ip"])

    def init_br_snat_metadata_path(self):
        self.metadata_host_info = {
            "gateway_ip": self.provider_gateway_ip,
            "provider_ip": self.provider_gateway_ip,
            "mac_address": DEFAULT_META_GATEWAY_MAC,
            "service_protocol_port": cfg.CONF.METADATA.host_proxy_listen_port}
        self.metadata_path_defaults(
            pvid=self.provider_vlan_id,
            to_int_ofport=self.ofport_meta_to_int,
            metadata_ofport=self.metadata_ofport,
            metadata_host_info=self.metadata_host_info)

    def process_install_metadata_path_flows(self, port_info):
        if not self.meta_br:
            return

        try:
            self.install_port_metadata_path_direct_flows(port_info)
        except Exception as err:
            LOG.debug("Failed to install networking path direct flows "
                      "for port %s, error: %s",
                      port_info['port_id'], err)
        try:
            self.install_port_metadata_path_nat_and_arp_flows(port_info)
        except Exception as err:
            LOG.debug("Failed to install networking path nat and "
                      "ARP responder flows for port %s, error: %s",
                      port_info['port_id'], err)

    def install_port_metadata_path_nat_and_arp_flows(
            self, port_info):
        phys_port = self.agent_api.phys_ofports['meta']
        info = self.instance_infos.get(port_info['port_id'])
        if not info:
            return
        provider_ip_addr = info["provider_ip"]
        provider_port_mac = info["provider_port_mac"]

        port_fixed_ip = self._get_fixed_ip(port_info)
        if not port_fixed_ip:
            return

        self.add_flow_snat_br_meta(
            port_info["vlan"], port_info['mac_address'], port_fixed_ip,
            provider_port_mac, provider_ip_addr)
        self.install_arp_responder(
            ip=provider_ip_addr,
            mac=provider_port_mac)
        self.add_flow_ingress_dnat_direct_to_int_br(
            port_info["vlan"], self.provider_vlan_id, provider_ip_addr,
            port_info['mac_address'], port_fixed_ip,
            phys_port,
            self.metadata_ofport)

    def install_port_metadata_path_direct_flows(self, port_info):
        self.add_flow_int_br_egress_direct(
            port_info["ofport"], port_info["vlan"],
            self.ofport_int_to_meta)
        self.add_flow_int_br_ingress_output(
            self.ofport_int_to_meta, port_info["vlan"],
            port_info['mac_address'], port_info["ofport"])

    @coordination.synchronized('meta-net-{port_info[network_id]}')
    def install_dhcp_ports_arp_responder(self, port_info):
        filters = {'network_id': (port_info['network_id'], ),
                   'device_owner': (constants.DEVICE_OWNER_DHCP, )}
        dhcp_ports = self.rcache_api.get_resources(resources.PORT, filters)
        for p in dhcp_ports:
            for ip in p['fixed_ips']:
                ip_addr = netaddr.IPNetwork(str(ip.ip_address))
                if ip_addr.version != constants.IP_VERSION_4:
                    continue
                self.install_arp_responder(
                    bridge=self.int_br,
                    ip=str(ip.ip_address),
                    mac=str(p.mac_address),
                    table=p_const.TRANSIENT_TABLE,
                    in_port=port_info["ofport"])

        self.NETWORK_DHCP_PORTS[port_info['network_id']] = dhcp_ports
        self.NETWORK_PORTS[port_info['network_id']].add(port_info['port_id'])

    @coordination.synchronized('meta-net-{port_info[network_id]}')
    def remove_dhcp_ports_arp_responder(self, port_info):
        if self.NETWORK_PORTS[port_info['network_id']]:
            self.NETWORK_PORTS[port_info['network_id']].remove(
                port_info['port_id'])

        # No ports from this network, remove the DHCP ports ARP responder.
        if not self.NETWORK_PORTS[port_info['network_id']]:
            dhcp_ports = self.NETWORK_DHCP_PORTS.pop(
                port_info['network_id'], [])
            for p in dhcp_ports:
                for ip in p['fixed_ips']:
                    ip_addr = netaddr.IPNetwork(str(ip.ip_address))
                    if ip_addr.version != constants.IP_VERSION_4:
                        continue
                    self.delete_arp_responder(
                        bridge=self.int_br,
                        ip=str(ip.ip_address),
                        table=p_const.ARP_SPOOF_TABLE,
                        in_port=port_info["ofport"])
            self.NETWORK_PORTS.pop(port_info['network_id'], [])
