# Copyright 2014, Hewlett-Packard Development Company, L.P.
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
import sys

import netaddr
from neutron_lib import constants as n_const
from neutron_lib.plugins.ml2 import ovs_constants
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import excutils
from osprofiler import profiler

from neutron.agent.common import ovs_lib
from neutron.agent.linux.openvswitch_firewall import firewall as ovs_firewall
from neutron.common import utils as n_utils
from neutron.ipam import utils as ipam_utils

LOG = logging.getLogger(__name__)


# A class to represent a DVR-hosted subnet including vif_ports resident on
# that subnet
class LocalDVRSubnetMapping:
    def __init__(self, subnet, csnat_ofport=ovs_constants.OFPORT_INVALID):
        # set of compute ports on this dvr subnet
        self.compute_ports = {}
        # set of dvr router interfaces on this subnet
        self.dvr_ports = {}
        self.subnet = subnet
        self.csnat_ofport = csnat_ofport
        self.dvr_owned = False

    def __str__(self):
        return ("subnet = %s compute_ports = %s csnat_port = %s"
                " is_dvr_owned = %s" %
                (self.subnet, self.get_compute_ofports(),
                 self.get_csnat_ofport(), self.is_dvr_owned()))

    def get_subnet_info(self):
        return self.subnet

    def set_dvr_owned(self, owned):
        self.dvr_owned = owned

    def is_dvr_owned(self):
        return self.dvr_owned

    def add_compute_ofport(self, vif_id, ofport):
        self.compute_ports[vif_id] = ofport

    def remove_compute_ofport(self, vif_id):
        self.compute_ports.pop(vif_id, 0)

    def remove_all_compute_ofports(self):
        self.compute_ports.clear()

    def get_compute_ofports(self):
        return self.compute_ports

    def set_csnat_ofport(self, ofport):
        self.csnat_ofport = ofport

    def get_csnat_ofport(self):
        return self.csnat_ofport

    def add_dvr_ofport(self, vif_id, ofport):
        self.dvr_ports[vif_id] = ofport

    def remove_dvr_ofport(self, vif_id):
        self.dvr_ports.pop(vif_id, 0)

    def get_dvr_ofports(self):
        return self.dvr_ports


class OVSPort:
    def __init__(self, id, ofport, mac, device_owner):
        self.id = id
        self.mac = mac
        self.ofport = ofport
        self.subnets = set()
        self.device_owner = device_owner
        # Currently, this is updated only for DVR router interfaces
        self.ips = collections.defaultdict(list)

    def __str__(self):
        return ("OVSPort: id = %s, ofport = %s, mac = %s, "
                "device_owner = %s, subnets = %s, ips = %s" %
                (self.id, self.ofport, self.mac,
                 self.device_owner, self.subnets,
                 self.ips))

    def add_subnet(self, subnet_id, fixed_ip=None):
        self.subnets.add(subnet_id)
        if fixed_ip is None:
            return

        self.ips[subnet_id].append(fixed_ip)

    def remove_subnet(self, subnet_id):
        self.subnets.remove(subnet_id)
        self.ips.pop(subnet_id, None)

    def remove_all_subnets(self):
        self.subnets.clear()
        self.ips.clear()

    def get_subnets(self):
        return self.subnets

    def get_device_owner(self):
        return self.device_owner

    def get_mac(self):
        return self.mac

    def get_ofport(self):
        return self.ofport

    def get_ip(self, subnet_id):
        return self.ips.get(subnet_id)


@profiler.trace_cls("ovs_dvr_agent")
class OVSDVRNeutronAgent:
    '''Implements OVS-based DVR (Distributed Virtual Router) agent'''
    # history
    #   1.0 Initial version

    def __init__(self, context, plugin_rpc, integ_br, tun_br,
                 bridge_mappings, phys_brs, int_ofports, phys_ofports,
                 patch_int_ofport=ovs_constants.OFPORT_INVALID,
                 patch_tun_ofport=ovs_constants.OFPORT_INVALID,
                 host=None, enable_tunneling=False,
                 enable_distributed_routing=False):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.host = host
        self.enable_tunneling = enable_tunneling
        self.enable_distributed_routing = enable_distributed_routing
        self.bridge_mappings = bridge_mappings
        self.int_ofports = int_ofports
        self.phys_ofports = phys_ofports
        self.reset_ovs_parameters(integ_br, tun_br, phys_brs,
                                  patch_int_ofport, patch_tun_ofport)
        self.reset_dvr_parameters()
        self.dvr_mac_address = None
        if self.enable_distributed_routing:
            self.get_dvr_mac_address()
        self.conf = cfg.CONF
        self.firewall = None

    def set_firewall(self, firewall=None):
        self.firewall = firewall

    def setup_dvr_flows(self, bridge_mappings=None):
        bridge_mappings = bridge_mappings or self.bridge_mappings
        self.setup_dvr_flows_on_integ_br()
        self.setup_dvr_flows_on_tun_br()
        self.setup_dvr_flows_on_phys_br(bridge_mappings)
        self.setup_dvr_mac_flows_on_all_brs()

    def reset_ovs_parameters(self, integ_br, tun_br, phys_brs,
                             patch_int_ofport, patch_tun_ofport):
        '''Reset the openvswitch parameters'''
        self.int_br = integ_br
        self.tun_br = tun_br
        self.phys_brs = phys_brs
        self.patch_int_ofport = patch_int_ofport
        self.patch_tun_ofport = patch_tun_ofport

    def reset_dvr_parameters(self):
        '''Reset the DVR parameters'''
        self.local_dvr_map = {}
        self.local_csnat_map = {}
        self.local_ports = {}
        self.registered_dvr_macs = set()

    def reset_dvr_flows(self, integ_br, tun_br, phys_brs,
                        patch_int_ofport, patch_tun_ofport,
                        bridge_mappings=None):
        '''Reset the openvswitch and DVR parameters and DVR flows'''
        self.reset_ovs_parameters(
            integ_br, tun_br, phys_brs, patch_int_ofport, patch_tun_ofport)
        self.reset_dvr_parameters()
        self.setup_dvr_flows(bridge_mappings)

    def get_dvr_mac_address(self):
        try:
            self.get_dvr_mac_address_with_retry()
        except oslo_messaging.RemoteError as e:
            LOG.error('L2 agent could not get DVR MAC address at '
                      'startup due to RPC error.  It happens when the '
                      'server does not support this RPC API.  Detailed '
                      'message: %s', e)
        except oslo_messaging.MessagingTimeout:
            LOG.error('DVR: Failed to obtain a valid local '
                      'DVR MAC address')

        if not self.in_distributed_mode():
            sys.exit(1)

    def get_dvr_mac_address_with_retry(self):
        # Get the local DVR MAC Address from the Neutron Server.
        # This is the first place where we contact the server on startup
        # so retry in case it's not ready to respond
        for retry_count in reversed(range(5)):
            try:
                details = self.plugin_rpc.get_dvr_mac_address_by_host(
                    self.context, self.host)
            except oslo_messaging.MessagingTimeout as e:
                with excutils.save_and_reraise_exception() as ctx:
                    if retry_count > 0:
                        ctx.reraise = False
                        LOG.warning('L2 agent could not get DVR MAC '
                                    'address from server. Retrying. '
                                    'Detailed message: %s', e)
            else:
                LOG.debug("L2 Agent DVR: Received response for "
                          "get_dvr_mac_address_by_host() from "
                          "plugin: %r", details)
                self.dvr_mac_address = (
                    netaddr.EUI(details['mac_address'],
                                dialect=netaddr.mac_unix_expanded))
                return

    def setup_dvr_flows_on_integ_br(self):
        '''Setup up initial dvr flows into br-int'''

        LOG.info("L2 Agent operating in DVR Mode with MAC %s",
                 self.dvr_mac_address)
        # Add a canary flow to int_br to track OVS restarts
        self.int_br.setup_canary_table()

        # Insert 'drop' action as the default for Table DVR_TO_SRC_MAC
        self.int_br.install_drop(
            table_id=ovs_constants.DVR_TO_SRC_MAC, priority=1)

        self.int_br.install_drop(
            table_id=ovs_constants.DVR_TO_SRC_MAC_PHYSICAL, priority=1)

        for physical_network in self.bridge_mappings:
            self.int_br.install_drop(table_id=ovs_constants.LOCAL_SWITCHING,
                                     priority=2,
                                     in_port=self.int_ofports[
                                         physical_network])

    def setup_dvr_flows_on_tun_br(self):
        '''Setup up initial dvr flows into br-tun'''
        if not self.enable_tunneling:
            return

        self._setup_dvr_flows_on_tun_br(self.tun_br, self.patch_int_ofport)

    @staticmethod
    def _setup_dvr_flows_on_tun_br(tun_br, patch_int_ofport):
        tun_br.install_goto(dest_table_id=ovs_constants.DVR_PROCESS,
                            priority=1,
                            in_port=patch_int_ofport)

        # table-miss should be sent to learning table
        tun_br.install_goto(table_id=ovs_constants.DVR_NOT_LEARN,
                            dest_table_id=ovs_constants.LEARN_FROM_TUN)

        tun_br.install_goto(table_id=ovs_constants.DVR_PROCESS,
                            dest_table_id=ovs_constants.PATCH_LV_TO_TUN)

    def setup_dvr_flows_on_phys_br(self, bridge_mappings=None):
        '''Setup up initial dvr flows into br-phys'''
        bridge_mappings = bridge_mappings or self.bridge_mappings
        for physical_network in bridge_mappings:
            self.phys_brs[physical_network].install_goto(
                in_port=self.phys_ofports[physical_network],
                priority=2,
                dest_table_id=ovs_constants.DVR_PROCESS_PHYSICAL)
            self.phys_brs[physical_network].install_goto(
                priority=1,
                dest_table_id=ovs_constants.DVR_NOT_LEARN_PHYSICAL)
            self.phys_brs[physical_network].install_goto(
                table_id=ovs_constants.DVR_PROCESS_PHYSICAL,
                priority=0,
                dest_table_id=ovs_constants.LOCAL_VLAN_TRANSLATION)
            self.phys_brs[physical_network].install_drop(
                table_id=ovs_constants.LOCAL_VLAN_TRANSLATION,
                in_port=self.phys_ofports[physical_network],
                priority=2)
            self.phys_brs[physical_network].install_normal(
                table_id=ovs_constants.DVR_NOT_LEARN_PHYSICAL,
                priority=1)

    def _add_dvr_mac_for_phys_br(self, physical_network, mac):
        self.int_br.add_dvr_mac_physical(
            mac=mac, port=self.int_ofports[physical_network])
        phys_br = self.phys_brs[physical_network]
        phys_br.add_dvr_mac_physical(
            mac=mac, port=self.phys_ofports[physical_network])

    def _add_arp_dvr_mac_for_phys_br(self, physical_network, mac):
        self.int_br.add_dvr_gateway_mac_arp_vlan(
            mac=mac, port=self.int_ofports[physical_network])

    def _remove_dvr_mac_for_phys_br(self, physical_network, mac):
        # REVISIT(yamamoto): match in_port as well?
        self.int_br.remove_dvr_mac_vlan(mac=mac)
        phys_br = self.phys_brs[physical_network]
        # REVISIT(yamamoto): match in_port as well?
        phys_br.remove_dvr_mac_vlan(mac=mac)

    def _add_dvr_mac_for_tun_br(self, mac):
        self.int_br.add_dvr_mac_tun(mac=mac, port=self.patch_tun_ofport)
        self.tun_br.add_dvr_mac_tun(mac=mac, port=self.patch_int_ofport)

    def _add_arp_dvr_mac_for_tun_br(self, mac):
        self.int_br.add_dvr_gateway_mac_arp_tun(
            mac=mac, port=self.patch_tun_ofport)

    def _remove_dvr_mac_for_tun_br(self, mac):
        self.int_br.remove_dvr_mac_tun(mac=mac, port=self.patch_tun_ofport)
        # REVISIT(yamamoto): match in_port as well?
        self.tun_br.remove_dvr_mac_tun(mac=mac)

    def _add_dvr_mac(self, mac):
        for physical_network in self.bridge_mappings:
            self._add_dvr_mac_for_phys_br(physical_network, mac)
        if self.enable_tunneling:
            self._add_dvr_mac_for_tun_br(mac)
        LOG.debug("Added DVR MAC flow for %s", mac)
        self.registered_dvr_macs.add(mac)

    def _add_dvr_mac_for_arp(self, mac):
        for physical_network in self.bridge_mappings:
            self._add_arp_dvr_mac_for_phys_br(physical_network, mac)
        if self.enable_tunneling:
            self._add_arp_dvr_mac_for_tun_br(mac)
        LOG.debug("Added ARP DVR MAC flow for %s", mac)

    def _remove_dvr_mac(self, mac):
        for physical_network in self.bridge_mappings:
            self._remove_dvr_mac_for_phys_br(physical_network, mac)
        if self.enable_tunneling:
            self._remove_dvr_mac_for_tun_br(mac)
        LOG.debug("Removed DVR MAC flow for %s", mac)
        self.registered_dvr_macs.remove(mac)

    def setup_dvr_mac_flows_on_all_brs(self):
        dvr_macs = self.plugin_rpc.get_dvr_mac_address_list(self.context)
        LOG.debug("L2 Agent DVR: Received these MACs: %r", dvr_macs)
        for mac in dvr_macs:
            c_mac = netaddr.EUI(mac['mac_address'],
                                dialect=netaddr.mac_unix_expanded)
            if c_mac == self.dvr_mac_address:
                self._add_dvr_mac_for_arp(c_mac)
                LOG.debug("Added the DVR MAC rule for ARP %s", c_mac)
                continue
            self._add_dvr_mac(c_mac)

    def dvr_mac_address_update(self, dvr_macs):
        if not self.dvr_mac_address:
            LOG.debug("Self mac unknown, ignoring this "
                      "dvr_mac_address_update() ")
            return

        dvr_host_macs = set()
        for entry in dvr_macs:
            e_mac = netaddr.EUI(entry['mac_address'],
                                dialect=netaddr.mac_unix_expanded)
            if e_mac == self.dvr_mac_address:
                continue
            dvr_host_macs.add(e_mac)

        if dvr_host_macs == self.registered_dvr_macs:
            LOG.debug("DVR Mac address already up to date")
            return

        dvr_macs_added = dvr_host_macs - self.registered_dvr_macs
        dvr_macs_removed = self.registered_dvr_macs - dvr_host_macs

        for oldmac in dvr_macs_removed:
            self._remove_dvr_mac(oldmac)

        for newmac in dvr_macs_added:
            self._add_dvr_mac(newmac)

    def in_distributed_mode(self):
        return self.dvr_mac_address is not None

    def process_tunneled_network(self, network_type, lvid, segmentation_id):
        self.tun_br.provision_local_vlan(
            network_type=network_type,
            lvid=lvid,
            segmentation_id=segmentation_id,
            distributed=self.in_distributed_mode())

    def _bind_distributed_router_interface_port(self, port, lvm,
                                                fixed_ips, device_owner):
        # since distributed router port must have only one fixed
        # IP, directly use fixed_ips[0]
        fixed_ip = fixed_ips[0]
        subnet_uuid = fixed_ip['subnet_id']
        if subnet_uuid in self.local_dvr_map:
            ldm = self.local_dvr_map[subnet_uuid]
        else:
            # set up LocalDVRSubnetMapping available for this subnet
            subnet_info = self.plugin_rpc.get_subnet_for_dvr(
                self.context, subnet_uuid, fixed_ips=fixed_ips)
            if not subnet_info:
                LOG.warning("DVR: Unable to retrieve subnet information "
                            "for subnet_id %s. The subnet or the gateway "
                            "may have already been deleted", subnet_uuid)
                return
            LOG.debug("get_subnet_for_dvr for subnet %(uuid)s "
                      "returned with %(info)s",
                      {"uuid": subnet_uuid, "info": subnet_info})
            ldm = LocalDVRSubnetMapping(subnet_info)
            self.local_dvr_map[subnet_uuid] = ldm

        # DVR takes over
        ldm.set_dvr_owned(True)

        vlan_to_use = lvm.vlan
        if lvm.network_type in ovs_constants.DVR_PHYSICAL_NETWORK_TYPES:
            vlan_to_use = lvm.segmentation_id

        subnet_info = ldm.get_subnet_info()
        ip_version = subnet_info['ip_version']

        if self.firewall and isinstance(self.firewall,
                                        ovs_firewall.OVSFirewallDriver):
            tunnel_direct_info = {"network_type": lvm.network_type,
                                  "physical_network": lvm.physical_network}
            self.firewall.install_accepted_egress_direct_flow(
                subnet_info['gateway_mac'], lvm.vlan, port.ofport,
                tunnel_direct_info=tunnel_direct_info)

        local_compute_ports = (
            self.plugin_rpc.get_ports_on_host_by_subnet(
                self.context, self.host, subnet_uuid))
        LOG.debug("DVR: List of ports received from "
                  "get_ports_on_host_by_subnet %s",
                  local_compute_ports)
        vif_by_id = self.int_br.get_vifs_by_ids(
            [local_port['id'] for local_port in local_compute_ports])

        # A router port has an OVS interface with type internal. Once the
        # interface is created, a valid ofport will be assigned.
        vif_by_id = {k: v for k, v in vif_by_id.items()
                     if not v or v.ofport not in
                     (ovs_lib.INVALID_OFPORT, ovs_lib.UNASSIGNED_OFPORT)}

        for local_port in local_compute_ports:
            vif = vif_by_id.get(local_port['id'])
            if not vif:
                continue
            ldm.add_compute_ofport(vif.vif_id, vif.ofport)
            if vif.vif_id in self.local_ports:
                # ensure if a compute port is already on
                # a different dvr routed subnet
                # if yes, queue this subnet to that port
                comp_ovsport = self.local_ports[vif.vif_id]
                comp_ovsport.add_subnet(subnet_uuid)
            else:
                # the compute port is discovered first here that its on
                # a dvr routed subnet queue this subnet to that port
                comp_ovsport = OVSPort(vif.vif_id, vif.ofport,
                                       vif.vif_mac, local_port['device_owner'])
                comp_ovsport.add_subnet(subnet_uuid)
                self.local_ports[vif.vif_id] = comp_ovsport
            # create rule for just this vm port
            self.int_br.install_dvr_to_src_mac(
                network_type=lvm.network_type,
                vlan_tag=vlan_to_use,
                gateway_mac=subnet_info['gateway_mac'],
                dst_mac=comp_ovsport.get_mac(),
                dst_port=comp_ovsport.get_ofport())
        self.int_br.install_dvr_dst_mac_for_arp(
            lvm.network_type,
            vlan_tag=lvm.vlan,
            gateway_mac=port.vif_mac,
            dvr_mac=self.dvr_mac_address,
            rtr_port=port.ofport)

        if lvm.network_type in ovs_constants.DVR_PHYSICAL_NETWORK_TYPES:
            # TODO(vivek) remove the IPv6 related flows once SNAT is not
            # used for IPv6 DVR.
            br = self.phys_brs[lvm.physical_network]
        if lvm.network_type in ovs_constants.TUNNEL_NETWORK_TYPES:
            br = self.tun_br
        # TODO(vivek) remove the IPv6 related flows once SNAT is not
        # used for IPv6 DVR.
        if ip_version == 4:
            br.install_dvr_process_ipv4(
                vlan_tag=lvm.vlan, gateway_ip=fixed_ip['ip_address'])
        else:
            br.install_dvr_process_ipv6(
                vlan_tag=lvm.vlan, gateway_mac=port.vif_mac)
        br.install_dvr_process(
            vlan_tag=lvm.vlan, vif_mac=port.vif_mac,
            dvr_mac_address=self.dvr_mac_address)

        # the dvr router interface is itself a port, so capture it
        # queue this subnet to that port. A subnet appears only once as
        # a router interface on any given router
        ovsport = OVSPort(port.vif_id, port.ofport,
                          port.vif_mac, device_owner)
        ovsport.add_subnet(subnet_uuid, fixed_ip['ip_address'])
        self.local_ports[port.vif_id] = ovsport
        ldm.add_dvr_ofport(port.vif_id, port.ofport)

        if (ip_version == n_const.IP_VERSION_4 and
                subnet_info.get('gateway_mac')):
            # Change ARP reply destination MAC address from
            # dvr_host_mac to gateway_mac.
            self.int_br.change_arp_destination_mac(
                target_mac_address=subnet_info['gateway_mac'],
                orig_mac_address=self.dvr_mac_address)

    def _bind_port_on_dvr_subnet(self, port, lvm, fixed_ips,
                                 device_owner):
        ports = self.plugin_rpc.get_ports(self.context,
                                          filters={'id': [port.vif_id]})
        aaps = []
        if len(ports) == 1:
            aaps = ports[0].get("allowed_address_pairs", [])

        # Handle new compute port added use-case
        subnet_uuid = None
        for ips in fixed_ips:
            if ips['subnet_id'] not in self.local_dvr_map:
                continue
            subnet_uuid = ips['subnet_id']
            ldm = self.local_dvr_map[subnet_uuid]
            if not ldm.is_dvr_owned():
                # well this is CSNAT stuff, let dvr come in
                # and do plumbing for this vm later
                continue

            # This confirms that this compute port belongs
            # to a dvr hosted subnet.
            # Accommodate this VM Port into the existing rule in
            # the integration bridge
            LOG.debug("DVR: Plumbing compute port %s", port.vif_id)
            subnet_info = ldm.get_subnet_info()
            ldm.add_compute_ofport(port.vif_id, port.ofport)
            if port.vif_id in self.local_ports:
                # ensure if a compute port is already on a different
                # dvr routed subnet
                # if yes, queue this subnet to that port
                ovsport = self.local_ports[port.vif_id]
                ovsport.add_subnet(subnet_uuid)
            else:
                # the compute port is discovered first here that its
                # on a dvr routed subnet, queue this subnet to that port
                ovsport = OVSPort(port.vif_id, port.ofport,
                                  port.vif_mac, device_owner)
                ovsport.add_subnet(subnet_uuid)
                self.local_ports[port.vif_id] = ovsport
            vlan_to_use = lvm.vlan
            if lvm.network_type in ovs_constants.DVR_PHYSICAL_NETWORK_TYPES:
                vlan_to_use = lvm.segmentation_id
            # create a rule for this vm port
            dst_port = ovsport.get_ofport()
            self.int_br.install_dvr_to_src_mac(
                network_type=lvm.network_type,
                vlan_tag=vlan_to_use,
                gateway_mac=subnet_info['gateway_mac'],
                dst_mac=ovsport.get_mac(),
                dst_port=dst_port)
            for aap in aaps:
                aap_ip_cidr = netaddr.IPNetwork(aap['ip_address'])
                if n_utils.is_cidr_host(str(aap_ip_cidr.cidr)):
                    if ipam_utils.check_subnet_ip(
                            ldm.subnet['cidr'], str(aap_ip_cidr.ip)):
                        self.int_br.install_dvr_to_src_mac(
                            network_type=lvm.network_type,
                            vlan_tag=vlan_to_use,
                            gateway_mac=subnet_info['gateway_mac'],
                            dst_mac=aap["mac_address"],
                            dst_port=dst_port)

    def _bind_centralized_snat_port_on_dvr_subnet(self, port, lvm,
                                                  fixed_ips, device_owner):
        # We only pass the subnet uuid so the server code will correctly
        # use the gateway_ip value from the subnet when looking up the
        # centralized-SNAT (CSNAT) port, get it early from the first fixed_ip.
        subnet_uuid = fixed_ips[0]['subnet_id']
        if port.vif_id in self.local_ports:
            # throw an error if CSNAT port is already on a different
            # dvr routed subnet
            ovsport = self.local_ports[port.vif_id]
            subs = list(ovsport.get_subnets())
            if subs[0] == subnet_uuid:
                return
            LOG.error("Centralized-SNAT port %(port)s on subnet "
                      "%(port_subnet)s already seen on a different "
                      "subnet %(orig_subnet)s", {
                          "port": port.vif_id,
                          "port_subnet": subnet_uuid,
                          "orig_subnet": subs[0],
                      })
            return
        ldm = None
        subnet_info = None
        if subnet_uuid not in self.local_dvr_map:
            # no csnat ports seen on this subnet - create csnat state
            # for this subnet
            subnet_info = self.plugin_rpc.get_subnet_for_dvr(
                self.context, subnet_uuid, fixed_ips=None)
            if not subnet_info:
                LOG.warning("DVR: Unable to retrieve subnet information "
                            "for subnet_id %s. The subnet or the gateway "
                            "may have already been deleted", subnet_uuid)
                return
            LOG.debug("get_subnet_for_dvr for subnet %(uuid)s "
                      "returned with %(info)s",
                      {"uuid": subnet_uuid, "info": subnet_info})
            ldm = LocalDVRSubnetMapping(subnet_info, port.ofport)
            self.local_dvr_map[subnet_uuid] = ldm
        else:
            ldm = self.local_dvr_map[subnet_uuid]
            subnet_info = ldm.get_subnet_info()
            # Store csnat OF Port in the existing DVRSubnetMap
            ldm.set_csnat_ofport(port.ofport)

        # create ovsPort footprint for csnat port
        ovsport = OVSPort(port.vif_id, port.ofport,
                          port.vif_mac, device_owner)
        ovsport.add_subnet(subnet_uuid)
        self.local_ports[port.vif_id] = ovsport
        vlan_to_use = lvm.vlan
        if lvm.network_type in ovs_constants.DVR_PHYSICAL_NETWORK_TYPES:
            vlan_to_use = lvm.segmentation_id
        self.int_br.install_dvr_to_src_mac(
            network_type=lvm.network_type,
            vlan_tag=vlan_to_use,
            gateway_mac=subnet_info['gateway_mac'],
            dst_mac=ovsport.get_mac(),
            dst_port=ovsport.get_ofport())

    def bind_port_to_dvr(self, port, local_vlan_map,
                         fixed_ips, device_owner):
        if not self.in_distributed_mode():
            return

        if (local_vlan_map.network_type not in
                (ovs_constants.TUNNEL_NETWORK_TYPES +
                 ovs_constants.DVR_PHYSICAL_NETWORK_TYPES)):
            LOG.debug("DVR: Port %s is with network_type %s not supported"
                      " for dvr plumbing", port.vif_id,
                      local_vlan_map.network_type)
            return

        if (port.vif_id in self.local_ports and
                self.local_ports[port.vif_id].ofport != port.ofport):
            LOG.info("DVR: Port %(vif)s changed port number to "
                     "%(ofport)s, rebinding.",
                     {'vif': port.vif_id, 'ofport': port.ofport})
            self.unbind_port_from_dvr(port, local_vlan_map)

        if port.ofport in (ovs_lib.INVALID_OFPORT,
                           ovs_lib.UNASSIGNED_OFPORT):
            return

        if device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
            self._bind_distributed_router_interface_port(port,
                                                         local_vlan_map,
                                                         fixed_ips,
                                                         device_owner)

        if device_owner and n_utils.is_dvr_serviced(device_owner):
            self._bind_port_on_dvr_subnet(port, local_vlan_map,
                                          fixed_ips,
                                          device_owner)

        if device_owner == n_const.DEVICE_OWNER_ROUTER_SNAT:
            self._bind_centralized_snat_port_on_dvr_subnet(port,
                                                           local_vlan_map,
                                                           fixed_ips,
                                                           device_owner)

    def _unbind_distributed_router_interface_port(self, port, lvm):
        ovsport = self.local_ports[port.vif_id]
        # removal of distributed router interface
        subnet_ids = ovsport.get_subnets()
        subnet_set = set(subnet_ids)
        network_type = lvm.network_type
        physical_network = lvm.physical_network
        vlan_to_use = lvm.vlan
        if network_type in ovs_constants.DVR_PHYSICAL_NETWORK_TYPES:
            vlan_to_use = lvm.segmentation_id
        # ensure we process for all the subnets laid on this removed port
        for sub_uuid in subnet_set:
            if sub_uuid not in self.local_dvr_map:
                continue
            ldm = self.local_dvr_map[sub_uuid]
            subnet_info = ldm.get_subnet_info()
            ip_version = subnet_info['ip_version']

            fixed_ip = ovsport.get_ip(sub_uuid)
            is_dvr_gateway_port = False
            subnet_gateway = subnet_info.get('gateway_ip')
            # since distributed router port must have only one fixed IP,
            # directly use fixed_ip[0]
            if fixed_ip and fixed_ip[0] == subnet_gateway:
                is_dvr_gateway_port = True

            # remove vm dvr src mac rules only if the ovsport
            # is gateway for the subnet or if the gateway is
            # not set on the subnet
            if is_dvr_gateway_port or not subnet_gateway:
                # DVR is no more owner
                ldm.set_dvr_owned(False)
                # remove all vm rules for this dvr subnet
                # clear of compute_ports altogether
                compute_ports = ldm.get_compute_ofports()
                for vif_id in compute_ports:
                    comp_port = self.local_ports[vif_id]
                    self.int_br.delete_dvr_to_src_mac(
                        network_type=network_type,
                        vlan_tag=vlan_to_use, dst_mac=comp_port.get_mac())
                ldm.remove_all_compute_ofports()

            self.int_br.delete_dvr_dst_mac_for_arp(
                network_type=network_type,
                vlan_tag=vlan_to_use,
                gateway_mac=port.vif_mac,
                dvr_mac=self.dvr_mac_address,
                rtr_port=port.ofport)
            if (ldm.get_csnat_ofport() == ovs_constants.OFPORT_INVALID and
                    len(ldm.get_dvr_ofports()) <= 1):
                # if there is no csnat port for this subnet and if this is
                # the last dvr port in the subnet, remove this subnet from
                # local_dvr_map, as no dvr (or) csnat ports available on this
                # agent anymore
                self.local_dvr_map.pop(sub_uuid, None)
            if network_type in ovs_constants.DVR_PHYSICAL_NETWORK_TYPES:
                br = self.phys_brs[physical_network]
            if network_type in ovs_constants.TUNNEL_NETWORK_TYPES:
                br = self.tun_br
            if ip_version == 4:
                if subnet_info['gateway_ip']:
                    br.delete_dvr_process_ipv4(
                        vlan_tag=lvm.vlan,
                        gateway_ip=subnet_info['gateway_ip'])
            else:
                br.delete_dvr_process_ipv6(
                    vlan_tag=lvm.vlan, gateway_mac=subnet_info['gateway_mac'])
            ovsport.remove_subnet(sub_uuid)
            ldm.remove_dvr_ofport(port.vif_id)

            if self.firewall and isinstance(self.firewall,
                                            ovs_firewall.OVSFirewallDriver):
                self.firewall.delete_accepted_egress_direct_flow(
                    subnet_info['gateway_mac'], lvm.vlan)

            if (ip_version == n_const.IP_VERSION_4 and
                    subnet_info.get('gateway_mac')):
                # remove ARP reply destination MAC address change flow
                self.int_br.delete_arp_destination_change(
                    target_mac_address=subnet_info['gateway_mac'],
                    orig_mac_address=self.dvr_mac_address)

        if lvm.network_type in ovs_constants.DVR_PHYSICAL_NETWORK_TYPES:
            br = self.phys_brs[physical_network]
        if lvm.network_type in ovs_constants.TUNNEL_NETWORK_TYPES:
            br = self.tun_br
        br.delete_dvr_process(vlan_tag=lvm.vlan, vif_mac=port.vif_mac)

        # release port state
        self.local_ports.pop(port.vif_id, None)

    def _unbind_port_on_dvr_subnet(self, port, lvm):
        ports = self.plugin_rpc.get_ports(self.context,
                                          filters={'id': [port.vif_id]})
        aaps = []
        if len(ports) == 1:
            aaps = ports[0].get("allowed_address_pairs", [])

        ovsport = self.local_ports[port.vif_id]
        # This confirms that this compute port being removed belonged
        # to a dvr hosted subnet.
        LOG.debug("DVR: Removing plumbing for compute port %s", port)
        subnet_ids = ovsport.get_subnets()
        # ensure we process for all the subnets laid on this port
        for sub_uuid in subnet_ids:
            if sub_uuid not in self.local_dvr_map:
                continue
            if aaps:
                local_compute_ports = (
                    self.plugin_rpc.get_ports_on_host_by_subnet(
                        self.context, self.host, sub_uuid))
                local_aap_macs = set()
                for lport in local_compute_ports:
                    if lport['id'] != port.vif_id:
                        local_aap_macs.update({
                            aap["mac_address"] for aap in lport.get(
                                "allowed_address_pairs", [])})
            ldm = self.local_dvr_map[sub_uuid]
            ldm.remove_compute_ofport(port.vif_id)
            vlan_to_use = lvm.vlan
            if lvm.network_type in ovs_constants.DVR_PHYSICAL_NETWORK_TYPES:
                vlan_to_use = lvm.segmentation_id
            # first remove this vm port rule
            self.int_br.delete_dvr_to_src_mac(
                network_type=lvm.network_type,
                vlan_tag=vlan_to_use, dst_mac=ovsport.get_mac())
        for aap in aaps:
            aap_ip_cidr = netaddr.IPNetwork(aap['ip_address'])
            if n_utils.is_cidr_host(str(aap_ip_cidr.cidr)):
                if ipam_utils.check_subnet_ip(ldm.subnet['cidr'],
                                              str(aap_ip_cidr.ip)):
                    if aap["mac_address"] not in local_aap_macs:
                        self.int_br.delete_dvr_to_src_mac(
                            network_type=lvm.network_type,
                            vlan_tag=vlan_to_use, dst_mac=aap["mac_address"])
        # release port state
        self.local_ports.pop(port.vif_id, None)

    def _unbind_centralized_snat_port_on_dvr_subnet(self, port, lvm):
        ovsport = self.local_ports[port.vif_id]
        # This confirms that this compute port being removed belonged
        # to a dvr hosted subnet.
        LOG.debug("DVR: Removing plumbing for csnat port %s", port)
        sub_uuid = list(ovsport.get_subnets())[0]
        # ensure we process for all the subnets laid on this port
        if sub_uuid not in self.local_dvr_map:
            return
        ldm = self.local_dvr_map[sub_uuid]
        ldm.set_csnat_ofport(ovs_constants.OFPORT_INVALID)
        vlan_to_use = lvm.vlan
        if lvm.network_type in ovs_constants.DVR_PHYSICAL_NETWORK_TYPES:
            vlan_to_use = lvm.segmentation_id
        # then remove csnat port rule
        self.int_br.delete_dvr_to_src_mac(
            network_type=lvm.network_type,
            vlan_tag=vlan_to_use, dst_mac=ovsport.get_mac())
        if not ldm.is_dvr_owned():
            # if not owned by DVR (only used for csnat), remove this
            # subnet state altogether
            self.local_dvr_map.pop(sub_uuid, None)
        # release port state
        self.local_ports.pop(port.vif_id, None)

    def unbind_port_from_dvr(self, vif_port, local_vlan_map):
        if not self.in_distributed_mode():
            return
        # Handle port removed use-case
        if vif_port and vif_port.vif_id not in self.local_ports:
            LOG.debug("DVR: Non distributed port, ignoring %s", vif_port)
            return

        ovsport = self.local_ports[vif_port.vif_id]
        device_owner = ovsport.get_device_owner()

        if device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE:
            self._unbind_distributed_router_interface_port(vif_port,
                                                           local_vlan_map)

        if device_owner and n_utils.is_dvr_serviced(device_owner):
            self._unbind_port_on_dvr_subnet(vif_port,
                                            local_vlan_map)

        if device_owner == n_const.DEVICE_OWNER_ROUTER_SNAT:
            self._unbind_centralized_snat_port_on_dvr_subnet(vif_port,
                                                             local_vlan_map)
