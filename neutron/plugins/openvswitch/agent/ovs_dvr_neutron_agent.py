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

from oslo_log import log as logging
import oslo_messaging
from oslo_utils import excutils

from neutron.common import constants as n_const
from neutron.common import utils as n_utils
from neutron.i18n import _LE, _LI, _LW
from neutron.plugins.common import constants as p_const
from neutron.plugins.openvswitch.common import constants

LOG = logging.getLogger(__name__)


# A class to represent a DVR-hosted subnet including vif_ports resident on
# that subnet
class LocalDVRSubnetMapping(object):
    def __init__(self, subnet, csnat_ofport=constants.OFPORT_INVALID):
        # set of commpute ports on on this dvr subnet
        self.compute_ports = {}
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


class OVSPort(object):
    def __init__(self, id, ofport, mac, device_owner):
        self.id = id
        self.mac = mac
        self.ofport = ofport
        self.subnets = set()
        self.device_owner = device_owner

    def __str__(self):
        return ("OVSPort: id = %s, ofport = %s, mac = %s, "
                "device_owner = %s, subnets = %s" %
                (self.id, self.ofport, self.mac,
                 self.device_owner, self.subnets))

    def add_subnet(self, subnet_id):
        self.subnets.add(subnet_id)

    def remove_subnet(self, subnet_id):
        self.subnets.remove(subnet_id)

    def remove_all_subnets(self):
        self.subnets.clear()

    def get_subnets(self):
        return self.subnets

    def get_device_owner(self):
        return self.device_owner

    def get_mac(self):
        return self.mac

    def get_ofport(self):
        return self.ofport


class OVSDVRNeutronAgent(object):
    '''
    Implements OVS-based DVR(Distributed Virtual Router), for overlay networks.
    '''
    # history
    #   1.0 Initial version

    def __init__(self, context, plugin_rpc, integ_br, tun_br,
                 bridge_mappings, phys_brs, int_ofports, phys_ofports,
                 patch_int_ofport=constants.OFPORT_INVALID,
                 patch_tun_ofport=constants.OFPORT_INVALID,
                 host=None, enable_tunneling=False,
                 enable_distributed_routing=False):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.host = host
        self.enable_tunneling = enable_tunneling
        self.enable_distributed_routing = enable_distributed_routing
        self.bridge_mappings = bridge_mappings
        self.phys_brs = phys_brs
        self.int_ofports = int_ofports
        self.phys_ofports = phys_ofports
        self.reset_ovs_parameters(integ_br, tun_br,
                                  patch_int_ofport, patch_tun_ofport)
        self.reset_dvr_parameters()
        self.dvr_mac_address = None
        if self.enable_distributed_routing:
            self.get_dvr_mac_address()

    def setup_dvr_flows(self):
        self.setup_dvr_flows_on_integ_br()
        self.setup_dvr_flows_on_tun_br()
        self.setup_dvr_flows_on_phys_br()
        self.setup_dvr_mac_flows_on_all_brs()

    def reset_ovs_parameters(self, integ_br, tun_br,
                             patch_int_ofport, patch_tun_ofport):
        '''Reset the openvswitch parameters'''
        self.int_br = integ_br
        self.tun_br = tun_br
        self.patch_int_ofport = patch_int_ofport
        self.patch_tun_ofport = patch_tun_ofport

    def reset_dvr_parameters(self):
        '''Reset the DVR parameters'''
        self.local_dvr_map = {}
        self.local_csnat_map = {}
        self.local_ports = {}
        self.registered_dvr_macs = set()

    def get_dvr_mac_address(self):
        try:
            self.get_dvr_mac_address_with_retry()
        except oslo_messaging.RemoteError as e:
            LOG.warning(_LW('L2 agent could not get DVR MAC address at '
                            'startup due to RPC error.  It happens when the '
                            'server does not support this RPC API.  Detailed '
                            'message: %s'), e)
        except oslo_messaging.MessagingTimeout:
            LOG.error(_LE('DVR: Failed to obtain a valid local '
                          'DVR MAC address - L2 Agent operating '
                          'in Non-DVR Mode'))

        if not self.in_distributed_mode():
            # switch all traffic using L2 learning
            # REVISIT(yamamoto): why to install the same flow as
            # setup_integration_br?
            self.int_br.install_normal()

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
                        LOG.warning(_LW('L2 agent could not get DVR MAC '
                                        'address from server. Retrying. '
                                        'Detailed message: %s'), e)
            else:
                LOG.debug("L2 Agent DVR: Received response for "
                          "get_dvr_mac_address_by_host() from "
                          "plugin: %r", details)
                self.dvr_mac_address = details['mac_address']
                return

    def setup_dvr_flows_on_integ_br(self):
        '''Setup up initial dvr flows into br-int'''
        if not self.in_distributed_mode():
            return

        LOG.info(_LI("L2 Agent operating in DVR Mode with MAC %s"),
                 self.dvr_mac_address)
        # Remove existing flows in integration bridge
        self.int_br.delete_flows()

        # Add a canary flow to int_br to track OVS restarts
        self.int_br.setup_canary_table()

        # Insert 'drop' action as the default for Table DVR_TO_SRC_MAC
        self.int_br.install_drop(table_id=constants.DVR_TO_SRC_MAC, priority=1)

        self.int_br.install_drop(table_id=constants.DVR_TO_SRC_MAC_VLAN,
                                 priority=1)

        # Insert 'normal' action as the default for Table LOCAL_SWITCHING
        self.int_br.install_normal(table_id=constants.LOCAL_SWITCHING,
                                   priority=1)

        for physical_network in self.bridge_mappings:
            self.int_br.install_drop(table_id=constants.LOCAL_SWITCHING,
                                     priority=2,
                                     in_port=self.int_ofports[
                                         physical_network])

    def setup_dvr_flows_on_tun_br(self):
        '''Setup up initial dvr flows into br-tun'''
        if not self.enable_tunneling or not self.in_distributed_mode():
            return

        self.tun_br.install_goto(dest_table_id=constants.DVR_PROCESS,
                                 priority=1,
                                 in_port=self.patch_int_ofport)

        # table-miss should be sent to learning table
        self.tun_br.install_goto(table_id=constants.DVR_NOT_LEARN,
                                 dest_table_id=constants.LEARN_FROM_TUN)

        self.tun_br.install_goto(table_id=constants.DVR_PROCESS,
                                 dest_table_id=constants.PATCH_LV_TO_TUN)

    def setup_dvr_flows_on_phys_br(self):
        '''Setup up initial dvr flows into br-phys'''
        if not self.in_distributed_mode():
            return

        for physical_network in self.bridge_mappings:
            self.phys_brs[physical_network].install_goto(
                in_port=self.phys_ofports[physical_network],
                priority=2,
                dest_table_id=constants.DVR_PROCESS_VLAN)
            self.phys_brs[physical_network].install_goto(
                priority=1,
                dest_table_id=constants.DVR_NOT_LEARN_VLAN)
            self.phys_brs[physical_network].install_goto(
                table_id=constants.DVR_PROCESS_VLAN,
                priority=0,
                dest_table_id=constants.LOCAL_VLAN_TRANSLATION)
            self.phys_brs[physical_network].install_drop(
                table_id=constants.LOCAL_VLAN_TRANSLATION,
                in_port=self.phys_ofports[physical_network],
                priority=2)
            self.phys_brs[physical_network].install_normal(
                table_id=constants.DVR_NOT_LEARN_VLAN,
                priority=1)

    def _add_dvr_mac_for_phys_br(self, physical_network, mac):
        self.int_br.add_dvr_mac_vlan(mac=mac,
                                     port=self.int_ofports[physical_network])
        phys_br = self.phys_brs[physical_network]
        phys_br.add_dvr_mac_vlan(mac=mac,
                                 port=self.phys_ofports[physical_network])

    def _remove_dvr_mac_for_phys_br(self, physical_network, mac):
        # REVISIT(yamamoto): match in_port as well?
        self.int_br.remove_dvr_mac_vlan(mac=mac)
        phys_br = self.phys_brs[physical_network]
        # REVISIT(yamamoto): match in_port as well?
        phys_br.remove_dvr_mac_vlan(mac=mac)

    def _add_dvr_mac_for_tun_br(self, mac):
        self.int_br.add_dvr_mac_tun(mac=mac, port=self.patch_tun_ofport)
        self.tun_br.add_dvr_mac_tun(mac=mac, port=self.patch_int_ofport)

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

    def _remove_dvr_mac(self, mac):
        for physical_network in self.bridge_mappings:
            self._remove_dvr_mac_for_phys_br(physical_network, mac)
        if self.enable_tunneling:
            self._remove_dvr_mac_for_tun_br(mac)
        LOG.debug("Removed DVR MAC flow for %s", mac)
        self.registered_dvr_macs.remove(mac)

    def setup_dvr_mac_flows_on_all_brs(self):
        if not self.in_distributed_mode():
            LOG.debug("Not in distributed mode, ignoring invocation "
                      "of get_dvr_mac_address_list() ")
            return
        dvr_macs = self.plugin_rpc.get_dvr_mac_address_list(self.context)
        LOG.debug("L2 Agent DVR: Received these MACs: %r", dvr_macs)
        for mac in dvr_macs:
            if mac['mac_address'] == self.dvr_mac_address:
                continue
            self._add_dvr_mac(mac['mac_address'])

    def dvr_mac_address_update(self, dvr_macs):
        if not self.dvr_mac_address:
            LOG.debug("Self mac unknown, ignoring this "
                      "dvr_mac_address_update() ")
            return

        dvr_host_macs = set()
        for entry in dvr_macs:
            if entry['mac_address'] == self.dvr_mac_address:
                continue
            dvr_host_macs.add(entry['mac_address'])

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

    def is_dvr_router_interface(self, device_owner):
        return device_owner == n_const.DEVICE_OWNER_DVR_INTERFACE

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
        csnat_ofport = constants.OFPORT_INVALID
        ldm = None
        if subnet_uuid in self.local_dvr_map:
            ldm = self.local_dvr_map[subnet_uuid]
            csnat_ofport = ldm.get_csnat_ofport()
            if csnat_ofport == constants.OFPORT_INVALID:
                LOG.error(_LE("DVR: Duplicate DVR router interface detected "
                              "for subnet %s"), subnet_uuid)
                return
        else:
            # set up LocalDVRSubnetMapping available for this subnet
            subnet_info = self.plugin_rpc.get_subnet_for_dvr(self.context,
                                                             subnet_uuid)
            if not subnet_info:
                LOG.error(_LE("DVR: Unable to retrieve subnet information "
                              "for subnet_id %s"), subnet_uuid)
                return
            LOG.debug("get_subnet_for_dvr for subnet %(uuid)s "
                      "returned with %(info)s",
                      {"uuid": subnet_uuid, "info": subnet_info})
            ldm = LocalDVRSubnetMapping(subnet_info)
            self.local_dvr_map[subnet_uuid] = ldm

        # DVR takes over
        ldm.set_dvr_owned(True)

        vlan_to_use = lvm.vlan
        if lvm.network_type == p_const.TYPE_VLAN:
            vlan_to_use = lvm.segmentation_id

        subnet_info = ldm.get_subnet_info()
        ip_version = subnet_info['ip_version']
        local_compute_ports = (
            self.plugin_rpc.get_ports_on_host_by_subnet(
                self.context, self.host, subnet_uuid))
        LOG.debug("DVR: List of ports received from "
                  "get_ports_on_host_by_subnet %s",
                  local_compute_ports)
        for prt in local_compute_ports:
            vif = self.int_br.get_vif_port_by_id(prt['id'])
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
                                  vif.vif_mac, prt['device_owner'])
                comp_ovsport.add_subnet(subnet_uuid)
                self.local_ports[vif.vif_id] = comp_ovsport
            # create rule for just this vm port
            self.int_br.install_dvr_to_src_mac(
                network_type=lvm.network_type,
                vlan_tag=vlan_to_use,
                gateway_mac=subnet_info['gateway_mac'],
                dst_mac=comp_ovsport.get_mac(),
                dst_port=comp_ovsport.get_ofport())

        if lvm.network_type == p_const.TYPE_VLAN:
            # TODO(vivek) remove the IPv6 related flows once SNAT is not
            # used for IPv6 DVR.
            br = self.phys_brs[lvm.physical_network]
        if lvm.network_type in constants.TUNNEL_NETWORK_TYPES:
            br = self.tun_br
        # TODO(vivek) remove the IPv6 related flows once SNAT is not
        # used for IPv6 DVR.
        if ip_version == 4:
            br.install_dvr_process_ipv4(
                vlan_tag=lvm.vlan, gateway_ip=subnet_info['gateway_ip'])
        else:
            br.install_dvr_process_ipv6(
                vlan_tag=lvm.vlan, gateway_mac=subnet_info['gateway_mac'])
        br.install_dvr_process(
            vlan_tag=lvm.vlan, vif_mac=port.vif_mac,
            dvr_mac_address=self.dvr_mac_address)

        # the dvr router interface is itself a port, so capture it
        # queue this subnet to that port. A subnet appears only once as
        # a router interface on any given router
        ovsport = OVSPort(port.vif_id, port.ofport,
                          port.vif_mac, device_owner)
        ovsport.add_subnet(subnet_uuid)
        self.local_ports[port.vif_id] = ovsport

    def _bind_port_on_dvr_subnet(self, port, lvm, fixed_ips,
                                 device_owner):
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
            if lvm.network_type == p_const.TYPE_VLAN:
                vlan_to_use = lvm.segmentation_id
            # create a rule for this vm port
            self.int_br.install_dvr_to_src_mac(
                network_type=lvm.network_type,
                vlan_tag=vlan_to_use,
                gateway_mac=subnet_info['gateway_mac'],
                dst_mac=ovsport.get_mac(),
                dst_port=ovsport.get_ofport())

    def _bind_centralized_snat_port_on_dvr_subnet(self, port, lvm,
                                                  fixed_ips, device_owner):
        # since centralized-SNAT (CSNAT) port must have only one fixed
        # IP, directly use fixed_ips[0]
        fixed_ip = fixed_ips[0]
        if port.vif_id in self.local_ports:
            # throw an error if CSNAT port is already on a different
            # dvr routed subnet
            ovsport = self.local_ports[port.vif_id]
            subs = list(ovsport.get_subnets())
            if subs[0] == fixed_ip['subnet_id']:
                return
            LOG.error(_LE("Centralized-SNAT port %(port)s on subnet "
                          "%(port_subnet)s already seen on a different "
                          "subnet %(orig_subnet)s"), {
                "port": port.vif_id,
                "port_subnet": fixed_ip['subnet_id'],
                "orig_subnet": subs[0],
            })
            return
        subnet_uuid = fixed_ip['subnet_id']
        ldm = None
        subnet_info = None
        if subnet_uuid not in self.local_dvr_map:
            # no csnat ports seen on this subnet - create csnat state
            # for this subnet
            subnet_info = self.plugin_rpc.get_subnet_for_dvr(self.context,
                                                             subnet_uuid)
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
        if lvm.network_type == p_const.TYPE_VLAN:
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

        if local_vlan_map.network_type not in (constants.TUNNEL_NETWORK_TYPES
                                               + [p_const.TYPE_VLAN]):
            LOG.debug("DVR: Port %s is with network_type %s not supported"
                      " for dvr plumbing" % (port.vif_id,
                                             local_vlan_map.network_type))
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
        if network_type == p_const.TYPE_VLAN:
            vlan_to_use = lvm.segmentation_id
        # ensure we process for all the subnets laid on this removed port
        for sub_uuid in subnet_set:
            if sub_uuid not in self.local_dvr_map:
                continue
            ldm = self.local_dvr_map[sub_uuid]
            subnet_info = ldm.get_subnet_info()
            ip_version = subnet_info['ip_version']
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

            if ldm.get_csnat_ofport() == constants.OFPORT_INVALID:
                # if there is no csnat port for this subnet, remove
                # this subnet from local_dvr_map, as no dvr (or) csnat
                # ports available on this agent anymore
                self.local_dvr_map.pop(sub_uuid, None)
            if network_type == p_const.TYPE_VLAN:
                br = self.phys_br[physical_network]
            if network_type in constants.TUNNEL_NETWORK_TYPES:
                br = self.tun_br
            if ip_version == 4:
                br.delete_dvr_process_ipv4(
                    vlan_tag=lvm.vlan, gateway_ip=subnet_info['gateway_ip'])
            else:
                br.delete_dvr_process_ipv6(
                    vlan_tag=lvm.vlan, gateway_mac=subnet_info['gateway_mac'])
            ovsport.remove_subnet(sub_uuid)

        if lvm.network_type == p_const.TYPE_VLAN:
            br = self.phys_br[physical_network]
        if lvm.network_type in constants.TUNNEL_NETWORK_TYPES:
            br = self.tun_br
        br.delete_dvr_process(vlan_tag=lvm.vlan, vif_mac=port.vif_mac)

        # release port state
        self.local_ports.pop(port.vif_id, None)

    def _unbind_port_on_dvr_subnet(self, port, lvm):
        ovsport = self.local_ports[port.vif_id]
        # This confirms that this compute port being removed belonged
        # to a dvr hosted subnet.
        LOG.debug("DVR: Removing plumbing for compute port %s", port)
        subnet_ids = ovsport.get_subnets()
        # ensure we process for all the subnets laid on this port
        for sub_uuid in subnet_ids:
            if sub_uuid not in self.local_dvr_map:
                continue
            ldm = self.local_dvr_map[sub_uuid]
            ldm.remove_compute_ofport(port.vif_id)
            vlan_to_use = lvm.vlan
            if lvm.network_type == p_const.TYPE_VLAN:
                vlan_to_use = lvm.segmentation_id
            # first remove this vm port rule
            self.int_br.delete_dvr_to_src_mac(
                network_type=lvm.network_type,
                vlan_tag=vlan_to_use, dst_mac=ovsport.get_mac())
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
        ldm.set_csnat_ofport(constants.OFPORT_INVALID)
        vlan_to_use = lvm.vlan
        if lvm.network_type == p_const.TYPE_VLAN:
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
