# Copyright (c) 2015 OpenStack Foundation
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

import binascii
import collections

import netaddr
from neutron_lib import constants as lib_constants
from oslo_log import log as logging
from oslo_utils import excutils
from pyroute2.netlink import exceptions \
    as pyroute2_exc  # pylint: disable=no-name-in-module

from neutron.agent.l3 import dvr_fip_ns
from neutron.agent.l3 import dvr_router_base
from neutron.agent.linux import ip_lib
from neutron.common import utils as common_utils
from neutron.privileged.agent.linux import ip_lib as priv_ip_lib

LOG = logging.getLogger(__name__)
# xor-folding mask used for IPv6 rule index
MASK_30 = 0x3fffffff

# Tracks the arp entry cache
Arp_entry = collections.namedtuple(
    'Arp_entry', 'ip mac subnet_id operation')


class DvrLocalRouter(dvr_router_base.DvrRouterBase):
    def __init__(self, host, *args, **kwargs):
        super(DvrLocalRouter, self).__init__(host, *args, **kwargs)

        self.floating_ips_dict = {}
        # Linklocal subnet for router and floating IP namespace link
        self.rtr_fip_subnet = None
        self.rtr_fip_connect = False
        self.fip_ns = None
        self._pending_arp_set = set()

    def initialize(self, process_monitor):
        super().initialize(process_monitor)
        self._load_used_fip_information()

    def _load_used_fip_information(self):
        """Load FIP from the FipRulePriorityAllocator state file.

        If, for any reason, the FIP is not stored in the state file, this
        method reads the namespace "ip rule" list and search for the
        corresponding fixed IP of the FIP. If present, this "ip rule" is
        (1) deleted, (2) a new rule priority is allocated and (3) the "ip rule"
        is written again with the new assigned priority.

        At the end of the method, all existing "ip rule" registers in
        FIP_RT_TBL table (where FIP rules are stored) that don't match with
        any register memoized in self._rule_priorities is deleted.
        """
        ex_gw_port = self.get_ex_gw_port()
        if not ex_gw_port:
            return

        fip_ns = self.agent.get_fip_ns(ex_gw_port['network_id'])
        for fip in self.get_floating_ips():
            floating_ip = fip['floating_ip_address']
            fixed_ip = fip['fixed_ip_address']
            if not fixed_ip:
                continue

            rule_pr = fip_ns.lookup_rule_priority(floating_ip)
            if rule_pr:
                self.floating_ips_dict[floating_ip] = (fixed_ip, rule_pr)
                continue

            rule_pr = fip_ns.allocate_rule_priority(floating_ip)
            ip_lib.add_ip_rule(self.ns_name, fixed_ip,
                               table=dvr_fip_ns.FIP_RT_TBL,
                               priority=rule_pr)
            self.floating_ips_dict[floating_ip] = (fixed_ip, rule_pr)

        self._cleanup_unused_fip_ip_rules()

    def _cleanup_unused_fip_ip_rules(self):
        if not self.router_namespace.exists():
            # It could be a new router, thus the namespace is not created yet.
            return

        ip_rules = ip_lib.list_ip_rules(self.ns_name,
                                        lib_constants.IP_VERSION_4)
        ip_rules = [ipr for ipr in ip_rules
                    if ipr['table'] == dvr_fip_ns.FIP_RT_TBL]
        for ip_rule in ip_rules:
            for fixed_ip, rule_pr in self.floating_ips_dict.values():
                if (ip_rule['from'] == fixed_ip and
                        ip_rule['priority'] == rule_pr):
                    break
            else:
                ip_lib.delete_ip_rule(self.ns_name, ip_rule['from'],
                                      table=dvr_fip_ns.FIP_RT_TBL,
                                      priority=ip_rule['priority'])

    def migrate_centralized_floating_ip(self, fip, interface_name, device):
        # Remove the centralized fip first and then add fip to the host
        ip_cidr = common_utils.ip_to_cidr(fip['floating_ip_address'])
        self.floating_ip_removed_dist(ip_cidr)
        # Now add the floating_ip to the current host
        return self.floating_ip_added_dist(fip, ip_cidr)

    def floating_forward_rules(self, fip):
        """Override this function defined in router_info for dvr routers."""
        if not self.fip_ns:
            return []

        if fip.get(lib_constants.DVR_SNAT_BOUND):
            return []

        # For dvr_no_external node should not process any floating IP
        # iptables rules.
        if (self.agent_conf.agent_mode ==
                lib_constants.L3_AGENT_MODE_DVR_NO_EXTERNAL):
            return []

        fixed_ip = fip['fixed_ip_address']
        floating_ip = fip['floating_ip_address']
        rtr_2_fip_name = self.fip_ns.get_rtr_ext_device_name(self.router_id)
        dnat_from_floatingip_to_fixedip = (
            'PREROUTING', '-d %s/32 -i %s -j DNAT --to-destination %s' % (
                floating_ip, rtr_2_fip_name, fixed_ip))
        to_source = '-s %s/32 -j SNAT --to-source %s' % (fixed_ip, floating_ip)
        if self.iptables_manager.random_fully:
            to_source += ' --random-fully'
        snat_from_fixedip_to_floatingip = ('float-snat', to_source)
        return [dnat_from_floatingip_to_fixedip,
                snat_from_fixedip_to_floatingip]

    def floating_mangle_rules(self, floating_ip, fixed_ip, internal_mark):
        if not self.fip_ns:
            return []

        rtr_2_fip_name = self.fip_ns.get_rtr_ext_device_name(self.router_id)
        mark_traffic_to_floating_ip = (
            'floatingip', '-d %s/32 -i %s -j MARK --set-xmark %s' % (
                floating_ip, rtr_2_fip_name, internal_mark))
        mark_traffic_from_fixed_ip = (
            'FORWARD', '-s %s/32 -j $float-snat' % fixed_ip)
        return [mark_traffic_to_floating_ip, mark_traffic_from_fixed_ip]

    def add_centralized_floatingip(self, fip, fip_cidr):
        """Implements floatingip in centralized network node.
        This is a dummy function and is overridden in dvr_edge_router.py
        to add the floatingip function to the snat namespace.
        """

    def remove_centralized_floatingip(self, fip_cidr):
        """Removes floatingip from centralized network node.
        This is a dummy function and is overridden in dvr_edge_router.py
        to remove the floatingip function from the snat namespace.
        """

    def floating_ip_added_dist(self, fip, fip_cidr):
        """Add floating IP to respective namespace based on agent mode."""
        if fip.get(lib_constants.DVR_SNAT_BOUND):
            return self.add_centralized_floatingip(fip, fip_cidr)
        if not self._check_if_floatingip_bound_to_host(fip):
            # TODO(Swami): Need to figure out what status
            # should be returned when the floating IP is
            # not destined for this agent and if the floating
            # IP is configured in a different compute host.
            # This should not happen once we fix the server
            # side code, but still a check to make sure if
            # the floating IP is intended for this host should
            # be done.
            return

        # dvr_no_external host should not process any floating IP route rules.
        if (self.agent_conf.agent_mode ==
                lib_constants.L3_AGENT_MODE_DVR_NO_EXTERNAL):
            return

        floating_ip = fip['floating_ip_address']
        fixed_ip = fip['fixed_ip_address']
        self._add_floating_ip_rule(floating_ip, fixed_ip)
        fip_2_rtr_name = self.fip_ns.get_int_device_name(self.router_id)
        # Add routing rule in fip namespace
        fip_ns_name = self.fip_ns.get_name()
        if self.rtr_fip_subnet is None:
            self.rtr_fip_subnet = self.fip_ns.local_subnets.allocate(
                self.router_id)
        rtr_2_fip, __ = self.rtr_fip_subnet.get_pair()
        device = ip_lib.IPDevice(fip_2_rtr_name, namespace=fip_ns_name)
        device.route.add_route(fip_cidr, str(rtr_2_fip.ip))
        interface_name = (
            self.fip_ns.get_ext_device_name(
                self.fip_ns.agent_gateway_port['id']))
        ip_lib.send_ip_addr_adv_notif(fip_ns_name,
                                      interface_name,
                                      floating_ip)
        return lib_constants.FLOATINGIP_STATUS_ACTIVE

    def _add_floating_ip_rule(self, floating_ip, fixed_ip):
        rule_pr = self.fip_ns.allocate_rule_priority(floating_ip)
        self.floating_ips_dict[floating_ip] = (fixed_ip, rule_pr)

        ip_lib.add_ip_rule(namespace=self.ns_name, ip=fixed_ip,
                           table=dvr_fip_ns.FIP_RT_TBL,
                           priority=int(str(rule_pr)))

    def _remove_floating_ip_rule(self, floating_ip):
        if floating_ip in self.floating_ips_dict:
            fixed_ip, rule_pr = self.floating_ips_dict[floating_ip]
            ip_lib.delete_ip_rule(self.ns_name, ip=fixed_ip,
                                  table=dvr_fip_ns.FIP_RT_TBL,
                                  priority=int(str(rule_pr)))
            self.fip_ns.deallocate_rule_priority(floating_ip)
        else:
            LOG.error('Floating IP %s not stored in this agent. Because of '
                      'the initialization method '
                      '"_load_used_fip_information", all floating IPs should '
                      'be memoized in the local memory.', floating_ip)

    def floating_ip_removed_dist(self, fip_cidr):
        """Remove floating IP from FIP namespace."""
        centralized_fip_cidrs = self.get_centralized_fip_cidr_set()
        if fip_cidr in centralized_fip_cidrs:
            self.remove_centralized_floatingip(fip_cidr)
            return
        floating_ip = fip_cidr.split('/')[0]
        fip_2_rtr_name = self.fip_ns.get_int_device_name(self.router_id)
        if self.rtr_fip_subnet is None:
            self.rtr_fip_subnet = self.fip_ns.local_subnets.lookup(
                self.router_id)
        if self.rtr_fip_subnet:
            rtr_2_fip, fip_2_rtr = self.rtr_fip_subnet.get_pair()
            fip_ns_name = self.fip_ns.get_name()
            self._remove_floating_ip_rule(floating_ip)

            device = ip_lib.IPDevice(fip_2_rtr_name, namespace=fip_ns_name)

            device.route.delete_route(fip_cidr, via=str(rtr_2_fip.ip))
            return device

    def floating_ip_moved_dist(self, fip):
        """Handle floating IP move between fixed IPs."""
        floating_ip = fip['floating_ip_address']
        self._remove_floating_ip_rule(floating_ip)
        self._add_floating_ip_rule(floating_ip, fip['fixed_ip_address'])

    def add_floating_ip(self, fip, interface_name, device):
        # Special Handling for DVR - update FIP namespace
        ip_cidr = common_utils.ip_to_cidr(fip['floating_ip_address'])
        return self.floating_ip_added_dist(fip, ip_cidr)

    def remove_floating_ip(self, device, ip_cidr):
        fip_2_rtr_device = self.floating_ip_removed_dist(ip_cidr)
        if fip_2_rtr_device:
            fip_2_rtr_device.delete_conntrack_state(ip_cidr)

    def move_floating_ip(self, fip):
        self.floating_ip_moved_dist(fip)
        return lib_constants.FLOATINGIP_STATUS_ACTIVE

    def _get_internal_port(self, subnet_id):
        """Return internal router port based on subnet_id."""
        router_ports = self.router.get(lib_constants.INTERFACE_KEY, [])
        for port in router_ports:
            fips = port['fixed_ips']
            for f in fips:
                if f['subnet_id'] == subnet_id:
                    return port

    def _cache_arp_entry(self, ip, mac, subnet_id, operation):
        """Cache the arp entries if device not ready."""
        arp_entry_tuple = Arp_entry(ip=ip,
                                    mac=mac,
                                    subnet_id=subnet_id,
                                    operation=operation)
        self._pending_arp_set.add(arp_entry_tuple)

    def _process_arp_cache_for_internal_port(self, subnet_id):
        """Function to process the cached arp entries."""
        arp_remove = set()
        device, device_exists = self.get_arp_related_dev(subnet_id)
        for arp_entry in self._pending_arp_set:
            if subnet_id == arp_entry.subnet_id:
                try:
                    state = self._update_arp_entry(
                        arp_entry.ip, arp_entry.mac,
                        arp_entry.subnet_id, arp_entry.operation,
                        device=device,
                        device_exists=device_exists)
                except Exception:
                    state = False
                if state:
                    # If the arp update was successful, then
                    # go ahead and add it to the remove set
                    arp_remove.add(arp_entry)

        self._pending_arp_set -= arp_remove

    def _delete_arp_cache_for_internal_port(self, subnet_id):
        """Function to delete the cached arp entries."""
        arp_delete = set()
        for arp_entry in self._pending_arp_set:
            if subnet_id == arp_entry.subnet_id:
                arp_delete.add(arp_entry)
        self._pending_arp_set -= arp_delete

    def _update_arp_entry(
            self, ip, mac, subnet_id, operation, device,
            device_exists=True):
        """Add or delete arp entry into router namespace for the subnet."""

        try:
            if device_exists:
                if operation == 'add':
                    device.neigh.add(ip, mac)
                elif operation == 'delete':
                    device.neigh.delete(ip, mac)
                return True
            else:
                if operation == 'add':
                    LOG.warning("Device %s does not exist so ARP entry "
                                "cannot be updated, will cache "
                                "information to be applied later "
                                "when the device exists",
                                device)
                    self._cache_arp_entry(ip, mac, subnet_id, operation)
                return False
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception("DVR: Failed updating arp entry")

    def get_arp_related_dev(self, subnet_id):
        port = self._get_internal_port(subnet_id)
        # update arp entry only if the subnet is attached to the router
        if not port:
            return None, False
        interface_name = self.get_internal_device_name(port['id'])
        device = ip_lib.IPDevice(interface_name, namespace=self.ns_name)
        device_exists = device.exists()
        return device, device_exists

    def _set_subnet_arp_info(self, subnet):
        """Set ARP info retrieved from Plugin for existing ports."""
        # TODO(Carl) Can we eliminate the need to make this RPC while
        # processing a router.
        subnet_ports = self.agent.get_ports_by_subnet(subnet['id'])
        ignored_device_owners = (
            lib_constants.ROUTER_INTERFACE_OWNERS +
            tuple(common_utils.get_dvr_allowed_address_pair_device_owners()))
        device, device_exists = self.get_arp_related_dev(subnet['id'])

        subnet_ip_version = netaddr.IPNetwork(subnet['cidr']).version
        for p in subnet_ports:
            if p['device_owner'] not in ignored_device_owners:
                for fixed_ip in p['fixed_ips']:
                    if fixed_ip['subnet_id'] == subnet['id']:
                        self._update_arp_entry(fixed_ip['ip_address'],
                                               p['mac_address'],
                                               subnet['id'],
                                               'add',
                                               device=device,
                                               device_exists=device_exists)
                for allowed_address_pair in p.get('allowed_address_pairs', []):
                    if ('/' not in str(allowed_address_pair['ip_address']) or
                            common_utils.is_cidr_host(
                                allowed_address_pair['ip_address'])):
                        ip_address = common_utils.cidr_to_ip(
                            allowed_address_pair['ip_address'])
                        ip_version = common_utils.get_ip_version(ip_address)
                        if ip_version == subnet_ip_version:
                            self._update_arp_entry(
                                ip_address,
                                allowed_address_pair['mac_address'],
                                subnet['id'],
                                'add',
                                device=device,
                                device_exists=device_exists)

        # subnet_ports does not have snat port if the port is still unbound
        # by the time this function is called. So ensure to add arp entry
        # for snat port if port details are updated in router info.
        for p in self.get_snat_interfaces():
            for fixed_ip in p['fixed_ips']:
                if fixed_ip['subnet_id'] == subnet['id']:
                    self._update_arp_entry(fixed_ip['ip_address'],
                                           p['mac_address'],
                                           subnet['id'],
                                           'add',
                                           device=device,
                                           device_exists=device_exists)
        self._process_arp_cache_for_internal_port(subnet['id'])

    @staticmethod
    def _get_snat_idx(ip_cidr):
        """Generate index for DVR snat rules and route tables.

        The index value has to be 32 bits or less but more than the system
        generated entries i.e. 32768. For IPv4 use the numeric value of the
        cidr. For IPv6 generate a crc32 bit hash and xor-fold to 30 bits.
        Use the freed range to extend smaller values so that they become
        greater than system generated entries.
        """
        net = netaddr.IPNetwork(ip_cidr)
        if net.version == 6:
            if isinstance(ip_cidr, str):
                ip_cidr = ip_cidr.encode()  # Needed for Python 3.x
            # the crc32 & 0xffffffff is for Python 2.6 and 3.0 compatibility
            snat_idx = binascii.crc32(ip_cidr) & 0xffffffff
            # xor-fold the hash to reserve upper range to extend smaller values
            snat_idx = (snat_idx >> 30) ^ (snat_idx & MASK_30)
            if snat_idx < 32768:
                snat_idx = snat_idx + MASK_30
        else:
            snat_idx = net.value
        return snat_idx

    def _delete_gateway_device_if_exists(self, ns_ip_device, gw_ip_addr,
                                         snat_idx):
        try:
            ns_ip_device.route.delete_gateway(gw_ip_addr, table=snat_idx)
        except priv_ip_lib.NetworkInterfaceNotFound:
            pass

    def _stale_ip_rule_cleanup(self, namespace, ns_ipd, ip_version):
        ip_rules_list = ip_lib.list_ip_rules(namespace, ip_version)
        snat_table_list = []
        for ip_rule in ip_rules_list:
            snat_table = ip_rule['table']
            priority = ip_rule['priority']
            if snat_table in ['local', 'default', 'main']:
                continue
            if (ip_version == lib_constants.IP_VERSION_4 and
                snat_table in range(dvr_fip_ns.FIP_PR_START,
                                    dvr_fip_ns.FIP_PR_END)):
                continue
            gateway_cidr = ip_rule['from']
            ip_lib.delete_ip_rule(namespace, ip=gateway_cidr, table=snat_table,
                                  priority=priority)
            snat_table_list.append(snat_table)
        for tb in snat_table_list:
            ns_ipd.route.flush(ip_version, table=tb)

    def gateway_redirect_cleanup(self, rtr_interface):
        ns_ipd = ip_lib.IPDevice(rtr_interface, namespace=self.ns_name)
        self._stale_ip_rule_cleanup(self.ns_name, ns_ipd,
                                    lib_constants.IP_VERSION_4)
        self._stale_ip_rule_cleanup(self.ns_name, ns_ipd,
                                    lib_constants.IP_VERSION_6)

    def _snat_redirect_modify(self, gateway, sn_port, sn_int, is_add):
        """Adds or removes rules and routes for SNAT redirection."""
        cmd = ['net.ipv4.conf.%s.send_redirects=0' % sn_int]
        try:
            ns_ipd = ip_lib.IPDevice(sn_int, namespace=self.ns_name)
            for port_fixed_ip in sn_port['fixed_ips']:
                # Iterate and find the gateway IP address matching
                # the IP version
                port_ip_addr = port_fixed_ip['ip_address']
                port_ip_vers = netaddr.IPAddress(port_ip_addr).version
                for gw_fixed_ip in gateway['fixed_ips']:
                    gw_ip_addr = gw_fixed_ip['ip_address']
                    if netaddr.IPAddress(gw_ip_addr).version == port_ip_vers:
                        sn_port_cidr = common_utils.ip_to_cidr(
                            port_ip_addr, port_fixed_ip['prefixlen'])
                        snat_idx = self._get_snat_idx(sn_port_cidr)
                        if is_add:
                            ns_ipd.route.add_gateway(gw_ip_addr,
                                                     table=snat_idx)
                            ip_lib.add_ip_rule(namespace=self.ns_name,
                                               ip=sn_port_cidr,
                                               table=snat_idx,
                                               priority=snat_idx)
                            ip_lib.sysctl(cmd, namespace=self.ns_name)
                        else:
                            self._delete_gateway_device_if_exists(ns_ipd,
                                                                  gw_ip_addr,
                                                                  snat_idx)
                            ip_lib.delete_ip_rule(self.ns_name,
                                                  ip=sn_port_cidr,
                                                  table=snat_idx,
                                                  priority=snat_idx)
        except Exception:
            if is_add:
                exc = 'DVR: error adding redirection logic'
            else:
                exc = ('DVR: snat remove failed to clear the rule '
                       'and device')
            LOG.exception(exc)

    def _snat_redirect_add(self, gateway, sn_port, sn_int):
        """Adds rules and routes for SNAT redirection."""
        self._snat_redirect_modify(gateway, sn_port, sn_int, is_add=True)

    def _snat_redirect_remove(self, gateway, sn_port, sn_int):
        """Removes rules and routes for SNAT redirection."""
        self._snat_redirect_modify(gateway, sn_port, sn_int, is_add=False)

    def internal_network_added(self, port):
        super(DvrLocalRouter, self).internal_network_added(port)

        # NOTE: The following function _set_subnet_arp_info
        # should be called to dynamically populate the arp
        # entries for the dvr services ports into the router
        # namespace. This does not have dependency on the
        # external_gateway port or the agent_mode.
        ex_gw_port = self.get_ex_gw_port()
        for subnet in port['subnets']:
            self._set_subnet_arp_info(subnet)
            if ex_gw_port:
                # Check for address_scopes here if gateway exists.
                address_scopes_match = self._check_if_address_scopes_match(
                    port, ex_gw_port)
                if (address_scopes_match and
                    (self.agent_conf.agent_mode in
                        [lib_constants.L3_AGENT_MODE_DVR,
                         lib_constants.L3_AGENT_MODE_DVR_SNAT])):
                    self._add_interface_routing_rule_to_router_ns(port)
                    self._add_interface_route_to_fip_ns(port)
        self._snat_redirect_add_from_port(port)

    def _snat_redirect_add_from_port(self, port):
        ex_gw_port = self.get_ex_gw_port()
        if not ex_gw_port:
            return
        address_scopes_match = self._check_if_address_scopes_match(
            port, ex_gw_port)
        if (address_scopes_match and
            (self.agent_conf.agent_mode in
                [lib_constants.L3_AGENT_MODE_DVR,
                 lib_constants.L3_AGENT_MODE_DVR_SNAT])):
            return
        sn_port = self.get_snat_port_for_internal_port(port)
        if not sn_port:
            return

        interface_name = self.get_internal_device_name(port['id'])
        self._snat_redirect_add(sn_port, port, interface_name)

    def _dvr_internal_network_removed(self, port):
        # Clean up the cached arp entries related to the port subnet
        for subnet in port['subnets']:
            self._delete_arp_cache_for_internal_port(subnet)

        if not self.ex_gw_port:
            return

        # Delete DVR address_scope static route for the removed interface
        # Check for address_scopes here.
        address_scopes_match = self._check_if_address_scopes_match(
            port, self.ex_gw_port)
        if (address_scopes_match and
            (self.agent_conf.agent_mode in
                [lib_constants.L3_AGENT_MODE_DVR,
                 lib_constants.L3_AGENT_MODE_DVR_SNAT])):
            self._delete_interface_route_in_fip_ns(port)
            self._delete_interface_routing_rule_in_router_ns(port)
            # If address scopes match there is no need to cleanup the
            # snat redirect rules, hence return here.
            return
        sn_port = self.get_snat_port_for_internal_port(port, self.snat_ports)
        if not sn_port:
            return

        # DVR handling code for SNAT
        interface_name = self.get_internal_device_name(port['id'])
        self._snat_redirect_remove(sn_port, port, interface_name)

    def internal_network_removed(self, port):
        self._dvr_internal_network_removed(port)
        super(DvrLocalRouter, self).internal_network_removed(port)

    def get_floating_agent_gw_interface(self, ext_net_id):
        """Filter Floating Agent GW port for the external network."""
        fip_ports = self.router.get(
            lib_constants.FLOATINGIP_AGENT_INTF_KEY, [])
        return next(
            (p for p in fip_ports if p['network_id'] == ext_net_id), None)

    def get_snat_external_device_interface_name(self, port_id):
        pass

    def get_external_device_interface_name(self, ex_gw_port):
        fip_int = self.fip_ns.get_int_device_name(self.router_id)
        if ip_lib.device_exists(fip_int, namespace=self.fip_ns.get_name()):
            return self.fip_ns.get_rtr_ext_device_name(self.router_id)

    def enable_snat_redirect_rules(self, ex_gw_port):
        for p in self.internal_ports:
            gateway = self.get_snat_port_for_internal_port(p)
            if not gateway:
                continue
            address_scopes_match = self._check_if_address_scopes_match(
                p, ex_gw_port)
            if (not address_scopes_match or
                (self.agent_conf.agent_mode ==
                    lib_constants.L3_AGENT_MODE_DVR_NO_EXTERNAL)):
                internal_dev = self.get_internal_device_name(p['id'])
                self._snat_redirect_add(gateway, p, internal_dev)

    def disable_snat_redirect_rules(self, ex_gw_port):
        for p in self.internal_ports:
            gateway = self.get_snat_port_for_internal_port(
                p, self.snat_ports)
            if not gateway:
                continue
            address_scopes_match = self._check_if_address_scopes_match(
                p, ex_gw_port)
            if (not address_scopes_match or
                (self.agent_conf.agent_mode ==
                    lib_constants.L3_AGENT_MODE_DVR_NO_EXTERNAL)):
                internal_dev = self.get_internal_device_name(p['id'])
                self._snat_redirect_remove(gateway, p, internal_dev)

    def external_gateway_added(self, ex_gw_port, interface_name):
        # TODO(Carl) Refactor external_gateway_added/updated/removed to use
        # super class implementation where possible.  Looks like preserve_ips,
        # and ns_name are the key differences.
        cmd = ['net.ipv4.conf.all.send_redirects=0']
        ip_lib.sysctl(cmd, namespace=self.ns_name)

        self.enable_snat_redirect_rules(ex_gw_port)
        for port in self.get_snat_interfaces():
            for ip in port['fixed_ips']:
                subnet_id = ip['subnet_id']
                device, device_exists = self.get_arp_related_dev(subnet_id)
                self._update_arp_entry(ip['ip_address'],
                                       port['mac_address'],
                                       subnet_id,
                                       'add',
                                       device=device,
                                       device_exists=device_exists)

    def external_gateway_updated(self, ex_gw_port, interface_name):
        pass

    def process_floating_ip_nat_rules(self):
        """Configure NAT rules for the router's floating IPs.

        Configures iptables rules for the floating ips of the given router
        """
        # Clear out all iptables rules for floating ips
        self.iptables_manager.ipv4['nat'].clear_rules_by_tag('floating_ip')

        floating_ips = self.get_floating_ips()
        # Loop once to ensure that floating ips are configured.
        for fip in floating_ips:
            # If floating IP is snat_bound, then the iptables rule should
            # not be installed to qrouter namespace, since the mixed snat
            # namespace may already install it.
            if fip.get(lib_constants.DVR_SNAT_BOUND):
                continue
            # Rebuild iptables rules for the floating ip.
            for chain, rule in self.floating_forward_rules(fip):
                self.iptables_manager.ipv4['nat'].add_rule(
                    chain, rule, tag='floating_ip')

        self.iptables_manager.apply()

    def external_gateway_removed(self, ex_gw_port, interface_name):
        # TODO(Carl) Should this be calling process_snat_dnat_for_fip?
        self.process_floating_ip_nat_rules()
        if self.fip_ns:
            to_fip_interface_name = (
                self.get_external_device_interface_name(ex_gw_port))
            self.process_floating_ip_addresses(to_fip_interface_name)
            # Remove the router to fip namespace connection after the
            # gateway is removed.
            self.fip_ns.delete_rtr_2_fip_link(self)
            self.rtr_fip_connect = False
        # NOTE:_snat_redirect_remove should be only called when the
        # gateway is cleared and should not be called when the gateway
        # is moved or rescheduled.
        if not self.router.get('gw_port'):
            self.disable_snat_redirect_rules(ex_gw_port)

    def _handle_router_snat_rules(self, ex_gw_port, interface_name):
        """Configures NAT rules for Floating IPs for DVR."""

        self.iptables_manager.ipv4['nat'].empty_chain('POSTROUTING')
        self.iptables_manager.ipv4['nat'].empty_chain('snat')

        ex_gw_port = self.get_ex_gw_port()
        if not ex_gw_port:
            return

        ext_device_name = self.get_external_device_interface_name(ex_gw_port)
        floatingips = self.get_floating_ips()
        if not ext_device_name or not floatingips:
            # Without router to fip device, or without any floating ip,
            # the snat rules should not be added
            return

        # Add back the jump to float-snat
        self.iptables_manager.ipv4['nat'].add_rule('snat', '-j $float-snat')

        rule = self._prevent_snat_for_internal_traffic_rule(ext_device_name)
        self.iptables_manager.ipv4['nat'].add_rule(*rule)

    def _get_address_scope_mark(self):
        # Prepare address scope iptables rule for internal ports
        internal_ports = self.router.get(lib_constants.INTERFACE_KEY, [])
        ports_scopemark = self._get_port_devicename_scopemark(
            internal_ports, self.get_internal_device_name)
        # DVR local router will use rfp port as external port
        ext_port = self.get_ex_gw_port()
        if not ext_port:
            return ports_scopemark

        ext_device_name = self.get_external_device_interface_name(ext_port)
        if not ext_device_name:
            return ports_scopemark

        ext_scope_mark = self._get_port_devicename_scopemark(
                [ext_port], self.get_internal_device_name,
                interface_name=ext_device_name)
        for ip_version in (lib_constants.IP_VERSION_4,
                           lib_constants.IP_VERSION_6):
            ports_scopemark[ip_version].update(
                ext_scope_mark[ip_version])
        return ports_scopemark

    def _check_if_floatingip_bound_to_host(self, fip):
        """Check if the floating IP is bound to this host."""
        return self.host in (fip.get('host'), fip.get('dest_host'))

    def process_external(self):
        if self.agent_conf.agent_mode != (
                lib_constants.L3_AGENT_MODE_DVR_NO_EXTERNAL):
            ex_gw_port = self.get_ex_gw_port()
            if ex_gw_port:
                self.create_dvr_external_gateway_on_agent(ex_gw_port)
                self.connect_rtr_2_fip()
        super(DvrLocalRouter, self).process_external()

    def _check_rtr_2_fip_connect(self):
        """Checks if the rtr to fip connect exists, if not sets to false."""
        fip_ns_name = self.fip_ns.get_name()
        if ip_lib.network_namespace_exists(fip_ns_name):
            fip_2_rtr_name = self.fip_ns.get_int_device_name(self.router_id)
            if not ip_lib.device_exists(fip_2_rtr_name, namespace=fip_ns_name):
                self.rtr_fip_connect = False

    def connect_rtr_2_fip(self):
        self._check_rtr_2_fip_connect()
        if self.fip_ns.agent_gateway_port and not self.rtr_fip_connect:
            ex_gw_port = self.get_ex_gw_port()
            self.fip_ns.create_rtr_2_fip_link(self)
            self.set_address_scope_interface_routes(ex_gw_port)
            self.rtr_fip_connect = True
            self.routes_updated([], self.router['routes'])

    def _check_if_address_scopes_match(self, int_port, ex_gw_port):
        """Checks and returns the matching state for v4 or v6 scopes."""
        int_port_addr_scopes = int_port.get('address_scopes', {})
        ext_port_addr_scopes = ex_gw_port.get('address_scopes', {})
        key = (
            lib_constants.IP_VERSION_6 if self._port_has_ipv6_subnet(int_port)
            else lib_constants.IP_VERSION_4)
        # NOTE: DVR does not support IPv6 for the floating namespace yet, so
        # until we fix it, we probably should use the snat redirect path for
        # the ports that have IPv6 address configured.
        int_port_addr_value = int_port_addr_scopes.get(str(key))
        # If the address scope of the interface is none, then don't need
        # to compare and just return.
        if int_port_addr_value is None:
            return False
        if ((key != lib_constants.IP_VERSION_6) and
                int_port_addr_scopes.get(str(key)) in
                ext_port_addr_scopes.values()):
            return True
        return False

    def _delete_interface_route_in_fip_ns(self, router_port):
        rtr_2_fip_ip, fip_2_rtr_name = self.get_rtr_fip_ip_and_interface_name()
        fip_ns_name = self.fip_ns.get_name()
        if ip_lib.network_namespace_exists(fip_ns_name):
            device = ip_lib.IPDevice(fip_2_rtr_name, namespace=fip_ns_name)
            if not device.exists():
                return
            for subnet in router_port['subnets']:
                rtr_port_cidr = subnet['cidr']
                device.route.delete_route(rtr_port_cidr, via=str(rtr_2_fip_ip))

    def _add_interface_route_to_fip_ns(self, router_port):
        rtr_2_fip_ip, fip_2_rtr_name = self.get_rtr_fip_ip_and_interface_name()
        fip_ns_name = self.fip_ns.get_name()
        if ip_lib.network_namespace_exists(fip_ns_name):
            device = ip_lib.IPDevice(fip_2_rtr_name, namespace=fip_ns_name)
            if not device.exists():
                return
            for subnet in router_port['subnets']:
                rtr_port_cidr = subnet['cidr']
                device.route.add_route(rtr_port_cidr, str(rtr_2_fip_ip))

    def _add_interface_routing_rule_to_router_ns(self, router_port):
        for subnet in router_port['subnets']:
            rtr_port_cidr = subnet['cidr']
            ip_lib.add_ip_rule(namespace=self.ns_name, ip=rtr_port_cidr,
                               table=dvr_fip_ns.FIP_RT_TBL,
                               priority=dvr_fip_ns.FAST_PATH_EXIT_PR)

    def _delete_interface_routing_rule_in_router_ns(self, router_port):
        for subnet in router_port['subnets']:
            rtr_port_cidr = subnet['cidr']
            ip_lib.delete_ip_rule(self.ns_name, ip=rtr_port_cidr,
                                  table=dvr_fip_ns.FIP_RT_TBL,
                                  priority=dvr_fip_ns.FAST_PATH_EXIT_PR)

    def get_rtr_fip_ip_and_interface_name(self):
        """Function that returns the router to fip interface name and ip."""
        if self.rtr_fip_subnet is None:
            self.rtr_fip_subnet = self.fip_ns.local_subnets.allocate(
                self.router_id)
        rtr_2_fip, __ = self.rtr_fip_subnet.get_pair()
        fip_2_rtr_name = self.fip_ns.get_int_device_name(self.router_id)
        return rtr_2_fip.ip, fip_2_rtr_name

    def set_address_scope_interface_routes(self, ex_gw_port):
        """Sets routing rules for router interfaces if addr scopes match."""
        for port in self.internal_ports:
            if self._check_if_address_scopes_match(port, ex_gw_port):
                self._add_interface_routing_rule_to_router_ns(port)
                self._add_interface_route_to_fip_ns(port)

    def create_dvr_external_gateway_on_agent(self, ex_gw_port):
        fip_agent_port = self.get_floating_agent_gw_interface(
            ex_gw_port['network_id'])
        if not fip_agent_port:
            fip_agent_port = self.agent.plugin_rpc.get_agent_gateway_port(
                self.agent.context, ex_gw_port['network_id'])
            LOG.debug("FloatingIP agent gateway port received from the "
                      "plugin: %s", fip_agent_port)
        self.fip_ns.create_or_update_gateway_port(fip_agent_port)

    def update_routing_table(self, operation, route):
        # TODO(Swami): The static routes should be added to the
        # specific namespace based on the availability of the
        # network interfaces. In the case of DVR the static routes
        # for local internal router networks can be added to the
        # snat_namespace and router_namespace but should not be
        # added to the fip namespace. Likewise the static routes
        # for the external router networks should only be added to
        # the snat_namespace and fip_namespace.
        # The current code adds static routes to all namespaces in
        # order to reduce the complexity. This should be revisited
        # later.
        if self.fip_ns and self.fip_ns.agent_gateway_port:
            fip_ns_name = self.fip_ns.get_name()
            agent_gw_port = self.fip_ns.agent_gateway_port
            route_apply = self._check_if_route_applicable_to_fip_namespace(
                route, agent_gw_port)
            if route_apply:
                if self.rtr_fip_subnet is None:
                    self.rtr_fip_subnet = self.fip_ns.local_subnets.allocate(
                        self.router_id)
                rtr_2_fip, fip_2_rtr = self.rtr_fip_subnet.get_pair()
                tbl_index = self._get_snat_idx(fip_2_rtr)
                self._update_fip_route_table_with_next_hop_routes(
                    operation, route, fip_ns_name, tbl_index)
        super(DvrLocalRouter, self).update_routing_table(operation, route)

    def _update_fip_route_table_with_next_hop_routes(self, operation, route,
                                                     fip_ns_name, tbl_index):
        cmd = (ip_lib.add_ip_route if operation == 'replace' else
               ip_lib.delete_ip_route)
        try:
            cmd(fip_ns_name, route['destination'], via=route['nexthop'],
                table=tbl_index, proto='boot')
        except priv_ip_lib.NetworkNamespaceNotFound:
            LOG.debug("The FIP namespace %(ns)s does not exist for "
                      "router %(id)s",
                      {'ns': fip_ns_name, 'id': self.router_id})
        except (OSError, pyroute2_exc.NetlinkError):
            pass

    def _check_if_route_applicable_to_fip_namespace(self, route,
                                                    agent_gateway_port):
        ip_cidrs = common_utils.fixed_ip_cidrs(agent_gateway_port['fixed_ips'])
        nexthop_cidr = netaddr.IPAddress(route['nexthop'])
        for gw_cidr in ip_cidrs:
            gw_subnet_cidr = netaddr.IPNetwork(gw_cidr)
            # NOTE: In the case of DVR routers apply the extra routes
            # on the FIP namespace only if it is associated with the
            # external agent gateway subnets.
            if nexthop_cidr in gw_subnet_cidr:
                return True
        return False

    def get_router_cidrs(self, device):
        """As no floatingip will be set on the rfp device. Get floatingip from
        the route of fip namespace.
        """
        if not self.fip_ns:
            return set()

        fip_ns_name = self.fip_ns.get_name()
        fip_2_rtr_name = self.fip_ns.get_int_device_name(self.router_id)
        device = ip_lib.IPDevice(fip_2_rtr_name, namespace=fip_ns_name)
        if not device.exists():
            return set()

        if self.rtr_fip_subnet is None:
            self.rtr_fip_subnet = self.fip_ns.local_subnets.allocate(
                self.router_id)
        rtr_2_fip, _fip_2_rtr = self.rtr_fip_subnet.get_pair()
        exist_routes = device.route.list_routes(
            lib_constants.IP_VERSION_4, via=str(rtr_2_fip.ip))
        return {common_utils.ip_to_cidr(route['cidr'])
                for route in exist_routes}

    def process(self):
        ex_gw_port = self.get_ex_gw_port()
        if ex_gw_port:
            self.fip_ns = self.agent.get_fip_ns(ex_gw_port['network_id'])
            self.fip_ns.scan_fip_ports(self)

        super(DvrLocalRouter, self).process()
