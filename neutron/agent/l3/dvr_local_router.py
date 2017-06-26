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
from neutron_lib import exceptions
from oslo_log import log as logging
from oslo_utils import excutils
import six

from neutron._i18n import _LE, _LW
from neutron.agent.l3 import dvr_fip_ns
from neutron.agent.l3 import dvr_router_base
from neutron.agent.linux import ip_lib
from neutron.common import constants as n_const
from neutron.common import utils as common_utils

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
        self.dist_fip_count = None
        self.fip_ns = None
        self._pending_arp_set = set()

    def get_floating_ips(self):
        """Filter Floating IPs to be hosted on this agent."""
        floating_ips = super(DvrLocalRouter, self).get_floating_ips()
        return [i for i in floating_ips if (
                   (i['host'] == self.host) or
                   (i.get('dest_host') == self.host))]

    def floating_forward_rules(self, floating_ip, fixed_ip):
        """Override this function defined in router_info for dvr routers."""
        if not self.fip_ns:
            return []

        rtr_2_fip_name = self.fip_ns.get_rtr_ext_device_name(self.router_id)
        dnat_from_floatingip_to_fixedip = (
            'PREROUTING', '-d %s/32 -i %s -j DNAT --to-destination %s' % (
                floating_ip, rtr_2_fip_name, fixed_ip))
        snat_from_fixedip_to_floatingip = (
            'float-snat', '-s %s/32 -j SNAT --to-source %s' % (
                fixed_ip, floating_ip))
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

    def floating_ip_added_dist(self, fip, fip_cidr):
        """Add floating IP to FIP namespace."""
        floating_ip = fip['floating_ip_address']
        fixed_ip = fip['fixed_ip_address']
        self._add_floating_ip_rule(floating_ip, fixed_ip)
        fip_2_rtr_name = self.fip_ns.get_int_device_name(self.router_id)
        #Add routing rule in fip namespace
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
                                      floating_ip,
                                      self.agent_conf.send_arp_for_ha)
        # update internal structures
        self.dist_fip_count = self.dist_fip_count + 1

    def _add_floating_ip_rule(self, floating_ip, fixed_ip):
        rule_pr = self.fip_ns.allocate_rule_priority(floating_ip)
        self.floating_ips_dict[floating_ip] = rule_pr
        ip_rule = ip_lib.IPRule(namespace=self.ns_name)
        ip_rule.rule.add(ip=fixed_ip,
                         table=dvr_fip_ns.FIP_RT_TBL,
                         priority=rule_pr)

    def _remove_floating_ip_rule(self, floating_ip):
        if floating_ip in self.floating_ips_dict:
            rule_pr = self.floating_ips_dict[floating_ip]
            ip_rule = ip_lib.IPRule(namespace=self.ns_name)
            ip_rule.rule.delete(ip=floating_ip,
                                table=dvr_fip_ns.FIP_RT_TBL,
                                priority=rule_pr)
            self.fip_ns.deallocate_rule_priority(floating_ip)
            #TODO(rajeev): Handle else case - exception/log?

    def floating_ip_removed_dist(self, fip_cidr):
        """Remove floating IP from FIP namespace."""
        floating_ip = fip_cidr.split('/')[0]
        rtr_2_fip_name = self.fip_ns.get_rtr_ext_device_name(self.router_id)
        fip_2_rtr_name = self.fip_ns.get_int_device_name(self.router_id)
        if self.rtr_fip_subnet is None:
            self.rtr_fip_subnet = self.fip_ns.local_subnets.allocate(
                self.router_id)

        rtr_2_fip, fip_2_rtr = self.rtr_fip_subnet.get_pair()
        fip_ns_name = self.fip_ns.get_name()
        self._remove_floating_ip_rule(floating_ip)

        device = ip_lib.IPDevice(fip_2_rtr_name, namespace=fip_ns_name)

        device.route.delete_route(fip_cidr, str(rtr_2_fip.ip))
        # check if this is the last FIP for this router
        self.dist_fip_count = self.dist_fip_count - 1
        if self.dist_fip_count == 0:
            #remove default route entry
            device = ip_lib.IPDevice(rtr_2_fip_name, namespace=self.ns_name)
            ns_ip = ip_lib.IPWrapper(namespace=fip_ns_name)
            device.route.delete_gateway(str(fip_2_rtr.ip),
                                        table=dvr_fip_ns.FIP_RT_TBL)
            if self.fip_ns.agent_gateway_port:
                interface_name = self.fip_ns.get_ext_device_name(
                    self.fip_ns.agent_gateway_port['id'])
                fg_device = ip_lib.IPDevice(
                    interface_name, namespace=fip_ns_name)
                if fg_device.exists():
                    # Remove the fip namespace rules and routes associated to
                    # fpr interface route table.
                    tbl_index = self._get_snat_idx(fip_2_rtr)
                    fip_rt_rule = ip_lib.IPRule(namespace=fip_ns_name)
                    # Flush the table
                    fg_device.route.flush(lib_constants.IP_VERSION_4,
                                          table=tbl_index)
                    fg_device.route.flush(lib_constants.IP_VERSION_6,
                                          table=tbl_index)
                    # Remove the rule lookup
                    # IP is ignored in delete, but we still require it
                    # for getting the ip_version.
                    fip_rt_rule.rule.delete(ip=fip_2_rtr.ip,
                                            iif=fip_2_rtr_name,
                                            table=tbl_index,
                                            priority=tbl_index)
            self.fip_ns.local_subnets.release(self.router_id)
            self.rtr_fip_subnet = None
            ns_ip.del_veth(fip_2_rtr_name)

    def floating_ip_moved_dist(self, fip):
        """Handle floating IP move between fixed IPs."""
        floating_ip = fip['floating_ip_address']
        self._remove_floating_ip_rule(floating_ip)
        self._add_floating_ip_rule(floating_ip, fip['fixed_ip_address'])

    def add_floating_ip(self, fip, interface_name, device):
        # Special Handling for DVR - update FIP namespace
        ip_cidr = common_utils.ip_to_cidr(fip['floating_ip_address'])
        self.floating_ip_added_dist(fip, ip_cidr)
        return lib_constants.FLOATINGIP_STATUS_ACTIVE

    def remove_floating_ip(self, device, ip_cidr):
        self.floating_ip_removed_dist(ip_cidr)

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
        for arp_entry in self._pending_arp_set:
            if subnet_id == arp_entry.subnet_id:
                try:
                    state = self._update_arp_entry(
                        arp_entry.ip, arp_entry.mac,
                        arp_entry.subnet_id, arp_entry.operation)
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

    def _update_arp_entry(self, ip, mac, subnet_id, operation):
        """Add or delete arp entry into router namespace for the subnet."""
        port = self._get_internal_port(subnet_id)
        # update arp entry only if the subnet is attached to the router
        if not port:
            return False

        try:
            # TODO(mrsmith): optimize the calls below for bulk calls
            interface_name = self.get_internal_device_name(port['id'])
            device = ip_lib.IPDevice(interface_name, namespace=self.ns_name)
            if device.exists():
                if operation == 'add':
                    device.neigh.add(ip, mac)
                elif operation == 'delete':
                    device.neigh.delete(ip, mac)
                return True
            else:
                if operation == 'add':
                    LOG.warning(_LW("Device %s does not exist so ARP entry "
                                    "cannot be updated, will cache "
                                    "information to be applied later "
                                    "when the device exists"),
                                device)
                    self._cache_arp_entry(ip, mac, subnet_id, operation)
                return False
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("DVR: Failed updating arp entry"))

    def _set_subnet_arp_info(self, subnet_id):
        """Set ARP info retrieved from Plugin for existing ports."""
        # TODO(Carl) Can we eliminate the need to make this RPC while
        # processing a router.
        subnet_ports = self.agent.get_ports_by_subnet(subnet_id)

        for p in subnet_ports:
            if p['device_owner'] not in lib_constants.ROUTER_INTERFACE_OWNERS:
                for fixed_ip in p['fixed_ips']:
                    self._update_arp_entry(fixed_ip['ip_address'],
                                           p['mac_address'],
                                           subnet_id,
                                           'add')
        self._process_arp_cache_for_internal_port(subnet_id)

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
            if isinstance(ip_cidr, six.text_type):
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
            ns_ip_device.route.delete_gateway(gw_ip_addr,
                                        table=snat_idx)
        except exceptions.DeviceNotFoundError:
            pass

    def _stale_ip_rule_cleanup(self, ns_ipr, ns_ipd, ip_version):
        ip_rules_list = ns_ipr.rule.list_rules(ip_version)
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
            ns_ipr.rule.delete(ip=gateway_cidr,
                               table=snat_table,
                               priority=priority)
            snat_table_list.append(snat_table)
        for tb in snat_table_list:
            ns_ipd.route.flush(ip_version, table=tb)

    def gateway_redirect_cleanup(self, rtr_interface):
        ns_ipr = ip_lib.IPRule(namespace=self.ns_name)
        ns_ipd = ip_lib.IPDevice(rtr_interface, namespace=self.ns_name)
        self._stale_ip_rule_cleanup(ns_ipr, ns_ipd, lib_constants.IP_VERSION_4)
        self._stale_ip_rule_cleanup(ns_ipr, ns_ipd, lib_constants.IP_VERSION_6)

    def _snat_redirect_modify(self, gateway, sn_port, sn_int, is_add):
        """Adds or removes rules and routes for SNAT redirection."""
        cmd = ['net.ipv4.conf.%s.send_redirects=0' % sn_int]
        try:
            ns_ipr = ip_lib.IPRule(namespace=self.ns_name)
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
                            ns_ipr.rule.add(ip=sn_port_cidr,
                                            table=snat_idx,
                                            priority=snat_idx)
                            ip_lib.sysctl(cmd, namespace=self.ns_name)
                        else:
                            self._delete_gateway_device_if_exists(ns_ipd,
                                                                  gw_ip_addr,
                                                                  snat_idx)
                            ns_ipr.rule.delete(ip=sn_port_cidr,
                                               table=snat_idx,
                                               priority=snat_idx)
        except Exception:
            if is_add:
                exc = _LE('DVR: error adding redirection logic')
            else:
                exc = _LE('DVR: snat remove failed to clear the rule '
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
        for subnet in port['subnets']:
            self._set_subnet_arp_info(subnet['id'])
        self._snat_redirect_add_from_port(port)

    def _snat_redirect_add_from_port(self, port):
        ex_gw_port = self.get_ex_gw_port()
        if not ex_gw_port:
            return

        sn_port = self.get_snat_port_for_internal_port(port)
        if not sn_port:
            return

        interface_name = self.get_internal_device_name(port['id'])
        self._snat_redirect_add(sn_port, port, interface_name)

    def _dvr_internal_network_removed(self, port):
        if not self.ex_gw_port:
            return

        sn_port = self.get_snat_port_for_internal_port(port, self.snat_ports)
        if not sn_port:
            return

        # DVR handling code for SNAT
        interface_name = self.get_internal_device_name(port['id'])
        self._snat_redirect_remove(sn_port, port, interface_name)
        # Clean up the cached arp entries related to the port subnet
        for subnet in port['subnets']:
            self._delete_arp_cache_for_internal_port(subnet)

    def internal_network_removed(self, port):
        self._dvr_internal_network_removed(port)
        super(DvrLocalRouter, self).internal_network_removed(port)

    def get_floating_agent_gw_interface(self, ext_net_id):
        """Filter Floating Agent GW port for the external network."""
        fip_ports = self.router.get(n_const.FLOATINGIP_AGENT_INTF_KEY, [])
        return next(
            (p for p in fip_ports if p['network_id'] == ext_net_id), None)

    def get_external_device_interface_name(self, ex_gw_port):
        fip_int = self.fip_ns.get_int_device_name(self.router_id)
        if ip_lib.device_exists(fip_int, namespace=self.fip_ns.get_name()):
            return self.fip_ns.get_rtr_ext_device_name(self.router_id)

    def external_gateway_added(self, ex_gw_port, interface_name):
        # TODO(Carl) Refactor external_gateway_added/updated/removed to use
        # super class implementation where possible.  Looks like preserve_ips,
        # and ns_name are the key differences.
        cmd = ['net.ipv4.conf.all.send_redirects=0']
        ip_lib.sysctl(cmd, namespace=self.ns_name)
        for p in self.internal_ports:
            gateway = self.get_snat_port_for_internal_port(p)
            id_name = self.get_internal_device_name(p['id'])
            if gateway:
                self._snat_redirect_add(gateway, p, id_name)

        for port in self.get_snat_interfaces():
            for ip in port['fixed_ips']:
                self._update_arp_entry(ip['ip_address'],
                                       port['mac_address'],
                                       ip['subnet_id'],
                                       'add')

    def external_gateway_updated(self, ex_gw_port, interface_name):
        pass

    def external_gateway_removed(self, ex_gw_port, interface_name):
        # TODO(Carl) Should this be calling process_snat_dnat_for_fip?
        self.process_floating_ip_nat_rules()
        if self.fip_ns:
            to_fip_interface_name = (
                self.get_external_device_interface_name(ex_gw_port))
            self.process_floating_ip_addresses(to_fip_interface_name)
        # NOTE:_snat_redirect_remove should be only called when the
        # gateway is cleared and should not be called when the gateway
        # is moved or rescheduled.
        if not self.router.get('gw_port'):
            for p in self.internal_ports:
                # NOTE: When removing the gateway port, pass in the snat_port
                # cache along with the current ports.
                gateway = self.get_snat_port_for_internal_port(
                    p, self.snat_ports)
                if not gateway:
                    continue
                internal_interface = self.get_internal_device_name(p['id'])
                self._snat_redirect_remove(gateway, p, internal_interface)

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

        ext_scope = self._get_external_address_scope()
        ext_scope_mark = self.get_address_scope_mark_mask(ext_scope)
        ports_scopemark[lib_constants.IP_VERSION_4][ext_device_name] = (
            ext_scope_mark)
        return ports_scopemark

    def process_external(self):
        ex_gw_port = self.get_ex_gw_port()
        if ex_gw_port:
            self.create_dvr_fip_interfaces(ex_gw_port)
        super(DvrLocalRouter, self).process_external()

    def create_dvr_fip_interfaces(self, ex_gw_port):
        floating_ips = self.get_floating_ips()
        fip_agent_port = self.get_floating_agent_gw_interface(
            ex_gw_port['network_id'])
        if fip_agent_port:
            LOG.debug("FloatingIP agent gateway port received from the "
                "plugin: %s", fip_agent_port)
        if floating_ips:
            if not fip_agent_port:
                LOG.debug("No FloatingIP agent gateway port possibly due to "
                          "late binding of the private port to the host, "
                          "requesting agent gateway port for 'network-id' :"
                          "%s", ex_gw_port['network_id'])
                fip_agent_port = self.agent.plugin_rpc.get_agent_gateway_port(
                    self.agent.context, ex_gw_port['network_id'])
                if not fip_agent_port:
                    LOG.error(_LE("No FloatingIP agent gateway port "
                                  "returned from server for 'network-id': "
                                  "%s"), ex_gw_port['network_id'])
            if fip_agent_port:
                if 'subnets' not in fip_agent_port:
                    LOG.error(_LE('Missing subnet/agent_gateway_port'))
                else:
                    self.fip_ns.create_or_update_gateway_port(fip_agent_port)

            if self.fip_ns.agent_gateway_port:
                self.fip_ns.create_rtr_2_fip_link(self)
                self.routes_updated(self.routes, self.router['routes'])

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

    def _update_fip_route_table_with_next_hop_routes(
        self, operation, route, fip_ns_name, tbl_index):
        cmd = ['ip', 'route', operation, 'to', route['destination'],
               'via', route['nexthop'], 'table', tbl_index]
        ip_wrapper = ip_lib.IPWrapper(namespace=fip_ns_name)
        if ip_wrapper.netns.exists(fip_ns_name):
            ip_wrapper.netns.execute(cmd, check_exit_code=False)
        else:
            LOG.debug("The FIP namespace %(ns)s does not exist for "
                      "router %(id)s",
                      {'ns': fip_ns_name, 'id': self.router_id})

    def _check_if_route_applicable_to_fip_namespace(
        self, route, agent_gateway_port):
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
