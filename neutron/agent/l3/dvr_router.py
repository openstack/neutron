# Copyright (c) 2015 Openstack Foundation
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

from oslo_log import log as logging
from oslo_utils import excutils

from neutron.agent.l3 import dvr_fip_ns
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import router_info as router
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.common import constants as l3_constants
from neutron.common import utils as common_utils
from neutron.i18n import _LE, _LW

LOG = logging.getLogger(__name__)
# xor-folding mask used for IPv6 rule index
MASK_30 = 0x3fffffff

# Tracks the arp entry cache
Arp_entry = collections.namedtuple(
    'Arp_entry', 'ip mac subnet_id operation')


class DvrRouter(router.RouterInfo):
    def __init__(self, agent, host, *args, **kwargs):
        super(DvrRouter, self).__init__(*args, **kwargs)

        self.agent = agent
        self.host = host

        self.floating_ips_dict = {}
        self.snat_iptables_manager = None
        # Linklocal subnet for router and floating IP namespace link
        self.rtr_fip_subnet = None
        self.dist_fip_count = None
        self.snat_namespace = None
        self._pending_arp_set = set()

    def get_floating_ips(self):
        """Filter Floating IPs to be hosted on this agent."""
        floating_ips = super(DvrRouter, self).get_floating_ips()
        return [i for i in floating_ips if i['host'] == self.host]

    def get_snat_interfaces(self):
        return self.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, [])

    def get_snat_int_device_name(self, port_id):
        long_name = dvr_snat_ns.SNAT_INT_DEV_PREFIX + port_id
        return long_name[:self.driver.DEV_NAME_LEN]

    def _handle_fip_nat_rules(self, interface_name, action):
        """Configures NAT rules for Floating IPs for DVR.

           Remove all the rules. This is safe because if
           use_namespaces is set as False then the agent can
           only configure one router, otherwise each router's
           NAT rules will be in their own namespace.
        """
        self.iptables_manager.ipv4['nat'].empty_chain('POSTROUTING')
        self.iptables_manager.ipv4['nat'].empty_chain('snat')

        # Add back the jump to float-snat
        self.iptables_manager.ipv4['nat'].add_rule('snat', '-j $float-snat')

        # And add them back if the action is add_rules
        if action == 'add_rules' and interface_name:
            rule = ('POSTROUTING', '! -i %(interface_name)s '
                    '! -o %(interface_name)s -m conntrack ! '
                    '--ctstate DNAT -j ACCEPT' %
                    {'interface_name': interface_name})
            self.iptables_manager.ipv4['nat'].add_rule(*rule)
        self.iptables_manager.apply()

    def floating_ip_added_dist(self, fip, fip_cidr):
        """Add floating IP to FIP namespace."""
        floating_ip = fip['floating_ip_address']
        fixed_ip = fip['fixed_ip_address']
        rule_pr = self.fip_ns.allocate_rule_priority()
        self.floating_ips_dict[floating_ip] = rule_pr
        fip_2_rtr_name = self.fip_ns.get_int_device_name(self.router_id)
        ip_rule = ip_lib.IPRule(namespace=self.ns_name)
        ip_rule.rule.add(fixed_ip, dvr_fip_ns.FIP_RT_TBL, rule_pr)
        #Add routing rule in fip namespace
        fip_ns_name = self.fip_ns.get_name()
        rtr_2_fip, _ = self.rtr_fip_subnet.get_pair()
        device = ip_lib.IPDevice(fip_2_rtr_name, namespace=fip_ns_name)
        device.route.add_route(fip_cidr, str(rtr_2_fip.ip))
        interface_name = (
            self.fip_ns.get_ext_device_name(
                self.fip_ns.agent_gateway_port['id']))
        ip_lib.send_ip_addr_adv_notif(fip_ns_name,
                                      interface_name,
                                      floating_ip,
                                      self.agent_conf)
        # update internal structures
        self.dist_fip_count = self.dist_fip_count + 1

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
        if floating_ip in self.floating_ips_dict:
            rule_pr = self.floating_ips_dict[floating_ip]
            ip_rule = ip_lib.IPRule(namespace=self.ns_name)
            ip_rule.rule.delete(floating_ip, dvr_fip_ns.FIP_RT_TBL, rule_pr)
            self.fip_ns.deallocate_rule_priority(rule_pr)
            #TODO(rajeev): Handle else case - exception/log?

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
            self.fip_ns.local_subnets.release(self.router_id)
            self.rtr_fip_subnet = None
            ns_ip.del_veth(fip_2_rtr_name)
            is_last = self.fip_ns.unsubscribe(self.router_id)
            if is_last:
                # TODO(Carl) I can't help but think that another router could
                # come in and want to start using this namespace while this is
                # destroying it.  The two could end up conflicting on
                # creating/destroying interfaces and such.  I think I'd like a
                # semaphore to sync creation/deletion of this namespace.
                self.fip_ns.delete()
                self.fip_ns = None

    def add_floating_ip(self, fip, interface_name, device):
        if not self._add_fip_addr_to_device(fip, device):
            return l3_constants.FLOATINGIP_STATUS_ERROR

        # Special Handling for DVR - update FIP namespace
        ip_cidr = common_utils.ip_to_cidr(fip['floating_ip_address'])
        self.floating_ip_added_dist(fip, ip_cidr)
        return l3_constants.FLOATINGIP_STATUS_ACTIVE

    def remove_floating_ip(self, device, ip_cidr):
        super(DvrRouter, self).remove_floating_ip(device, ip_cidr)
        self.floating_ip_removed_dist(ip_cidr)

    def create_snat_namespace(self):
        # TODO(mlavalle): in the near future, this method should contain the
        # code in the L3 agent that creates a gateway for a dvr. The first step
        # is to move the creation of the snat namespace here
        self.snat_namespace = dvr_snat_ns.SnatNamespace(self.router['id'],
                                                        self.agent_conf,
                                                        self.driver,
                                                        self.use_ipv6)
        self.snat_namespace.create()
        return self.snat_namespace

    def _get_internal_port(self, subnet_id):
        """Return internal router port based on subnet_id."""
        router_ports = self.router.get(l3_constants.INTERFACE_KEY, [])
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
            if ip_lib.device_exists(interface_name, namespace=self.ns_name):
                if operation == 'add':
                    device.neigh.add(ip, mac)
                elif operation == 'delete':
                    device.neigh.delete(ip, mac)
                return True
            else:
                if operation == 'add':
                    LOG.warn(_LW("Device %s does not exist so ARP entry "
                                 "cannot be updated, will cache information "
                                 "to be applied later when the device exists"),
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
            if p['device_owner'] not in l3_constants.ROUTER_INTERFACE_OWNERS:
                for fixed_ip in p['fixed_ips']:
                    self._update_arp_entry(fixed_ip['ip_address'],
                                           p['mac_address'],
                                           subnet_id,
                                           'add')
        self._process_arp_cache_for_internal_port(subnet_id)

    def _map_internal_interfaces(self, int_port, snat_ports):
        """Return the SNAT port for the given internal interface port."""
        fixed_ip = int_port['fixed_ips'][0]
        subnet_id = fixed_ip['subnet_id']
        match_port = [p for p in snat_ports if
                      p['fixed_ips'][0]['subnet_id'] == subnet_id]
        if match_port:
            return match_port[0]
        else:
            LOG.error(_LE('DVR: no map match_port found!'))

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
            # the crc32 & 0xffffffff is for Python 2.6 and 3.0 compatibility
            snat_idx = binascii.crc32(ip_cidr) & 0xffffffff
            # xor-fold the hash to reserve upper range to extend smaller values
            snat_idx = (snat_idx >> 30) ^ (snat_idx & MASK_30)
            if snat_idx < 32768:
                snat_idx = snat_idx + MASK_30
        else:
            snat_idx = net.value
        return snat_idx

    def _snat_redirect_modify(self, gateway, sn_port, sn_int, is_add):
        """Adds or removes rules and routes for SNAT redirection."""
        try:
            ns_ipr = ip_lib.IPRule(namespace=self.ns_name)
            ns_ipd = ip_lib.IPDevice(sn_int, namespace=self.ns_name)
            if is_add:
                ns_ipwrapr = ip_lib.IPWrapper(namespace=self.ns_name)
            for port_fixed_ip in sn_port['fixed_ips']:
                # Find the first gateway IP address matching this IP version
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
                            ns_ipr.rule.add(sn_port_cidr, snat_idx, snat_idx)
                            ns_ipwrapr.netns.execute(
                                ['sysctl', '-w',
                                 'net.ipv4.conf.%s.send_redirects=0' % sn_int])
                        else:
                            ns_ipd.route.delete_gateway(gw_ip_addr,
                                                        table=snat_idx)
                            ns_ipr.rule.delete(sn_port_cidr, snat_idx,
                                               snat_idx)
                        break
        except Exception:
            if is_add:
                exc = _LE('DVR: error adding redirection logic')
            else:
                exc = _LE('DVR: removed snat failed')
            LOG.exception(exc)

    def _snat_redirect_add(self, gateway, sn_port, sn_int):
        """Adds rules and routes for SNAT redirection."""
        self._snat_redirect_modify(gateway, sn_port, sn_int, is_add=True)

    def _snat_redirect_remove(self, gateway, sn_port, sn_int):
        """Removes rules and routes for SNAT redirection."""
        self._snat_redirect_modify(gateway, sn_port, sn_int, is_add=False)

    def get_gw_port_host(self):
        host = self.router.get('gw_port_host')
        if not host:
            LOG.debug("gw_port_host missing from router: %s",
                      self.router['id'])
        return host

    def _is_this_snat_host(self):
        # TODO(Carl) This is a sign that dvr needs two router classes.
        mode = self.agent_conf.agent_mode
        return (mode == l3_constants.L3_AGENT_MODE_DVR_SNAT
                and self.get_gw_port_host() == self.host)

    def internal_network_added(self, port):
        super(DvrRouter, self).internal_network_added(port)

        # NOTE: The following function _set_subnet_arp_info
        # should be called to dynamically populate the arp
        # entries for the dvr services ports into the router
        # namespace. This does not have dependency on the
        # external_gateway port or the agent_mode.
        for subnet in port['subnets']:
            self._set_subnet_arp_info(subnet['id'])

        ex_gw_port = self.get_ex_gw_port()
        if not ex_gw_port:
            return

        snat_ports = self.get_snat_interfaces()
        sn_port = self._map_internal_interfaces(port, snat_ports)
        if not sn_port:
            return

        interface_name = self.get_internal_device_name(port['id'])
        self._snat_redirect_add(sn_port, port, interface_name)

        if not self._is_this_snat_host():
            return

        ns_name = dvr_snat_ns.SnatNamespace.get_snat_ns_name(self.router['id'])
        interface_name = self.get_snat_int_device_name(sn_port['id'])
        self._internal_network_added(
            ns_name,
            sn_port['network_id'],
            sn_port['id'],
            sn_port['fixed_ips'],
            sn_port['mac_address'],
            interface_name,
            dvr_snat_ns.SNAT_INT_DEV_PREFIX)

    def _dvr_internal_network_removed(self, port):
        if not self.ex_gw_port:
            return

        sn_port = self._map_internal_interfaces(port, self.snat_ports)
        if not sn_port:
            return

        # DVR handling code for SNAT
        interface_name = self.get_internal_device_name(port['id'])
        self._snat_redirect_remove(sn_port, port, interface_name)
        # Clean up the cached arp entries related to the port subnet
        for subnet in port['subnets']:
            self._delete_arp_cache_for_internal_port(subnet)

        mode = self.agent_conf.agent_mode
        is_this_snat_host = (mode == l3_constants.L3_AGENT_MODE_DVR_SNAT
            and self.ex_gw_port['binding:host_id'] == self.host)
        if not is_this_snat_host:
            return

        snat_interface = (
            self.get_snat_int_device_name(sn_port['id']))
        ns_name = self.snat_namespace.name
        prefix = dvr_snat_ns.SNAT_INT_DEV_PREFIX
        if ip_lib.device_exists(snat_interface, namespace=ns_name):
            self.driver.unplug(snat_interface, namespace=ns_name,
                               prefix=prefix)

    def internal_network_removed(self, port):
        self._dvr_internal_network_removed(port)
        super(DvrRouter, self).internal_network_removed(port)

    def get_floating_agent_gw_interface(self, ext_net_id):
        """Filter Floating Agent GW port for the external network."""
        fip_ports = self.router.get(l3_constants.FLOATINGIP_AGENT_INTF_KEY, [])
        return next(
            (p for p in fip_ports if p['network_id'] == ext_net_id), None)

    def get_external_device_interface_name(self, ex_gw_port):
        fip_int = self.fip_ns.get_int_device_name(self.router_id)
        if ip_lib.device_exists(fip_int, namespace=self.fip_ns.get_name()):
            return self.fip_ns.get_rtr_ext_device_name(self.router_id)

    def _create_dvr_gateway(self, ex_gw_port, gw_interface_name,
                            snat_ports):
        """Create SNAT namespace."""
        snat_ns = self.create_snat_namespace()
        # connect snat_ports to br_int from SNAT namespace
        for port in snat_ports:
            # create interface_name
            interface_name = self.get_snat_int_device_name(port['id'])
            self._internal_network_added(snat_ns.name, port['network_id'],
                                         port['id'], port['fixed_ips'],
                                         port['mac_address'], interface_name,
                                         dvr_snat_ns.SNAT_INT_DEV_PREFIX)
        self._external_gateway_added(ex_gw_port, gw_interface_name,
                                     snat_ns.name, preserve_ips=[])
        self.snat_iptables_manager = iptables_manager.IptablesManager(
            namespace=snat_ns.name,
            use_ipv6=self.use_ipv6)
        # kicks the FW Agent to add rules for the snat namespace
        self.agent.process_router_add(self)

    def external_gateway_added(self, ex_gw_port, interface_name):
        # TODO(Carl) Refactor external_gateway_added/updated/removed to use
        # super class implementation where possible.  Looks like preserve_ips,
        # and ns_name are the key differences.
        ip_wrapr = ip_lib.IPWrapper(namespace=self.ns_name)
        ip_wrapr.netns.execute(['sysctl', '-w',
                               'net.ipv4.conf.all.send_redirects=0'])
        snat_ports = self.get_snat_interfaces()
        for p in self.internal_ports:
            gateway = self._map_internal_interfaces(p, snat_ports)
            id_name = self.get_internal_device_name(p['id'])
            if gateway:
                self._snat_redirect_add(gateway, p, id_name)

        if self._is_this_snat_host():
            self._create_dvr_gateway(ex_gw_port, interface_name, snat_ports)

        for port in snat_ports:
            for ip in port['fixed_ips']:
                self._update_arp_entry(ip['ip_address'],
                                       port['mac_address'],
                                       ip['subnet_id'],
                                       'add')

    def external_gateway_updated(self, ex_gw_port, interface_name):
        if not self._is_this_snat_host():
            # no centralized SNAT gateway for this node/agent
            LOG.debug("not hosting snat for router: %s", self.router['id'])
            return

        self._external_gateway_added(ex_gw_port,
                                     interface_name,
                                     self.snat_namespace.name,
                                     preserve_ips=[])

    def external_gateway_removed(self, ex_gw_port, interface_name):
        # TODO(Carl) Should this be calling process_snat_dnat_for_fip?
        self.process_floating_ip_nat_rules()
        if self.fip_ns:
            to_fip_interface_name = (
                self.get_external_device_interface_name(ex_gw_port))
            self.process_floating_ip_addresses(to_fip_interface_name)
        snat_ports = self.get_snat_interfaces()
        for p in self.internal_ports:
            gateway = self._map_internal_interfaces(p, snat_ports)
            internal_interface = self.get_internal_device_name(p['id'])
            self._snat_redirect_remove(gateway, p, internal_interface)

        if not self._is_this_snat_host():
            # no centralized SNAT gateway for this node/agent
            LOG.debug("not hosting snat for router: %s", self.router['id'])
            return

        self.driver.unplug(interface_name,
                           bridge=self.agent_conf.external_network_bridge,
                           namespace=self.snat_namespace.name,
                           prefix=router.EXTERNAL_DEV_PREFIX)

        self.snat_namespace.delete()
        self.snat_namespace = None

    def _handle_router_snat_rules(self, ex_gw_port,
                                  interface_name, action):
        if not self.snat_iptables_manager:
            LOG.debug("DVR router: no snat rules to be handled")
            return

        with self.snat_iptables_manager.defer_apply():
            self._empty_snat_chains(self.snat_iptables_manager)

            # NOTE DVR doesn't add the jump to float snat like the super class.

            self._add_snat_rules(ex_gw_port, self.snat_iptables_manager,
                                 interface_name, action)

    def perform_snat_action(self, snat_callback, *args):
        # NOTE DVR skips this step in a few cases...
        if not self.get_ex_gw_port():
            return
        if self.get_gw_port_host() != self.host:
            return

        super(DvrRouter, self).perform_snat_action(snat_callback, *args)

    def process_external(self, agent):
        ex_gw_port = self.get_ex_gw_port()
        if ex_gw_port:
            self.create_dvr_fip_interfaces(ex_gw_port)
        super(DvrRouter, self).process_external(agent)

    def create_dvr_fip_interfaces(self, ex_gw_port):
        floating_ips = self.get_floating_ips()
        fip_agent_port = self.get_floating_agent_gw_interface(
            ex_gw_port['network_id'])
        LOG.debug("FloatingIP agent gateway port received from the plugin: "
                  "%s", fip_agent_port)
        if floating_ips:
            is_first = self.fip_ns.subscribe(self.router_id)
            if is_first and not fip_agent_port:
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
            if is_first and fip_agent_port:
                if 'subnets' not in fip_agent_port:
                    LOG.error(_LE('Missing subnet/agent_gateway_port'))
                else:
                    self.fip_ns.create_gateway_port(fip_agent_port)

        if self.fip_ns.agent_gateway_port and floating_ips:
            if self.dist_fip_count == 0:
                self.fip_ns.create_rtr_2_fip_link(self)

                # kicks the FW Agent to add rules for the IR namespace if
                # configured
                self.agent.process_router_add(self)

    def process(self, agent):
        ex_gw_port = self.get_ex_gw_port()
        if ex_gw_port:
            self.fip_ns = agent.get_fip_ns(ex_gw_port['network_id'])
            self.fip_ns.scan_fip_ports(self)

        super(DvrRouter, self).process(agent)
