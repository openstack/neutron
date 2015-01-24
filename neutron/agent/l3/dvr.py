# Copyright (c) 2014 Openstack Foundation
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
import netaddr
import os

from neutron.agent.l3 import link_local_allocator as lla
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.common import constants as l3_constants
from neutron.common import utils as common_utils
from neutron.i18n import _LE
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

SNAT_INT_DEV_PREFIX = 'sg-'
FIP_EXT_DEV_PREFIX = 'fg-'
FIP_NS_PREFIX = 'fip-'
SNAT_NS_PREFIX = 'snat-'
FIP_2_ROUTER_DEV_PREFIX = 'fpr-'
ROUTER_2_FIP_DEV_PREFIX = 'rfp-'
FIP_LL_SUBNET = '169.254.30.0/23'
# Rule priority range for FIPs
FIP_PR_START = 32768
FIP_PR_END = FIP_PR_START + 40000
# Route Table index for FIPs
FIP_RT_TBL = 16
# xor-folding mask used for IPv6 rule index
MASK_30 = 0x3fffffff


class AgentMixin(object):
    def __init__(self, host):
        # dvr data
        self.agent_gateway_port = None
        self.fip_ns_subscribers = set()
        self.local_subnets = lla.LinkLocalAllocator(
            os.path.join(self.conf.state_path, 'fip-linklocal-networks'),
            FIP_LL_SUBNET)
        self.fip_priorities = set(range(FIP_PR_START,
                                        FIP_PR_END))

        super(AgentMixin, self).__init__(host)

    def _fip_ns_subscribe(self, router_id):
        is_first = (len(self.fip_ns_subscribers) == 0)
        self.fip_ns_subscribers.add(router_id)
        return is_first

    def _fip_ns_unsubscribe(self, router_id):
        self.fip_ns_subscribers.discard(router_id)
        return len(self.fip_ns_subscribers) == 0

    def _destroy_snat_namespace(self, ns):
        ns_ip = ip_lib.IPWrapper(self.root_helper, namespace=ns)
        # delete internal interfaces
        for d in ns_ip.get_devices(exclude_loopback=True):
            if d.name.startswith(SNAT_INT_DEV_PREFIX):
                LOG.debug('Unplugging DVR device %s', d.name)
                self.driver.unplug(d.name, namespace=ns,
                                   prefix=SNAT_INT_DEV_PREFIX)

        # TODO(mrsmith): delete ext-gw-port
        LOG.debug('DVR: destroy snat ns: %s', ns)
        if self.conf.router_delete_namespaces:
            self._delete_namespace(ns_ip, ns)

    def _destroy_fip_namespace(self, ns):
        ns_ip = ip_lib.IPWrapper(self.root_helper, namespace=ns)
        for d in ns_ip.get_devices(exclude_loopback=True):
            if d.name.startswith(FIP_2_ROUTER_DEV_PREFIX):
                # internal link between IRs and FIP NS
                ns_ip.del_veth(d.name)
            elif d.name.startswith(FIP_EXT_DEV_PREFIX):
                # single port from FIP NS to br-ext
                # TODO(carl) Where does the port get deleted?
                LOG.debug('DVR: unplug: %s', d.name)
                self.driver.unplug(d.name,
                                   bridge=self.conf.external_network_bridge,
                                   namespace=ns,
                                   prefix=FIP_EXT_DEV_PREFIX)
        LOG.debug('DVR: destroy fip ns: %s', ns)
        # TODO(mrsmith): add LOG warn if fip count != 0
        if self.conf.router_delete_namespaces:
            self._delete_namespace(ns_ip, ns)
        self.agent_gateway_port = None

    def _set_subnet_arp_info(self, ri, port):
        """Set ARP info retrieved from Plugin for existing ports."""
        if 'id' not in port['subnet'] or not ri.router['distributed']:
            return
        subnet_id = port['subnet']['id']
        subnet_ports = (
            self.plugin_rpc.get_ports_by_subnet(self.context,
                                                subnet_id))

        for p in subnet_ports:
            if p['device_owner'] not in l3_constants.ROUTER_INTERFACE_OWNERS:
                for fixed_ip in p['fixed_ips']:
                    self._update_arp_entry(ri, fixed_ip['ip_address'],
                                           p['mac_address'],
                                           subnet_id, 'add')

    def get_internal_port(self, ri, subnet_id):
        """Return internal router port based on subnet_id."""
        router_ports = ri.router.get(l3_constants.INTERFACE_KEY, [])
        for port in router_ports:
            fips = port['fixed_ips']
            for f in fips:
                if f['subnet_id'] == subnet_id:
                    return port

    def scan_fip_ports(self, ri):
        # don't scan if not dvr or count is not None
        if not ri.router.get('distributed') or ri.dist_fip_count is not None:
            return

        # scan system for any existing fip ports
        ri.dist_fip_count = 0
        rtr_2_fip_interface = self.get_rtr_int_device_name(ri.router_id)
        if ip_lib.device_exists(rtr_2_fip_interface,
                                root_helper=self.root_helper,
                                namespace=ri.ns_name):
            device = ip_lib.IPDevice(rtr_2_fip_interface, self.root_helper,
                                     namespace=ri.ns_name)
            existing_cidrs = [addr['cidr'] for addr in device.addr.list()]
            fip_cidrs = [c for c in existing_cidrs if
                         common_utils.is_cidr_host(c)]
            ri.dist_fip_count = len(fip_cidrs)

    def get_fip_ext_device_name(self, port_id):
        return (FIP_EXT_DEV_PREFIX +
                port_id)[:self.driver.DEV_NAME_LEN]

    def get_rtr_int_device_name(self, router_id):
        return (ROUTER_2_FIP_DEV_PREFIX +
                router_id)[:self.driver.DEV_NAME_LEN]

    def get_fip_int_device_name(self, router_id):
        return (FIP_2_ROUTER_DEV_PREFIX +
                router_id)[:self.driver.DEV_NAME_LEN]

    def get_snat_int_device_name(self, port_id):
        return (SNAT_INT_DEV_PREFIX +
                port_id)[:self.driver.DEV_NAME_LEN]

    def get_fip_ns_name(self, ext_net_id):
        return (FIP_NS_PREFIX + ext_net_id)

    def get_snat_ns_name(self, router_id):
        return (SNAT_NS_PREFIX + router_id)

    def get_snat_interfaces(self, ri):
        return ri.router.get(l3_constants.SNAT_ROUTER_INTF_KEY, [])

    def get_gw_port_host(self, router):
        host = router.get('gw_port_host')
        if not host:
            LOG.debug("gw_port_host missing from router: %s",
                      router['id'])
        return host

    def _get_snat_idx(self, ip_cidr):
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

    def _map_internal_interfaces(self, ri, int_port, snat_ports):
        """Return the SNAT port for the given internal interface port."""
        fixed_ip = int_port['fixed_ips'][0]
        subnet_id = fixed_ip['subnet_id']
        match_port = [p for p in snat_ports if
                      p['fixed_ips'][0]['subnet_id'] == subnet_id]
        if match_port:
            return match_port[0]
        else:
            LOG.error(_LE('DVR: no map match_port found!'))

    def internal_ns_interface_added(self, ip_cidr,
                                    interface_name, ns_name):
        ip_wrapper = ip_lib.IPWrapper(self.root_helper, namespace=ns_name)
        ip_wrapper.netns.execute(['ip', 'addr', 'add',
                                  ip_cidr, 'dev', interface_name])

    def _handle_router_fip_nat_rules(self, ri, interface_name, action):
        """Configures NAT rules for Floating IPs for DVR.

           Remove all the rules. This is safe because if
           use_namespaces is set as False then the agent can
           only configure one router, otherwise each router's
           NAT rules will be in their own namespace.
        """
        ri.iptables_manager.ipv4['nat'].empty_chain('POSTROUTING')
        ri.iptables_manager.ipv4['nat'].empty_chain('snat')

        # Add back the jump to float-snat
        ri.iptables_manager.ipv4['nat'].add_rule('snat', '-j $float-snat')

        # And add them back if the action is add_rules
        if action == 'add_rules' and interface_name:
            rule = ('POSTROUTING', '! -i %(interface_name)s '
                    '! -o %(interface_name)s -m conntrack ! '
                    '--ctstate DNAT -j ACCEPT' %
                    {'interface_name': interface_name})
            ri.iptables_manager.ipv4['nat'].add_rule(*rule)
        ri.iptables_manager.apply()

    def _create_dvr_gateway(self, ri, ex_gw_port, gw_interface_name,
                            snat_ports):
        """Create SNAT namespace."""
        snat_ns_name = self.get_snat_ns_name(ri.router['id'])
        self._create_namespace(snat_ns_name)
        # connect snat_ports to br_int from SNAT namespace
        for port in snat_ports:
            # create interface_name
            self._set_subnet_info(port)
            interface_name = self.get_snat_int_device_name(port['id'])
            self._internal_network_added(snat_ns_name, port['network_id'],
                                         port['id'], port['ip_cidr'],
                                         port['mac_address'], interface_name,
                                         SNAT_INT_DEV_PREFIX)
        self._external_gateway_added(ri, ex_gw_port, gw_interface_name,
                                     snat_ns_name, preserve_ips=[])
        ri.snat_iptables_manager = iptables_manager.IptablesManager(
            root_helper=self.root_helper,
            namespace=snat_ns_name,
            use_ipv6=self.use_ipv6)
        # kicks the FW Agent to add rules for the snat namespace
        self.process_router_add(ri)

    def agent_gateway_added(self, ns_name, ex_gw_port,
                            interface_name):
        """Add Floating IP gateway port to FIP namespace."""
        if not ip_lib.device_exists(interface_name,
                                    root_helper=self.root_helper,
                                    namespace=ns_name):
            self.driver.plug(ex_gw_port['network_id'],
                             ex_gw_port['id'], interface_name,
                             ex_gw_port['mac_address'],
                             bridge=self.conf.external_network_bridge,
                             namespace=ns_name,
                             prefix=FIP_EXT_DEV_PREFIX)

        self.driver.init_l3(interface_name, [ex_gw_port['ip_cidr']],
                            namespace=ns_name)
        ip_address = ex_gw_port['ip_cidr'].split('/')[0]
        ip_lib.send_gratuitous_arp(ns_name,
                                   interface_name,
                                   ip_address,
                                   self.conf.send_arp_for_ha,
                                   self.root_helper)

        gw_ip = ex_gw_port['subnet']['gateway_ip']
        if gw_ip:
            ipd = ip_lib.IPDevice(interface_name, self.root_helper,
                                  namespace=ns_name)
            ipd.route.add_gateway(gw_ip)

        cmd = ['sysctl', '-w', 'net.ipv4.conf.%s.proxy_arp=1' % interface_name]
        ip_wrapper = ip_lib.IPWrapper(self.root_helper, namespace=ns_name)
        ip_wrapper.netns.execute(cmd, check_exit_code=False)

    def _create_agent_gateway_port(self, ri, network_id):
        """Create Floating IP gateway port.

           Request port creation from Plugin then creates
           Floating IP namespace and adds gateway port.
        """
        self.agent_gateway_port = (
            self.plugin_rpc.get_agent_gateway_port(
                self.context, network_id))
        if 'subnet' not in self.agent_gateway_port:
            LOG.error(_LE('Missing subnet/agent_gateway_port'))
            return
        self._set_subnet_info(self.agent_gateway_port)

        # add fip-namespace and agent_gateway_port
        fip_ns_name = (
            self.get_fip_ns_name(str(network_id)))
        self._create_namespace(fip_ns_name)
        ri.fip_iptables_manager = iptables_manager.IptablesManager(
            root_helper=self.root_helper, namespace=fip_ns_name,
            use_ipv6=self.use_ipv6)
        # no connection tracking needed in fip namespace
        ri.fip_iptables_manager.ipv4['raw'].add_rule('PREROUTING',
                                                     '-j CT --notrack')
        ri.fip_iptables_manager.apply()
        interface_name = (
            self.get_fip_ext_device_name(self.agent_gateway_port['id']))
        self.agent_gateway_added(fip_ns_name, self.agent_gateway_port,
                                 interface_name)

    def create_rtr_2_fip_link(self, ri, network_id):
        """Create interface between router and Floating IP namespace."""
        rtr_2_fip_name = self.get_rtr_int_device_name(ri.router_id)
        fip_2_rtr_name = self.get_fip_int_device_name(ri.router_id)
        fip_ns_name = self.get_fip_ns_name(str(network_id))

        # add link local IP to interface
        if ri.rtr_fip_subnet is None:
            ri.rtr_fip_subnet = self.local_subnets.allocate(ri.router_id)
        rtr_2_fip, fip_2_rtr = ri.rtr_fip_subnet.get_pair()
        ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                      namespace=ri.ns_name)
        if not ip_lib.device_exists(rtr_2_fip_name, self.root_helper,
                                    namespace=ri.ns_name):
            int_dev = ip_wrapper.add_veth(rtr_2_fip_name,
                                          fip_2_rtr_name, fip_ns_name)
            self.internal_ns_interface_added(str(rtr_2_fip),
                                             rtr_2_fip_name, ri.ns_name)
            self.internal_ns_interface_added(str(fip_2_rtr),
                                             fip_2_rtr_name, fip_ns_name)
            int_dev[0].link.set_up()
            int_dev[1].link.set_up()
        # add default route for the link local interface
        device = ip_lib.IPDevice(rtr_2_fip_name, self.root_helper,
                                 namespace=ri.ns_name)
        device.route.add_gateway(str(fip_2_rtr.ip), table=FIP_RT_TBL)
        #setup the NAT rules and chains
        self._handle_router_fip_nat_rules(ri, rtr_2_fip_name, 'add_rules')
        # kicks the FW Agent to add rules for the IR namespace if configured
        self.process_router_add(ri)

    def floating_ip_added_dist(self, ri, fip, fip_cidr):
        """Add floating IP to FIP namespace."""
        floating_ip = fip['floating_ip_address']
        fixed_ip = fip['fixed_ip_address']
        rule_pr = self.fip_priorities.pop()
        ri.floating_ips_dict[floating_ip] = rule_pr
        fip_2_rtr_name = self.get_fip_int_device_name(ri.router_id)
        ip_rule = ip_lib.IpRule(self.root_helper, namespace=ri.ns_name)
        ip_rule.add_rule_from(fixed_ip, FIP_RT_TBL, rule_pr)
        #Add routing rule in fip namespace
        fip_ns_name = self.get_fip_ns_name(str(fip['floating_network_id']))
        rtr_2_fip, _ = ri.rtr_fip_subnet.get_pair()
        device = ip_lib.IPDevice(fip_2_rtr_name, self.root_helper,
                                 namespace=fip_ns_name)
        device.route.add_route(fip_cidr, str(rtr_2_fip.ip))
        interface_name = (
            self.get_fip_ext_device_name(self.agent_gateway_port['id']))
        ip_lib.send_garp_for_proxyarp(fip_ns_name,
                                      interface_name,
                                      floating_ip,
                                      self.conf.send_arp_for_ha,
                                      self.root_helper)
        # update internal structures
        ri.dist_fip_count = ri.dist_fip_count + 1

    def floating_ip_removed_dist(self, ri, fip_cidr):
        """Remove floating IP from FIP namespace."""
        floating_ip = fip_cidr.split('/')[0]
        rtr_2_fip_name = self.get_rtr_int_device_name(ri.router_id)
        fip_2_rtr_name = self.get_fip_int_device_name(ri.router_id)
        if ri.rtr_fip_subnet is None:
            ri.rtr_fip_subnet = self.local_subnets.allocate(ri.router_id)
        rtr_2_fip, fip_2_rtr = ri.rtr_fip_subnet.get_pair()
        fip_ns_name = self.get_fip_ns_name(str(self._fetch_external_net_id()))
        ip_rule_rtr = ip_lib.IpRule(self.root_helper, namespace=ri.ns_name)
        if floating_ip in ri.floating_ips_dict:
            rule_pr = ri.floating_ips_dict[floating_ip]
            ip_rule_rtr.delete_rule_priority(rule_pr)
            self.fip_priorities.add(rule_pr)
            #TODO(rajeev): Handle else case - exception/log?

        device = ip_lib.IPDevice(fip_2_rtr_name, self.root_helper,
                                 namespace=fip_ns_name)

        device.route.delete_route(fip_cidr, str(rtr_2_fip.ip))
        # check if this is the last FIP for this router
        ri.dist_fip_count = ri.dist_fip_count - 1
        if ri.dist_fip_count == 0:
            #remove default route entry
            device = ip_lib.IPDevice(rtr_2_fip_name, self.root_helper,
                                     namespace=ri.ns_name)
            ns_ip = ip_lib.IPWrapper(self.root_helper, namespace=fip_ns_name)
            device.route.delete_gateway(str(fip_2_rtr.ip),
                                        table=FIP_RT_TBL)
            self.local_subnets.release(ri.router_id)
            ri.rtr_fip_subnet = None
            ns_ip.del_veth(fip_2_rtr_name)
            is_last = self._fip_ns_unsubscribe(ri.router_id)
            # clean up fip-namespace if this is the last FIP
            if is_last:
                self._destroy_fip_namespace(fip_ns_name)

    def _snat_redirect_add(self, ri, gateway, sn_port, sn_int):
        """Adds rules and routes for SNAT redirection."""
        try:
            snat_idx = self._get_snat_idx(sn_port['ip_cidr'])
            ns_ipr = ip_lib.IpRule(self.root_helper, namespace=ri.ns_name)
            ns_ipd = ip_lib.IPDevice(sn_int, self.root_helper,
                                     namespace=ri.ns_name)
            ns_ipd.route.add_gateway(gateway, table=snat_idx)
            ns_ipr.add_rule_from(sn_port['ip_cidr'], snat_idx, snat_idx)
            ns_ipr.netns.execute(['sysctl', '-w', 'net.ipv4.conf.%s.'
                                 'send_redirects=0' % sn_int])
        except Exception:
            LOG.exception(_LE('DVR: error adding redirection logic'))

    def _snat_redirect_remove(self, ri, sn_port, sn_int):
        """Removes rules and routes for SNAT redirection."""
        try:
            snat_idx = self._get_snat_idx(sn_port['ip_cidr'])
            ns_ipr = ip_lib.IpRule(self.root_helper, namespace=ri.ns_name)
            ns_ipd = ip_lib.IPDevice(sn_int, self.root_helper,
                                     namespace=ri.ns_name)
            ns_ipd.route.delete_gateway(table=snat_idx)
            ns_ipr.delete_rule_priority(snat_idx)
        except Exception:
            LOG.exception(_LE('DVR: removed snat failed'))

    def _update_arp_entry(self, ri, ip, mac, subnet_id, operation):
        """Add or delete arp entry into router namespace for the subnet."""
        port = self.get_internal_port(ri, subnet_id)
        # update arp entry only if the subnet is attached to the router
        if port:
            ip_cidr = str(ip) + '/32'
            try:
                # TODO(mrsmith): optimize the calls below for bulk calls
                net = netaddr.IPNetwork(ip_cidr)
                interface_name = self.get_internal_device_name(port['id'])
                device = ip_lib.IPDevice(interface_name, self.root_helper,
                                         namespace=ri.ns_name)
                if operation == 'add':
                    device.neigh.add(net.version, ip, mac)
                elif operation == 'delete':
                    device.neigh.delete(net.version, ip, mac)
            except Exception:
                LOG.exception(_LE("DVR: Failed updating arp entry"))
                self.fullsync = True

    def add_arp_entry(self, context, payload):
        """Add arp entry into router namespace.  Called from RPC."""
        arp_table = payload['arp_table']
        router_id = payload['router_id']
        ip = arp_table['ip_address']
        mac = arp_table['mac_address']
        subnet_id = arp_table['subnet_id']
        ri = self.router_info.get(router_id)
        if ri:
            self._update_arp_entry(ri, ip, mac, subnet_id, 'add')

    def del_arp_entry(self, context, payload):
        """Delete arp entry from router namespace.  Called from RPC."""
        arp_table = payload['arp_table']
        router_id = payload['router_id']
        ip = arp_table['ip_address']
        mac = arp_table['mac_address']
        subnet_id = arp_table['subnet_id']
        ri = self.router_info.get(router_id)
        if ri:
            self._update_arp_entry(ri, ip, mac, subnet_id, 'delete')
