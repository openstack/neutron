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
import weakref

from neutron.agent.l3 import dvr_fip_ns
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.common import constants as l3_constants
from neutron.i18n import _LE
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

SNAT_INT_DEV_PREFIX = 'sg-'
SNAT_NS_PREFIX = 'snat-'
# xor-folding mask used for IPv6 rule index
MASK_30 = 0x3fffffff


class AgentMixin(object):
    def __init__(self, host):
        # dvr data
        self._fip_namespaces = weakref.WeakValueDictionary()
        super(AgentMixin, self).__init__(host)

    def get_fip_ns(self, ext_net_id):
        # TODO(Carl) is this necessary?  Code that this replaced was careful to
        # convert these to string like this so I preserved that.
        ext_net_id = str(ext_net_id)

        fip_ns = self._fip_namespaces.get(ext_net_id)
        if fip_ns and not fip_ns.destroyed:
            return fip_ns

        fip_ns = dvr_fip_ns.FipNamespace(ext_net_id,
                                         self.conf,
                                         self.driver,
                                         self.use_ipv6)
        self._fip_namespaces[ext_net_id] = fip_ns

        return fip_ns

    def _destroy_snat_namespace(self, ns):
        ns_ip = ip_lib.IPWrapper(namespace=ns)
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
        ex_net_id = ns[len(dvr_fip_ns.FIP_NS_PREFIX):]
        fip_ns = self.get_fip_ns(ex_net_id)
        fip_ns.destroy()

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

    def get_snat_int_device_name(self, port_id):
        return (SNAT_INT_DEV_PREFIX +
                port_id)[:self.driver.DEV_NAME_LEN]

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
            namespace=snat_ns_name,
            use_ipv6=self.use_ipv6)
        # kicks the FW Agent to add rules for the snat namespace
        self.process_router_add(ri)

    def _snat_redirect_add(self, ri, gateway, sn_port, sn_int):
        """Adds rules and routes for SNAT redirection."""
        try:
            ip_cidr = sn_port['ip_cidr']
            snat_idx = self._get_snat_idx(ip_cidr)
            ns_ipr = ip_lib.IpRule(namespace=ri.ns_name)
            ns_ipd = ip_lib.IPDevice(sn_int, namespace=ri.ns_name)
            ns_ipd.route.add_gateway(gateway, table=snat_idx)
            ns_ipr.add(ip_cidr, snat_idx, snat_idx)
            ns_ipr.netns.execute(['sysctl', '-w', 'net.ipv4.conf.%s.'
                                 'send_redirects=0' % sn_int])
        except Exception:
            LOG.exception(_LE('DVR: error adding redirection logic'))

    def _snat_redirect_remove(self, ri, sn_port, sn_int):
        """Removes rules and routes for SNAT redirection."""
        try:
            ip_cidr = sn_port['ip_cidr']
            snat_idx = self._get_snat_idx(ip_cidr)
            ns_ipr = ip_lib.IpRule(namespace=ri.ns_name)
            ns_ipd = ip_lib.IPDevice(sn_int, namespace=ri.ns_name)
            ns_ipd.route.delete_gateway(table=snat_idx)
            ns_ipr.delete(ip_cidr, snat_idx, snat_idx)
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
                device = ip_lib.IPDevice(interface_name, namespace=ri.ns_name)
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
