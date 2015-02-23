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

import netaddr
from oslo_utils import excutils

from neutron.agent.l3 import dvr_fip_ns
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import router_info as router
from neutron.agent.linux import ip_lib
from neutron.common import constants as l3_constants
from neutron.common import utils as common_utils
from neutron.i18n import _LE
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


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

    def get_floating_ips(self):
        """Filter Floating IPs to be hosted on this agent."""
        floating_ips = super(DvrRouter, self).get_floating_ips()
        return [i for i in floating_ips if i['host'] == self.host]

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
        ip_rule = ip_lib.IpRule(namespace=self.ns_name)
        ip_rule.add(fixed_ip, dvr_fip_ns.FIP_RT_TBL, rule_pr)
        #Add routing rule in fip namespace
        fip_ns_name = self.fip_ns.get_name()
        rtr_2_fip, _ = self.rtr_fip_subnet.get_pair()
        device = ip_lib.IPDevice(fip_2_rtr_name, namespace=fip_ns_name)
        device.route.add_route(fip_cidr, str(rtr_2_fip.ip))
        interface_name = (
            self.fip_ns.get_ext_device_name(
                self.fip_ns.agent_gateway_port['id']))
        ip_lib.send_garp_for_proxyarp(fip_ns_name,
                                      interface_name,
                                      floating_ip,
                                      self.agent_conf.send_arp_for_ha)
        # update internal structures
        self.dist_fip_count = self.dist_fip_count + 1

    def floating_ip_removed_dist(self, fip_cidr):
        """Remove floating IP from FIP namespace."""
        floating_ip = fip_cidr.split('/')[0]
        rtr_2_fip_name = self.fip_ns.get_rtr_ext_device_name(self.router_id)
        fip_2_rtr_name = self.fip_ns.get_int_device_name(self.router_id)
        if self.rtr_fip_subnet is None:
            self.rtr_fip_subnet = self.local_subnets.allocate(self.router_id)

        rtr_2_fip, fip_2_rtr = self.rtr_fip_subnet.get_pair()
        fip_ns_name = self.fip_ns.get_name()
        if floating_ip in self.floating_ips_dict:
            rule_pr = self.floating_ips_dict[floating_ip]
            ip_rule = ip_lib.IpRule(namespace=self.ns_name)
            ip_rule.delete(floating_ip, dvr_fip_ns.FIP_RT_TBL, rule_pr)
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
        # and ri.namespace to handle DVR based FIP
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

    def delete_snat_namespace(self):
        # TODO(mlavalle): in the near future, this method should contain the
        # code in the L3 agent that removes an external gateway for a dvr. The
        # first step is to move the deletion of the snat namespace here
        self.snat_namespace.delete()
        self.snat_namespace = None

    def _get_internal_port(self, subnet_id):
        """Return internal router port based on subnet_id."""
        router_ports = self.router.get(l3_constants.INTERFACE_KEY, [])
        for port in router_ports:
            fips = port['fixed_ips']
            for f in fips:
                if f['subnet_id'] == subnet_id:
                    return port

    def _update_arp_entry(self, ip, mac, subnet_id, operation):
        """Add or delete arp entry into router namespace for the subnet."""
        port = self._get_internal_port(subnet_id)
        # update arp entry only if the subnet is attached to the router
        if not port:
            return

        ip_cidr = str(ip) + '/32'
        try:
            # TODO(mrsmith): optimize the calls below for bulk calls
            net = netaddr.IPNetwork(ip_cidr)
            interface_name = self.get_internal_device_name(port['id'])
            device = ip_lib.IPDevice(interface_name, namespace=self.ns_name)
            if operation == 'add':
                device.neigh.add(net.version, ip, mac)
            elif operation == 'delete':
                device.neigh.delete(net.version, ip, mac)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("DVR: Failed updating arp entry"))

    def _set_subnet_arp_info(self, port):
        """Set ARP info retrieved from Plugin for existing ports."""
        if 'id' not in port['subnet']:
            return

        subnet_id = port['subnet']['id']

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
