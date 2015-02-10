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

from neutron.agent.l3 import dvr_fip_ns
from neutron.agent.l3 import router_info as router
from neutron.agent.linux import ip_lib


class DvrRouter(router.RouterInfo):
    def __init__(self, *args, **kwargs):
        super(DvrRouter, self).__init__(*args, **kwargs)

        self.floating_ips_dict = {}
        self.snat_iptables_manager = None
        # Linklocal subnet for router and floating IP namespace link
        self.rtr_fip_subnet = None
        self.dist_fip_count = None

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
        ip_rule = ip_lib.IpRule(self.root_helper, namespace=self.ns_name)
        ip_rule.add(fixed_ip, dvr_fip_ns.FIP_RT_TBL, rule_pr)
        #Add routing rule in fip namespace
        fip_ns_name = self.fip_ns.get_name()
        rtr_2_fip, _ = self.rtr_fip_subnet.get_pair()
        device = ip_lib.IPDevice(fip_2_rtr_name, self.root_helper,
                                 namespace=fip_ns_name)
        device.route.add_route(fip_cidr, str(rtr_2_fip.ip))
        interface_name = (
            self.fip_ns.get_ext_device_name(
                self.fip_ns.agent_gateway_port['id']))
        ip_lib.send_garp_for_proxyarp(fip_ns_name,
                                      interface_name,
                                      floating_ip,
                                      self.agent_conf.send_arp_for_ha,
                                      self.root_helper)
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
            ip_rule = ip_lib.IpRule(self.root_helper, namespace=self.ns_name)
            ip_rule.delete(floating_ip, dvr_fip_ns.FIP_RT_TBL, rule_pr)
            self.fip_ns.deallocate_rule_priority(rule_pr)
            #TODO(rajeev): Handle else case - exception/log?

        device = ip_lib.IPDevice(fip_2_rtr_name, self.root_helper,
                                 namespace=fip_ns_name)

        device.route.delete_route(fip_cidr, str(rtr_2_fip.ip))
        # check if this is the last FIP for this router
        self.dist_fip_count = self.dist_fip_count - 1
        if self.dist_fip_count == 0:
            #remove default route entry
            device = ip_lib.IPDevice(rtr_2_fip_name,
                                     self.root_helper,
                                     namespace=self.ns_name)
            ns_ip = ip_lib.IPWrapper(self.root_helper,
                                     namespace=fip_ns_name)
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
                self.fip_ns.destroy()
                self.fip_ns = None
