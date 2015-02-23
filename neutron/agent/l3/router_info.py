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

import netaddr

from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.common import constants as l3_constants
from neutron.common import exceptions as n_exc
from neutron.common import utils as common_utils
from neutron.i18n import _LW
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)
INTERNAL_DEV_PREFIX = 'qr-'


class RouterInfo(object):

    def __init__(self,
                 router_id,
                 router,
                 agent_conf,
                 interface_driver,
                 use_ipv6=False):
        self.router_id = router_id
        self.ex_gw_port = None
        self._snat_enabled = None
        self._snat_action = None
        self.internal_ports = []
        self.floating_ips = set()
        # Invoke the setter for establishing initial SNAT action
        self.router = router
        self.use_ipv6 = use_ipv6
        self.ns_name = None
        self.router_namespace = None
        if agent_conf.use_namespaces:
            ns = namespaces.RouterNamespace(
                router_id, agent_conf, interface_driver, use_ipv6)
            self.router_namespace = ns
            self.ns_name = ns.name
        self.iptables_manager = iptables_manager.IptablesManager(
            use_ipv6=use_ipv6,
            namespace=self.ns_name)
        self.routes = []
        self.agent_conf = agent_conf
        self.driver = interface_driver
        # radvd is a neutron.agent.linux.ra.DaemonMonitor
        self.radvd = None

    @property
    def router(self):
        return self._router

    @router.setter
    def router(self, value):
        self._router = value
        if not self._router:
            return
        # enable_snat by default if it wasn't specified by plugin
        self._snat_enabled = self._router.get('enable_snat', True)
        # Set a SNAT action for the router
        if self._router.get('gw_port'):
            self._snat_action = ('add_rules' if self._snat_enabled
                                 else 'remove_rules')
        elif self.ex_gw_port:
            # Gateway port was removed, remove rules
            self._snat_action = 'remove_rules'

    @property
    def is_ha(self):
        # TODO(Carl) Refactoring should render this obsolete.  Remove it.
        return False

    def get_internal_device_name(self, port_id):
        return (INTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def perform_snat_action(self, snat_callback, *args):
        # Process SNAT rules for attached subnets
        if self._snat_action:
            snat_callback(self, self._router.get('gw_port'),
                          *args, action=self._snat_action)
        self._snat_action = None

    def _update_routing_table(self, operation, route):
        cmd = ['ip', 'route', operation, 'to', route['destination'],
               'via', route['nexthop']]
        ip_wrapper = ip_lib.IPWrapper(namespace=self.ns_name)
        ip_wrapper.netns.execute(cmd, check_exit_code=False)

    def routes_updated(self):
        new_routes = self.router['routes']

        old_routes = self.routes
        adds, removes = common_utils.diff_list_of_dict(old_routes,
                                                       new_routes)
        for route in adds:
            LOG.debug("Added route entry is '%s'", route)
            # remove replaced route from deleted route
            for del_route in removes:
                if route['destination'] == del_route['destination']:
                    removes.remove(del_route)
            #replace success even if there is no existing route
            self._update_routing_table('replace', route)
        for route in removes:
            LOG.debug("Removed route entry is '%s'", route)
            self._update_routing_table('delete', route)
        self.routes = new_routes

    def get_ex_gw_port(self):
        return self.router.get('gw_port')

    def get_floating_ips(self):
        """Filter Floating IPs to be hosted on this agent."""
        return self.router.get(l3_constants.FLOATINGIP_KEY, [])

    def floating_forward_rules(self, floating_ip, fixed_ip):
        return [('PREROUTING', '-d %s -j DNAT --to %s' %
                 (floating_ip, fixed_ip)),
                ('OUTPUT', '-d %s -j DNAT --to %s' %
                 (floating_ip, fixed_ip)),
                ('float-snat', '-s %s -j SNAT --to %s' %
                 (fixed_ip, floating_ip))]

    def process_floating_ip_nat_rules(self):
        """Configure NAT rules for the router's floating IPs.

        Configures iptables rules for the floating ips of the given router
        """
        # Clear out all iptables rules for floating ips
        self.iptables_manager.ipv4['nat'].clear_rules_by_tag('floating_ip')

        floating_ips = self.get_floating_ips()
        # Loop once to ensure that floating ips are configured.
        for fip in floating_ips:
            # Rebuild iptables rules for the floating ip.
            fixed = fip['fixed_ip_address']
            fip_ip = fip['floating_ip_address']
            for chain, rule in self.floating_forward_rules(fip_ip, fixed):
                self.iptables_manager.ipv4['nat'].add_rule(chain, rule,
                                                           tag='floating_ip')

        self.iptables_manager.apply()

    def process_snat_dnat_for_fip(self):
        try:
            self.process_floating_ip_nat_rules()
        except Exception:
            # TODO(salv-orlando): Less broad catching
            raise n_exc.FloatingIpSetupException(
                'L3 agent failure to setup NAT for floating IPs')

    def _add_fip_addr_to_device(self, fip, device):
        """Configures the floating ip address on the device.
        """
        try:
            ip_cidr = common_utils.ip_to_cidr(fip['floating_ip_address'])
            net = netaddr.IPNetwork(ip_cidr)
            device.addr.add(net.version, ip_cidr, str(net.broadcast))
            return True
        except RuntimeError:
            # any exception occurred here should cause the floating IP
            # to be set in error state
            LOG.warn(_LW("Unable to configure IP address for "
                         "floating IP: %s"), fip['id'])

    def add_floating_ip(self, fip, interface_name, device):
        raise NotImplementedError()

    def remove_floating_ip(self, device, ip_cidr):
        net = netaddr.IPNetwork(ip_cidr)
        device.addr.delete(net.version, ip_cidr)
        self.driver.delete_conntrack_state(namespace=self.ns_name, ip=ip_cidr)

    def get_router_cidrs(self, device):
        return set([addr['cidr'] for addr in device.addr.list()])

    def process_floating_ip_addresses(self, interface_name):
        """Configure IP addresses on router's external gateway interface.

        Ensures addresses for existing floating IPs and cleans up
        those that should not longer be configured.
        """

        fip_statuses = {}
        if interface_name is None:
            LOG.debug('No Interface for floating IPs router: %s',
                      self.router['id'])
            return fip_statuses

        device = ip_lib.IPDevice(interface_name, namespace=self.ns_name)
        existing_cidrs = self.get_router_cidrs(device)
        new_cidrs = set()

        floating_ips = self.get_floating_ips()
        # Loop once to ensure that floating ips are configured.
        for fip in floating_ips:
            fip_ip = fip['floating_ip_address']
            ip_cidr = common_utils.ip_to_cidr(fip_ip)
            new_cidrs.add(ip_cidr)
            fip_statuses[fip['id']] = l3_constants.FLOATINGIP_STATUS_ACTIVE
            if ip_cidr not in existing_cidrs:
                fip_statuses[fip['id']] = self.add_floating_ip(
                    fip, interface_name, device)

        fips_to_remove = (
            ip_cidr for ip_cidr in existing_cidrs - new_cidrs
            if common_utils.is_cidr_host(ip_cidr))
        for ip_cidr in fips_to_remove:
            self.remove_floating_ip(device, ip_cidr)

        return fip_statuses

    def configure_fip_addresses(self, interface_name):
        try:
            return self.process_floating_ip_addresses(interface_name)
        except Exception:
            # TODO(salv-orlando): Less broad catching
            raise n_exc.FloatingIpSetupException('L3 agent failure to setup '
                'floating IPs')

    def put_fips_in_error_state(self):
        fip_statuses = {}
        for fip in self.router.get(l3_constants.FLOATINGIP_KEY, []):
            fip_statuses[fip['id']] = l3_constants.FLOATINGIP_STATUS_ERROR
        return fip_statuses

    def create(self):
        if self.router_namespace:
            self.router_namespace.create()

    def delete(self):
        self.radvd.disable()
        if self.router_namespace:
            self.router_namespace.delete()
