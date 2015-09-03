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

from oslo_log import log as logging

from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.agent.linux import ra
from neutron.common import constants as l3_constants
from neutron.common import exceptions as n_exc
from neutron.common import ipv6_utils
from neutron.common import utils as common_utils
from neutron.i18n import _LW

LOG = logging.getLogger(__name__)
INTERNAL_DEV_PREFIX = namespaces.INTERNAL_DEV_PREFIX
EXTERNAL_DEV_PREFIX = namespaces.EXTERNAL_DEV_PREFIX

FLOATINGIP_STATUS_NOCHANGE = object()


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

    def initialize(self, process_monitor):
        """Initialize the router on the system.

        This differs from __init__ in that this method actually affects the
        system creating namespaces, starting processes, etc.  The other merely
        initializes the python object.  This separates in-memory object
        initialization from methods that actually go do stuff to the system.

        :param process_monitor: The agent's process monitor instance.
        """
        self.process_monitor = process_monitor
        self.radvd = ra.DaemonMonitor(self.router_id,
                                      self.ns_name,
                                      process_monitor,
                                      self.get_internal_device_name)

        if self.router_namespace:
            self.router_namespace.create()

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

    @property
    def is_ha(self):
        # TODO(Carl) Refactoring should render this obsolete.  Remove it.
        return False

    def get_internal_device_name(self, port_id):
        return (INTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_external_device_name(self, port_id):
        return (EXTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_external_device_interface_name(self, ex_gw_port):
        return self.get_external_device_name(ex_gw_port['id'])

    def _update_routing_table(self, operation, route, namespace):
        cmd = ['ip', 'route', operation, 'to', route['destination'],
               'via', route['nexthop']]
        ip_wrapper = ip_lib.IPWrapper(namespace=namespace)
        ip_wrapper.netns.execute(cmd, check_exit_code=False)

    def update_routing_table(self, operation, route, namespace=None):
        if namespace is None:
            namespace = self.ns_name
        self._update_routing_table(operation, route, namespace)

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
            self.update_routing_table('replace', route)
        for route in removes:
            LOG.debug("Removed route entry is '%s'", route)
            self.update_routing_table('delete', route)
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
            device.addr.add(ip_cidr)
            return True
        except RuntimeError:
            # any exception occurred here should cause the floating IP
            # to be set in error state
            LOG.warn(_LW("Unable to configure IP address for "
                         "floating IP: %s"), fip['id'])

    def add_floating_ip(self, fip, interface_name, device):
        raise NotImplementedError()

    def remove_floating_ip(self, device, ip_cidr):
        device.delete_addr_and_conntrack_state(ip_cidr)

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
                LOG.debug('Floating ip %(id)s added, status %(status)s',
                          {'id': fip['id'],
                           'status': fip_statuses.get(fip['id'])})

                # mark the status as not changed. we can't remove it because
                # that's how the caller determines that it was removed
                if fip_statuses[fip['id']] == fip['status']:
                    fip_statuses[fip['id']] = FLOATINGIP_STATUS_NOCHANGE
        fips_to_remove = (
            ip_cidr for ip_cidr in existing_cidrs - new_cidrs
            if common_utils.is_cidr_host(ip_cidr))
        for ip_cidr in fips_to_remove:
            LOG.debug("Removing floating ip %s from interface %s in "
                      "namespace %s", ip_cidr, interface_name, self.ns_name)
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

    def delete(self, agent):
        self.router['gw_port'] = None
        self.router[l3_constants.INTERFACE_KEY] = []
        self.router[l3_constants.FLOATINGIP_KEY] = []
        self.process(agent)
        self.disable_radvd()
        if self.router_namespace:
            self.router_namespace.delete()

    def _internal_network_updated(self, port, subnet_id, prefix, old_prefix,
                                  updated_cidrs):
        interface_name = self.get_internal_device_name(port['id'])
        if prefix != l3_constants.PROVISIONAL_IPV6_PD_PREFIX:
            fixed_ips = port['fixed_ips']
            for fixed_ip in fixed_ips:
                if fixed_ip['subnet_id'] == subnet_id:
                    v6addr = common_utils.ip_to_cidr(fixed_ip['ip_address'],
                                                     fixed_ip.get('prefixlen'))
                    if v6addr not in updated_cidrs:
                        self.driver.add_ipv6_addr(interface_name, v6addr,
                                                  self.ns_name)
        else:
            self.driver.delete_ipv6_addr_with_prefix(interface_name,
                                                     old_prefix,
                                                     self.ns_name)

    def _internal_network_added(self, ns_name, network_id, port_id,
                                fixed_ips, mac_address,
                                interface_name, prefix):
        LOG.debug("adding internal network: prefix(%s), port(%s)",
                  prefix, port_id)
        self.driver.plug(network_id, port_id, interface_name, mac_address,
                         namespace=ns_name,
                         prefix=prefix)

        ip_cidrs = common_utils.fixed_ip_cidrs(fixed_ips)
        self.driver.init_router_port(
            interface_name, ip_cidrs, namespace=ns_name)
        for fixed_ip in fixed_ips:
            ip_lib.send_ip_addr_adv_notif(ns_name,
                                          interface_name,
                                          fixed_ip['ip_address'],
                                          self.agent_conf)

    def internal_network_added(self, port):
        network_id = port['network_id']
        port_id = port['id']
        fixed_ips = port['fixed_ips']
        mac_address = port['mac_address']

        interface_name = self.get_internal_device_name(port_id)

        self._internal_network_added(self.ns_name,
                                     network_id,
                                     port_id,
                                     fixed_ips,
                                     mac_address,
                                     interface_name,
                                     INTERNAL_DEV_PREFIX)

    def internal_network_removed(self, port):
        interface_name = self.get_internal_device_name(port['id'])
        LOG.debug("removing internal network: port(%s) interface(%s)",
                  port['id'], interface_name)
        if ip_lib.device_exists(interface_name, namespace=self.ns_name):
            self.driver.unplug(interface_name, namespace=self.ns_name,
                               prefix=INTERNAL_DEV_PREFIX)

    def _get_existing_devices(self):
        ip_wrapper = ip_lib.IPWrapper(namespace=self.ns_name)
        ip_devs = ip_wrapper.get_devices(exclude_loopback=True)
        return [ip_dev.name for ip_dev in ip_devs]

    @staticmethod
    def _get_updated_ports(existing_ports, current_ports):
        updated_ports = dict()
        current_ports_dict = {p['id']: p for p in current_ports}
        for existing_port in existing_ports:
            current_port = current_ports_dict.get(existing_port['id'])
            if current_port:
                if (sorted(existing_port['fixed_ips'],
                           key=common_utils.safe_sort_key) !=
                        sorted(current_port['fixed_ips'],
                               key=common_utils.safe_sort_key)):
                    updated_ports[current_port['id']] = current_port
        return updated_ports

    @staticmethod
    def _port_has_ipv6_subnet(port):
        if 'subnets' in port:
            for subnet in port['subnets']:
                if (netaddr.IPNetwork(subnet['cidr']).version == 6 and
                    subnet['cidr'] != l3_constants.PROVISIONAL_IPV6_PD_PREFIX):
                    return True

    def enable_radvd(self, internal_ports=None):
        LOG.debug('Spawning radvd daemon in router device: %s', self.router_id)
        if not internal_ports:
            internal_ports = self.internal_ports
        self.radvd.enable(internal_ports)

    def disable_radvd(self):
        LOG.debug('Terminating radvd daemon in router device: %s',
                  self.router_id)
        self.radvd.disable()

    def internal_network_updated(self, interface_name, ip_cidrs):
        self.driver.init_l3(interface_name, ip_cidrs=ip_cidrs,
            namespace=self.ns_name)

    def _process_internal_ports(self, pd):
        existing_port_ids = set(p['id'] for p in self.internal_ports)

        internal_ports = self.router.get(l3_constants.INTERFACE_KEY, [])
        current_port_ids = set(p['id'] for p in internal_ports
                               if p['admin_state_up'])

        new_port_ids = current_port_ids - existing_port_ids
        new_ports = [p for p in internal_ports if p['id'] in new_port_ids]
        old_ports = [p for p in self.internal_ports
                     if p['id'] not in current_port_ids]
        updated_ports = self._get_updated_ports(self.internal_ports,
                                                internal_ports)

        enable_ra = False
        for p in new_ports:
            self.internal_network_added(p)
            LOG.debug("appending port %s to internal_ports cache", p)
            self.internal_ports.append(p)
            enable_ra = enable_ra or self._port_has_ipv6_subnet(p)
            for subnet in p['subnets']:
                if ipv6_utils.is_ipv6_pd_enabled(subnet):
                    interface_name = self.get_internal_device_name(p['id'])
                    pd.enable_subnet(self.router_id, subnet['id'],
                                     subnet['cidr'],
                                     interface_name, p['mac_address'])

        for p in old_ports:
            self.internal_network_removed(p)
            LOG.debug("removing port %s from internal_ports cache", p)
            self.internal_ports.remove(p)
            enable_ra = enable_ra or self._port_has_ipv6_subnet(p)
            for subnet in p['subnets']:
                if ipv6_utils.is_ipv6_pd_enabled(subnet):
                    pd.disable_subnet(self.router_id, subnet['id'])

        updated_cidrs = []
        if updated_ports:
            for index, p in enumerate(internal_ports):
                if not updated_ports.get(p['id']):
                    continue
                self.internal_ports[index] = updated_ports[p['id']]
                interface_name = self.get_internal_device_name(p['id'])
                ip_cidrs = common_utils.fixed_ip_cidrs(p['fixed_ips'])
                LOG.debug("updating internal network for port %s", p)
                updated_cidrs += ip_cidrs
                self.internal_network_updated(interface_name, ip_cidrs)
                enable_ra = enable_ra or self._port_has_ipv6_subnet(p)

        # Check if there is any pd prefix update
        for p in internal_ports:
            if p['id'] in (set(current_port_ids) & set(existing_port_ids)):
                for subnet in p.get('subnets', []):
                    if ipv6_utils.is_ipv6_pd_enabled(subnet):
                        old_prefix = pd.update_subnet(self.router_id,
                                                      subnet['id'],
                                                      subnet['cidr'])
                        if old_prefix:
                            self._internal_network_updated(p, subnet['id'],
                                                           subnet['cidr'],
                                                           old_prefix,
                                                           updated_cidrs)
                            enable_ra = True

        # Enable RA
        if enable_ra:
            self.enable_radvd(internal_ports)

        existing_devices = self._get_existing_devices()
        current_internal_devs = set(n for n in existing_devices
                                    if n.startswith(INTERNAL_DEV_PREFIX))
        current_port_devs = set(self.get_internal_device_name(port_id)
                                for port_id in current_port_ids)
        stale_devs = current_internal_devs - current_port_devs
        for stale_dev in stale_devs:
            LOG.debug('Deleting stale internal router device: %s',
                      stale_dev)
            pd.remove_stale_ri_ifname(self.router_id, stale_dev)
            self.driver.unplug(stale_dev,
                               namespace=self.ns_name,
                               prefix=INTERNAL_DEV_PREFIX)

    def _list_floating_ip_cidrs(self):
        # Compute a list of addresses this router is supposed to have.
        # This avoids unnecessarily removing those addresses and
        # causing a momentarily network outage.
        floating_ips = self.get_floating_ips()
        return [common_utils.ip_to_cidr(ip['floating_ip_address'])
                for ip in floating_ips]

    def _plug_external_gateway(self, ex_gw_port, interface_name, ns_name):
        self.driver.plug(ex_gw_port['network_id'],
                         ex_gw_port['id'],
                         interface_name,
                         ex_gw_port['mac_address'],
                         bridge=self.agent_conf.external_network_bridge,
                         namespace=ns_name,
                         prefix=EXTERNAL_DEV_PREFIX)

    def _get_external_gw_ips(self, ex_gw_port):
        gateway_ips = []
        enable_ra_on_gw = False
        if 'subnets' in ex_gw_port:
            gateway_ips = [subnet['gateway_ip']
                           for subnet in ex_gw_port['subnets']
                           if subnet['gateway_ip']]
        if self.use_ipv6 and not self.is_v6_gateway_set(gateway_ips):
            # No IPv6 gateway is available, but IPv6 is enabled.
            if self.agent_conf.ipv6_gateway:
                # ipv6_gateway configured, use address for default route.
                gateway_ips.append(self.agent_conf.ipv6_gateway)
            else:
                # ipv6_gateway is also not configured.
                # Use RA for default route.
                enable_ra_on_gw = True
        return gateway_ips, enable_ra_on_gw

    def _external_gateway_added(self, ex_gw_port, interface_name,
                                ns_name, preserve_ips):
        LOG.debug("External gateway added: port(%s), interface(%s), ns(%s)",
                  ex_gw_port, interface_name, ns_name)
        self._plug_external_gateway(ex_gw_port, interface_name, ns_name)

        # Build up the interface and gateway IP addresses that
        # will be added to the interface.
        ip_cidrs = common_utils.fixed_ip_cidrs(ex_gw_port['fixed_ips'])

        gateway_ips, enable_ra_on_gw = self._get_external_gw_ips(ex_gw_port)
        self.driver.init_router_port(
            interface_name,
            ip_cidrs,
            namespace=ns_name,
            gateway_ips=gateway_ips,
            extra_subnets=ex_gw_port.get('extra_subnets', []),
            preserve_ips=preserve_ips,
            enable_ra_on_gw=enable_ra_on_gw,
            clean_connections=True)
        for fixed_ip in ex_gw_port['fixed_ips']:
            ip_lib.send_ip_addr_adv_notif(ns_name,
                                          interface_name,
                                          fixed_ip['ip_address'],
                                          self.agent_conf)

    def is_v6_gateway_set(self, gateway_ips):
        """Check to see if list of gateway_ips has an IPv6 gateway.
        """
        # Note - don't require a try-except here as all
        # gateway_ips elements are valid addresses, if they exist.
        return any(netaddr.IPAddress(gw_ip).version == 6
                   for gw_ip in gateway_ips)

    def external_gateway_added(self, ex_gw_port, interface_name):
        preserve_ips = self._list_floating_ip_cidrs()
        self._external_gateway_added(
            ex_gw_port, interface_name, self.ns_name, preserve_ips)

    def external_gateway_updated(self, ex_gw_port, interface_name):
        preserve_ips = self._list_floating_ip_cidrs()
        self._external_gateway_added(
            ex_gw_port, interface_name, self.ns_name, preserve_ips)

    def external_gateway_removed(self, ex_gw_port, interface_name):
        LOG.debug("External gateway removed: port(%s), interface(%s)",
                  ex_gw_port, interface_name)
        self.driver.unplug(interface_name,
                           bridge=self.agent_conf.external_network_bridge,
                           namespace=self.ns_name,
                           prefix=EXTERNAL_DEV_PREFIX)

    @staticmethod
    def _gateway_ports_equal(port1, port2):
        return port1 == port2

    def _process_external_gateway(self, ex_gw_port, pd):
        # TODO(Carl) Refactor to clarify roles of ex_gw_port vs self.ex_gw_port
        ex_gw_port_id = (ex_gw_port and ex_gw_port['id'] or
                         self.ex_gw_port and self.ex_gw_port['id'])

        interface_name = None
        if ex_gw_port_id:
            interface_name = self.get_external_device_name(ex_gw_port_id)
        if ex_gw_port:
            if not self.ex_gw_port:
                self.external_gateway_added(ex_gw_port, interface_name)
                pd.add_gw_interface(self.router['id'], interface_name)
            elif not self._gateway_ports_equal(ex_gw_port, self.ex_gw_port):
                self.external_gateway_updated(ex_gw_port, interface_name)
        elif not ex_gw_port and self.ex_gw_port:
            self.external_gateway_removed(self.ex_gw_port, interface_name)
            pd.remove_gw_interface(self.router['id'])

        existing_devices = self._get_existing_devices()
        stale_devs = [dev for dev in existing_devices
                      if dev.startswith(EXTERNAL_DEV_PREFIX)
                      and dev != interface_name]
        for stale_dev in stale_devs:
            LOG.debug('Deleting stale external router device: %s', stale_dev)
            pd.remove_gw_interface(self.router['id'])
            self.driver.unplug(stale_dev,
                               bridge=self.agent_conf.external_network_bridge,
                               namespace=self.ns_name,
                               prefix=EXTERNAL_DEV_PREFIX)

        # Process SNAT rules for external gateway
        gw_port = self._router.get('gw_port')
        self._handle_router_snat_rules(gw_port, interface_name)

    def external_gateway_nat_rules(self, ex_gw_ip, interface_name):
        dont_snat_traffic_to_internal_ports_if_not_to_floating_ip = (
            'POSTROUTING', '! -i %(interface_name)s '
                           '! -o %(interface_name)s -m conntrack ! '
                           '--ctstate DNAT -j ACCEPT' %
                           {'interface_name': interface_name})

        snat_normal_external_traffic = (
            'snat', '-o %s -j SNAT --to-source %s' %
                    (interface_name, ex_gw_ip))

        # Makes replies come back through the router to reverse DNAT
        ext_in_mark = self.agent_conf.external_ingress_mark
        snat_internal_traffic_to_floating_ip = (
            'snat', '-m mark ! --mark %s/%s '
                    '-m conntrack --ctstate DNAT '
                    '-j SNAT --to-source %s'
                    % (ext_in_mark, l3_constants.ROUTER_MARK_MASK, ex_gw_ip))

        return [dont_snat_traffic_to_internal_ports_if_not_to_floating_ip,
                snat_normal_external_traffic,
                snat_internal_traffic_to_floating_ip]

    def external_gateway_mangle_rules(self, interface_name):
        mark = self.agent_conf.external_ingress_mark
        mark_packets_entering_external_gateway_port = (
            'mark', '-i %s -j MARK --set-xmark %s/%s' %
                    (interface_name, mark, l3_constants.ROUTER_MARK_MASK))
        return [mark_packets_entering_external_gateway_port]

    def _empty_snat_chains(self, iptables_manager):
        iptables_manager.ipv4['nat'].empty_chain('POSTROUTING')
        iptables_manager.ipv4['nat'].empty_chain('snat')
        iptables_manager.ipv4['mangle'].empty_chain('mark')

    def _add_snat_rules(self, ex_gw_port, iptables_manager,
                        interface_name):
        if self._snat_enabled and ex_gw_port:
            # ex_gw_port should not be None in this case
            # NAT rules are added only if ex_gw_port has an IPv4 address
            for ip_addr in ex_gw_port['fixed_ips']:
                ex_gw_ip = ip_addr['ip_address']
                if netaddr.IPAddress(ex_gw_ip).version == 4:
                    rules = self.external_gateway_nat_rules(ex_gw_ip,
                                                            interface_name)
                    for rule in rules:
                        iptables_manager.ipv4['nat'].add_rule(*rule)
                    rules = self.external_gateway_mangle_rules(interface_name)
                    for rule in rules:
                        iptables_manager.ipv4['mangle'].add_rule(*rule)
                    break

    def _handle_router_snat_rules(self, ex_gw_port, interface_name):
        self._empty_snat_chains(self.iptables_manager)

        self.iptables_manager.ipv4['nat'].add_rule('snat', '-j $float-snat')

        self._add_snat_rules(ex_gw_port,
                             self.iptables_manager,
                             interface_name)

    def process_external(self, agent):
        fip_statuses = {}
        existing_floating_ips = self.floating_ips
        try:
            with self.iptables_manager.defer_apply():
                ex_gw_port = self.get_ex_gw_port()
                self._process_external_gateway(ex_gw_port, agent.pd)
                if not ex_gw_port:
                    return

                # Process SNAT/DNAT rules and addresses for floating IPs
                self.process_snat_dnat_for_fip()

            # Once NAT rules for floating IPs are safely in place
            # configure their addresses on the external gateway port
            interface_name = self.get_external_device_interface_name(
                ex_gw_port)
            fip_statuses = self.configure_fip_addresses(interface_name)

        except (n_exc.FloatingIpSetupException,
                n_exc.IpTablesApplyException) as e:
                # All floating IPs must be put in error state
                LOG.exception(e)
                fip_statuses = self.put_fips_in_error_state()
        finally:
            agent.update_fip_statuses(
                self, existing_floating_ips, fip_statuses)

    @common_utils.exception_logger()
    def process(self, agent):
        """Process updates to this router

        This method is the point where the agent requests that updates be
        applied to this router.

        :param agent: Passes the agent in order to send RPC messages.
        """
        LOG.debug("process router updates")
        self._process_internal_ports(agent.pd)
        agent.pd.sync_router(self.router['id'])
        self.process_external(agent)
        # Process static routes for router
        self.routes_updated()

        # Update ex_gw_port and enable_snat on the router info cache
        self.ex_gw_port = self.get_ex_gw_port()
        # TODO(Carl) FWaaS uses this.  Why is it set after processing is done?
        self.enable_snat = self.router.get('enable_snat')
