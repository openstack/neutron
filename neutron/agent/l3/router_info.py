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
from neutron.common import utils as common_utils
from neutron.i18n import _LW

LOG = logging.getLogger(__name__)
INTERNAL_DEV_PREFIX = namespaces.INTERNAL_DEV_PREFIX
EXTERNAL_DEV_PREFIX = namespaces.EXTERNAL_DEV_PREFIX

EXTERNAL_INGRESS_MARK_MASK = '0xffffffff'
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

    def get_external_device_name(self, port_id):
        return (EXTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_external_device_interface_name(self, ex_gw_port):
        return self.get_external_device_name(ex_gw_port['id'])

    def perform_snat_action(self, snat_callback, *args):
        # Process SNAT rules for attached subnets
        if self._snat_action:
            snat_callback(self._router.get('gw_port'),
                          *args,
                          action=self._snat_action)
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
        device.addr.delete(ip_cidr)
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
                LOG.debug('Floating ip %(id)s added, status %(status)s',
                          {'id': fip['id'],
                           'status': fip_statuses.get(fip['id'])})
            elif fip_statuses[fip['id']] == fip['status']:
                # mark the status as not changed. we can't remove it because
                # that's how the caller determines that it was removed
                fip_statuses[fip['id']] = FLOATINGIP_STATUS_NOCHANGE
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

    def delete(self, agent):
        self.router['gw_port'] = None
        self.router[l3_constants.INTERFACE_KEY] = []
        self.router[l3_constants.FLOATINGIP_KEY] = []
        self.process(agent)
        self.disable_radvd()
        if self.router_namespace:
            self.router_namespace.delete()

    def _internal_network_added(self, ns_name, network_id, port_id,
                                fixed_ips, mac_address,
                                interface_name, prefix):
        if not ip_lib.device_exists(interface_name,
                                    namespace=ns_name):
            self.driver.plug(network_id, port_id, interface_name, mac_address,
                             namespace=ns_name,
                             prefix=prefix)

        ip_cidrs = common_utils.fixed_ip_cidrs(fixed_ips)
        self.driver.init_l3(interface_name, ip_cidrs, namespace=ns_name)
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
                if sorted(existing_port['fixed_ips']) != (
                        sorted(current_port['fixed_ips'])):
                    updated_ports[current_port['id']] = current_port
        return updated_ports

    @staticmethod
    def _port_has_ipv6_subnet(port):
        if 'subnets' in port:
            for subnet in port['subnets']:
                if netaddr.IPNetwork(subnet['cidr']).version == 6:
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

    def _process_internal_ports(self):
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
            self.internal_ports.append(p)
            enable_ra = enable_ra or self._port_has_ipv6_subnet(p)

        for p in old_ports:
            self.internal_network_removed(p)
            self.internal_ports.remove(p)
            enable_ra = enable_ra or self._port_has_ipv6_subnet(p)

        if updated_ports:
            for index, p in enumerate(internal_ports):
                if not updated_ports.get(p['id']):
                    continue
                self.internal_ports[index] = updated_ports[p['id']]
                interface_name = self.get_internal_device_name(p['id'])
                ip_cidrs = common_utils.fixed_ip_cidrs(p['fixed_ips'])
                self.internal_network_updated(interface_name, ip_cidrs)
                enable_ra = enable_ra or self._port_has_ipv6_subnet(p)

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
        if not ip_lib.device_exists(interface_name, namespace=ns_name):
            self.driver.plug(ex_gw_port['network_id'],
                             ex_gw_port['id'],
                             interface_name,
                             ex_gw_port['mac_address'],
                             bridge=self.agent_conf.external_network_bridge,
                             namespace=ns_name,
                             prefix=EXTERNAL_DEV_PREFIX)

    def _get_external_gw_ips(self, ex_gw_port):
        gateway_ips = []
        if 'subnets' in ex_gw_port:
            gateway_ips = [subnet['gateway_ip']
                           for subnet in ex_gw_port['subnets']
                           if subnet['gateway_ip']]
        if self.use_ipv6 and not self.is_v6_gateway_set(gateway_ips):
            # No IPv6 gateway is available, but IPv6 is enabled.
            if self.agent_conf.ipv6_gateway:
                # ipv6_gateway configured, use address for default route.
                gateway_ips.append(self.agent_conf.ipv6_gateway)
        return gateway_ips

    def _external_gateway_added(self, ex_gw_port, interface_name,
                                ns_name, preserve_ips):
        self._plug_external_gateway(ex_gw_port, interface_name, ns_name)

        # Build up the interface and gateway IP addresses that
        # will be added to the interface.
        ip_cidrs = common_utils.fixed_ip_cidrs(ex_gw_port['fixed_ips'])

        gateway_ips = self._get_external_gw_ips(ex_gw_port)
        enable_ra_on_gw = False
        if self.use_ipv6 and not self.is_v6_gateway_set(gateway_ips):
            # There is no IPv6 gw_ip, use RouterAdvt for default route.
            enable_ra_on_gw = True
        self.driver.init_l3(interface_name,
                            ip_cidrs,
                            namespace=ns_name,
                            gateway_ips=gateway_ips,
                            extra_subnets=ex_gw_port.get('extra_subnets', []),
                            preserve_ips=preserve_ips,
                            enable_ra_on_gw=enable_ra_on_gw)
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
        self.driver.unplug(interface_name,
                           bridge=self.agent_conf.external_network_bridge,
                           namespace=self.ns_name,
                           prefix=EXTERNAL_DEV_PREFIX)

    def _process_external_gateway(self, ex_gw_port):
        # TODO(Carl) Refactor to clarify roles of ex_gw_port vs self.ex_gw_port
        ex_gw_port_id = (ex_gw_port and ex_gw_port['id'] or
                         self.ex_gw_port and self.ex_gw_port['id'])

        interface_name = None
        if ex_gw_port_id:
            interface_name = self.get_external_device_name(ex_gw_port_id)
        if ex_gw_port:
            def _gateway_ports_equal(port1, port2):
                def _get_filtered_dict(d, ignore):
                    return dict((k, v) for k, v in d.iteritems()
                                if k not in ignore)

                keys_to_ignore = set(['binding:host_id'])
                port1_filtered = _get_filtered_dict(port1, keys_to_ignore)
                port2_filtered = _get_filtered_dict(port2, keys_to_ignore)
                return port1_filtered == port2_filtered

            if not self.ex_gw_port:
                self.external_gateway_added(ex_gw_port, interface_name)
            elif not _gateway_ports_equal(ex_gw_port, self.ex_gw_port):
                self.external_gateway_updated(ex_gw_port, interface_name)
        elif not ex_gw_port and self.ex_gw_port:
            self.external_gateway_removed(self.ex_gw_port, interface_name)

        existing_devices = self._get_existing_devices()
        stale_devs = [dev for dev in existing_devices
                      if dev.startswith(EXTERNAL_DEV_PREFIX)
                      and dev != interface_name]
        for stale_dev in stale_devs:
            LOG.debug('Deleting stale external router device: %s', stale_dev)
            self.driver.unplug(stale_dev,
                               bridge=self.agent_conf.external_network_bridge,
                               namespace=self.ns_name,
                               prefix=EXTERNAL_DEV_PREFIX)

        # Process SNAT rules for external gateway
        self.perform_snat_action(self._handle_router_snat_rules,
                                 interface_name)

    def external_gateway_nat_rules(self, ex_gw_ip, interface_name):
        mark = self.agent_conf.external_ingress_mark
        rules = [('POSTROUTING', '! -i %(interface_name)s '
                  '! -o %(interface_name)s -m conntrack ! '
                  '--ctstate DNAT -j ACCEPT' %
                  {'interface_name': interface_name}),
                 ('snat', '-o %s -j SNAT --to-source %s' %
                  (interface_name, ex_gw_ip)),
                 ('snat', '-m mark ! --mark %s '
                  '-m conntrack --ctstate DNAT '
                  '-j SNAT --to-source %s' % (mark, ex_gw_ip))]
        return rules

    def external_gateway_mangle_rules(self, interface_name):
        mark = self.agent_conf.external_ingress_mark
        rules = [('mark', '-i %s -j MARK --set-xmark %s/%s' %
                 (interface_name, mark, EXTERNAL_INGRESS_MARK_MASK))]
        return rules

    def _empty_snat_chains(self, iptables_manager):
        iptables_manager.ipv4['nat'].empty_chain('POSTROUTING')
        iptables_manager.ipv4['nat'].empty_chain('snat')
        iptables_manager.ipv4['mangle'].empty_chain('mark')

    def _add_snat_rules(self, ex_gw_port, iptables_manager,
                        interface_name, action):
        if action == 'add_rules' and ex_gw_port:
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

    def _handle_router_snat_rules(self, ex_gw_port,
                                  interface_name, action):
        self._empty_snat_chains(self.iptables_manager)

        self.iptables_manager.ipv4['nat'].add_rule('snat', '-j $float-snat')

        self._add_snat_rules(ex_gw_port,
                             self.iptables_manager,
                             interface_name,
                             action)

    def process_external(self, agent):
        existing_floating_ips = self.floating_ips
        try:
            with self.iptables_manager.defer_apply():
                ex_gw_port = self.get_ex_gw_port()
                self._process_external_gateway(ex_gw_port)
                # TODO(Carl) Return after setting existing_floating_ips and
                # still call update_fip_statuses?
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

        agent.update_fip_statuses(self, existing_floating_ips, fip_statuses)

    @common_utils.exception_logger()
    def process(self, agent):
        """Process updates to this router

        This method is the point where the agent requests that updates be
        applied to this router.

        :param agent: Passes the agent in order to send RPC messages.
        """
        self._process_internal_ports()
        self.process_external(agent)
        # Process static routes for router
        self.routes_updated()

        # Update ex_gw_port and enable_snat on the router info cache
        self.ex_gw_port = self.get_ex_gw_port()
        self.snat_ports = self.router.get(
            l3_constants.SNAT_ROUTER_INTF_KEY, [])
        self.enable_snat = self.router.get('enable_snat')
