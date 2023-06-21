# Copyright (c) 2014 OpenStack Foundation
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

import abc
import collections

import netaddr
from neutron_lib import constants as lib_constants
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.utils import helpers
from oslo_log import log as logging
from oslo_utils import netutils
from pyroute2.netlink import exceptions as pyroute2_exc

from neutron._i18n import _
from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.agent.linux import ra
from neutron.common import coordination
from neutron.common import ipv6_utils
from neutron.common import utils as common_utils
from neutron.ipam import utils as ipam_utils

LOG = logging.getLogger(__name__)
INTERNAL_DEV_PREFIX = namespaces.INTERNAL_DEV_PREFIX
EXTERNAL_DEV_PREFIX = namespaces.EXTERNAL_DEV_PREFIX

FLOATINGIP_STATUS_NOCHANGE = object()
ADDRESS_SCOPE_MARK_MASK = "0xffff0000"
ADDRESS_SCOPE_MARK_ID_MIN = 1024
ADDRESS_SCOPE_MARK_ID_MAX = 2048
DEFAULT_ADDRESS_SCOPE = "noscope"


class BaseRouterInfo(object, metaclass=abc.ABCMeta):

    def __init__(self,
                 agent,
                 router_id,
                 router,
                 agent_conf,
                 interface_driver,
                 use_ipv6=False):
        self.agent = agent
        self.router_id = router_id
        # Invoke the setter for establishing initial SNAT action
        self._snat_enabled = None
        self.router = router
        self.agent_conf = agent_conf
        self.driver = interface_driver
        self.use_ipv6 = use_ipv6

        self.internal_ports = []
        self.ns_name = None
        self.process_monitor = None

    def initialize(self, process_monitor):
        """Initialize the router on the system.

        This differs from __init__ in that this method actually affects the
        system creating namespaces, starting processes, etc.  The other merely
        initializes the python object.  This separates in-memory object
        initialization from methods that actually go do stuff to the system.

        :param process_monitor: The agent's process monitor instance.
        """
        self.process_monitor = process_monitor

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

    @abc.abstractmethod
    def delete(self, agent):
        pass

    @abc.abstractmethod
    def process(self, agent):
        """Process updates to this router

        This method is the point where the agent requests that updates be
        applied to this router.

        :param agent: Passes the agent in order to send RPC messages.
        """
        pass

    def get_ex_gw_port(self):
        return self.router.get('gw_port')

    def get_gw_ns_name(self):
        return self.ns_name

    def get_internal_device_name(self, port_id):
        return (INTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_external_device_name(self, port_id):
        return (EXTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def get_external_device_interface_name(self, ex_gw_port):
        return self.get_external_device_name(ex_gw_port['id'])


class RouterInfo(BaseRouterInfo):

    def __init__(self,
                 agent,
                 router_id,
                 router,
                 agent_conf,
                 interface_driver,
                 use_ipv6=False):
        super(RouterInfo, self).__init__(agent, router_id, router, agent_conf,
                                         interface_driver, use_ipv6)

        self.ex_gw_port = None
        self.fip_map = {}
        self.pd_subnets = {}
        self.floating_ips = set()
        ns = self.create_router_namespace_object(
            router_id, agent_conf, interface_driver, use_ipv6)
        self.router_namespace = ns
        self.ns_name = ns.name
        self.available_mark_ids = set(range(ADDRESS_SCOPE_MARK_ID_MIN,
                                            ADDRESS_SCOPE_MARK_ID_MAX))
        self._address_scope_to_mark_id = {
            DEFAULT_ADDRESS_SCOPE: self.available_mark_ids.pop()}
        self.iptables_manager = iptables_manager.IptablesManager(
            use_ipv6=use_ipv6,
            namespace=self.ns_name)
        self.initialize_address_scope_iptables()
        self.initialize_metadata_iptables()
        self.routes = []
        # radvd is a neutron.agent.linux.ra.DaemonMonitor
        self.radvd = None
        self.centralized_port_forwarding_fip_set = set()
        self.fip_managed_by_port_forwardings = None
        self.qos_gateway_ips = set()

    def initialize(self, process_monitor):
        super(RouterInfo, self).initialize(process_monitor)
        self.radvd = ra.DaemonMonitor(self.router_id,
                                      self.ns_name,
                                      process_monitor,
                                      self.get_internal_device_name,
                                      self.agent_conf)

        self.router_namespace.create()

    def create_router_namespace_object(
            self, router_id, agent_conf, iface_driver, use_ipv6):
        return namespaces.RouterNamespace(
            router_id, agent_conf, iface_driver, use_ipv6)

    def is_router_primary(self):
        return True

    def _update_routing_table(self, operation, route, namespace):
        method = (ip_lib.add_ip_route if operation == 'replace' else
                  ip_lib.delete_ip_route)
        try:
            method(namespace, route['destination'], via=route['nexthop'])
        except (RuntimeError, OSError, pyroute2_exc.NetlinkError):
            pass

    def update_routing_table(self, operation, route):
        self._update_routing_table(operation, route, self.ns_name)

    def _update_routing_table_ecmp(self, route_list, namespace):
        multipath = [dict(via=route['nexthop'])
                     for route in route_list]
        try:
            ip_lib.add_ip_route(namespace, route_list[0]['destination'],
                                via=multipath)
        except (RuntimeError, OSError, pyroute2_exc.NetlinkError):
            pass

    def update_routing_table_ecmp(self, route_list):
        self._update_routing_table_ecmp(route_list, self.ns_name)

    def check_and_remove_ecmp_route(self, old_routes, remove_route):
        route_list = []
        for route in old_routes:
            if route['destination'] == remove_route['destination']:
                route_list.append(route)
        # An ECMP route is composed of multiple routes with the same
        # destination address, and two scenarios should be considered
        # when removing a nexthop address from an ECMP route.
        # a. The original ECMP route has only two nexthops, deleting
        #    one of them will make it a normal route.
        # b. The original ECMP route has more than two nexthops,
        #    delete one of the nexthops, it is still an ECMP route.
        if len(route_list) == 2:
            for r in route_list:
                if r['nexthop'] != remove_route['nexthop']:
                    self.update_routing_table('replace', r)
            return True

        if len(route_list) > 2:
            route_list.remove(remove_route)
            self.update_routing_table_ecmp(route_list)
            return True

        return False

    def check_and_add_ecmp_route(self, old_routes, new_route):
        route_list = []
        for route in old_routes:
            if route['destination'] == new_route['destination']:
                route_list.append(route)

        if route_list:
            route_list.append(new_route)
            self.update_routing_table_ecmp(route_list)
            return True

        return False

    def routes_updated(self, old_routes, new_routes):
        adds, removes = helpers.diff_list_of_dict(old_routes,
                                                  new_routes)
        for route in removes:
            # Judge if modifying an ECMP route or not, if not,
            # just delete it, if it is, replace it
            # update old_routes after modify
            if not self.check_and_remove_ecmp_route(old_routes, route):
                LOG.debug("Removed route entry is '%s'", route)
                self.update_routing_table('delete', route)
            old_routes.remove(route)

        for route in adds:
            if not self.check_and_add_ecmp_route(old_routes, route):
                LOG.debug("Added route entry is '%s'", route)
                # replace success even if there is no existing route
                self.update_routing_table('replace', route)
            old_routes.append(route)

    def get_floating_ips(self):
        """Filter Floating IPs to be hosted on this agent."""
        return self.router.get(lib_constants.FLOATINGIP_KEY, [])

    def get_port_forwarding_fips(self):
        """Get router port forwarding floating IPs."""
        return self.router.get('_pf_floatingips', [])

    def floating_forward_rules(self, fip):
        fixed_ip = fip['fixed_ip_address']
        floating_ip = fip['floating_ip_address']
        to_source = '-s %s/32 -j SNAT --to-source %s' % (fixed_ip, floating_ip)
        if self.iptables_manager.random_fully:
            to_source += ' --random-fully'
        return [('PREROUTING', '-d %s/32 -j DNAT --to-destination %s' %
                 (floating_ip, fixed_ip)),
                ('OUTPUT', '-d %s/32 -j DNAT --to-destination %s' %
                 (floating_ip, fixed_ip)),
                ('float-snat', to_source)]

    def floating_mangle_rules(self, floating_ip, fixed_ip, internal_mark):
        mark_traffic_to_floating_ip = (
            'floatingip', '-d %s/32 -j MARK --set-xmark %s' % (
                floating_ip, internal_mark))
        mark_traffic_from_fixed_ip = (
            'FORWARD', '-s %s/32 -j $float-snat' % fixed_ip)
        return [mark_traffic_to_floating_ip, mark_traffic_from_fixed_ip]

    def get_address_scope_mark_mask(self, address_scope=None):
        if not address_scope:
            address_scope = DEFAULT_ADDRESS_SCOPE

        if address_scope not in self._address_scope_to_mark_id:
            self._address_scope_to_mark_id[address_scope] = (
                self.available_mark_ids.pop())

        mark_id = self._address_scope_to_mark_id[address_scope]
        # NOTE: Address scopes use only the upper 16 bits of the 32 fwmark
        return "%s/%s" % (hex(mark_id << 16), ADDRESS_SCOPE_MARK_MASK)

    def get_port_address_scope_mark(self, port):
        """Get the IP version 4 and 6 address scope mark for the port

        :param port: A port dict from the RPC call
        :returns: A dict mapping the address family to the address scope mark
        """
        port_scopes = port.get('address_scopes', {})

        address_scope_mark_masks = (
            (int(k), self.get_address_scope_mark_mask(v))
            for k, v in port_scopes.items())
        return collections.defaultdict(self.get_address_scope_mark_mask,
                                       address_scope_mark_masks)

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
            for chain, rule in self.floating_forward_rules(fip):
                self.iptables_manager.ipv4['nat'].add_rule(chain, rule,
                                                           tag='floating_ip')

        self.iptables_manager.apply()

    def _process_pd_iptables_rules(self, prefix, subnet_id):
        """Configure iptables rules for prefix delegated subnets"""
        ext_scope = self._get_external_address_scope()
        ext_scope_mark = self.get_address_scope_mark_mask(ext_scope)
        ex_gw_device = self.get_external_device_name(
            self.get_ex_gw_port()['id'])
        scope_rule = self.address_scope_mangle_rule(ex_gw_device,
                                                    ext_scope_mark)
        self.iptables_manager.ipv6['mangle'].add_rule(
            'scope',
            '-d %s ' % prefix + scope_rule,
            tag=('prefix_delegation_%s' % subnet_id))

    def process_floating_ip_address_scope_rules(self):
        """Configure address scope related iptables rules for the router's
         floating IPs.
        """

        # Clear out all iptables rules for floating ips
        self.iptables_manager.ipv4['mangle'].clear_rules_by_tag('floating_ip')
        all_floating_ips = self.get_floating_ips()
        ext_scope = self._get_external_address_scope()
        # Filter out the floating ips that have fixed ip in the same address
        # scope. Because the packets for them will always be in one address
        # scope, no need to manipulate MARK/CONNMARK for them.
        floating_ips = [fip for fip in all_floating_ips
                        if fip.get('fixed_ip_address_scope') != ext_scope]
        if floating_ips:
            ext_scope_mark = self.get_address_scope_mark_mask(ext_scope)
            ports_scopemark = self._get_address_scope_mark()
            devices_in_ext_scope = {
                device for device, mark
                in ports_scopemark[lib_constants.IP_VERSION_4].items()
                if mark == ext_scope_mark}
            # Add address scope for floatingip egress
            for device in devices_in_ext_scope:
                self.iptables_manager.ipv4['mangle'].add_rule(
                    'float-snat',
                    '-o %s -j MARK --set-xmark %s'
                    % (device, ext_scope_mark),
                    tag='floating_ip')

        # Loop once to ensure that floating ips are configured.
        for fip in floating_ips:
            # Rebuild iptables rules for the floating ip.
            fip_ip = fip['floating_ip_address']
            # Send the floating ip traffic to the right address scope
            fixed_ip = fip['fixed_ip_address']
            fixed_scope = fip.get('fixed_ip_address_scope')
            internal_mark = self.get_address_scope_mark_mask(fixed_scope)
            mangle_rules = self.floating_mangle_rules(
                fip_ip, fixed_ip, internal_mark)
            for chain, rule in mangle_rules:
                self.iptables_manager.ipv4['mangle'].add_rule(
                    chain, rule, tag='floating_ip')

    def process_snat_dnat_for_fip(self):
        try:
            self.process_floating_ip_nat_rules()
        except Exception:
            # TODO(salv-orlando): Less broad catching
            msg = _('L3 agent failure to setup NAT for floating IPs')
            LOG.exception(msg)
            raise l3_exc.FloatingIpSetupException(msg)

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
            LOG.warning("Unable to configure IP address for "
                        "floating IP: %s", fip['id'])

    def add_floating_ip(self, fip, interface_name, device):
        raise NotImplementedError()

    def migrate_centralized_floating_ip(self, fip, interface_name, device):
        """Implements centralized->distributed floating IP migration.
        Overridden in dvr_local_router.py
        """
        return FLOATINGIP_STATUS_NOCHANGE

    def gateway_redirect_cleanup(self, rtr_interface):
        pass

    def remove_floating_ip(self, device, ip_cidr):
        device.delete_addr_and_conntrack_state(ip_cidr)

    def move_floating_ip(self, fip):
        return lib_constants.FLOATINGIP_STATUS_ACTIVE

    def remove_external_gateway_ip(self, device, ip_cidr):
        device.delete_addr_and_conntrack_state(ip_cidr)

    def get_router_cidrs(self, device):
        return set([addr['cidr'] for addr in device.addr.list()])

    def get_centralized_fip_cidr_set(self):
        return set()

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
        gw_cidrs = self._get_gw_ips_cidr()
        centralized_fip_cidrs = self.get_centralized_fip_cidr_set()
        floating_ips = self.get_floating_ips()
        # Loop once to ensure that floating ips are configured.
        for fip in floating_ips:
            fip_ip = fip['floating_ip_address']
            ip_cidr = common_utils.ip_to_cidr(fip_ip)
            new_cidrs.add(ip_cidr)
            fip_statuses[fip['id']] = lib_constants.FLOATINGIP_STATUS_ACTIVE

            if ip_cidr not in existing_cidrs:
                fip_statuses[fip['id']] = self.add_floating_ip(
                    fip, interface_name, device)
                LOG.debug('Floating ip %(id)s added, status %(status)s',
                          {'id': fip['id'],
                           'status': fip_statuses.get(fip['id'])})
            elif (fip_ip in self.fip_map and
                  self.fip_map[fip_ip] != fip['fixed_ip_address']):
                LOG.debug("Floating IP was moved from fixed IP "
                          "%(old)s to %(new)s",
                          {'old': self.fip_map[fip_ip],
                           'new': fip['fixed_ip_address']})
                fip_statuses[fip['id']] = self.move_floating_ip(fip)
            elif (ip_cidr in centralized_fip_cidrs and
                  fip.get('host') == self.host):
                LOG.debug("Floating IP is migrating from centralized "
                          "to distributed: %s", fip)
                fip_statuses[fip['id']] = self.migrate_centralized_floating_ip(
                    fip, interface_name, device)
            elif fip_statuses[fip['id']] == fip['status']:
                # mark the status as not changed. we can't remove it because
                # that's how the caller determines that it was removed
                fip_statuses[fip['id']] = FLOATINGIP_STATUS_NOCHANGE
        fips_to_remove = (
            ip_cidr
            for ip_cidr in (existing_cidrs - new_cidrs - gw_cidrs -
                            self.centralized_port_forwarding_fip_set)
            if common_utils.is_cidr_host(ip_cidr))
        for ip_cidr in fips_to_remove:
            LOG.debug("Removing floating ip %s from interface %s in "
                      "namespace %s", ip_cidr, interface_name, self.ns_name)
            self.remove_floating_ip(device, ip_cidr)

        return fip_statuses

    def _get_gw_ips_cidr(self):
        gw_cidrs = set()
        ex_gw_port = self.get_ex_gw_port()
        if ex_gw_port:
            for ip_addr in ex_gw_port['fixed_ips']:
                ex_gw_ip = ip_addr['ip_address']
                addr = netaddr.IPAddress(ex_gw_ip)
                if addr.version == lib_constants.IP_VERSION_4:
                    gw_cidrs.add(common_utils.ip_to_cidr(ex_gw_ip))
        return gw_cidrs

    def configure_fip_addresses(self, interface_name):
        try:
            return self.process_floating_ip_addresses(interface_name)
        except Exception:
            # TODO(salv-orlando): Less broad catching
            msg = _('L3 agent failure to setup floating IPs')
            LOG.exception(msg)
            raise l3_exc.FloatingIpSetupException(msg)

    def put_fips_in_error_state(self):
        fip_statuses = {}
        for fip in self.router.get(lib_constants.FLOATINGIP_KEY, []):
            fip_statuses[fip['id']] = lib_constants.FLOATINGIP_STATUS_ERROR
        return fip_statuses

    def delete(self):
        self.router['gw_port'] = None
        self.router[lib_constants.INTERFACE_KEY] = []
        self.router[lib_constants.FLOATINGIP_KEY] = []
        self.process_delete()
        self.disable_radvd()
        self.router_namespace.delete()

    def _internal_network_updated(self, port, subnet_id, prefix, old_prefix,
                                  updated_cidrs):
        interface_name = self.get_internal_device_name(port['id'])
        if prefix != lib_constants.PROVISIONAL_IPV6_PD_PREFIX:
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
                                interface_name, prefix, mtu=None):
        LOG.debug("adding internal network: prefix(%s), port(%s)",
                  prefix, port_id)
        self.driver.plug(network_id, port_id, interface_name, mac_address,
                         namespace=ns_name,
                         prefix=prefix, mtu=mtu)

        ip_cidrs = common_utils.fixed_ip_cidrs(fixed_ips)
        self.driver.init_router_port(
            interface_name, ip_cidrs, namespace=ns_name)
        for fixed_ip in fixed_ips:
            ip_lib.send_ip_addr_adv_notif(ns_name,
                                          interface_name,
                                          fixed_ip['ip_address'])

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
                                     INTERNAL_DEV_PREFIX,
                                     mtu=port.get('mtu'))

    def internal_network_removed(self, port):
        interface_name = self.get_internal_device_name(port['id'])
        LOG.debug("removing internal network: port(%s) interface(%s)",
                  port['id'], interface_name)
        if ip_lib.device_exists(interface_name, namespace=self.ns_name):
            self.driver.unplug(interface_name, namespace=self.ns_name,
                               prefix=INTERNAL_DEV_PREFIX)

    def _get_existing_devices(self):
        ip_wrapper = ip_lib.IPWrapper(namespace=self.ns_name)
        ip_devs = ip_wrapper.get_devices()
        return [ip_dev.name for ip_dev in ip_devs]

    def _update_internal_ports_cache(self, port):
        # NOTE(slaweq): self.internal_ports is a list of port objects but
        # when it is updated in _process_internal_ports() method,
        # but it can be based only on indexes of elements in
        # self.internal_ports as index of element to updated is unknown.
        # It has to be done based on port_id and this method is doing exactly
        # that.
        for index, p in enumerate(self.internal_ports):
            if p['id'] == port['id']:
                self.internal_ports[index] = port
                break
        else:
            self.internal_ports.append(port)

    @staticmethod
    def _get_updated_ports(existing_ports, current_ports):
        updated_ports = []
        current_ports_dict = {p['id']: p for p in current_ports}
        for existing_port in existing_ports:
            current_port = current_ports_dict.get(existing_port['id'])
            if current_port:
                fixed_ips_changed = (
                    sorted(existing_port['fixed_ips'],
                           key=helpers.safe_sort_key) !=
                    sorted(current_port['fixed_ips'],
                           key=helpers.safe_sort_key))
                mtu_changed = existing_port['mtu'] != current_port['mtu']
                if fixed_ips_changed or mtu_changed:
                    updated_ports.append(current_port)
        return updated_ports

    @staticmethod
    def _port_has_ipv6_subnet(port):
        if 'subnets' in port:
            for subnet in port['subnets']:
                if (netaddr.IPNetwork(subnet['cidr']).version == 6 and
                        subnet['cidr'] !=
                        lib_constants.PROVISIONAL_IPV6_PD_PREFIX):
                    return True

    def enable_radvd(self, internal_ports=None):
        LOG.debug('Spawning radvd daemon in router device: %s', self.router_id)
        if not internal_ports:
            internal_ports = self.internal_ports
        self.radvd.enable(internal_ports)

    def disable_radvd(self):
        if self.radvd:
            LOG.debug('Terminating radvd daemon in router device: %s',
                      self.router_id)
            self.radvd.disable()

    def internal_network_updated(self, port):
        interface_name = self.get_internal_device_name(port['id'])
        ip_cidrs = common_utils.fixed_ip_cidrs(port['fixed_ips'])
        mtu = port['mtu']
        self.driver.set_mtu(interface_name, mtu, namespace=self.ns_name,
                            prefix=INTERNAL_DEV_PREFIX)
        self.driver.init_router_port(
            interface_name,
            ip_cidrs=ip_cidrs,
            namespace=self.ns_name)

    def address_scope_mangle_rule(self, device_name, mark_mask):
        return '-i %s -j MARK --set-xmark %s' % (device_name, mark_mask)

    def address_scope_filter_rule(self, device_name, mark_mask):
        return '-o %s -m mark ! --mark %s -j DROP' % (
            device_name, mark_mask)

    def _process_internal_ports(self):
        existing_port_ids = set(p['id'] for p in self.internal_ports)

        internal_ports = self.router.get(lib_constants.INTERFACE_KEY, [])
        current_port_ids = set(p['id'] for p in internal_ports
                               if p['admin_state_up'])

        new_port_ids = current_port_ids - existing_port_ids
        new_ports = [p for p in internal_ports if p['id'] in new_port_ids]
        old_ports = [p for p in self.internal_ports
                     if p['id'] not in current_port_ids]
        updated_ports = self._get_updated_ports(self.internal_ports,
                                                internal_ports)

        enable_ra = False
        for p in old_ports:
            self.internal_network_removed(p)
            LOG.debug("removing port %s from internal_ports cache", p)
            self.internal_ports.remove(p)
            enable_ra = enable_ra or self._port_has_ipv6_subnet(p)
            for subnet in p['subnets']:
                if ipv6_utils.is_ipv6_pd_enabled(subnet):
                    self.agent.pd.disable_subnet(self.router_id, subnet['id'])
                    self.pd_subnets.pop(subnet['id'], None)

        for p in new_ports:
            self.internal_network_added(p)
            LOG.debug("appending port %s to internal_ports cache", p)
            self._update_internal_ports_cache(p)
            enable_ra = enable_ra or self._port_has_ipv6_subnet(p)
            for subnet in p['subnets']:
                if ipv6_utils.is_ipv6_pd_enabled(subnet):
                    interface_name = self.get_internal_device_name(p['id'])
                    self.agent.pd.enable_subnet(self.router_id, subnet['id'],
                                                subnet['cidr'],
                                                interface_name,
                                                p['mac_address'])
                    if (subnet['cidr'] !=
                            lib_constants.PROVISIONAL_IPV6_PD_PREFIX):
                        self.pd_subnets[subnet['id']] = subnet['cidr']

        updated_cidrs = []
        for p in updated_ports:
            self._update_internal_ports_cache(p)
            updated_cidrs += common_utils.fixed_ip_cidrs(p['fixed_ips'])
            self.internal_network_updated(p)
            enable_ra = enable_ra or self._port_has_ipv6_subnet(p)

        # Check if there is any pd prefix update
        for p in internal_ports:
            if p['id'] in (set(current_port_ids) & set(existing_port_ids)):
                for subnet in p.get('subnets', []):
                    if ipv6_utils.is_ipv6_pd_enabled(subnet):
                        old_prefix = self.agent.pd.update_subnet(
                            self.router_id,
                            subnet['id'],
                            subnet['cidr'])
                        if old_prefix:
                            self._internal_network_updated(p, subnet['id'],
                                                           subnet['cidr'],
                                                           old_prefix,
                                                           updated_cidrs)
                            self.pd_subnets[subnet['id']] = subnet['cidr']
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
            self.agent.pd.remove_stale_ri_ifname(self.router_id, stale_dev)
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
                         namespace=ns_name,
                         prefix=EXTERNAL_DEV_PREFIX,
                         mtu=ex_gw_port.get('mtu'))

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

    def _add_route_to_gw(self, ex_gw_port, device_name,
                         namespace, preserve_ips):
        # Note: ipv6_gateway is an ipv6 LLA
        # and so doesn't need a special route
        for subnet in ex_gw_port.get('subnets', []):
            is_gateway_not_in_subnet = (subnet['gateway_ip'] and
                                        not ipam_utils.check_subnet_ip(
                                            subnet['cidr'],
                                            subnet['gateway_ip']))
            if is_gateway_not_in_subnet:
                preserve_ips.append(subnet['gateway_ip'])
                device = ip_lib.IPDevice(device_name, namespace=namespace)
                device.route.add_route(subnet['gateway_ip'], scope='link')

    def _configure_ipv6_params_on_gw(self, ex_gw_port, ns_name, interface_name,
                                     enabled):
        if not self.use_ipv6:
            return

        disable_ra = not enabled
        if enabled:
            gateway_ips = self._get_external_gw_ips(ex_gw_port)
            if not self.is_v6_gateway_set(gateway_ips):
                # There is no IPv6 gw_ip, use RouterAdvt for default route.
                self.driver.configure_ipv6_ra(
                    ns_name, interface_name,
                    lib_constants.ACCEPT_RA_WITH_FORWARDING)
            else:
                # Otherwise, disable it
                disable_ra = True
        if disable_ra:
            self.driver.configure_ipv6_ra(ns_name, interface_name,
                                          lib_constants.ACCEPT_RA_DISABLED)
        self.driver.configure_ipv6_forwarding(ns_name, interface_name, enabled)
        # This will make sure the 'all' setting is the same as the interface,
        # which is needed for forwarding to work.  Don't disable once it's
        # been enabled so as to not send spurious MLDv2 packets out.
        if enabled:
            self.driver.configure_ipv6_forwarding(ns_name, 'all', enabled)

    def _external_gateway_added(self, ex_gw_port, interface_name,
                                ns_name, preserve_ips):
        LOG.debug("External gateway added: port(%s), interface(%s), ns(%s)",
                  ex_gw_port, interface_name, ns_name)
        self._plug_external_gateway(ex_gw_port, interface_name, ns_name)

        # Build up the interface and gateway IP addresses that
        # will be added to the interface.
        ip_cidrs = common_utils.fixed_ip_cidrs(ex_gw_port['fixed_ips'])

        gateway_ips = self._get_external_gw_ips(ex_gw_port)

        self._add_route_to_gw(ex_gw_port, device_name=interface_name,
                              namespace=ns_name, preserve_ips=preserve_ips)
        self.driver.init_router_port(
            interface_name,
            ip_cidrs,
            namespace=ns_name,
            extra_subnets=ex_gw_port.get('extra_subnets', []),
            preserve_ips=preserve_ips,
            clean_connections=True)

        device = ip_lib.IPDevice(interface_name, namespace=ns_name)
        current_gateways = set()
        for ip_version in (lib_constants.IP_VERSION_4,
                           lib_constants.IP_VERSION_6):
            gateway = device.route.get_gateway(ip_version=ip_version)
            if gateway and gateway.get('via'):
                current_gateways.add(gateway.get('via'))
        for ip in current_gateways - set(gateway_ips):
            device.route.delete_gateway(ip)
        for ip in gateway_ips:
            device.route.add_gateway(ip)

        self._configure_ipv6_params_on_gw(ex_gw_port, ns_name, interface_name,
                                          True)

        for fixed_ip in ex_gw_port['fixed_ips']:
            ip_lib.send_ip_addr_adv_notif(ns_name,
                                          interface_name,
                                          fixed_ip['ip_address'])

    def is_v6_gateway_set(self, gateway_ips):
        """Check to see if list of gateway_ips has an IPv6 gateway.
        """
        # Note - don't require a try-except here as all
        # gateway_ips elements are valid addresses, if they exist.
        return any(netaddr.IPAddress(gw_ip).version == 6
                   for gw_ip in gateway_ips)

    def external_gateway_added(self, ex_gw_port, interface_name):
        preserve_ips = self._list_floating_ip_cidrs() + list(
            self.centralized_port_forwarding_fip_set)
        preserve_ips.extend(self.agent.pd.get_preserve_ips(self.router_id))
        self._external_gateway_added(
            ex_gw_port, interface_name, self.ns_name, preserve_ips)

    def external_gateway_updated(self, ex_gw_port, interface_name):
        preserve_ips = self._list_floating_ip_cidrs() + list(
            self.centralized_port_forwarding_fip_set)
        preserve_ips.extend(self.agent.pd.get_preserve_ips(self.router_id))
        self._external_gateway_added(
            ex_gw_port, interface_name, self.ns_name, preserve_ips)

    def external_gateway_removed(self, ex_gw_port, interface_name):
        LOG.debug("External gateway removed: port(%s), interface(%s)",
                  ex_gw_port, interface_name)
        device = ip_lib.IPDevice(interface_name, namespace=self.ns_name)
        for ip_addr in ex_gw_port['fixed_ips']:
            prefixlen = ip_addr.get('prefixlen')
            self.remove_external_gateway_ip(device,
                                            common_utils.ip_to_cidr(
                                                ip_addr['ip_address'],
                                                prefixlen))
        self.driver.unplug(interface_name,
                           namespace=self.ns_name,
                           prefix=EXTERNAL_DEV_PREFIX)

    @staticmethod
    def _gateway_ports_equal(port1, port2):
        return port1 == port2

    def _delete_stale_external_devices(self, interface_name):
        existing_devices = self._get_existing_devices()
        stale_devs = [dev for dev in existing_devices
                      if dev.startswith(EXTERNAL_DEV_PREFIX) and
                      dev != interface_name]
        for stale_dev in stale_devs:
            LOG.debug('Deleting stale external router device: %s', stale_dev)
            self.agent.pd.remove_gw_interface(self.router['id'])
            self.driver.unplug(stale_dev,
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
            if not self.ex_gw_port:
                self.external_gateway_added(ex_gw_port, interface_name)
                self.agent.pd.add_gw_interface(self.router['id'],
                                               interface_name)
            elif not self._gateway_ports_equal(ex_gw_port, self.ex_gw_port):
                self.external_gateway_updated(ex_gw_port, interface_name)
        elif not ex_gw_port and self.ex_gw_port:
            self.external_gateway_removed(self.ex_gw_port, interface_name)
            self.agent.pd.remove_gw_interface(self.router['id'])
        elif not ex_gw_port and not self.ex_gw_port:
            for p in self.internal_ports:
                interface_name = self.get_internal_device_name(p['id'])
                self.gateway_redirect_cleanup(interface_name)

        self._delete_stale_external_devices(interface_name)

        # Process SNAT rules for external gateway
        gw_port = self._router.get('gw_port')
        self._handle_router_snat_rules(gw_port, interface_name)

    def _prevent_snat_for_internal_traffic_rule(self, interface_name):
        return (
            'POSTROUTING', '! -o %(interface_name)s -m conntrack '
                           '! --ctstate DNAT -j ACCEPT' %
            {'interface_name': interface_name})

    def external_gateway_nat_fip_rules(self, ex_gw_ip, interface_name):
        dont_snat_traffic_to_internal_ports_if_not_to_floating_ip = (
            self._prevent_snat_for_internal_traffic_rule(interface_name))
        # Makes replies come back through the router to reverse DNAT
        ext_in_mark = self.agent_conf.external_ingress_mark
        to_source = ('-m mark ! --mark %s/%s '
                     '-m conntrack --ctstate DNAT '
                     '-j SNAT --to-source %s'
                     % (ext_in_mark, lib_constants.ROUTER_MARK_MASK, ex_gw_ip))
        if self.iptables_manager.random_fully:
            to_source += ' --random-fully'
        snat_internal_traffic_to_floating_ip = ('snat', to_source)
        return [dont_snat_traffic_to_internal_ports_if_not_to_floating_ip,
                snat_internal_traffic_to_floating_ip]

    def external_gateway_nat_snat_rules(self, ex_gw_ip, interface_name):
        to_source = '-o %s -j SNAT --to-source %s' % (interface_name, ex_gw_ip)
        if self.iptables_manager.random_fully:
            to_source += ' --random-fully'
        return [('snat', to_source)]

    def external_gateway_mangle_rules(self, interface_name):
        mark = self.agent_conf.external_ingress_mark
        mark_packets_entering_external_gateway_port = (
            'mark', '-i %s -j MARK --set-xmark %s/%s' %
            (interface_name, mark, lib_constants.ROUTER_MARK_MASK))
        return [mark_packets_entering_external_gateway_port]

    def _empty_snat_chains(self, iptables_manager):
        iptables_manager.ipv4['nat'].empty_chain('POSTROUTING')
        iptables_manager.ipv4['nat'].empty_chain('snat')
        iptables_manager.ipv4['mangle'].empty_chain('mark')
        iptables_manager.ipv4['mangle'].empty_chain('POSTROUTING')

    def _add_snat_rules(self, ex_gw_port, iptables_manager,
                        interface_name):
        self.process_external_port_address_scope_routing(iptables_manager)

        if ex_gw_port:
            # ex_gw_port should not be None in this case
            # NAT rules are added only if ex_gw_port has an IPv4 address
            for ip_addr in ex_gw_port['fixed_ips']:
                ex_gw_ip = ip_addr['ip_address']
                if netaddr.IPAddress(ex_gw_ip).version == 4:
                    if self._snat_enabled:
                        rules = self.external_gateway_nat_snat_rules(
                            ex_gw_ip, interface_name)
                        for rule in rules:
                            iptables_manager.ipv4['nat'].add_rule(*rule)

                    rules = self.external_gateway_nat_fip_rules(
                        ex_gw_ip, interface_name)
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

    def _process_external_on_delete(self):
        fip_statuses = {}
        try:
            ex_gw_port = self.get_ex_gw_port()
            self._process_external_gateway(ex_gw_port)
            if not ex_gw_port:
                return

            interface_name = self.get_external_device_interface_name(
                ex_gw_port)
            fip_statuses = self.configure_fip_addresses(interface_name)

        except l3_exc.FloatingIpSetupException:
            # All floating IPs must be put in error state
            LOG.exception("Failed to process floating IPs.")
            fip_statuses = self.put_fips_in_error_state()
        finally:
            self.update_fip_statuses(fip_statuses)

    @coordination.synchronized('router-lock-ns-{self.ns_name}')
    def process_external(self):
        fip_statuses = {}
        try:
            with self.iptables_manager.defer_apply():
                ex_gw_port = self.get_ex_gw_port()
                self._process_external_gateway(ex_gw_port)
                if not ex_gw_port:
                    return

                # Process SNAT/DNAT rules and addresses for floating IPs
                self.process_snat_dnat_for_fip()

            # Once NAT rules for floating IPs are safely in place
            # configure their addresses on the external gateway port
            interface_name = self.get_external_device_interface_name(
                ex_gw_port)
            fip_statuses = self.configure_fip_addresses(interface_name)

        except (l3_exc.FloatingIpSetupException,
                l3_exc.IpTablesApplyException):
            # All floating IPs must be put in error state
            LOG.exception("Failed to process floating IPs.")
            fip_statuses = self.put_fips_in_error_state()
        finally:
            self.update_fip_statuses(fip_statuses)

    def update_fip_statuses(self, fip_statuses):
        # Identify floating IPs which were disabled
        existing_floating_ips = self.floating_ips
        self.floating_ips = set(fip_statuses.keys())
        for fip_id in existing_floating_ips - self.floating_ips:
            fip_statuses[fip_id] = lib_constants.FLOATINGIP_STATUS_DOWN
        # filter out statuses that didn't change
        fip_statuses = {f: stat for f, stat in fip_statuses.items()
                        if stat != FLOATINGIP_STATUS_NOCHANGE}
        if not fip_statuses:
            return
        LOG.debug('Sending floating ip statuses: %s', fip_statuses)
        # Update floating IP status on the neutron server
        self.agent.plugin_rpc.update_floatingip_statuses(
            self.agent.context, self.router_id, fip_statuses)

    def initialize_address_scope_iptables(self):
        self._initialize_address_scope_iptables(self.iptables_manager)

    def _initialize_address_scope_iptables(self, iptables_manager):
        # Add address scope related chains
        iptables_manager.ipv4['mangle'].add_chain('scope')
        iptables_manager.ipv6['mangle'].add_chain('scope')

        iptables_manager.ipv4['mangle'].add_chain('floatingip')
        iptables_manager.ipv4['mangle'].add_chain('float-snat')

        iptables_manager.ipv4['filter'].add_chain('scope')
        iptables_manager.ipv6['filter'].add_chain('scope')
        iptables_manager.ipv4['filter'].add_rule('FORWARD', '-j $scope')
        iptables_manager.ipv6['filter'].add_rule('FORWARD', '-j $scope')

        # Add rules for marking traffic for address scopes
        mark_new_ingress_address_scope_by_interface = (
            '-j $scope')
        copy_address_scope_for_existing = (
            '-m connmark ! --mark 0x0/0xffff0000 '
            '-j CONNMARK --restore-mark '
            '--nfmask 0xffff0000 --ctmask 0xffff0000')
        mark_new_ingress_address_scope_by_floatingip = (
            '-j $floatingip')
        save_mark_to_connmark = (
            '-m connmark --mark 0x0/0xffff0000 '
            '-j CONNMARK --save-mark '
            '--nfmask 0xffff0000 --ctmask 0xffff0000')

        iptables_manager.ipv4['mangle'].add_rule(
            'PREROUTING', mark_new_ingress_address_scope_by_interface)
        iptables_manager.ipv4['mangle'].add_rule(
            'PREROUTING', copy_address_scope_for_existing)
        # The floating ip scope rules must come after the CONNTRACK rules
        # because the (CONN)MARK targets are non-terminating (this is true
        # despite them not being documented as such) and the floating ip
        # rules need to override the mark from CONNMARK to cross scopes.
        iptables_manager.ipv4['mangle'].add_rule(
            'PREROUTING', mark_new_ingress_address_scope_by_floatingip)
        iptables_manager.ipv4['mangle'].add_rule(
            'float-snat', save_mark_to_connmark)
        iptables_manager.ipv6['mangle'].add_rule(
            'PREROUTING', mark_new_ingress_address_scope_by_interface)
        iptables_manager.ipv6['mangle'].add_rule(
            'PREROUTING', copy_address_scope_for_existing)

    def initialize_metadata_iptables(self):
        # Always mark incoming metadata requests, that way any stray
        # requests that arrive before the filter metadata redirect
        # rule is installed will be dropped.
        mark_metadata_for_internal_interfaces = (
            '-d %(metadata_cidr)s '
            '-i %(interface_name)s '
            '-p tcp -m tcp --dport 80 '
            '-j MARK --set-xmark %(value)s/%(mask)s' %
            {'metadata_cidr': lib_constants.METADATA_V4_CIDR,
             'interface_name': INTERNAL_DEV_PREFIX + '+',
             'value': self.agent_conf.metadata_access_mark,
             'mask': lib_constants.ROUTER_MARK_MASK})
        drop_non_local_metadata = (
            '-m mark --mark %s/%s -j DROP' % (
                self.agent_conf.metadata_access_mark,
                lib_constants.ROUTER_MARK_MASK))
        self.iptables_manager.ipv4['mangle'].add_rule(
            'PREROUTING', mark_metadata_for_internal_interfaces)
        self.iptables_manager.ipv4['filter'].add_rule(
            'scope', drop_non_local_metadata)

        if netutils.is_ipv6_enabled():
            mark_metadata_v6_for_internal_interfaces = (
                '-d %(metadata_v6_ip)s/128 '
                '-i %(interface_name)s '
                '-p tcp -m tcp --dport 80 '
                '-j MARK --set-xmark %(value)s/%(mask)s' %
                {'metadata_v6_ip': lib_constants.METADATA_V6_IP,
                 'interface_name': INTERNAL_DEV_PREFIX + '+',
                 'value': self.agent_conf.metadata_access_mark,
                 'mask': lib_constants.ROUTER_MARK_MASK})
            drop_non_local_v6_metadata = (
                '-m mark --mark %s/%s -j DROP' % (
                    self.agent_conf.metadata_access_mark,
                    lib_constants.ROUTER_MARK_MASK))
            self.iptables_manager.ipv6['mangle'].add_rule(
                'PREROUTING', mark_metadata_v6_for_internal_interfaces)
            self.iptables_manager.ipv6['filter'].add_rule(
                'scope', drop_non_local_v6_metadata)

    def _get_port_devicename_scopemark(
            self, ports, name_generator, interface_name=None):
        devicename_scopemark = {lib_constants.IP_VERSION_4: dict(),
                                lib_constants.IP_VERSION_6: dict()}
        for p in ports:
            if interface_name is None:
                device_name = name_generator(p['id'])
            else:
                device_name = interface_name
            ip_cidrs = common_utils.fixed_ip_cidrs(p['fixed_ips'])
            port_as_marks = self.get_port_address_scope_mark(p)
            for ip_version in {common_utils.get_ip_version(cidr)
                               for cidr in ip_cidrs}:
                devicename_scopemark[ip_version][device_name] = (
                    port_as_marks[ip_version])

        return devicename_scopemark

    def _get_address_scope_mark(self):
        # Prepare address scope iptables rule for internal ports
        internal_ports = self.router.get(lib_constants.INTERFACE_KEY, [])
        ports_scopemark = self._get_port_devicename_scopemark(
            internal_ports, self.get_internal_device_name)

        # Prepare address scope iptables rule for external port
        external_port = self.get_ex_gw_port()
        if external_port:
            external_port_scopemark = self._get_port_devicename_scopemark(
                [external_port], self.get_external_device_name)
            for ip_version in (lib_constants.IP_VERSION_4,
                               lib_constants.IP_VERSION_6):
                ports_scopemark[ip_version].update(
                    external_port_scopemark[ip_version])
        return ports_scopemark

    def _add_address_scope_mark(self, iptables_manager, ports_scopemark):
        external_device_name = None
        external_port = self.get_ex_gw_port()
        if external_port:
            external_device_name = self.get_external_device_name(
                external_port['id'])

        # Process address scope iptables rules
        for ip_version in (lib_constants.IP_VERSION_4,
                           lib_constants.IP_VERSION_6):
            scopemarks = ports_scopemark[ip_version]
            iptables = iptables_manager.get_tables(ip_version)
            iptables['mangle'].empty_chain('scope')
            iptables['filter'].empty_chain('scope')
            dont_block_external = (ip_version == lib_constants.IP_VERSION_4 and
                                   self._snat_enabled and external_port)
            for device_name, mark in scopemarks.items():
                # Add address scope iptables rule
                iptables['mangle'].add_rule(
                    'scope',
                    self.address_scope_mangle_rule(device_name, mark))
                if dont_block_external and device_name == external_device_name:
                    continue
                iptables['filter'].add_rule(
                    'scope',
                    self.address_scope_filter_rule(device_name, mark))
        for subnet_id, prefix in self.pd_subnets.items():
            if prefix != lib_constants.PROVISIONAL_IPV6_PD_PREFIX:
                self._process_pd_iptables_rules(prefix, subnet_id)

    def process_ports_address_scope_iptables(self):
        ports_scopemark = self._get_address_scope_mark()
        self._add_address_scope_mark(self.iptables_manager, ports_scopemark)

    def _get_external_address_scope(self):
        external_port = self.get_ex_gw_port()
        if not external_port:
            return

        scopes = external_port.get('address_scopes', {})
        return scopes.get(str(lib_constants.IP_VERSION_4))

    def process_external_port_address_scope_routing(self, iptables_manager):
        if not self._snat_enabled:
            return

        external_port = self.get_ex_gw_port()
        if not external_port:
            return

        external_devicename = self.get_external_device_name(
            external_port['id'])

        # Saves the originating address scope by saving the packet MARK to
        # the CONNMARK for new connections so that returning traffic can be
        # match to it.
        rule = ('-o %s -m connmark --mark 0x0/0xffff0000 '
                '-j CONNMARK --save-mark '
                '--nfmask 0xffff0000 --ctmask 0xffff0000' %
                external_devicename)

        iptables_manager.ipv4['mangle'].add_rule('POSTROUTING', rule)

        address_scope = self._get_external_address_scope()
        if not address_scope:
            return

        # Prevents snat within the same address scope
        rule = '-o %s -m connmark --mark %s -j ACCEPT' % (
            external_devicename,
            self.get_address_scope_mark_mask(address_scope))
        iptables_manager.ipv4['nat'].add_rule('snat', rule)

    @coordination.synchronized('router-lock-ns-{self.ns_name}')
    def process_address_scope(self):
        with self.iptables_manager.defer_apply():
            self.process_ports_address_scope_iptables()
            self.process_floating_ip_address_scope_rules()

    @common_utils.exception_logger()
    def process_delete(self):
        """Process the delete of this router

        This method is the point where the agent requests that this router
        be deleted. This is a separate code path from process in that it
        avoids any changes to the qrouter namespace that will be removed
        at the end of the operation.

        :param agent: Passes the agent in order to send RPC messages.
        """
        LOG.debug("Process delete, router %s", self.router['id'])
        if self.router_namespace.exists():
            self._process_internal_ports()
            self.agent.pd.sync_router(self.router['id'])
            self._process_external_on_delete()
        else:
            LOG.warning("Can't gracefully delete the router %s: "
                        "no router namespace found", self.router['id'])

    @common_utils.exception_logger()
    def process(self):
        LOG.debug("Process updates, router %s", self.router['id'])
        self.centralized_port_forwarding_fip_set = set(self.router.get(
            'port_forwardings_fip_set', set()))
        self._process_internal_ports()
        self.agent.pd.sync_router(self.router['id'])
        self.process_external()
        self.process_address_scope()
        # Process static routes for router
        self.routes_updated(self.routes, self.router['routes'])
        self.routes = self.router['routes']

        # Update ex_gw_port on the router info cache
        self.ex_gw_port = self.get_ex_gw_port()
        self.fip_map = dict((fip['floating_ip_address'],
                             fip['fixed_ip_address'])
                            for fip in self.get_floating_ips())
        self.fip_managed_by_port_forwardings = self.router.get(
            'fip_managed_by_port_forwardings')
