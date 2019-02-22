# Copyright 2012 OpenStack Foundation
# All Rights Reserved.
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

import errno
import re
import time

import eventlet
import netaddr
from neutron_lib import constants
from neutron_lib import exceptions
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from pyroute2.netlink import rtnl
from pyroute2.netlink.rtnl import ifaddrmsg
from pyroute2.netlink.rtnl import ifinfmsg
from pyroute2 import NetlinkError
from pyroute2 import netns

from neutron._i18n import _
from neutron.agent.common import utils
from neutron.common import ipv6_utils
from neutron.common import utils as common_utils
from neutron.privileged.agent.linux import ip_lib as privileged

LOG = logging.getLogger(__name__)


IP_NONLOCAL_BIND = 'net.ipv4.ip_nonlocal_bind'

LOOPBACK_DEVNAME = 'lo'
FB_TUNNEL_DEVICE_NAMES = ['gre0', 'gretap0', 'tunl0', 'erspan0', 'sit0',
                          'ip6tnl0', 'ip6gre0']
IP_RULE_TABLES = {'default': 253,
                  'main': 254,
                  'local': 255}

# Rule indexes: pyroute2.netlink.rtnl
# Rule names: https://www.systutorials.com/docs/linux/man/8-ip-rule/
# NOTE(ralonsoh): 'masquerade' type is printed as 'nat' in 'ip rule' command
IP_RULE_TYPES = {0: 'unspecified',
                 1: 'unicast',
                 6: 'blackhole',
                 7: 'unreachable',
                 8: 'prohibit',
                 10: 'nat'}

IP_ADDRESS_SCOPE = {rtnl.rtscopes['RT_SCOPE_UNIVERSE']: 'global',
                    rtnl.rtscopes['RT_SCOPE_SITE']: 'site',
                    rtnl.rtscopes['RT_SCOPE_LINK']: 'link',
                    rtnl.rtscopes['RT_SCOPE_HOST']: 'host'}

IP_ADDRESS_SCOPE_NAME = {v: k for k, v in IP_ADDRESS_SCOPE.items()}

SYS_NET_PATH = '/sys/class/net'
DEFAULT_GW_PATTERN = re.compile(r"via (\S+)")
METRIC_PATTERN = re.compile(r"metric (\S+)")
DEVICE_NAME_PATTERN = re.compile(r"(\d+?): (\S+?):.*")


def remove_interface_suffix(interface):
    """Remove a possible "<if>@<endpoint>" suffix from an interface' name.

    This suffix can appear in some kernel versions, and intends on specifying,
    for example, a veth's pair. However, this interface name is useless to us
    as further 'ip' commands require that the suffix be removed.
    """
    # If '@' is not present, this will do nothing.
    return interface.partition("@")[0]


class AddressNotReady(exceptions.NeutronException):
    message = _("Failure waiting for address %(address)s to "
                "become ready: %(reason)s")


class InvalidArgument(exceptions.NeutronException):
    message = _("Invalid value %(value)s for parameter %(parameter)s "
                "provided.")


class SubProcessBase(object):
    def __init__(self, namespace=None,
                 log_fail_as_error=True):
        self.namespace = namespace
        self.log_fail_as_error = log_fail_as_error
        try:
            self.force_root = cfg.CONF.ip_lib_force_root
        except cfg.NoSuchOptError:
            # Only callers that need to force use of the root helper
            # need to register the option.
            self.force_root = False

    def _run(self, options, command, args):
        if self.namespace:
            return self._as_root(options, command, args)
        elif self.force_root:
            # Force use of the root helper to ensure that commands
            # will execute in dom0 when running under XenServer/XCP.
            return self._execute(options, command, args, run_as_root=True)
        else:
            return self._execute(options, command, args)

    def _as_root(self, options, command, args, use_root_namespace=False):
        namespace = self.namespace if not use_root_namespace else None

        return self._execute(options, command, args, run_as_root=True,
                             namespace=namespace)

    def _execute(self, options, command, args, run_as_root=False,
                 namespace=None):
        opt_list = ['-%s' % o for o in options]
        ip_cmd = add_namespace_to_cmd(['ip'], namespace)
        cmd = ip_cmd + opt_list + [command] + list(args)
        return utils.execute(cmd, run_as_root=run_as_root,
                             log_fail_as_error=self.log_fail_as_error)

    def set_log_fail_as_error(self, fail_with_error):
        self.log_fail_as_error = fail_with_error

    def get_log_fail_as_error(self):
        return self.log_fail_as_error


class IPWrapper(SubProcessBase):
    def __init__(self, namespace=None):
        super(IPWrapper, self).__init__(namespace=namespace)
        self.netns = IpNetnsCommand(self)

    def device(self, name):
        return IPDevice(name, namespace=self.namespace)

    def get_devices_info(self, exclude_loopback=True,
                         exclude_fb_tun_devices=True):
        devices = get_devices_info(self.namespace)

        retval = []
        for device in devices:
            if (exclude_loopback and device['name'] == LOOPBACK_DEVNAME or
                    exclude_fb_tun_devices and
                    device['name'] in FB_TUNNEL_DEVICE_NAMES):
                continue
            retval.append(device)
        return retval

    def get_devices(self, exclude_loopback=True, exclude_fb_tun_devices=True):
        retval = []
        try:
            devices = privileged.get_device_names(self.namespace)
        except privileged.NetworkNamespaceNotFound:
            return retval

        for name in devices:
            if (exclude_loopback and name == LOOPBACK_DEVNAME or
                    exclude_fb_tun_devices and name in FB_TUNNEL_DEVICE_NAMES):
                continue
            retval.append(IPDevice(name, namespace=self.namespace))
        return retval

    def get_device_by_ip(self, ip):
        """Get the IPDevice from system which has ip configured.

        @param ip: look for the device holding this ip. If this is None,
                   None is returned.
        @type ip: str.
        """
        if not ip:
            return None

        cidr = common_utils.ip_to_cidr(ip)
        kwargs = {'address': common_utils.cidr_to_ip(cidr)}
        if not common_utils.is_cidr_host(cidr):
            kwargs['mask'] = common_utils.cidr_mask_length(cidr)
        devices = get_devices_with_ip(self.namespace, **kwargs)
        if not devices:
            # Search by broadcast address.
            broadcast = common_utils.cidr_broadcast_address(cidr)
            if broadcast:
                devices = get_devices_with_ip(self.namespace,
                                              broadcast=broadcast)

        if devices:
            return IPDevice(devices[0]['name'], namespace=self.namespace)

    def add_tuntap(self, name, mode='tap'):
        privileged.create_interface(
            name, self.namespace, "tuntap", mode=mode)
        return IPDevice(name, namespace=self.namespace)

    def add_veth(self, name1, name2, namespace2=None):
        peer = {'ifname': name2}

        if namespace2 is None:
            namespace2 = self.namespace
        else:
            self.ensure_namespace(namespace2)
            peer['net_ns_fd'] = namespace2

        privileged.create_interface(
            name1, self.namespace, 'veth', peer=peer)

        return (IPDevice(name1, namespace=self.namespace),
                IPDevice(name2, namespace=namespace2))

    def add_macvtap(self, name, src_dev, mode='bridge'):
        privileged.create_interface(name,
                                    self.namespace,
                                    "macvtap",
                                    physical_interface=src_dev,
                                    mode=mode)
        return IPDevice(name, namespace=self.namespace)

    def del_veth(self, name):
        """Delete a virtual interface between two namespaces."""
        privileged.delete_interface(name, self.namespace)

    def add_dummy(self, name):
        """Create a Linux dummy interface with the given name."""
        privileged.create_interface(name, self.namespace, "dummy")
        return IPDevice(name, namespace=self.namespace)

    def ensure_namespace(self, name):
        if not self.netns.exists(name):
            ip = self.netns.add(name)
            lo = ip.device(LOOPBACK_DEVNAME)
            lo.link.set_up()
        else:
            ip = IPWrapper(namespace=name)
        return ip

    def namespace_is_empty(self):
        return not self.get_devices()

    def garbage_collect_namespace(self):
        """Conditionally destroy the namespace if it is empty."""
        if self.namespace and self.netns.exists(self.namespace):
            if self.namespace_is_empty():
                self.netns.delete(self.namespace)
                return True
        return False

    def add_device_to_namespace(self, device):
        if self.namespace:
            device.link.set_netns(self.namespace)

    def add_vlan(self, name, physical_interface, vlan_id):
        privileged.create_interface(name,
                                    self.namespace,
                                    "vlan",
                                    physical_interface=physical_interface,
                                    vlan_id=vlan_id)
        return IPDevice(name, namespace=self.namespace)

    def add_vxlan(self, name, vni, group=None, dev=None, ttl=None, tos=None,
                  local=None, srcport=None, dstport=None, proxy=False):
        kwargs = {'vxlan_id': vni}
        if group:
            kwargs['vxlan_group'] = group
        if dev:
            kwargs['physical_interface'] = dev
        if ttl:
            kwargs['vxlan_ttl'] = ttl
        if tos:
            kwargs['vxlan_tos'] = tos
        if local:
            kwargs['vxlan_local'] = local
        if proxy:
            kwargs['vxlan_proxy'] = proxy
        # tuple: min,max
        if srcport:
            if len(srcport) == 2 and srcport[0] <= srcport[1]:
                kwargs['vxlan_port_range'] = (str(srcport[0]), str(srcport[1]))
            else:
                raise exceptions.NetworkVxlanPortRangeError(
                    vxlan_range=srcport)
        if dstport:
            kwargs['vxlan_port'] = dstport
        privileged.create_interface(name, self.namespace, "vxlan", **kwargs)
        return (IPDevice(name, namespace=self.namespace))


class IPDevice(SubProcessBase):
    def __init__(self, name, namespace=None, kind='link'):
        super(IPDevice, self).__init__(namespace=namespace)
        self._name = name
        self.kind = kind
        self.link = IpLinkCommand(self)
        self.addr = IpAddrCommand(self)
        self.route = IpRouteCommand(self)
        self.neigh = IpNeighCommand(self)

    def __eq__(self, other):
        return (other is not None and self.name == other.name and
                self.namespace == other.namespace)

    def __str__(self):
        return self.name

    def __repr__(self):
        return "<IPDevice(name=%s, namespace=%s)>" % (self._name,
                                                      self.namespace)

    def exists(self):
        """Return True if the device exists in the namespace."""
        return privileged.interface_exists(self.name, self.namespace)

    def delete_addr_and_conntrack_state(self, cidr):
        """Delete an address along with its conntrack state

        This terminates any active connections through an IP.

        :param cidr: the IP address for which state should be removed.
            This can be passed as a string with or without /NN.
            A netaddr.IPAddress or netaddr.Network representing the IP address
            can also be passed.
        """
        self.addr.delete(cidr)

        ip_str = str(netaddr.IPNetwork(cidr).ip)
        ip_wrapper = IPWrapper(namespace=self.namespace)

        # Delete conntrack state for ingress traffic
        # If 0 flow entries have been deleted
        # conntrack -D will return 1
        try:
            ip_wrapper.netns.execute(["conntrack", "-D", "-d", ip_str],
                                     check_exit_code=True,
                                     extra_ok_codes=[1])

        except RuntimeError:
            LOG.exception("Failed deleting ingress connection state of"
                          " floatingip %s", ip_str)

        # Delete conntrack state for egress traffic
        try:
            ip_wrapper.netns.execute(["conntrack", "-D", "-q", ip_str],
                                     check_exit_code=True,
                                     extra_ok_codes=[1])
        except RuntimeError:
            LOG.exception("Failed deleting egress connection state of"
                          " floatingip %s", ip_str)

    def delete_socket_conntrack_state(self, cidr, dport, protocol):
        ip_str = str(netaddr.IPNetwork(cidr).ip)
        ip_wrapper = IPWrapper(namespace=self.namespace)
        cmd = ["conntrack", "-D", "-d", ip_str, '-p', protocol,
               '--dport', dport]
        try:
            ip_wrapper.netns.execute(cmd, check_exit_code=True,
                                     extra_ok_codes=[1])

        except RuntimeError:
            LOG.exception("Failed deleting ingress connection state of "
                          "socket %(ip)s:%(port)s", {'ip': ip_str,
                                                     'port': dport})

    def disable_ipv6(self):
        if not ipv6_utils.is_enabled_and_bind_by_default():
            return
        sysctl_name = re.sub(r'\.', '/', self.name)
        cmd = ['net.ipv6.conf.%s.disable_ipv6=1' % sysctl_name]
        return sysctl(cmd, namespace=self.namespace)

    @property
    def name(self):
        if self._name:
            return self._name[:constants.DEVICE_NAME_MAX_LEN]
        return self._name

    @name.setter
    def name(self, name):
        self._name = name


class IpCommandBase(object):
    COMMAND = ''

    def __init__(self, parent):
        self._parent = parent

    def _run(self, options, args):
        return self._parent._run(options, self.COMMAND, args)

    def _as_root(self, options, args, use_root_namespace=False):
        return self._parent._as_root(options,
                                     self.COMMAND,
                                     args,
                                     use_root_namespace=use_root_namespace)


class IpDeviceCommandBase(IpCommandBase):
    @property
    def name(self):
        return self._parent.name

    @property
    def kind(self):
        return self._parent.kind


class IpLinkCommand(IpDeviceCommandBase):
    COMMAND = 'link'

    def set_address(self, mac_address):
        privileged.set_link_attribute(
            self.name, self._parent.namespace, address=mac_address)

    def set_allmulticast_on(self):
        privileged.set_link_flags(
            self.name, self._parent.namespace, ifinfmsg.IFF_ALLMULTI)

    def set_mtu(self, mtu_size):
        try:
            privileged.set_link_attribute(
                self.name, self._parent.namespace, mtu=mtu_size)
        except NetlinkError as e:
            if e.code == errno.EINVAL:
                raise InvalidArgument(parameter="MTU", value=mtu_size)
            raise

    def set_up(self):
        privileged.set_link_attribute(
            self.name, self._parent.namespace, state='up')

    def set_down(self):
        privileged.set_link_attribute(
            self.name, self._parent.namespace, state='down')

    def set_netns(self, namespace):
        privileged.set_link_attribute(
            self.name, self._parent.namespace, net_ns_fd=namespace)
        self._parent.namespace = namespace

    def set_name(self, name):
        privileged.set_link_attribute(
            self.name, self._parent.namespace, ifname=name)
        self._parent.name = name

    def set_alias(self, alias_name):
        privileged.set_link_attribute(
            self.name, self._parent.namespace, ifalias=alias_name)

    def create(self):
        privileged.create_interface(self.name, self._parent.namespace,
                                    self.kind)

    def delete(self):
        privileged.delete_interface(self.name, self._parent.namespace)

    @property
    def address(self):
        return self.attributes.get('link/ether')

    @property
    def state(self):
        return self.attributes.get('state')

    @property
    def allmulticast(self):
        return self.attributes.get('allmulticast')

    @property
    def mtu(self):
        return self.attributes.get('mtu')

    @property
    def qdisc(self):
        return self.attributes.get('qdisc')

    @property
    def qlen(self):
        return self.attributes.get('qlen')

    @property
    def alias(self):
        return self.attributes.get('alias')

    @property
    def attributes(self):
        return privileged.get_link_attributes(self.name,
                                              self._parent.namespace)


class IpAddrCommand(IpDeviceCommandBase):
    COMMAND = 'addr'

    def add(self, cidr, scope='global', add_broadcast=True):
        add_ip_address(cidr, self.name, self._parent.namespace, scope,
                       add_broadcast)

    def delete(self, cidr):
        delete_ip_address(cidr, self.name, self._parent.namespace)

    def flush(self, ip_version):
        flush_ip_addresses(ip_version, self.name, self._parent.namespace)

    def list(self, scope=None, to=None, filters=None, ip_version=None):
        """Get device details of a device named <self.name>."""
        def filter_device(device, filters):
            # Accepted filters: dynamic, permanent, tentative, dadfailed.
            for filter in filters:
                if filter == 'permanent' and device['dynamic']:
                    return False
                elif not device[filter]:
                    return False
            return True

        kwargs = {}
        if to:
            cidr = common_utils.ip_to_cidr(to)
            kwargs = {'address': common_utils.cidr_to_ip(cidr)}
            if not common_utils.is_cidr_host(cidr):
                kwargs['mask'] = common_utils.cidr_mask_length(cidr)
        if scope:
            kwargs['scope'] = IP_ADDRESS_SCOPE_NAME[scope]
        if ip_version:
            kwargs['family'] = common_utils.get_socket_address_family(
                ip_version)

        devices = get_devices_with_ip(self._parent.namespace, name=self.name,
                                      **kwargs)
        if not filters:
            return devices

        filtered_devices = []
        for device in (device for device in devices
                       if filter_device(device, filters)):
            filtered_devices.append(device)

        return filtered_devices

    def wait_until_address_ready(self, address, wait_time=30):
        """Wait until an address is no longer marked 'tentative'

        raises AddressNotReady if times out or address not present on interface
        """
        def is_address_ready():
            try:
                addr_info = self.list(to=address)[0]
            except IndexError:
                raise AddressNotReady(
                    address=address,
                    reason=_('Address not present on interface'))
            if not addr_info['tentative']:
                return True
            if addr_info['dadfailed']:
                raise AddressNotReady(
                    address=address, reason=_('Duplicate address detected'))
            return False
        errmsg = _("Exceeded %s second limit waiting for "
                   "address to leave the tentative state.") % wait_time
        common_utils.wait_until_true(
            is_address_ready, timeout=wait_time, sleep=0.20,
            exception=AddressNotReady(address=address, reason=errmsg))


class IpRouteCommand(IpDeviceCommandBase):
    COMMAND = 'route'

    def __init__(self, parent, table=None):
        super(IpRouteCommand, self).__init__(parent)
        self._table = table

    def table(self, table):
        """Return an instance of IpRouteCommand which works on given table"""
        return IpRouteCommand(self._parent, table)

    def _table_args(self, override=None):
        if override:
            return ['table', override]
        return ['table', self._table] if self._table else []

    def _dev_args(self):
        return ['dev', self.name] if self.name else []

    def add_gateway(self, gateway, metric=None, table=None):
        ip_version = common_utils.get_ip_version(gateway)
        args = ['replace', 'default', 'via', gateway]
        if metric:
            args += ['metric', metric]
        args += self._dev_args()
        args += self._table_args(table)
        self._as_root([ip_version], tuple(args))

    def _run_as_root_detect_device_not_found(self, options, args):
        try:
            return self._as_root(options, tuple(args))
        except RuntimeError as rte:
            with excutils.save_and_reraise_exception() as ctx:
                if "Cannot find device" in str(rte):
                    ctx.reraise = False
                    raise exceptions.DeviceNotFoundError(device_name=self.name)

    def delete_gateway(self, gateway, table=None):
        ip_version = common_utils.get_ip_version(gateway)
        args = ['del', 'default',
                'via', gateway]
        args += self._dev_args()
        args += self._table_args(table)
        self._run_as_root_detect_device_not_found([ip_version], args)

    def _parse_routes(self, ip_version, output, **kwargs):
        for line in output.splitlines():
            parts = line.split()

            # Format of line is: "<cidr>|default [<key> <value>] ..."
            route = {k: v for k, v in zip(parts[1::2], parts[2::2])}
            route['cidr'] = parts[0]
            # Avoids having to explicitly pass around the IP version
            if route['cidr'] == 'default':
                route['cidr'] = constants.IP_ANY[ip_version]

            # ip route drops things like scope and dev from the output if it
            # was specified as a filter.  This allows us to add them back.
            if self.name:
                route['dev'] = self.name
            if self._table:
                route['table'] = self._table
            # Callers add any filters they use as kwargs
            route.update(kwargs)

            yield route

    def list_routes(self, ip_version, **kwargs):
        args = ['list']
        args += self._dev_args()
        args += self._table_args()
        for k, v in kwargs.items():
            args += [k, v]

        output = self._run([ip_version], tuple(args))
        return [r for r in self._parse_routes(ip_version, output, **kwargs)]

    def list_onlink_routes(self, ip_version):
        routes = self.list_routes(ip_version, scope='link')
        return [r for r in routes if 'src' not in r]

    def add_onlink_route(self, cidr):
        self.add_route(cidr, scope='link')

    def delete_onlink_route(self, cidr):
        self.delete_route(cidr, scope='link')

    def get_gateway(self, scope=None, filters=None, ip_version=None):
        options = [ip_version] if ip_version else []

        args = ['list']
        args += self._dev_args()
        args += self._table_args()
        if filters:
            args += filters

        retval = None

        if scope:
            args += ['scope', scope]

        route_list_lines = self._run(options, tuple(args)).split('\n')
        default_route_line = next((x.strip() for x in
                                   route_list_lines if
                                   x.strip().startswith('default')), None)
        if default_route_line:
            retval = dict()
            gateway = DEFAULT_GW_PATTERN.search(default_route_line)
            if gateway:
                retval.update(gateway=gateway.group(1))
            metric = METRIC_PATTERN.search(default_route_line)
            if metric:
                retval.update(metric=int(metric.group(1)))

        return retval

    def flush(self, ip_version, table=None, **kwargs):
        args = ['flush']
        args += self._table_args(table)
        for k, v in kwargs.items():
            args += [k, v]
        self._as_root([ip_version], tuple(args))

    def add_route(self, cidr, via=None, table=None, **kwargs):
        ip_version = common_utils.get_ip_version(cidr)
        args = ['replace', cidr]
        if via:
            args += ['via', via]
        args += self._dev_args()
        args += self._table_args(table)
        for k, v in kwargs.items():
            args += [k, v]
        self._run_as_root_detect_device_not_found([ip_version], args)

    def delete_route(self, cidr, via=None, table=None, **kwargs):
        ip_version = common_utils.get_ip_version(cidr)
        args = ['del', cidr]
        if via:
            args += ['via', via]
        args += self._dev_args()
        args += self._table_args(table)
        for k, v in kwargs.items():
            args += [k, v]
        self._run_as_root_detect_device_not_found([ip_version], args)


class IPRoute(SubProcessBase):
    def __init__(self, namespace=None, table=None):
        super(IPRoute, self).__init__(namespace=namespace)
        self.name = None
        self.route = IpRouteCommand(self, table=table)


class IpNeighCommand(IpDeviceCommandBase):
    COMMAND = 'neigh'

    def add(self, ip_address, mac_address, **kwargs):
        add_neigh_entry(ip_address,
                        mac_address,
                        self.name,
                        self._parent.namespace,
                        **kwargs)

    def delete(self, ip_address, mac_address, **kwargs):
        delete_neigh_entry(ip_address,
                           mac_address,
                           self.name,
                           self._parent.namespace,
                           **kwargs)

    def dump(self, ip_version, **kwargs):
        return dump_neigh_entries(ip_version,
                                  self.name,
                                  self._parent.namespace,
                                  **kwargs)

    def flush(self, ip_version, ip_address):
        """Flush neighbour entries

        Given address entry is removed from neighbour cache (ARP or NDP). To
        flush all entries pass string 'all' as an address.

        :param ip_version: Either 4 or 6 for IPv4 or IPv6 respectively
        :param ip_address: The prefix selecting the neighbours to flush
        """
        # NOTE(haleyb): There is no equivalent to 'flush' in pyroute2
        self._as_root([ip_version], ('flush', 'to', ip_address))


class IpNetnsCommand(IpCommandBase):
    COMMAND = 'netns'

    def add(self, name):
        create_network_namespace(name)
        wrapper = IPWrapper(namespace=name)
        wrapper.netns.execute(['sysctl', '-w',
                               'net.ipv4.conf.all.promote_secondaries=1'])
        return wrapper

    def delete(self, name):
        delete_network_namespace(name)

    def execute(self, cmds, addl_env=None, check_exit_code=True,
                log_fail_as_error=True, extra_ok_codes=None,
                run_as_root=False):
        ns_params = []
        if self._parent.namespace:
            run_as_root = True
            ns_params = ['ip', 'netns', 'exec', self._parent.namespace]

        env_params = []
        if addl_env:
            env_params = (['env'] +
                          ['%s=%s' % pair for pair in addl_env.items()])
        cmd = ns_params + env_params + list(cmds)
        return utils.execute(cmd, check_exit_code=check_exit_code,
                             extra_ok_codes=extra_ok_codes,
                             log_fail_as_error=log_fail_as_error,
                             run_as_root=run_as_root)

    def exists(self, name):
        return network_namespace_exists(name)


def vlan_in_use(segmentation_id, namespace=None):
    """Return True if VLAN ID is in use by an interface, else False."""
    interfaces = get_devices_info(namespace)
    vlans = {interface.get('vlan_id') for interface in interfaces
             if interface.get('vlan_id')}
    return segmentation_id in vlans


def vxlan_in_use(segmentation_id, namespace=None):
    """Return True if VXLAN VNID is in use by an interface, else False."""
    interfaces = get_devices_info(namespace)
    vxlans = {interface.get('vxlan_id') for interface in interfaces
              if interface.get('vxlan_id')}
    return segmentation_id in vxlans


def device_exists(device_name, namespace=None):
    """Return True if the device exists in the namespace."""
    return IPDevice(device_name, namespace=namespace).exists()


def device_exists_with_ips_and_mac(device_name, ip_cidrs, mac, namespace=None):
    """Return True if the device with the given IP addresses and MAC address
    exists in the namespace.
    """
    try:
        device = IPDevice(device_name, namespace=namespace)
        if mac and mac != device.link.address:
            return False
        device_ip_cidrs = [ip['cidr'] for ip in device.addr.list()]
        for ip_cidr in ip_cidrs:
            if ip_cidr not in device_ip_cidrs:
                return False
    except RuntimeError:
        return False
    else:
        return True


def get_device_mac(device_name, namespace=None):
    """Return the MAC address of the device."""
    return IPDevice(device_name, namespace=namespace).link.address


def get_device_mtu(device_name, namespace=None):
    """Return the MTU value of the device."""
    return IPDevice(device_name, namespace=namespace).link.mtu


NetworkNamespaceNotFound = privileged.NetworkNamespaceNotFound
NetworkInterfaceNotFound = privileged.NetworkInterfaceNotFound
IpAddressAlreadyExists = privileged.IpAddressAlreadyExists


def add_ip_address(cidr, device, namespace=None, scope='global',
                   add_broadcast=True):
    """Add an IP address.

    :param cidr: IP address to add, in CIDR notation
    :param device: Device name to use in adding address
    :param namespace: The name of the namespace in which to add the address
    :param scope: scope of address being added
    :param add_broadcast: should broadcast address be added
    """
    net = netaddr.IPNetwork(cidr)
    broadcast = None
    if add_broadcast and net.version == 4:
        # NOTE(slaweq): in case if cidr is /32 net.broadcast is None so
        # same IP address as cidr should be set as broadcast
        broadcast = str(net.broadcast or net.ip)
    privileged.add_ip_address(
        net.version, str(net.ip), net.prefixlen,
        device, namespace, scope, broadcast)


def delete_ip_address(cidr, device, namespace=None):
    """Delete an IP address.

    :param cidr: IP address to delete, in CIDR notation
    :param device: Device name to use in deleting address
    :param namespace: The name of the namespace in which to delete the address
    """
    net = netaddr.IPNetwork(cidr)
    privileged.delete_ip_address(
        net.version, str(net.ip), net.prefixlen, device, namespace)


def flush_ip_addresses(ip_version, device, namespace=None):
    """Flush all IP addresses.

    :param ip_version: IP version of addresses to flush
    :param device: Device name to use in flushing addresses
    :param namespace: The name of the namespace in which to flush the addresses
    """
    privileged.flush_ip_addresses(ip_version, device, namespace)


def get_routing_table(ip_version, namespace=None):
    """Return a list of dictionaries, each representing a route.

    @param ip_version: the routes of version to return, for example 4
    @param namespace
    @return: a list of dictionaries, each representing a route.
    The dictionary format is: {'destination': cidr,
                               'nexthop': ip,
                               'device': device_name,
                               'scope': scope}
    """
    # oslo.privsep turns lists to tuples in its IPC code. Change it back
    return list(privileged.get_routing_table(ip_version, namespace))


# NOTE(haleyb): These neighbour functions live outside the IpNeighCommand
# class since not all callers require it.
def add_neigh_entry(ip_address, mac_address, device, namespace=None, **kwargs):
    """Add a neighbour entry.

    :param ip_address: IP address of entry to add
    :param mac_address: MAC address of entry to add
    :param device: Device name to use in adding entry
    :param namespace: The name of the namespace in which to add the entry
    """
    ip_version = common_utils.get_ip_version(ip_address)
    privileged.add_neigh_entry(ip_version,
                               ip_address,
                               mac_address,
                               device,
                               namespace,
                               **kwargs)


def delete_neigh_entry(ip_address, mac_address, device, namespace=None,
                       **kwargs):
    """Delete a neighbour entry.

    :param ip_address: IP address of entry to delete
    :param mac_address: MAC address of entry to delete
    :param device: Device name to use in deleting entry
    :param namespace: The name of the namespace in which to delete the entry
    """
    ip_version = common_utils.get_ip_version(ip_address)
    privileged.delete_neigh_entry(ip_version,
                                  ip_address,
                                  mac_address,
                                  device,
                                  namespace,
                                  **kwargs)


def dump_neigh_entries(ip_version, device=None, namespace=None, **kwargs):
    """Dump all neighbour entries.

    :param ip_version: IP version of entries to show (4 or 6)
    :param device: Device name to use in dumping entries
    :param namespace: The name of the namespace in which to dump the entries
    :param kwargs: Callers add any filters they use as kwargs
    :return: a list of dictionaries, each representing a neighbour.
    The dictionary format is: {'dst': ip_address,
                               'lladdr': mac_address,
                               'device': device_name}
    """
    return list(privileged.dump_neigh_entries(ip_version,
                                              device,
                                              namespace,
                                              **kwargs))


def create_network_namespace(namespace, **kwargs):
    """Create a network namespace.

    :param namespace: The name of the namespace to create
    :param kwargs: Callers add any filters they use as kwargs
    """
    privileged.create_netns(namespace, **kwargs)


def delete_network_namespace(namespace, **kwargs):
    """Delete a network namespace.

    :param namespace: The name of the namespace to delete
    :param kwargs: Callers add any filters they use as kwargs
    """
    privileged.remove_netns(namespace, **kwargs)


def list_network_namespaces(**kwargs):
    """List all network namespace entries.

    :param kwargs: Callers add any filters they use as kwargs
    """
    if cfg.CONF.AGENT.use_helper_for_ns_read:
        return privileged.list_netns(**kwargs)
    else:
        return netns.listnetns(**kwargs)


def network_namespace_exists(namespace, **kwargs):
    """Check if a network namespace exists.

    :param namespace: The name of the namespace to check
    :param kwargs: Callers add any filters they use as kwargs
    """
    output = list_network_namespaces(**kwargs)
    return namespace in output


def ensure_device_is_ready(device_name, namespace=None):
    dev = IPDevice(device_name, namespace=namespace)
    try:
        # Ensure the device has a MAC address and is up, even if it is already
        # up. If the device doesn't exist, a RuntimeError will be raised.
        if not dev.link.address:
            LOG.error("Device %s cannot be used as it has no MAC "
                      "address", device_name)
            return False
        dev.link.set_up()
    except RuntimeError:
        return False
    return True


def iproute_arg_supported(command, arg):
    command += ['help']
    stdout, stderr = utils.execute(command, check_exit_code=False,
                                   return_stderr=True, log_fail_as_error=False)
    return any(arg in line for line in stderr.split('\n'))


def _arping(ns_name, iface_name, address, count, log_exception):
    # Due to a Linux kernel bug*, it's advised to spread gratuitous updates
    # more, injecting an interval between consequent packets that is longer
    # than 1s which is currently hardcoded** in arping. To achieve that, we
    # call arping tool the 'count' number of times, each issuing a single ARP
    # update, and wait between iterations.
    #
    # *  https://patchwork.ozlabs.org/patch/760372/
    # ** https://github.com/iputils/iputils/pull/86
    first = True
    # Since arping is used to send gratuitous ARP, a response is
    # not expected. In some cases (no response) and with some
    # platforms (>=Ubuntu 14.04), arping exit code can be 1.
    extra_ok_codes = [1]
    ip_wrapper = IPWrapper(namespace=ns_name)
    for i in range(count):
        if not first:
            # hopefully enough for kernel to get out of locktime loop
            time.sleep(2)
            # On the second (and subsequent) arping calls, we can get a
            # "bind: Cannot assign requested address" error since
            # the IP address might have been deleted concurrently.
            # We will log an error below if this isn't the case, so
            # no need to have execute() log one as well.
            extra_ok_codes = [1, 2]
        first = False

        # some Linux kernels* don't honour REPLYs. Send both gratuitous REQUEST
        # and REPLY packets (REQUESTs are left for backwards compatibility for
        # in case if some network peers, vice versa, honor REPLYs and not
        # REQUESTs)
        #
        # * https://patchwork.ozlabs.org/patch/763016/
        for arg in ('-U', '-A'):
            arping_cmd = ['arping', arg, '-I', iface_name, '-c', 1,
                          # Pass -w to set timeout to ensure exit if interface
                          # removed while running
                          '-w', 1.5, address]
            try:
                ip_wrapper.netns.execute(arping_cmd,
                                         extra_ok_codes=extra_ok_codes)
            except Exception as exc:
                # Since this is spawned in a thread and executed 2 seconds
                # apart, something may have been deleted while we were
                # sleeping. Downgrade message to info and return early
                # unless it was the first try.
                exists = device_exists_with_ips_and_mac(iface_name,
                                                        [address],
                                                        mac=None,
                                                        namespace=ns_name)
                msg = _("Failed sending gratuitous ARP to %(addr)s on "
                        "%(iface)s in namespace %(ns)s: %(err)s")
                logger_method = LOG.exception
                if not (log_exception and (first or exists)):
                    logger_method = LOG.info
                logger_method(msg, {'addr': address,
                                    'iface': iface_name,
                                    'ns': ns_name,
                                    'err': exc})
                if not exists:
                    LOG.info("Interface %(iface)s or address %(addr)s "
                             "in namespace %(ns)s was deleted concurrently",
                             {'iface': iface_name,
                              'addr': address,
                              'ns': ns_name})
                    return


def send_ip_addr_adv_notif(
        ns_name, iface_name, address, count=3, log_exception=True):
    """Send advance notification of an IP address assignment.

    If the address is in the IPv4 family, send gratuitous ARP.

    If the address is in the IPv6 family, no advance notification is
    necessary, since the Neighbor Discovery Protocol (NDP), Duplicate
    Address Discovery (DAD), and (for stateless addresses) router
    advertisements (RAs) are sufficient for address resolution and
    duplicate address detection.

    :param ns_name: Namespace name which GARPs are gonna be sent from.
    :param iface_name: Name of interface which GARPs are gonna be sent from.
    :param address: Advertised IP address.
    :param count: (Optional) How many GARPs are gonna be sent. Default is 3.
    :param log_exception: (Optional) True if possible failures should be logged
                          on exception level. Otherwise they are logged on
                          WARNING level. Default is True.
    """
    def arping():
        _arping(ns_name, iface_name, address, count, log_exception)

    if count > 0 and netaddr.IPAddress(address).version == 4:
        eventlet.spawn_n(arping)


def sysctl(cmd, namespace=None, log_fail_as_error=True):
    """Run sysctl command 'cmd'

    @param cmd: a list containing the sysctl command to run
    @param namespace: network namespace to run command in
    @param log_fail_as_error: failure logged as LOG.error

    execute() doesn't return the exit status of the command it runs,
    it returns stdout and stderr. Setting check_exit_code=True will cause
    it to raise a RuntimeError if the exit status of the command is
    non-zero, which in sysctl's case is an error. So we're normalizing
    that into zero (success) and one (failure) here to mimic what
    "echo $?" in a shell would be.

    This is all because sysctl is too verbose and prints the value you
    just set on success, unlike most other utilities that print nothing.

    execute() will have dumped a message to the logs with the actual
    output on failure, so it's not lost, and we don't need to print it
    here.
    """
    cmd = ['sysctl', '-w'] + cmd
    ip_wrapper = IPWrapper(namespace=namespace)
    try:
        ip_wrapper.netns.execute(cmd, run_as_root=True,
                                 log_fail_as_error=log_fail_as_error)
    except RuntimeError as rte:
        LOG.warning(
            "Setting %(cmd)s in namespace %(ns)s failed: %(err)s.",
            {'cmd': cmd,
             'ns': namespace,
             'err': rte})
        return 1

    return 0


def add_namespace_to_cmd(cmd, namespace=None):
    """Add an optional namespace to the command."""

    return ['ip', 'netns', 'exec', namespace] + cmd if namespace else cmd


def get_ipv6_lladdr(mac_addr):
    return '%s/64' % netaddr.EUI(mac_addr).ipv6_link_local()


def get_ip_nonlocal_bind(namespace=None):
    """Get kernel option value of ip_nonlocal_bind in given namespace."""
    cmd = ['sysctl', '-bn', IP_NONLOCAL_BIND]
    ip_wrapper = IPWrapper(namespace)
    return int(ip_wrapper.netns.execute(cmd, run_as_root=True))


def set_ip_nonlocal_bind(value, namespace=None, log_fail_as_error=True):
    """Set sysctl knob of ip_nonlocal_bind to given value."""
    cmd = ['%s=%d' % (IP_NONLOCAL_BIND, value)]
    return sysctl(cmd, namespace=namespace,
                  log_fail_as_error=log_fail_as_error)


def set_ip_nonlocal_bind_for_namespace(namespace, value, root_namespace=False):
    """Set ip_nonlocal_bind but don't raise exception on failure."""
    failed = set_ip_nonlocal_bind(value, namespace=namespace,
                                  log_fail_as_error=False)
    if failed and root_namespace:
        # Somewhere in the 3.19 kernel timeframe ip_nonlocal_bind was
        # changed to be a per-namespace attribute.  To be backwards
        # compatible we need to try both if at first we fail.
        LOG.debug('Namespace (%s) does not support setting %s, '
                  'trying in root namespace', namespace, IP_NONLOCAL_BIND)
        return set_ip_nonlocal_bind(value)
    if failed:
        LOG.warning(
            "%s will not be set to %d in the root namespace in order to "
            "not break DVR, which requires this value be set to 1. This "
            "may introduce a race between moving a floating IP to a "
            "different network node, and the peer side getting a "
            "populated ARP cache for a given floating IP address.",
            IP_NONLOCAL_BIND, value)


def get_ipv6_forwarding(device, namespace=None):
    """Get kernel value of IPv6 forwarding for device in given namespace."""
    cmd = ['sysctl', '-b', "net.ipv6.conf.%s.forwarding" % device]
    ip_wrapper = IPWrapper(namespace)
    return int(ip_wrapper.netns.execute(cmd, run_as_root=True))


def _parse_ip_rule(rule, ip_version):
    """Parse a pyroute2 rule and returns a dictionary

    Parameters contained in the returned dictionary:
    - priority: rule priority
    - from: source IP address
    - to: (optional) destination IP address
    - type: rule type (see RULE_TYPES)
    - table: table name or number (see RULE_TABLES)
    - fwmark: (optional) FW mark
    - iif: (optional) input interface name
    - oif: (optional) output interface name

     :param rule: pyroute2 rule dictionary
     :param ip_version: IP version (4, 6)
     :return: dictionary with IP rule information
    """
    parsed_rule = {'priority': str(rule['attrs'].get('FRA_PRIORITY', 0))}
    from_ip = rule['attrs'].get('FRA_SRC')
    if from_ip:
        parsed_rule['from'] = common_utils.ip_to_cidr(
            from_ip, prefix=rule['src_len'])
        if common_utils.is_cidr_host(parsed_rule['from']):
            parsed_rule['from'] = common_utils.cidr_to_ip(parsed_rule['from'])
    else:
        parsed_rule['from'] = constants.IP_ANY[ip_version]
    to_ip = rule['attrs'].get('FRA_DST')
    if to_ip:
        parsed_rule['to'] = common_utils.ip_to_cidr(
            to_ip, prefix=rule['dst_len'])
        if common_utils.is_cidr_host(parsed_rule['to']):
            parsed_rule['to'] = common_utils.cidr_to_ip(parsed_rule['to'])
    parsed_rule['type'] = IP_RULE_TYPES[rule['action']]
    table_num = rule['attrs']['FRA_TABLE']
    for table_name in (name for (name, index) in
                       IP_RULE_TABLES.items() if index == table_num):
        parsed_rule['table'] = table_name
        break
    else:
        parsed_rule['table'] = str(table_num)
    fwmark = rule['attrs'].get('FRA_FWMARK')
    if fwmark:
        fwmask = rule['attrs'].get('FRA_FWMASK')
        parsed_rule['fwmark'] = '{0:#x}/{1:#x}'.format(fwmark, fwmask)
    iifname = rule['attrs'].get('FRA_IIFNAME')
    if iifname:
        parsed_rule['iif'] = iifname
    oifname = rule['attrs'].get('FRA_OIFNAME')
    if oifname:
        parsed_rule['oif'] = oifname

    return parsed_rule


def list_ip_rules(namespace, ip_version):
    """List all IP rules in a namespace

    :param namespace: namespace name
    :param ip_version: IP version (4, 6)
    :return: list of dictionaries with the rules information
    """
    rules = privileged.list_ip_rules(namespace, ip_version)
    return [_parse_ip_rule(rule, ip_version) for rule in rules]


def _make_pyroute2_args(ip, iif, table, priority, to):
    """Returns a dictionary of arguments to be used in pyroute rule commands

    :param ip: (string) source IP or CIDR address (IPv4, IPv6)
    :param iif: (string) input interface name
    :param table: (string, int) table number (as an int or a string) or table
                  name ('default', 'main', 'local')
    :param priority: (string, int) rule priority
    :param to: (string) destination IP or CIDR address (IPv4, IPv6)
    :return: a dictionary with the kwargs needed in pyroute rule commands
    """
    ip_version = common_utils.get_ip_version(ip)
    # In case we need to add a rule based on an incoming interface, no
    # IP address is given; the rule default source ("from") address is
    # "all".
    cmd_args = {'family': common_utils.get_socket_address_family(ip_version)}
    if iif:
        cmd_args['iifname'] = iif
    else:
        cmd_args['src'] = common_utils.cidr_to_ip(ip)
        cmd_args['src_len'] = common_utils.cidr_mask(ip)
    if to:
        cmd_args['dst'] = common_utils.cidr_to_ip(to)
        cmd_args['dst_len'] = common_utils.cidr_mask(to)
    if table:
        cmd_args['table'] = IP_RULE_TABLES.get(table) or int(table)
    if priority:
        cmd_args['priority'] = int(priority)
    return cmd_args


def _exist_ip_rule(rules, ip, iif, table, priority, to):
    """Check if any rule matches the conditions"""
    for rule in rules:
        if iif and rule.get('iif') != iif:
            continue
        if not iif and rule['from'] != ip:
            continue
        if table and rule.get('table') != str(table):
            continue
        if priority and rule['priority'] != str(priority):
            continue
        if to and rule.get('to') != to:
            continue
        break
    else:
        return False
    return True


def add_ip_rule(namespace, ip, iif=None, table=None, priority=None, to=None):
    """Create an IP rule in a namespace

    :param namespace: (string) namespace name
    :param ip: (string) source IP or CIDR address (IPv4, IPv6)
    :param iif: (Optional) (string) input interface name
    :param table: (Optional) (string, int) table number
    :param priority: (Optional) (string, int) rule priority
    :param to: (Optional) (string) destination IP or CIDR address (IPv4, IPv6)
    """
    ip_version = common_utils.get_ip_version(ip)
    rules = list_ip_rules(namespace, ip_version)
    if _exist_ip_rule(rules, ip, iif, table, priority, to):
        return
    cmd_args = _make_pyroute2_args(ip, iif, table, priority, to)
    privileged.add_ip_rule(namespace, **cmd_args)


def delete_ip_rule(namespace, ip, iif=None, table=None, priority=None,
                   to=None):
    """Delete an IP rule in a namespace

    :param namespace: (string) namespace name
    :param ip: (string) source IP or CIDR address (IPv4, IPv6)
    :param iif: (Optional) (string) input interface name
    :param table: (Optional) (string, int) table number
    :param priority: (Optional) (string, int) rule priority
    :param to: (Optional) (string) destination IP or CIDR address (IPv4, IPv6)
    """
    cmd_args = _make_pyroute2_args(ip, iif, table, priority, to)
    privileged.delete_ip_rule(namespace, **cmd_args)


def get_attr(pyroute2_obj, attr_name):
    """Get an attribute from a PyRoute2 object"""
    rule_attrs = pyroute2_obj.get('attrs', [])
    for attr in (attr for attr in rule_attrs if attr[0] == attr_name):
        return attr[1]


def _parse_link_device(namespace, device, **kwargs):
    """Parse pytoute2 link device information

    For each link device, the IP address information is retrieved and returned
    in a dictionary.
    IP address scope: http://linux-ip.net/html/tools-ip-address.html
    """
    retval = []
    name = get_attr(device, 'IFLA_IFNAME')
    ip_addresses = privileged.get_ip_addresses(namespace,
                                               index=device['index'],
                                               **kwargs)
    for ip_address in ip_addresses:
        ip = get_attr(ip_address, 'IFA_ADDRESS')
        ip_length = ip_address['prefixlen']
        cidr = common_utils.ip_to_cidr(ip, prefix=ip_length)
        flags = get_attr(ip_address, 'IFA_FLAGS')
        dynamic = not bool(flags & ifaddrmsg.IFA_F_PERMANENT)
        tentative = bool(flags & ifaddrmsg.IFA_F_TENTATIVE)
        dadfailed = bool(flags & ifaddrmsg.IFA_F_DADFAILED)
        scope = IP_ADDRESS_SCOPE[ip_address['scope']]
        retval.append({'name': name,
                       'cidr': cidr,
                       'scope': scope,
                       'broadcast': get_attr(ip_address, 'IFA_BROADCAST'),
                       'dynamic': dynamic,
                       'tentative': tentative,
                       'dadfailed': dadfailed})
    return retval


def get_devices_with_ip(namespace, name=None, **kwargs):
    link_args = {}
    if name:
        link_args['ifname'] = name
    devices = privileged.get_link_devices(namespace, **link_args)
    retval = []
    for parsed_ips in (_parse_link_device(namespace, device, **kwargs)
                       for device in devices):
        retval += parsed_ips
    return retval


def get_devices_info(namespace, **kwargs):
    devices = privileged.get_link_devices(namespace, **kwargs)
    retval = {}
    for device in devices:
        ret = {'index': device['index'],
               'name': get_attr(device, 'IFLA_IFNAME'),
               'operstate': get_attr(device, 'IFLA_OPERSTATE'),
               'linkmode': get_attr(device, 'IFLA_LINKMODE'),
               'mtu': get_attr(device, 'IFLA_MTU'),
               'promiscuity': get_attr(device, 'IFLA_PROMISCUITY'),
               'mac': get_attr(device, 'IFLA_ADDRESS'),
               'broadcast': get_attr(device, 'IFLA_BROADCAST')}
        ifla_link = get_attr(device, 'IFLA_LINK')
        if ifla_link:
            ret['parent_index'] = ifla_link
        ifla_linkinfo = get_attr(device, 'IFLA_LINKINFO')
        if ifla_linkinfo:
            ret['kind'] = get_attr(ifla_linkinfo, 'IFLA_INFO_KIND')
            ifla_data = get_attr(ifla_linkinfo, 'IFLA_INFO_DATA')
            if ret['kind'] == 'vxlan':
                ret['vxlan_id'] = get_attr(ifla_data, 'IFLA_VXLAN_ID')
                ret['vxlan_group'] = get_attr(ifla_data, 'IFLA_VXLAN_GROUP')
                ret['vxlan_link_index'] = get_attr(ifla_data,
                                                   'IFLA_VXLAN_LINK')
            elif ret['kind'] == 'vlan':
                ret['vlan_id'] = get_attr(ifla_data, 'IFLA_VLAN_ID')
        retval[device['index']] = ret

    for device in retval.values():
        if device.get('parent_index'):
            parent_device = retval.get(device['parent_index'])
            if parent_device:
                device['parent_name'] = parent_device['name']
        elif device.get('vxlan_link_index'):
            device['vxlan_link_name'] = (
                retval[device['vxlan_link_index']]['name'])

    return list(retval.values())
