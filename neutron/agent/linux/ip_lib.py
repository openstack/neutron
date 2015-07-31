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

import eventlet
import netaddr
import os
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
import re

from neutron.agent.common import utils
from neutron.common import constants
from neutron.common import exceptions
from neutron.i18n import _LE

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.BoolOpt('ip_lib_force_root',
                default=False,
                help=_('Force ip_lib calls to use the root helper')),
]


LOOPBACK_DEVNAME = 'lo'

SYS_NET_PATH = '/sys/class/net'
DEFAULT_GW_PATTERN = re.compile(r"via (\S+)")
METRIC_PATTERN = re.compile(r"metric (\S+)")


class AddressNotReady(exceptions.NeutronException):
    message = _("Failure waiting for address %(address)s to "
                "become ready: %(reason)s")


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
            return self._execute(options, command, args, run_as_root=True,
                                 log_fail_as_error=self.log_fail_as_error)
        else:
            return self._execute(options, command, args,
                                 log_fail_as_error=self.log_fail_as_error)

    def _as_root(self, options, command, args, use_root_namespace=False):
        namespace = self.namespace if not use_root_namespace else None

        return self._execute(options, command, args, run_as_root=True,
                             namespace=namespace,
                             log_fail_as_error=self.log_fail_as_error)

    @classmethod
    def _execute(cls, options, command, args, run_as_root=False,
                 namespace=None, log_fail_as_error=True):
        opt_list = ['-%s' % o for o in options]
        ip_cmd = add_namespace_to_cmd(['ip'], namespace)
        cmd = ip_cmd + opt_list + [command] + list(args)
        return utils.execute(cmd, run_as_root=run_as_root,
                             log_fail_as_error=log_fail_as_error)

    def set_log_fail_as_error(self, fail_with_error):
        self.log_fail_as_error = fail_with_error


class IPWrapper(SubProcessBase):
    def __init__(self, namespace=None):
        super(IPWrapper, self).__init__(namespace=namespace)
        self.netns = IpNetnsCommand(self)

    def device(self, name):
        return IPDevice(name, namespace=self.namespace)

    def get_devices(self, exclude_loopback=False):
        retval = []
        if self.namespace:
            # we call out manually because in order to avoid screen scraping
            # iproute2 we use find to see what is in the sysfs directory, as
            # suggested by Stephen Hemminger (iproute2 dev).
            output = utils.execute(['ip', 'netns', 'exec', self.namespace,
                                    'find', SYS_NET_PATH, '-maxdepth', '1',
                                    '-type', 'l', '-printf', '%f '],
                                   run_as_root=True,
                                   log_fail_as_error=self.log_fail_as_error
                                   ).split()
        else:
            output = (
                i for i in os.listdir(SYS_NET_PATH)
                if os.path.islink(os.path.join(SYS_NET_PATH, i))
            )

        for name in output:
            if exclude_loopback and name == LOOPBACK_DEVNAME:
                continue
            retval.append(IPDevice(name, namespace=self.namespace))

        return retval

    def get_device_by_ip(self, ip):
        """Get the IPDevice from system which has ip configured."""
        for device in self.get_devices():
            if device.addr.list(to=ip):
                return device

    def add_tuntap(self, name, mode='tap'):
        self._as_root([], 'tuntap', ('add', name, 'mode', mode))
        return IPDevice(name, namespace=self.namespace)

    def add_veth(self, name1, name2, namespace2=None):
        args = ['add', name1, 'type', 'veth', 'peer', 'name', name2]

        if namespace2 is None:
            namespace2 = self.namespace
        else:
            self.ensure_namespace(namespace2)
            args += ['netns', namespace2]

        self._as_root([], 'link', tuple(args))

        return (IPDevice(name1, namespace=self.namespace),
                IPDevice(name2, namespace=namespace2))

    def del_veth(self, name):
        """Delete a virtual interface between two namespaces."""
        self._as_root([], 'link', ('del', name))

    def ensure_namespace(self, name):
        if not self.netns.exists(name):
            ip = self.netns.add(name)
            lo = ip.device(LOOPBACK_DEVNAME)
            lo.link.set_up()
        else:
            ip = IPWrapper(namespace=name)
        return ip

    def namespace_is_empty(self):
        return not self.get_devices(exclude_loopback=True)

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

    def add_vxlan(self, name, vni, group=None, dev=None, ttl=None, tos=None,
                  local=None, port=None, proxy=False):
        cmd = ['add', name, 'type', 'vxlan', 'id', vni]
        if group:
                cmd.extend(['group', group])
        if dev:
                cmd.extend(['dev', dev])
        if ttl:
                cmd.extend(['ttl', ttl])
        if tos:
                cmd.extend(['tos', tos])
        if local:
                cmd.extend(['local', local])
        if proxy:
                cmd.append('proxy')
        # tuple: min,max
        if port and len(port) == 2:
                cmd.extend(['port', port[0], port[1]])
        elif port:
            raise exceptions.NetworkVxlanPortRangeError(vxlan_range=port)
        self._as_root([], 'link', cmd)
        return (IPDevice(name, namespace=self.namespace))

    @classmethod
    def get_namespaces(cls):
        output = cls._execute([], 'netns', ('list',))
        return [l.strip() for l in output.split('\n')]


class IPDevice(SubProcessBase):
    def __init__(self, name, namespace=None):
        super(IPDevice, self).__init__(namespace=namespace)
        self.name = name
        self.link = IpLinkCommand(self)
        self.addr = IpAddrCommand(self)
        self.route = IpRouteCommand(self)
        self.neigh = IpNeighCommand(self)

    def __eq__(self, other):
        return (other is not None and self.name == other.name
                and self.namespace == other.namespace)

    def __str__(self):
        return self.name

    def delete_addr_and_conntrack_state(self, cidr):
        """Delete an address along with its conntrack state

        This terminates any active connections through an IP.

        cidr: the IP address for which state should be removed.  This can be
            passed as a string with or without /NN.  A netaddr.IPAddress or
            netaddr.Network representing the IP address can also be passed.
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
            LOG.exception(_LE("Failed deleting ingress connection state of"
                              " floatingip %s"), ip_str)

        # Delete conntrack state for egress traffic
        try:
            ip_wrapper.netns.execute(["conntrack", "-D", "-q", ip_str],
                                     check_exit_code=True,
                                     extra_ok_codes=[1])
        except RuntimeError:
            LOG.exception(_LE("Failed deleting egress connection state of"
                              " floatingip %s"), ip_str)


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


class IPRule(SubProcessBase):
    def __init__(self, namespace=None):
        super(IPRule, self).__init__(namespace=namespace)
        self.rule = IpRuleCommand(self)


class IpRuleCommand(IpCommandBase):
    COMMAND = 'rule'

    def _parse_line(self, ip_version, line):
        # Typical rules from 'ip rule show':
        # 4030201:  from 1.2.3.4/24 lookup 10203040
        # 1024:     from all iif qg-c43b1928-48 lookup noscope

        parts = line.split()
        if not parts:
            return {}

        # Format of line is: "priority: <key> <value> ..."
        settings = {k: v for k, v in zip(parts[1::2], parts[2::2])}
        settings['priority'] = parts[0][:-1]

        # Canonicalize some arguments
        if settings.get('from') == "all":
            settings['from'] = constants.IP_ANY[ip_version]
        if 'lookup' in settings:
            settings['table'] = settings.pop('lookup')

        return settings

    def _exists(self, ip_version, **kwargs):
        kwargs_strings = {k: str(v) for k, v in kwargs.items()}
        lines = self._as_root([ip_version], ['show']).splitlines()
        return kwargs_strings in (self._parse_line(ip_version, line)
                                  for line in lines)

    def _make__flat_args_tuple(self, *args, **kwargs):
        for kwargs_item in sorted(kwargs.items(), key=lambda i: i[0]):
            args += kwargs_item
        return tuple(args)

    def add(self, ip, **kwargs):
        ip_version = get_ip_version(ip)

        kwargs.update({'from': ip})

        if not self._exists(ip_version, **kwargs):
            args_tuple = self._make__flat_args_tuple('add', **kwargs)
            self._as_root([ip_version], args_tuple)

    def delete(self, ip, **kwargs):
        ip_version = get_ip_version(ip)

        # TODO(Carl) ip ignored in delete, okay in general?

        args_tuple = self._make__flat_args_tuple('del', **kwargs)
        self._as_root([ip_version], args_tuple)


class IpDeviceCommandBase(IpCommandBase):
    @property
    def name(self):
        return self._parent.name


class IpLinkCommand(IpDeviceCommandBase):
    COMMAND = 'link'

    def set_address(self, mac_address):
        self._as_root([], ('set', self.name, 'address', mac_address))

    def set_mtu(self, mtu_size):
        self._as_root([], ('set', self.name, 'mtu', mtu_size))

    def set_up(self):
        return self._as_root([], ('set', self.name, 'up'))

    def set_down(self):
        return self._as_root([], ('set', self.name, 'down'))

    def set_netns(self, namespace):
        self._as_root([], ('set', self.name, 'netns', namespace))
        self._parent.namespace = namespace

    def set_name(self, name):
        self._as_root([], ('set', self.name, 'name', name))
        self._parent.name = name

    def set_alias(self, alias_name):
        self._as_root([], ('set', self.name, 'alias', alias_name))

    def delete(self):
        self._as_root([], ('delete', self.name))

    @property
    def address(self):
        return self.attributes.get('link/ether')

    @property
    def state(self):
        return self.attributes.get('state')

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
        return self._parse_line(self._run(['o'], ('show', self.name)))

    def _parse_line(self, value):
        if not value:
            return {}

        device_name, settings = value.replace("\\", '').split('>', 1)
        tokens = settings.split()
        keys = tokens[::2]
        values = [int(v) if v.isdigit() else v for v in tokens[1::2]]

        retval = dict(zip(keys, values))
        return retval


class IpAddrCommand(IpDeviceCommandBase):
    COMMAND = 'addr'

    def add(self, cidr, scope='global'):
        net = netaddr.IPNetwork(cidr)
        args = ['add', cidr,
                'scope', scope,
                'dev', self.name]
        if net.version == 4:
            args += ['brd', str(net.broadcast)]
        self._as_root([net.version], tuple(args))

    def delete(self, cidr):
        ip_version = get_ip_version(cidr)
        self._as_root([ip_version],
                      ('del', cidr,
                       'dev', self.name))

    def flush(self, ip_version):
        self._as_root([ip_version], ('flush', self.name))

    def list(self, scope=None, to=None, filters=None, ip_version=None):
        options = [ip_version] if ip_version else []
        args = ['show', self.name]
        if filters:
            args += filters

        retval = []

        if scope:
            args += ['scope', scope]
        if to:
            args += ['to', to]

        for line in self._run(options, tuple(args)).split('\n'):
            line = line.strip()
            if not line.startswith('inet'):
                continue
            parts = line.split()
            if parts[0] == 'inet6':
                scope = parts[3]
            else:
                if parts[2] == 'brd':
                    scope = parts[5]
                else:
                    scope = parts[3]

            retval.append(dict(cidr=parts[1],
                               scope=scope,
                               dynamic=('dynamic' == parts[-1]),
                               tentative=('tentative' in line),
                               dadfailed=('dadfailed' == parts[-1])))
        return retval

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
                    reason=_LE('Address not present on interface'))
            if not addr_info['tentative']:
                return True
            if addr_info['dadfailed']:
                raise AddressNotReady(
                    address=address, reason=_LE('Duplicate adddress detected'))
        errmsg = _LE("Exceeded %s second limit waiting for "
                     "address to leave the tentative state.") % wait_time
        utils.utils.wait_until_true(
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

    def _table_args(self):
        return ['table', self._table] if self._table else []

    def add_gateway(self, gateway, metric=None, table=None):
        ip_version = get_ip_version(gateway)
        args = ['replace', 'default', 'via', gateway]
        if metric:
            args += ['metric', metric]
        args += ['dev', self.name]
        if table:
            args += ['table', table]
        else:
            args += self._table_args()
        self._as_root([ip_version], tuple(args))

    def delete_gateway(self, gateway, table=None):
        ip_version = get_ip_version(gateway)
        args = ['del', 'default',
                'via', gateway,
                'dev', self.name]
        if table:
            args += ['table', table]
        else:
            args += self._table_args()
        try:
            self._as_root([ip_version], tuple(args))
        except RuntimeError as rte:
            with (excutils.save_and_reraise_exception()) as ctx:
                if "Cannot find device" in str(rte):
                    ctx.reraise = False
                    raise exceptions.DeviceNotFoundError(
                        device_name=self.name)

    def list_onlink_routes(self, ip_version):
        def iterate_routes():
            args = ['list', 'dev', self.name, 'scope', 'link']
            args += self._table_args()
            output = self._run([ip_version], tuple(args))
            for line in output.split('\n'):
                line = line.strip()
                if line and not line.count('src'):
                    yield line

        return [x for x in iterate_routes()]

    def add_onlink_route(self, cidr):
        ip_version = get_ip_version(cidr)
        args = ['replace', cidr, 'dev', self.name, 'scope', 'link']
        args += self._table_args()
        self._as_root([ip_version], tuple(args))

    def delete_onlink_route(self, cidr):
        ip_version = get_ip_version(cidr)
        args = ['del', cidr, 'dev', self.name, 'scope', 'link']
        args += self._table_args()
        self._as_root([ip_version], tuple(args))

    def get_gateway(self, scope=None, filters=None, ip_version=None):
        options = [ip_version] if ip_version else []

        args = ['list', 'dev', self.name]
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

    def pullup_route(self, interface_name, ip_version):
        """Ensures that the route entry for the interface is before all
        others on the same subnet.
        """
        options = [ip_version]
        device_list = []
        device_route_list_lines = self._run(options,
                                            ('list',
                                             'proto', 'kernel',
                                             'dev', interface_name)
                                            ).split('\n')
        for device_route_line in device_route_list_lines:
            try:
                subnet = device_route_line.split()[0]
            except Exception:
                continue
            subnet_route_list_lines = self._run(options,
                                                ('list',
                                                 'proto', 'kernel',
                                                 'match', subnet)
                                                ).split('\n')
            for subnet_route_line in subnet_route_list_lines:
                i = iter(subnet_route_line.split())
                while(next(i) != 'dev'):
                    pass
                device = next(i)
                try:
                    while(next(i) != 'src'):
                        pass
                    src = next(i)
                except Exception:
                    src = ''
                if device != interface_name:
                    device_list.append((device, src))
                else:
                    break

            for (device, src) in device_list:
                self._as_root(options, ('del', subnet, 'dev', device))
                if (src != ''):
                    self._as_root(options,
                                  ('append', subnet,
                                   'proto', 'kernel',
                                   'src', src,
                                   'dev', device))
                else:
                    self._as_root(options,
                                  ('append', subnet,
                                   'proto', 'kernel',
                                   'dev', device))

    def add_route(self, cidr, ip, table=None):
        ip_version = get_ip_version(cidr)
        args = ['replace', cidr, 'via', ip, 'dev', self.name]
        if table:
            args += ['table', table]
        self._as_root([ip_version], tuple(args))

    def delete_route(self, cidr, ip, table=None):
        ip_version = get_ip_version(cidr)
        args = ['del', cidr, 'via', ip, 'dev', self.name]
        if table:
            args += ['table', table]
        self._as_root([ip_version], tuple(args))


class IpNeighCommand(IpDeviceCommandBase):
    COMMAND = 'neigh'

    def add(self, ip_address, mac_address):
        ip_version = get_ip_version(ip_address)
        self._as_root([ip_version],
                      ('replace', ip_address,
                       'lladdr', mac_address,
                       'nud', 'permanent',
                       'dev', self.name))

    def delete(self, ip_address, mac_address):
        ip_version = get_ip_version(ip_address)
        self._as_root([ip_version],
                      ('del', ip_address,
                       'lladdr', mac_address,
                       'dev', self.name))

    def show(self, ip_version):
        options = [ip_version]
        return self._as_root(options,
                             ('show',
                              'dev', self.name))

    def flush(self, ip_version, ip_address):
        """Flush neighbour entries

        Given address entry is removed from neighbour cache (ARP or NDP). To
        flush all entries pass string 'all' as an address.

        :param ip_version: Either 4 or 6 for IPv4 or IPv6 respectively
        :param ip_address: The prefix selecting the neighbours to flush
        """
        self._as_root([ip_version], ('flush', 'to', ip_address))


class IpNetnsCommand(IpCommandBase):
    COMMAND = 'netns'

    def add(self, name):
        self._as_root([], ('add', name), use_root_namespace=True)
        wrapper = IPWrapper(namespace=name)
        wrapper.netns.execute(['sysctl', '-w',
                               'net.ipv4.conf.all.promote_secondaries=1'])
        return wrapper

    def delete(self, name):
        self._as_root([], ('delete', name), use_root_namespace=True)

    def execute(self, cmds, addl_env=None, check_exit_code=True,
                extra_ok_codes=None, run_as_root=False):
        ns_params = []
        kwargs = {'run_as_root': run_as_root}
        if self._parent.namespace:
            kwargs['run_as_root'] = True
            ns_params = ['ip', 'netns', 'exec', self._parent.namespace]

        env_params = []
        if addl_env:
            env_params = (['env'] +
                          ['%s=%s' % pair for pair in addl_env.items()])
        cmd = ns_params + env_params + list(cmds)
        return utils.execute(cmd, check_exit_code=check_exit_code,
                             extra_ok_codes=extra_ok_codes, **kwargs)

    def exists(self, name):
        output = self._parent._execute(
            ['o'], 'netns', ['list'],
            run_as_root=cfg.CONF.AGENT.use_helper_for_ns_read)
        for line in output.split('\n'):
            if name == line.strip():
                return True
        return False


def device_exists(device_name, namespace=None):
    """Return True if the device exists in the namespace."""
    try:
        dev = IPDevice(device_name, namespace=namespace)
        dev.set_log_fail_as_error(False)
        address = dev.link.address
    except RuntimeError:
        return False
    return bool(address)


def device_exists_with_ips_and_mac(device_name, ip_cidrs, mac, namespace=None):
    """Return True if the device with the given IP addresses and MAC address
    exists in the namespace.
    """
    try:
        device = IPDevice(device_name, namespace=namespace)
        if mac != device.link.address:
            return False
        device_ip_cidrs = [ip['cidr'] for ip in device.addr.list()]
        for ip_cidr in ip_cidrs:
            if ip_cidr not in device_ip_cidrs:
                return False
    except RuntimeError:
        return False
    else:
        return True


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

    ip_wrapper = IPWrapper(namespace=namespace)
    table = ip_wrapper.netns.execute(
        ['ip', '-%s' % ip_version, 'route'],
        check_exit_code=True)

    routes = []
    # Example for route_lines:
    # default via 192.168.3.120 dev wlp3s0  proto static  metric 1024
    # 10.0.0.0/8 dev tun0  proto static  scope link  metric 1024
    # The first column is the destination, followed by key/value pairs.
    # The generator splits the routing table by newline, then strips and splits
    # each individual line.
    route_lines = (line.split() for line in table.split('\n') if line.strip())
    for route in route_lines:
        network = route[0]
        # Create a dict of key/value pairs (For example - 'dev': 'tun0')
        # excluding the first column.
        data = dict(route[i:i + 2] for i in range(1, len(route), 2))
        routes.append({'destination': network,
                       'nexthop': data.get('via'),
                       'device': data.get('dev'),
                       'scope': data.get('scope')})
    return routes


def ensure_device_is_ready(device_name, namespace=None):
    dev = IPDevice(device_name, namespace=namespace)
    dev.set_log_fail_as_error(False)
    try:
        # Ensure the device is up, even if it is already up. If the device
        # doesn't exist, a RuntimeError will be raised.
        dev.link.set_up()
    except RuntimeError:
        return False
    return True


def iproute_arg_supported(command, arg):
    command += ['help']
    stdout, stderr = utils.execute(command, check_exit_code=False,
                                   return_stderr=True, log_fail_as_error=False)
    return any(arg in line for line in stderr.split('\n'))


def _arping(ns_name, iface_name, address, count):
    # Pass -w to set timeout to ensure exit if interface removed while running
    arping_cmd = ['arping', '-A', '-I', iface_name, '-c', count,
                  '-w', 1.5 * count, address]
    try:
        ip_wrapper = IPWrapper(namespace=ns_name)
        ip_wrapper.netns.execute(arping_cmd, check_exit_code=True)
    except Exception:
        msg = _LE("Failed sending gratuitous ARP "
                  "to %(addr)s on %(iface)s in namespace %(ns)s")
        LOG.exception(msg, {'addr': address,
                            'iface': iface_name,
                            'ns': ns_name})


def send_ip_addr_adv_notif(ns_name, iface_name, address, config):
    """Send advance notification of an IP address assignment.

    If the address is in the IPv4 family, send gratuitous ARP.

    If the address is in the IPv6 family, no advance notification is
    necessary, since the Neighbor Discovery Protocol (NDP), Duplicate
    Address Discovery (DAD), and (for stateless addresses) router
    advertisements (RAs) are sufficient for address resolution and
    duplicate address detection.
    """
    count = config.send_arp_for_ha

    def arping():
        _arping(ns_name, iface_name, address, count)

    if count > 0 and netaddr.IPAddress(address).version == 4:
        eventlet.spawn_n(arping)


def add_namespace_to_cmd(cmd, namespace=None):
    """Add an optional namespace to the command."""

    return ['ip', 'netns', 'exec', namespace] + cmd if namespace else cmd


def get_ip_version(ip_or_cidr):
    return netaddr.IPNetwork(ip_or_cidr).version


def get_ipv6_lladdr(mac_addr):
    return '%s/64' % netaddr.EUI(mac_addr).ipv6_link_local()
