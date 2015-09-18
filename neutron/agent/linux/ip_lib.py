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

from neutron.agent.common import utils
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
        return [l.split()[0] for l in output.splitlines()]


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

    def _exists(self, ip, ip_version, table, rule_pr):
        # Typical rule from 'ip rule show':
        # 4030201:  from 1.2.3.4/24 lookup 10203040

        rule_pr = str(rule_pr) + ":"
        for line in self._as_root([ip_version], ['show']).splitlines():
            parts = line.split()
            if parts and (parts[0] == rule_pr and
                          parts[2] == str(ip) and
                          parts[-1] == str(table)):
                return True

        return False

    def add(self, ip, table, rule_pr):
        ip_version = get_ip_version(ip)
        if not self._exists(ip, ip_version, table, rule_pr):
            args = ['add', 'from', ip, 'table', table, 'priority', rule_pr]
            self._as_root([ip_version], tuple(args))

    def delete(self, ip, table, rule_pr):
        ip_version = get_ip_version(ip)
        args = ['del', 'table', table, 'priority', rule_pr]
        self._as_root([ip_version], tuple(args))


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
        self._as_root([], ('set', self.name, 'up'))

    def set_down(self):
        self._as_root([], ('set', self.name, 'down'))

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
            args += ['brd', str(net[-1])]
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
                               dynamic=('dynamic' == parts[-1])))
        return retval


class IpRouteCommand(IpDeviceCommandBase):
    COMMAND = 'route'

    def add_gateway(self, gateway, metric=None, table=None):
        ip_version = get_ip_version(gateway)
        args = ['replace', 'default', 'via', gateway]
        if metric:
            args += ['metric', metric]
        args += ['dev', self.name]
        if table:
            args += ['table', table]
        self._as_root([ip_version], tuple(args))

    def delete_gateway(self, gateway, table=None):
        ip_version = get_ip_version(gateway)
        args = ['del', 'default',
                'via', gateway,
                'dev', self.name]
        if table:
            args += ['table', table]
        self._as_root([ip_version], tuple(args))

    def list_onlink_routes(self, ip_version):
        def iterate_routes():
            output = self._run([ip_version],
                               ('list',
                                'dev', self.name,
                                'scope', 'link'))
            for line in output.split('\n'):
                line = line.strip()
                if line and not line.count('src'):
                    yield line

        return [x for x in iterate_routes()]

    def add_onlink_route(self, cidr):
        ip_version = get_ip_version(cidr)
        self._as_root([ip_version],
                      ('replace', cidr,
                       'dev', self.name,
                       'scope', 'link'))

    def delete_onlink_route(self, cidr):
        ip_version = get_ip_version(cidr)
        self._as_root([ip_version],
                      ('del', cidr,
                       'dev', self.name,
                       'scope', 'link'))

    def get_gateway(self, scope=None, filters=None, ip_version=None):
        options = [ip_version] if ip_version else []

        args = ['list', 'dev', self.name]
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
            gateway_index = 2
            parts = default_route_line.split()
            retval = dict(gateway=parts[gateway_index])
            if 'metric' in parts:
                metric_index = parts.index('metric') + 1
                retval.update(metric=int(parts[metric_index]))

        return retval

    def pullup_route(self, interface_name):
        """Ensures that the route entry for the interface is before all
        others on the same subnet.
        """
        device_list = []
        device_route_list_lines = self._run([],
                                            ('list',
                                             'proto', 'kernel',
                                             'dev', interface_name)
                                            ).split('\n')
        for device_route_line in device_route_list_lines:
            try:
                subnet = device_route_line.split()[0]
            except Exception:
                continue
            subnet_route_list_lines = self._run([],
                                                ('list',
                                                 'proto', 'kernel',
                                                 'match', subnet)
                                                ).split('\n')
            for subnet_route_line in subnet_route_list_lines:
                i = iter(subnet_route_line.split())
                while(i.next() != 'dev'):
                    pass
                device = i.next()
                try:
                    while(i.next() != 'src'):
                        pass
                    src = i.next()
                except Exception:
                    src = ''
                if device != interface_name:
                    device_list.append((device, src))
                else:
                    break

            for (device, src) in device_list:
                self._as_root([], ('del', subnet, 'dev', device))
                if (src != ''):
                    self._as_root([],
                                  ('append', subnet,
                                   'proto', 'kernel',
                                   'src', src,
                                   'dev', device))
                else:
                    self._as_root([],
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

    def show(self):
        return self._as_root([],
                      ('show',
                       'dev', self.name))


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
                log_fail_as_error=True, extra_ok_codes=None,
                run_as_root=False):
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
                             extra_ok_codes=extra_ok_codes,
                             log_fail_as_error=log_fail_as_error, **kwargs)

    def exists(self, name):
        output = self._parent._execute(
            ['o'], 'netns', ['list'],
            run_as_root=cfg.CONF.AGENT.use_helper_for_ns_read)
        for line in [l.split()[0] for l in output.splitlines()]:
            if name == line:
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


def get_routing_table(namespace=None):
    """Return a list of dictionaries, each representing a route.

    The dictionary format is: {'destination': cidr,
                               'nexthop': ip,
                               'device': device_name}
    """

    ip_wrapper = IPWrapper(namespace=namespace)
    table = ip_wrapper.netns.execute(['ip', 'route'], check_exit_code=True)

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
                       'device': data.get('dev')})
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
                                   return_stderr=True)
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
