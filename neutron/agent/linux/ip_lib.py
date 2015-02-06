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
import os

import netaddr
from oslo_config import cfg

from neutron.agent.linux import utils
from neutron.common import exceptions
from neutron.i18n import _LE
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.BoolOpt('ip_lib_force_root',
                default=False,
                help=_('Force ip_lib calls to use the root helper')),
]


LOOPBACK_DEVNAME = 'lo'
# NOTE(ethuleau): depend of the version of iproute2, the vlan
# interface details vary.
VLAN_INTERFACE_DETAIL = ['vlan protocol 802.1q',
                         'vlan protocol 802.1Q',
                         'vlan id']


class SubProcessBase(object):
    def __init__(self, root_helper=None, namespace=None,
                 log_fail_as_error=True):
        self.root_helper = root_helper
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
            return self._execute(options, command, args, self.root_helper,
                                 log_fail_as_error=self.log_fail_as_error)
        else:
            return self._execute(options, command, args,
                                 log_fail_as_error=self.log_fail_as_error)

    def enforce_root_helper(self):
        if not self.root_helper and os.geteuid() != 0:
            raise exceptions.SudoRequired()

    def _as_root(self, options, command, args, use_root_namespace=False):
        self.enforce_root_helper()

        namespace = self.namespace if not use_root_namespace else None

        return self._execute(options,
                             command,
                             args,
                             self.root_helper,
                             namespace,
                             log_fail_as_error=self.log_fail_as_error)

    @classmethod
    def _execute(cls, options, command, args, root_helper=None,
                 namespace=None, log_fail_as_error=True):
        opt_list = ['-%s' % o for o in options]
        if namespace:
            ip_cmd = ['ip', 'netns', 'exec', namespace, 'ip']
        else:
            ip_cmd = ['ip']
        return utils.execute(ip_cmd + opt_list + [command] + list(args),
                             root_helper=root_helper,
                             log_fail_as_error=log_fail_as_error)

    def set_log_fail_as_error(self, fail_with_error):
        self.log_fail_as_error = fail_with_error


class IPWrapper(SubProcessBase):
    def __init__(self, root_helper=None, namespace=None):
        super(IPWrapper, self).__init__(root_helper=root_helper,
                                        namespace=namespace)
        self.netns = IpNetnsCommand(self)

    def device(self, name):
        return IPDevice(name, self.root_helper, self.namespace)

    def get_devices(self, exclude_loopback=False):
        retval = []
        output = self._execute(['o', 'd'], 'link', ('list',),
                               self.root_helper, self.namespace)
        for line in output.split('\n'):
            if '<' not in line:
                continue
            tokens = line.split(' ', 2)
            if len(tokens) == 3:
                if any(v in tokens[2] for v in VLAN_INTERFACE_DETAIL):
                    delimiter = '@'
                else:
                    delimiter = ':'
                name = tokens[1].rpartition(delimiter)[0].strip()

                if exclude_loopback and name == LOOPBACK_DEVNAME:
                    continue

                retval.append(IPDevice(name,
                                       self.root_helper,
                                       self.namespace))
        return retval

    def add_tuntap(self, name, mode='tap'):
        self._as_root('', 'tuntap', ('add', name, 'mode', mode))
        return IPDevice(name, self.root_helper, self.namespace)

    def add_veth(self, name1, name2, namespace2=None):
        args = ['add', name1, 'type', 'veth', 'peer', 'name', name2]

        if namespace2 is None:
            namespace2 = self.namespace
        else:
            self.ensure_namespace(namespace2)
            args += ['netns', namespace2]

        self._as_root('', 'link', tuple(args))

        return (IPDevice(name1, self.root_helper, self.namespace),
                IPDevice(name2, self.root_helper, namespace2))

    def del_veth(self, name):
        """Delete a virtual interface between two namespaces."""
        self._as_root('', 'link', ('del', name))

    def ensure_namespace(self, name):
        if not self.netns.exists(name):
            ip = self.netns.add(name)
            lo = ip.device(LOOPBACK_DEVNAME)
            lo.link.set_up()
        else:
            ip = IPWrapper(self.root_helper, name)
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
        self._as_root('', 'link', cmd)
        return (IPDevice(name, self.root_helper, self.namespace))

    @classmethod
    def get_namespaces(cls, root_helper):
        output = cls._execute('', 'netns', ('list',), root_helper=root_helper)
        return [l.strip() for l in output.split('\n')]


class IpRule(IPWrapper):
    def add(self, ip, table, rule_pr):
        ip_version = netaddr.IPNetwork(ip).version
        args = ['add', 'from', ip, 'table', table, 'priority', rule_pr]
        ip = self._as_root([ip_version], 'rule', tuple(args))
        return ip

    def delete(self, ip, table, rule_pr):
        ip_version = netaddr.IPNetwork(ip).version
        args = ['del', 'table', table, 'priority', rule_pr]
        ip = self._as_root([ip_version], 'rule', tuple(args))
        return ip


class IPDevice(SubProcessBase):
    def __init__(self, name, root_helper=None, namespace=None):
        super(IPDevice, self).__init__(root_helper=root_helper,
                                       namespace=namespace)
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

    def _run(self, *args, **kwargs):
        return self._parent._run(kwargs.get('options', []), self.COMMAND, args)

    def _as_root(self, *args, **kwargs):
        return self._parent._as_root(kwargs.get('options', []),
                                     self.COMMAND,
                                     args,
                                     kwargs.get('use_root_namespace', False))


class IpDeviceCommandBase(IpCommandBase):
    @property
    def name(self):
        return self._parent.name


class IpLinkCommand(IpDeviceCommandBase):
    COMMAND = 'link'

    def set_address(self, mac_address):
        self._as_root('set', self.name, 'address', mac_address)

    def set_mtu(self, mtu_size):
        self._as_root('set', self.name, 'mtu', mtu_size)

    def set_up(self):
        self._as_root('set', self.name, 'up')

    def set_down(self):
        self._as_root('set', self.name, 'down')

    def set_netns(self, namespace):
        self._as_root('set', self.name, 'netns', namespace)
        self._parent.namespace = namespace

    def set_name(self, name):
        self._as_root('set', self.name, 'name', name)
        self._parent.name = name

    def set_alias(self, alias_name):
        self._as_root('set', self.name, 'alias', alias_name)

    def delete(self):
        self._as_root('delete', self.name)

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
        return self._parse_line(self._run('show', self.name, options='o'))

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

    def add(self, ip_version, cidr, broadcast, scope='global'):
        self._as_root('add',
                      cidr,
                      'brd',
                      broadcast,
                      'scope',
                      scope,
                      'dev',
                      self.name,
                      options=[ip_version])

    def delete(self, ip_version, cidr):
        self._as_root('del',
                      cidr,
                      'dev',
                      self.name,
                      options=[ip_version])

    def flush(self):
        self._as_root('flush', self.name)

    def list(self, scope=None, to=None, filters=None):
        if filters is None:
            filters = []

        retval = []

        if scope:
            filters += ['scope', scope]
        if to:
            filters += ['to', to]

        for line in self._run('show', self.name, *filters).split('\n'):
            line = line.strip()
            if not line.startswith('inet'):
                continue
            parts = line.split()
            if parts[0] == 'inet6':
                version = 6
                scope = parts[3]
                broadcast = '::'
            else:
                version = 4
                if parts[2] == 'brd':
                    broadcast = parts[3]
                    scope = parts[5]
                else:
                    # sometimes output of 'ip a' might look like:
                    # inet 192.168.100.100/24 scope global eth0
                    # and broadcast needs to be calculated from CIDR
                    broadcast = str(netaddr.IPNetwork(parts[1]).broadcast)
                    scope = parts[3]

            retval.append(dict(cidr=parts[1],
                               broadcast=broadcast,
                               scope=scope,
                               ip_version=version,
                               dynamic=('dynamic' == parts[-1])))
        return retval


class IpRouteCommand(IpDeviceCommandBase):
    COMMAND = 'route'

    def add_gateway(self, gateway, metric=None, table=None):
        args = ['replace', 'default', 'via', gateway]
        if metric:
            args += ['metric', metric]
        args += ['dev', self.name]
        if table:
            args += ['table', table]
        self._as_root(*args)

    def delete_gateway(self, gateway=None, table=None):
        args = ['del', 'default']
        if gateway:
            args += ['via', gateway]
        args += ['dev', self.name]
        if table:
            args += ['table', table]
        self._as_root(*args)

    def list_onlink_routes(self):
        def iterate_routes():
            output = self._run('list', 'dev', self.name, 'scope', 'link')
            for line in output.split('\n'):
                line = line.strip()
                if line and not line.count('src'):
                    yield line

        return [x for x in iterate_routes()]

    def add_onlink_route(self, cidr):
        self._as_root('replace', cidr, 'dev', self.name, 'scope', 'link')

    def delete_onlink_route(self, cidr):
        self._as_root('del', cidr, 'dev', self.name, 'scope', 'link')

    def get_gateway(self, scope=None, filters=None):
        if filters is None:
            filters = []

        retval = None

        if scope:
            filters += ['scope', scope]

        route_list_lines = self._run('list', 'dev', self.name,
                                     *filters).split('\n')
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
        device_route_list_lines = self._run('list', 'proto', 'kernel',
                                            'dev', interface_name).split('\n')
        for device_route_line in device_route_list_lines:
            try:
                subnet = device_route_line.split()[0]
            except Exception:
                continue
            subnet_route_list_lines = self._run('list', 'proto', 'kernel',
                                                'match', subnet).split('\n')
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
                self._as_root('del', subnet, 'dev', device)
                if (src != ''):
                    self._as_root('append', subnet, 'proto', 'kernel',
                                  'src', src, 'dev', device)
                else:
                    self._as_root('append', subnet, 'proto', 'kernel',
                                  'dev', device)

    def add_route(self, cidr, ip, table=None):
        args = ['replace', cidr, 'via', ip, 'dev', self.name]
        if table:
            args += ['table', table]
        self._as_root(*args)

    def delete_route(self, cidr, ip, table=None):
        args = ['del', cidr, 'via', ip, 'dev', self.name]
        if table:
            args += ['table', table]
        self._as_root(*args)


class IpNeighCommand(IpDeviceCommandBase):
    COMMAND = 'neigh'

    def add(self, ip_version, ip_address, mac_address):
        self._as_root('replace',
                      ip_address,
                      'lladdr',
                      mac_address,
                      'nud',
                      'permanent',
                      'dev',
                      self.name,
                      options=[ip_version])

    def delete(self, ip_version, ip_address, mac_address):
        self._as_root('del',
                      ip_address,
                      'lladdr',
                      mac_address,
                      'dev',
                      self.name,
                      options=[ip_version])


class IpNetnsCommand(IpCommandBase):
    COMMAND = 'netns'

    def add(self, name):
        self._as_root('add', name, use_root_namespace=True)
        wrapper = IPWrapper(self._parent.root_helper, name)
        wrapper.netns.execute(['sysctl', '-w',
                               'net.ipv4.conf.all.promote_secondaries=1'])
        return wrapper

    def delete(self, name):
        self._as_root('delete', name, use_root_namespace=True)

    def execute(self, cmds, addl_env=None, check_exit_code=True,
                extra_ok_codes=None):
        ns_params = []
        if self._parent.namespace:
            self._parent.enforce_root_helper()
            ns_params = ['ip', 'netns', 'exec', self._parent.namespace]

        env_params = []
        if addl_env:
            env_params = (['env'] +
                          ['%s=%s' % pair for pair in addl_env.items()])
        return utils.execute(
            ns_params + env_params + list(cmds),
            root_helper=self._parent.root_helper,
            check_exit_code=check_exit_code, extra_ok_codes=extra_ok_codes)

    def exists(self, name):
        root_helper = self._parent.root_helper
        if not cfg.CONF.AGENT.use_helper_for_ns_read:
            root_helper = None
        output = self._parent._execute('o', 'netns', ['list'],
                                       root_helper=root_helper)
        for line in output.split('\n'):
            if name == line.strip():
                return True
        return False


def device_exists(device_name, root_helper=None, namespace=None):
    """Return True if the device exists in the namespace."""
    try:
        dev = IPDevice(device_name, root_helper, namespace)
        dev.set_log_fail_as_error(False)
        address = dev.link.address
    except RuntimeError:
        return False
    return bool(address)


def device_exists_with_ip_mac(device_name, ip_cidr, mac, namespace=None,
                              root_helper=None):
    """Return True if the device with the given IP and MAC addresses
    exists in the namespace.
    """
    try:
        device = IPDevice(device_name, root_helper, namespace)
        if mac != device.link.address:
            return False
        if ip_cidr not in (ip['cidr'] for ip in device.addr.list()):
            return False
    except RuntimeError:
        return False
    else:
        return True


def get_routing_table(root_helper=None, namespace=None):
    """Return a list of dictionaries, each representing a route.

    The dictionary format is: {'destination': cidr,
                               'nexthop': ip,
                               'device': device_name}
    """

    ip_wrapper = IPWrapper(root_helper, namespace=namespace)
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


def ensure_device_is_ready(device_name, root_helper=None, namespace=None):
    dev = IPDevice(device_name, root_helper, namespace)
    dev.set_log_fail_as_error(False)
    try:
        # Ensure the device is up, even if it is already up. If the device
        # doesn't exist, a RuntimeError will be raised.
        dev.link.set_up()
    except RuntimeError:
        return False
    return True


def iproute_arg_supported(command, arg, root_helper=None):
    command += ['help']
    stdout, stderr = utils.execute(command, root_helper=root_helper,
                                   check_exit_code=False, return_stderr=True)
    return any(arg in line for line in stderr.split('\n'))


def _arping(ns_name, iface_name, address, count, root_helper):
    arping_cmd = ['arping', '-A', '-I', iface_name, '-c', count, address]
    try:
        ip_wrapper = IPWrapper(root_helper, namespace=ns_name)
        ip_wrapper.netns.execute(arping_cmd, check_exit_code=True)
    except Exception:
        msg = _LE("Failed sending gratuitous ARP "
                  "to %(addr)s on %(iface)s in namespace %(ns)s")
        LOG.exception(msg, {'addr': address,
                            'iface': iface_name,
                            'ns': ns_name})


def send_gratuitous_arp(ns_name, iface_name, address, count, root_helper):
    """Send a gratuitous arp using given namespace, interface, and address"""

    def arping():
        _arping(ns_name, iface_name, address, count, root_helper)

    if count > 0:
        eventlet.spawn_n(arping)


def send_garp_for_proxyarp(ns_name, iface_name, address, count, root_helper):
    """
    Send a gratuitous arp using given namespace, interface, and address

    This version should be used when proxy arp is in use since the interface
    won't actually have the address configured.  We actually need to configure
    the address on the interface and then remove it when the proxy arp has been
    sent.
    """
    def arping_with_temporary_address():
        # Configure the address on the interface
        device = IPDevice(iface_name, root_helper, namespace=ns_name)
        net = netaddr.IPNetwork(str(address))
        device.addr.add(net.version, str(net), str(net.broadcast))

        _arping(ns_name, iface_name, address, count, root_helper)

        # Delete the address from the interface
        device.addr.delete(net.version, str(net))

    if count > 0:
        eventlet.spawn_n(arping_with_temporary_address)
