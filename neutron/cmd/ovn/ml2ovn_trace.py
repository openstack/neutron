# Copyright 2021 Red Hat, Inc.
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

import argparse
import ipaddress
import subprocess
import sys

import openstack

from neutron._i18n import _


class cached_property:
    __slots__ = ('_fn', '__doc__')

    def __init__(self, fn):
        self._fn = fn
        self.__doc__ = fn.__doc__

    def __get__(self, obj, objtype=None):
        # class of wrapped method must have writable __dict__
        attr = self._fn(obj)
        setattr(obj, self._fn.__name__, attr)
        return attr


class OvnTrace:
    def __init__(self, eth_src_obj, ip_src_obj, eth_dst_obj, ip_dst_obj,
                 extra_flow, extra_args):
        self.inport = eth_src_obj.inport
        self.eth_src = eth_src_obj.mac
        self.ip_src = ip_src_obj.ip
        self.eth_dst = eth_dst_obj.mac
        self.ip_dst = ip_dst_obj.ip
        self.extra_flow = extra_flow
        self.extra_args = extra_args

    @property
    def microflow(self):
        ip_version = ipaddress.ip_address(self.ip_src).version
        generated_flow = (
            'inport == "{inport}" && '
            'eth.src == {eth_src} && '
            'ip{ip_src_v}.src == {ip_src} && '
            'eth.dst == {eth_dst} && '
            'ip{ip_dst_v}.dst == {ip_dst} && '
            'ip.ttl == 64'.format(
                inport=self.inport, eth_src=self.eth_src, ip_src_v=ip_version,
                ip_src=self.ip_src, eth_dst=self.eth_dst, ip_dst_v=ip_version,
                ip_dst=self.ip_dst))
        return ' && '.join(f for f in (generated_flow, self.extra_flow) if f)

    @property
    def args(self):
        return ('ovn-trace', *self.extra_args, self.microflow)

    def run(self):
        return subprocess.run(self.args, check=True)  # noqa: S603

    def __str__(self):
        return " ".join(self.args[:-1] + ("'%s'" % self.args[-1],))


class Interface:
    def __init__(self, query, direction, cloud, net, from_net, to_net):
        # Only store the state for running the queries, we don't want to
        # make network connections until after argument parsing is done
        self.query = query
        self.direction = direction
        self._cloud = cloud
        self._net = net
        self._from_net = from_net
        self._to_net = to_net

    @property
    def network_param(self):
        direction_net = (
            self._from_net if self.direction == 'from' else self._to_net)
        return direction_net or self._net

    @property
    def cloud(self):
        return self._cloud


class ServerInterface(Interface):

    def get_iface(self, iface_type):
        return next(iter(i for i in self.instance.addresses[self.network]
                         if i.get('OS-EXT-IPS:type') == iface_type))

    @cached_property
    def instance(self):
        matching_vms = self.cloud.search_servers(self.query)
        if len(matching_vms) < 1:
            raise Exception(_('Server not found'))
        if len(matching_vms) > 1:
            raise Exception(_('Multiple VMs match %s') % self.query)
        return matching_vms[0]

    @cached_property
    def network(self):
        if self.network_param:
            return self.network_param
        if len(self.instance.addresses) != 1:
            raise Exception(_("Could not determine server network"))
        return next(iter(key for key in self.instance.addresses))

    @cached_property
    def inport(self):
        return self.cloud.search_ports(
            filters={'device_id': self.instance.id})[0].id

    @cached_property
    def ip(self):
        iface = self.get_iface('fixed')
        return iface['addr']

    @cached_property
    def mac(self):
        iface = self.get_iface('fixed')
        return iface['OS-EXT-IPS-MAC:mac_addr']

    @cached_property
    def floating_ip(self):
        iface = self.get_iface('floating')
        return iface['addr']


class RouterInterface(Interface):

    @cached_property
    def network(self):
        return self.cloud.search_networks(self.network_param)[0]

    @cached_property
    def router(self):
        return self.cloud.search_routers(self.query)[0]

    @cached_property
    def interface(self):
        return next(iter(self.cloud.search_ports(
            filters={'device_id': self.router.id,
                     'network_id': self.network.id})))

    @cached_property
    def inport(self):
        return self.interface.id

    @cached_property
    def ip(self):
        return next(iter(ip['ip_address'] for ip in self.interface.fixed_ips))

    @cached_property
    def mac(self):
        return self.interface.mac_address


class SwitchPort(Interface):
    cache = {}


class IP(Interface):
    @property
    def ip(self):
        return self.query


class MAC(Interface):
    @property
    def mac(self):
        return self.query


_FROM_TO_TYPES = {'server': ServerInterface, 'router': RouterInterface}
_MAC_TYPES = dict(mac=MAC, **_FROM_TO_TYPES)
_IP_TYPES = dict(ip=IP, **_FROM_TO_TYPES)


def _parse_obj_value(value, types, default_type):
    """Parse an 'object=value' argument string.

    Returns a (class, query) tuple for later Interface construction.
    """
    try:
        obj_type, query = value.split('=', 1)
    except ValueError:
        obj_type = default_type
        query = value
    if obj_type not in types:
        raise argparse.ArgumentTypeError(
            _("Unknown object type %r") % obj_type)
    return types[obj_type], query


def _from_to_type(value):
    return _parse_obj_value(value, _FROM_TO_TYPES, 'server')


def _mac_type(value):
    return _parse_obj_value(value, _MAC_TYPES, 'mac')


def _ip_type(value):
    return _parse_obj_value(value, _IP_TYPES, 'ip')


def _make_interface(parsed_value, direction, cloud, net, from_net, to_net):
    cls, query = parsed_value
    return cls(query, direction, cloud, net, from_net, to_net)


def main():
    parser = argparse.ArgumentParser(
        description='Trace a packet through OVN')
    parser.add_argument(
        '--cloud', '-c', default='devstack',
        help='Cloud from clouds.yaml to connect to')
    parser.add_argument(
        '--net', '-n', help='Network to limit interface lookups to')
    parser.add_argument(
        '--from-net', help='Network to limit src interface lookups to')
    parser.add_argument(
        '--to-net', help='Network to limit dst interface lookups to')
    parser.add_argument(
        '--from', '-f', dest='from_', type=_from_to_type,
        metavar='[server|router]=VALUE',
        help='Fill eth-src/ip-src from the same object, e.g. server=vm1')
    parser.add_argument(
        '--eth-src', type=_mac_type, metavar='[mac|server|router]=VALUE',
        help='Object from which to fill eth.src')
    parser.add_argument(
        '--ip-src', type=_ip_type, metavar='[ip|server|router]=VALUE',
        help='Object from which to fill ip.src')
    parser.add_argument(
        '--to', '-t', type=_from_to_type, metavar='[server|router]=VALUE',
        help='Fill eth-dst/ip-dst from the same object, e.g. server=vm2')
    parser.add_argument(
        '--eth-dst', '--via', type=_mac_type,
        metavar='[mac|server|router]=VALUE',
        help='Object from which to fill eth.dst')
    parser.add_argument(
        '--ip-dst', type=_ip_type, metavar='[ip|server|router]=VALUE',
        help='Object from which to fill ip.dst')
    parser.add_argument(
        '--microflow', '-m', default='',
        help='Additional microflow text to append to the one generated')
    parser.add_argument(
        '--verbose', '-v', action='store_true', help='Enables verbose mode')
    parser.add_argument(
        '--dry-run', action='store_true',
        help="Print ovn-trace command, but don't run it")

    args, ovntrace_args = parser.parse_known_args()

    if args.from_ is None:
        if args.eth_src is None:
            parser.error(
                _('--eth-src is required when --from is not provided'))
        if args.ip_src is None:
            parser.error(
                _('--ip-src is required when --from is not provided'))
    if args.to is None:
        if args.eth_dst is None:
            parser.error(
                _('--eth-dst is required when --to is not provided'))
        if args.ip_dst is None:
            parser.error(
                _('--ip-dst is required when --to is not provided'))

    cloud = openstack.connect(cloud=args.cloud)

    def make(parsed_value, direction):
        return _make_interface(
            parsed_value, direction, cloud,
            args.net, args.from_net, args.to_net)

    from_obj = make(args.from_, 'from') if args.from_ else None
    eth_src = make(args.eth_src, 'from') if args.eth_src else from_obj
    ip_src = make(args.ip_src, 'from') if args.ip_src else from_obj
    to_obj = make(args.to, 'to') if args.to else None
    eth_dst = make(args.eth_dst, 'to') if args.eth_dst else to_obj
    ip_dst = make(args.ip_dst, 'to') if args.ip_dst else to_obj

    ovn_trace = OvnTrace(
        eth_src, ip_src, eth_dst, ip_dst, args.microflow, tuple(ovntrace_args))
    if not args.dry_run:
        if args.verbose:
            sys.stderr.write("%s\n" % ovn_trace)
        ovn_trace.run()
    else:
        print(ovn_trace)
