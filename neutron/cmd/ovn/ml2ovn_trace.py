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

import ipaddress
import subprocess  # nosec
import sys

import click
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
        return subprocess.run(self.args, check=True)  # nosec

    def __str__(self):
        return " ".join(self.args[:-1] + ("'%s'" % self.args[-1],))


class Interface:
    def __init__(self, query, direction, ctx):
        # Only store the state for running the queries, we don't want to
        # make network connections until after argument parsing is done
        self.query = query
        self.direction = direction
        self.ctx = ctx

    @property
    def network_param(self):
        return (self.ctx.params.get('%s_net' % self.direction) or
                self.ctx.params['net'])

    @property
    def cloud(self):
        return self.ctx.cloud


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
            raise Exception(_('Multiple VMs match %s' % self.query))
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


class RequiredUnless(click.Option):
    def __init__(self, *args, **kwargs):
        try:
            self.unless = kwargs.pop('unless')
            kwargs['required'] = True
        except KeyError:
            raise TypeError(_("Missing required argument: 'unless'"))
        super().__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        if self.unless in opts:
            self.required = False
        return super().handle_parse_result(ctx, opts, args)


class ObjEqValueParam(click.ParamType):
    types = {}
    name = "object=value"
    default_type = ""

    def __init__(self, direction):
        if direction not in ('from', 'to'):
            raise ValueError(_("Direction must be 'from' or 'to'"))
        self.direction = direction
        super().__init__()

    def get_metavar(self, param):
        return "[{}]=value".format("|".join(self.types.keys()))

    def convert(self, value, param, ctx):
        if isinstance(value, self.__class__):
            return value
        try:
            obj, value = value.split('=')
        except ValueError:
            obj = self.default_type
        try:
            return self.types[obj](value, self.direction, ctx)
        except KeyError:
            self.fail(f"Unknown object type {obj!r}", param, ctx)


class ToFromParam(ObjEqValueParam):
    types = {'server': ServerInterface, 'router': RouterInterface}
    default_type = 'server'


class MacParam(ObjEqValueParam):
    types = dict(mac=MAC, **ToFromParam.types)
    default_type = "mac"


class IpParam(ObjEqValueParam):
    types = dict(ip=IP, **ToFromParam.types)
    default_type = "ip"


def set_cloud(ctx, param, value):
    ctx.cloud = openstack.connect(cloud=value)
    return ctx.cloud


FromOpt = ToFromParam('from')
ToOpt = ToFromParam('to')
IpSrcOpt = IpParam('from')
EthSrcOpt = MacParam('from')
IpDstOpt = IpParam('to')
EthDstOpt = MacParam('to')


@click.command()
@click.option('--cloud', '-c', default='devstack', callback=set_cloud,
              help='Cloud from clouds.yaml to connect to')
@click.option('--net', '-n', help="Network to limit interfaces lookups to")
@click.option('--from-net', help="Network to limit src interface lookups to")
@click.option('--to-net', help="Network to limit dst interface lookups to")
@click.option('--from', '-f', 'from_', type=FromOpt,
              help='Fill eth-src/ip-src from the same object, e.g. server=vm1')
@click.option('--eth-src', type=EthSrcOpt, cls=RequiredUnless, unless='from_',
              help='Object from which to fill eth.src')
@click.option('--ip-src', type=IpSrcOpt, cls=RequiredUnless, unless='from_',
              help='Object from which to fill ip.src')
@click.option('--to', '-t', type=ToOpt,
              help='Fill eth-dst/ip-dst from the same object, e.g. server=vm2')
@click.option('--eth-dst', '--via', '-v', type=EthDstOpt, cls=RequiredUnless,
              unless='to', help='Object from which to fill eth.dst')
@click.option('--ip-dst', type=IpDstOpt, cls=RequiredUnless, unless='to',
              help='Object from which to fill ip.dst')
@click.option('--microflow', '-m', default='',
              help='Additional microflow text to append to the one generated')
@click.option('--verbose', '-v', is_flag=True, help='Enables verbose mode')
@click.option('--dry-run', is_flag=True,
              help="Print ovn-trace output, but don't run it")
@click.argument('ovntrace_args', nargs=-1, type=click.UNPROCESSED)
def main(cloud, net, from_net, to_net, from_, eth_src, ip_src, to, eth_dst,
         ip_dst, microflow, verbose, dry_run, ovntrace_args):
    ovn_trace = OvnTrace(eth_src or from_, ip_src or from_,
                         eth_dst or to, ip_dst or to, microflow, ovntrace_args)
    if not dry_run:
        if verbose:
            sys.stderr.write("%s\n" % ovn_trace)
        ovn_trace.run()
    else:
        print(ovn_trace)
