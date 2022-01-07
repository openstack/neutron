# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import ctypes
from ctypes import util as ctypes_util
import errno
import os
import socket

from neutron_lib import constants
from oslo_log import log as logging
import pyroute2
from pyroute2 import netlink
from pyroute2.netlink import exceptions as netlink_exceptions
from pyroute2.netlink import rtnl
from pyroute2.netlink.rtnl import ifinfmsg
from pyroute2.netlink.rtnl import ndmsg
from pyroute2 import NetlinkError
from pyroute2 import netns

from neutron._i18n import _
from neutron import privileged


LOG = logging.getLogger(__name__)

_IP_VERSION_FAMILY_MAP = {4: socket.AF_INET, 6: socket.AF_INET6}

NETNS_RUN_DIR = '/var/run/netns'

_CDLL = None


def _get_cdll():
    global _CDLL
    if not _CDLL:
        # NOTE(ralonsoh): from https://docs.python.org/3.6/library/
        # ctypes.html#ctypes.PyDLL: "Instances of this class behave like CDLL
        # instances, except that the Python GIL is not released during the
        # function call, and after the function execution the Python error
        # flag is checked."
        # Check https://bugs.launchpad.net/neutron/+bug/1870352
        _CDLL = ctypes.PyDLL(ctypes_util.find_library('c'), use_errno=True)
    return _CDLL


def _get_scope_name(scope):
    """Return the name of the scope (given as a number), or the scope number
    if the name is unknown.

    For backward compatibility (with "ip" tool) "global" scope is converted to
    "universe" before converting to number
    """
    scope = 'universe' if scope == 'global' else scope
    return rtnl.rt_scope.get(scope, scope)


# TODO(ralonsoh): move those exceptions out of priv_ip_lib to avoid other
# modules to import this one.
class NetworkNamespaceNotFound(RuntimeError):
    message = _("Network namespace %(netns_name)s could not be found.")

    def __init__(self, netns_name):
        super(NetworkNamespaceNotFound, self).__init__(
            self.message % {'netns_name': netns_name})


class NetworkInterfaceNotFound(RuntimeError):
    message = _("Network interface %(device)s not found in namespace "
                "%(namespace)s.")

    def __init__(self, message=None, device=None, namespace=None):
        # NOTE(slaweq): 'message' can be passed as an optional argument
        # because of how privsep daemon works. If exception is raised in
        # function called by privsep daemon, it will then try to reraise it
        # and will call it always with passing only message from originally
        # raised exception.
        message = message or self.message % {
                'device': device, 'namespace': namespace}
        super(NetworkInterfaceNotFound, self).__init__(message)


class InterfaceOperationNotSupported(RuntimeError):
    message = _("Operation not supported on interface %(device)s, namespace "
                "%(namespace)s.")

    def __init__(self, message=None, device=None, namespace=None):
        # NOTE(slaweq): 'message' can be passed as an optional argument
        # because of how privsep daemon works. If exception is raised in
        # function called by privsep daemon, it will then try to reraise it
        # and will call it always with passing only message from originally
        # raised exception.
        message = message or self.message % {
                'device': device, 'namespace': namespace}
        super(InterfaceOperationNotSupported, self).__init__(message)


class InvalidArgument(RuntimeError):
    message = _("Invalid parameter/value used on interface %(device)s, "
                "namespace %(namespace)s.")

    def __init__(self, message=None, device=None, namespace=None):
        # NOTE(slaweq): 'message' can be passed as an optional argument
        # because of how privsep daemon works. If exception is raised in
        # function called by privsep daemon, it will then try to reraise it
        # and will call it always with passing only message from originally
        # raised exception.
        message = message or self.message % {'device': device,
                                             'namespace': namespace}
        super(InvalidArgument, self).__init__(message)


class IpAddressAlreadyExists(RuntimeError):
    message = _("IP address %(ip)s already configured on %(device)s.")

    def __init__(self, message=None, ip=None, device=None):
        # NOTE(slaweq): 'message' can be passed as an optional argument
        # because of how privsep daemon works. If exception is raised in
        # function called by privsep daemon, it will then try to reraise it
        # and will call it always with passing only message from originally
        # raised exception.
        message = message or self.message % {'ip': ip, 'device': device}
        super(IpAddressAlreadyExists, self).__init__(message)


class InterfaceAlreadyExists(RuntimeError):
    message = _("Interface %(device)s already exists.")

    def __init__(self, message=None, device=None):
        # NOTE(slaweq): 'message' can be passed as an optional argument
        # because of how privsep daemon works. If exception is raised in
        # function called by privsep daemon, it will then try to reraise it
        # and will call it always with passing only message from originally
        # raised exception.
        message = message or self.message % {'device': device}
        super(InterfaceAlreadyExists, self).__init__(message)


def _make_route_dict(destination, nexthop, device, scope):
    return {'destination': destination,
            'nexthop': nexthop,
            'device': device,
            'scope': scope}


@privileged.default.entrypoint
def get_routing_table(ip_version, namespace=None):
    """Return a list of dictionaries, each representing a route.

    :param ip_version: IP version of routes to return, for example 4
    :param namespace: The name of the namespace from which to get the routes
    :return: a list of dictionaries, each representing a route.
    The dictionary format is: {'destination': cidr,
                               'nexthop': ip,
                               'device': device_name,
                               'scope': scope}
    """
    family = _IP_VERSION_FAMILY_MAP[ip_version]
    try:
        netns = pyroute2.NetNS(namespace, flags=0) if namespace else None
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise
    routes = []
    with pyroute2.IPDB(nl=netns) as ipdb:
        ipdb_routes = ipdb.routes
        ipdb_interfaces = ipdb.interfaces
        for route in ipdb_routes:
            if route['family'] != family:
                continue
            dst = route['dst']
            nexthop = route.get('gateway')
            oif = route.get('oif')
            scope = _get_scope_name(route['scope'])

            # If there is not a valid outgoing interface id, check if
            # this is a multipath route (i.e. same destination with
            # multiple outgoing interfaces)
            if oif:
                device = ipdb_interfaces[oif]['ifname']
                rt = _make_route_dict(dst, nexthop, device, scope)
                routes.append(rt)
            elif route.get('multipath'):
                for mpr in route['multipath']:
                    oif = mpr['oif']
                    device = ipdb_interfaces[oif]['ifname']
                    rt = _make_route_dict(dst, nexthop, device, scope)
                    routes.append(rt)

    return routes


def get_iproute(namespace):
    # From iproute.py:
    # `IPRoute` -- RTNL API to the current network namespace
    # `NetNS` -- RTNL API to another network namespace
    if namespace:
        # do not try and create the namespace
        return pyroute2.NetNS(namespace, flags=0)
    else:
        return pyroute2.IPRoute()


@privileged.default.entrypoint
def open_namespace(namespace):
    """Open namespace to test if the namespace is ready to be manipulated"""
    with pyroute2.NetNS(namespace, flags=0):
        pass


@privileged.default.entrypoint
def list_ns_pids(namespace):
    """List namespace process PIDs

    Based on Pyroute2.netns.ns_pids(). Remove when
    https://github.com/svinota/pyroute2/issues/633 is fixed.
    """
    ns_pids = []
    try:
        ns_path = os.path.join(NETNS_RUN_DIR, namespace)
        ns_inode = os.stat(ns_path).st_ino
    except (OSError, FileNotFoundError):
        return ns_pids

    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            pid_path = os.path.join('/proc', pid, 'ns', 'net')
            if os.stat(pid_path).st_ino == ns_inode:
                ns_pids.append(int(pid))
        except (OSError, FileNotFoundError):
            continue

    return ns_pids


def _translate_ip_device_exception(e, device=None, namespace=None):
    if e.code == errno.ENODEV:
        raise NetworkInterfaceNotFound(device=device, namespace=namespace)
    if e.code == errno.EOPNOTSUPP:
        raise InterfaceOperationNotSupported(device=device,
                                             namespace=namespace)
    if e.code == errno.EINVAL:
        raise InvalidArgument(device=device, namespace=namespace)


def get_link_id(device, namespace, raise_exception=True):
    with get_iproute(namespace) as ip:
        link_id = ip.link_lookup(ifname=device)
    if not link_id or len(link_id) < 1:
        if raise_exception:
            raise NetworkInterfaceNotFound(device=device, namespace=namespace)
        else:
            LOG.debug('Interface %(dev)s not found in namespace %(namespace)s',
                      {'dev': device, 'namespace': namespace})
            return None
    return link_id[0]


def _run_iproute_link(command, device, namespace=None, **kwargs):
    try:
        with get_iproute(namespace) as ip:
            idx = get_link_id(device, namespace)
            return ip.link(command, index=idx, **kwargs)
    except NetlinkError as e:
        _translate_ip_device_exception(e, device, namespace)
        raise
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


def _run_iproute_neigh(command, device, namespace, **kwargs):
    try:
        with get_iproute(namespace) as ip:
            idx = get_link_id(device, namespace)
            return ip.neigh(command, ifindex=idx, **kwargs)
    except NetlinkError as e:
        _translate_ip_device_exception(e, device, namespace)
        raise
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


def _run_iproute_addr(command, device, namespace, **kwargs):
    try:
        with get_iproute(namespace) as ip:
            idx = get_link_id(device, namespace)
            return ip.addr(command, index=idx, **kwargs)
    except NetlinkError as e:
        _translate_ip_device_exception(e, device, namespace)
        raise
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def add_ip_address(ip_version, ip, prefixlen, device, namespace, scope,
                   broadcast=None):
    family = _IP_VERSION_FAMILY_MAP[ip_version]
    try:
        _run_iproute_addr('add',
                          device,
                          namespace,
                          address=ip,
                          mask=prefixlen,
                          family=family,
                          broadcast=broadcast,
                          scope=_get_scope_name(scope))
    except NetlinkError as e:
        if e.code == errno.EEXIST:
            raise IpAddressAlreadyExists(ip=ip, device=device)
        raise


@privileged.default.entrypoint
def delete_ip_address(ip_version, ip, prefixlen, device, namespace):
    family = _IP_VERSION_FAMILY_MAP[ip_version]
    try:
        _run_iproute_addr("delete",
                          device,
                          namespace,
                          address=ip,
                          mask=prefixlen,
                          family=family)
    except NetlinkError as e:
        # when trying to delete a non-existent IP address, pyroute2 raises
        # NetlinkError with code EADDRNOTAVAIL (99, 'Cannot assign requested
        # address')
        # this shouldn't raise an error
        if e.code == errno.EADDRNOTAVAIL:
            return
        raise


@privileged.default.entrypoint
def flush_ip_addresses(ip_version, device, namespace):
    family = _IP_VERSION_FAMILY_MAP[ip_version]
    try:
        with get_iproute(namespace) as ip:
            idx = get_link_id(device, namespace)
            ip.flush_addr(index=idx, family=family)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def create_interface(ifname, namespace, kind, **kwargs):
    ifname = ifname[:constants.DEVICE_NAME_MAX_LEN]
    try:
        with get_iproute(namespace) as ip:
            physical_interface = kwargs.pop("physical_interface", None)
            if physical_interface:
                link_key = "vxlan_link" if kind == "vxlan" else "link"
                kwargs[link_key] = get_link_id(physical_interface, namespace)
            return ip.link("add", ifname=ifname, kind=kind, **kwargs)
    except NetlinkError as e:
        if e.code == errno.EEXIST:
            raise InterfaceAlreadyExists(device=ifname)
        raise
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def delete_interface(ifname, namespace, **kwargs):
    _run_iproute_link("del", ifname, namespace, **kwargs)


@privileged.default.entrypoint
def interface_exists(ifname, namespace):
    try:
        idx = get_link_id(ifname, namespace, raise_exception=False)
        return bool(idx)
    except OSError as e:
        if e.errno == errno.ENOENT:
            return False
        raise


@privileged.default.entrypoint
def set_link_flags(device, namespace, flags):
    link = _run_iproute_link("get", device, namespace)[0]
    new_flags = flags | link['flags']
    return _run_iproute_link("set", device, namespace, flags=new_flags)


@privileged.default.entrypoint
def set_link_attribute(device, namespace, **attributes):
    return _run_iproute_link("set", device, namespace, **attributes)


@privileged.default.entrypoint
def set_link_vf_feature(device, namespace, vf_config):
    return _run_iproute_link("set", device, namespace=namespace, vf=vf_config)


@privileged.default.entrypoint
def get_link_attributes(device, namespace):
    link = _run_iproute_link("get", device, namespace)[0]
    return {
        'mtu': link.get_attr('IFLA_MTU'),
        'qlen': link.get_attr('IFLA_TXQLEN'),
        'state': link.get_attr('IFLA_OPERSTATE'),
        'qdisc': link.get_attr('IFLA_QDISC'),
        'brd': link.get_attr('IFLA_BROADCAST'),
        'link/ether': link.get_attr('IFLA_ADDRESS'),
        'alias': link.get_attr('IFLA_IFALIAS'),
        'allmulticast': bool(link['flags'] & ifinfmsg.IFF_ALLMULTI),
        'link_kind': link.get_nested('IFLA_LINKINFO', 'IFLA_INFO_KIND')
    }


@privileged.default.entrypoint
def get_link_vfs(device, namespace):
    link = _run_iproute_link('get', device, namespace=namespace, ext_mask=1)[0]
    num_vfs = link.get_attr('IFLA_NUM_VF')
    vfs = {}
    if not num_vfs:
        return vfs

    vfinfo_list = link.get_attr('IFLA_VFINFO_LIST')
    for vinfo in vfinfo_list.get_attrs('IFLA_VF_INFO'):
        mac = vinfo.get_attr('IFLA_VF_MAC')
        link_state = vinfo.get_attr('IFLA_VF_LINK_STATE')
        vfs[mac['vf']] = {'mac': mac['mac'],
                          'link_state': link_state['link_state']}

    return vfs


@privileged.default.entrypoint
def add_neigh_entry(ip_version, ip_address, mac_address, device, namespace,
                    **kwargs):
    """Add a neighbour entry.

    :param ip_address: IP address of entry to add
    :param mac_address: MAC address of entry to add
    :param device: Device name to use in adding entry
    :param namespace: The name of the namespace in which to add the entry
    """
    family = _IP_VERSION_FAMILY_MAP[ip_version]
    _run_iproute_neigh('replace',
                       device,
                       namespace,
                       dst=ip_address,
                       lladdr=mac_address,
                       family=family,
                       state=ndmsg.states['permanent'],
                       **kwargs)


@privileged.default.entrypoint
def delete_neigh_entry(ip_version, ip_address, mac_address, device, namespace,
                       **kwargs):
    """Delete a neighbour entry.

    :param ip_address: IP address of entry to delete
    :param mac_address: MAC address of entry to delete
    :param device: Device name to use in deleting entry
    :param namespace: The name of the namespace in which to delete the entry
    """
    family = _IP_VERSION_FAMILY_MAP[ip_version]
    try:
        _run_iproute_neigh('delete',
                           device,
                           namespace,
                           dst=ip_address,
                           lladdr=mac_address,
                           family=family,
                           **kwargs)
    except NetlinkError as e:
        # trying to delete a non-existent entry shouldn't raise an error
        if e.code == errno.ENOENT:
            return
        raise


@privileged.default.entrypoint
def dump_neigh_entries(ip_version, device, namespace, **kwargs):
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
    family = _IP_VERSION_FAMILY_MAP[ip_version]
    entries = []
    dump = _run_iproute_neigh('dump',
                              device,
                              namespace,
                              family=family,
                              **kwargs)

    for entry in dump:
        attrs = dict(entry['attrs'])
        entries += [{'dst': attrs['NDA_DST'],
                     'lladdr': attrs.get('NDA_LLADDR'),
                     'device': device}]
    return entries


@privileged.default.entrypoint
def create_netns(name, **kwargs):
    """Create a network namespace.

    :param name: The name of the namespace to create
    """
    try:
        netns.create(name, libc=_get_cdll())
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


@privileged.default.entrypoint
def remove_netns(name, **kwargs):
    """Remove a network namespace.

    :param name: The name of the namespace to remove
    """
    try:
        netns.remove(name, libc=_get_cdll())
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise


@privileged.default.entrypoint
def list_netns(**kwargs):
    """List network namespaces.

    Caller requires raised priveleges to list namespaces
    """
    return netns.listnetns(**kwargs)


def make_serializable(value, attr_filter=None):
    """Make a pyroute2 object serializable

    This function converts 'netlink.nla_slot' object (key, value) in a list
    of two elements.
    """
    def _ensure_string(value):
        return value.decode() if isinstance(value, bytes) else value

    if isinstance(value, list):
            return [make_serializable(item, attr_filter) for item in value
                    if attr_filter is None or
                    not isinstance(item, netlink.nla_slot) or
                    (attr_filter and item.name in attr_filter)]
    elif isinstance(value, netlink.nla_slot):
        return [_ensure_string(value[0]), make_serializable(value[1],
                                                            attr_filter)]
    elif isinstance(value, netlink.nla_base):
        return make_serializable(value.dump(), attr_filter)
    elif isinstance(value, dict):
        return {_ensure_string(key): make_serializable(data, attr_filter)
                for key, data in value.items()}
    elif isinstance(value, tuple):
        return tuple(make_serializable(item, attr_filter) for item in value)
    return _ensure_string(value)


@privileged.default.entrypoint
def get_link_devices(namespace, attr_filter=None, **kwargs):
    """List interfaces in a namespace

    :return: (list) interfaces in a namespace
    """
    try:
        with get_iproute(namespace) as ip:
            return make_serializable(ip.get_links(**kwargs),
                                     attr_filter=attr_filter)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


def get_device_names(namespace, **kwargs):
    """List interface names in a namespace

    :return: a list of strings with the names of the interfaces in a namespace
    """
    devices_attrs = [link['attrs'] for link
                     in get_link_devices(namespace,
                                         attr_filter=['IFLA_IFNAME'], **kwargs)]
    device_names = []
    for device_attrs in devices_attrs:
        for link_name in (link_attr[1] for link_attr in device_attrs
                          if link_attr[0] == 'IFLA_IFNAME'):
            device_names.append(link_name)
    return device_names


@privileged.default.entrypoint
def get_ip_addresses(namespace, **kwargs):
    """List of IP addresses in a namespace

    :return: (tuple) IP addresses in a namespace
    """
    try:
        with get_iproute(namespace) as ip:
            return make_serializable(ip.get_addr(**kwargs))
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def list_ip_rules(namespace, ip_version, match=None, **kwargs):
    """List all IP rules"""
    try:
        with get_iproute(namespace) as ip:
            rules = make_serializable(ip.get_rules(
                family=_IP_VERSION_FAMILY_MAP[ip_version],
                match=match, **kwargs))
            for rule in rules:
                rule['attrs'] = {
                    key: value for key, value
                    in ((item[0], item[1]) for item in rule['attrs'])}
            return rules

    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def add_ip_rule(namespace, **kwargs):
    """Add a new IP rule"""
    try:
        with get_iproute(namespace) as ip:
            ip.rule('add', **kwargs)
    except netlink_exceptions.NetlinkError as e:
        if e.code == errno.EEXIST:
            return
        raise
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def delete_ip_rule(namespace, **kwargs):
    """Delete an IP rule"""
    try:
        with get_iproute(namespace) as ip:
            ip.rule('del', **kwargs)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


def _make_pyroute2_route_args(namespace, ip_version, cidr, device, via, table,
                              metric, scope, protocol):
    """Returns a dictionary of arguments to be used in pyroute route commands

    :param namespace: (string) name of the namespace
    :param ip_version: (int) [4, 6]
    :param cidr: (string) source IP or CIDR address (IPv4, IPv6)
    :param device: (string) input interface name
    :param via: (string) gateway IP address
    :param table: (string, int) table number or name
    :param metric: (int) route metric
    :param scope: (int) route scope
    :param protocol: (string) protocol name (pyroute2.netlink.rtnl.rt_proto)
    :return: a dictionary with the kwargs needed in pyroute rule commands
    """
    args = {'family': _IP_VERSION_FAMILY_MAP[ip_version]}
    if not scope:
        scope = 'global' if via else 'link'
    scope = _get_scope_name(scope)
    if scope:
        args['scope'] = scope
    if cidr:
        args['dst'] = cidr
    if device:
        args['oif'] = get_link_id(device, namespace)
    if via:
        args['gateway'] = via
    if table:
        args['table'] = int(table)
    if metric:
        args['priority'] = int(metric)
    if protocol:
        args['proto'] = protocol
    return args


@privileged.default.entrypoint
def add_ip_route(namespace, cidr, ip_version, device=None, via=None,
                 table=None, metric=None, scope=None, **kwargs):
    """Add an IP route"""
    kwargs.update(_make_pyroute2_route_args(
        namespace, ip_version, cidr, device, via, table, metric, scope,
        'static'))
    try:
        with get_iproute(namespace) as ip:
            ip.route('replace', **kwargs)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def list_ip_routes(namespace, ip_version, device=None, table=None, **kwargs):
    """List IP routes"""
    kwargs.update(_make_pyroute2_route_args(
        namespace, ip_version, None, device, None, table, None, None, None))
    try:
        with get_iproute(namespace) as ip:
            return make_serializable(ip.route('show', **kwargs))
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def delete_ip_route(namespace, cidr, ip_version, device=None, via=None,
                    table=None, scope=None, **kwargs):
    """Delete an IP route"""
    kwargs.update(_make_pyroute2_route_args(
        namespace, ip_version, cidr, device, via, table, None, scope, None))
    try:
        with get_iproute(namespace) as ip:
            ip.route('del', **kwargs)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise
