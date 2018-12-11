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

import errno
import socket

from neutron_lib import constants
from oslo_concurrency import lockutils
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


_IP_VERSION_FAMILY_MAP = {4: socket.AF_INET, 6: socket.AF_INET6}


def _get_scope_name(scope):
    """Return the name of the scope (given as a number), or the scope number
    if the name is unknown.

    For backward compatibility (with "ip" tool) "global" scope is converted to
    "universe" before converting to number
    """
    scope = 'universe' if scope == 'global' else scope
    return rtnl.rt_scope.get(scope, scope)


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
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
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


def _translate_ip_device_exception(e, device=None, namespace=None):
    if e.code == errno.ENODEV:
        raise NetworkInterfaceNotFound(device=device, namespace=namespace)
    if e.code == errno.EOPNOTSUPP:
        raise InterfaceOperationNotSupported(device=device,
                                             namespace=namespace)


def get_link_id(device, namespace):
    try:
        with get_iproute(namespace) as ip:
            return ip.link_lookup(ifname=device)[0]
    except IndexError:
        raise NetworkInterfaceNotFound(device=device, namespace=namespace)


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
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
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
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
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
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
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
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
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
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
def delete_interface(ifname, namespace, **kwargs):
    _run_iproute_link("del", ifname, namespace, **kwargs)


@privileged.default.entrypoint
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
def interface_exists(ifname, namespace):
    try:
        idx = get_link_id(ifname, namespace)
        return bool(idx)
    except NetworkInterfaceNotFound:
        return False
    except OSError as e:
        if e.errno == errno.ENOENT:
            return False
        raise


@privileged.default.entrypoint
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
def set_link_flags(device, namespace, flags):
    link = _run_iproute_link("get", device, namespace)[0]
    new_flags = flags | link['flags']
    return _run_iproute_link("set", device, namespace, flags=new_flags)


@privileged.default.entrypoint
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
def set_link_attribute(device, namespace, **attributes):
    return _run_iproute_link("set", device, namespace, **attributes)


@privileged.default.entrypoint
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
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
        'allmulticast': bool(link['flags'] & ifinfmsg.IFF_ALLMULTI)
    }


@privileged.default.entrypoint
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
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
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
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
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
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
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
def create_netns(name, **kwargs):
    """Create a network namespace.

    :param name: The name of the namespace to create
    """
    try:
        netns.create(name, **kwargs)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


@privileged.default.entrypoint
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
def remove_netns(name, **kwargs):
    """Remove a network namespace.

    :param name: The name of the namespace to remove
    """
    try:
        netns.remove(name, **kwargs)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise


@privileged.default.entrypoint
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
def list_netns(**kwargs):
    """List network namespaces.

    Caller requires raised priveleges to list namespaces
    """
    return netns.listnetns(**kwargs)


def make_serializable(value):
    """Make a pyroute2 object serializable

    This function converts 'netlink.nla_slot' object (key, value) in a list
    of two elements.
    """
    if isinstance(value, list):
        return [make_serializable(item) for item in value]
    elif isinstance(value, dict):
        return {key: make_serializable(data) for key, data in value.items()}
    elif isinstance(value, netlink.nla_slot):
        return [value[0], make_serializable(value[1])]
    elif isinstance(value, tuple):
        return tuple(make_serializable(item) for item in value)
    return value


@privileged.default.entrypoint
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
def get_link_devices(namespace, **kwargs):
    """List interfaces in a namespace

    :return: (list) interfaces in a namespace
    """
    try:
        with get_iproute(namespace) as ip:
            return make_serializable(ip.get_links(**kwargs))
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


def get_device_names(namespace, **kwargs):
    """List interface names in a namespace

    :return: a list of strings with the names of the interfaces in a namespace
    """
    devices_attrs = [link['attrs'] for link
                     in get_link_devices(namespace, **kwargs)]
    device_names = []
    for device_attrs in devices_attrs:
        for link_name in (link_attr[1] for link_attr in device_attrs
                          if link_attr[0] == 'IFLA_IFNAME'):
            device_names.append(link_name)
    return device_names


@privileged.default.entrypoint
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
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
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
def list_ip_rules(namespace, ip_version, match=None, **kwargs):
    """List all IP rules"""
    try:
        with get_iproute(namespace) as ip:
            rules = ip.get_rules(family=_IP_VERSION_FAMILY_MAP[ip_version],
                                 match=match, **kwargs)
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
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
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
# NOTE(slaweq): Because of issue with pyroute2.NetNS objects running in threads
# we need to lock this function to workaround this issue.
# For details please check https://bugs.launchpad.net/neutron/+bug/1811515
@lockutils.synchronized("privileged-ip-lib")
def delete_ip_rule(namespace, **kwargs):
    """Delete an IP rule"""
    try:
        with get_iproute(namespace) as ip:
            ip.rule('del', **kwargs)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise
