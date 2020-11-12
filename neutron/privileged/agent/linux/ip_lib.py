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
import socket

from neutron_lib import constants
import pyroute2
from pyroute2.netlink import rtnl
from pyroute2.netlink.rtnl import ndmsg
from pyroute2 import NetlinkError
from pyroute2 import netns

from neutron._i18n import _
from neutron import privileged


_IP_VERSION_FAMILY_MAP = {4: socket.AF_INET, 6: socket.AF_INET6}

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


class NetworkNamespaceNotFound(RuntimeError):
    message = _("Network namespace %(netns_name)s could not be found.")

    def __init__(self, netns_name):
        super(NetworkNamespaceNotFound, self).__init__(
            self.message % {'netns_name': netns_name})


class NetworkInterfaceNotFound(RuntimeError):
    pass


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


def _get_iproute(namespace):
    # From iproute.py:
    # `IPRoute` -- RTNL API to the current network namespace
    # `NetNS` -- RTNL API to another network namespace
    if namespace:
        # do not try and create the namespace
        return pyroute2.NetNS(namespace, flags=0)
    else:
        return pyroute2.IPRoute()


def _get_link_id(device, namespace):
    try:
        with _get_iproute(namespace) as ip:
            return ip.link_lookup(ifname=device)[0]
    except IndexError:
        msg = _("Network interface %(device)s not found in namespace "
                "%(namespace)s.") % {'device': device,
                                     'namespace': namespace}
        raise NetworkInterfaceNotFound(msg)


def _run_iproute_link(command, device, namespace, **kwargs):
    try:
        with _get_iproute(namespace) as ip:
            idx = _get_link_id(device, namespace)
            return ip.link(command, index=idx, **kwargs)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


def _run_iproute_neigh(command, device, namespace, **kwargs):
    try:
        with _get_iproute(namespace) as ip:
            idx = _get_link_id(device, namespace)
            return ip.neigh(command, ifindex=idx, **kwargs)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


def _run_iproute_addr(command, device, namespace, **kwargs):
    try:
        with _get_iproute(namespace) as ip:
            idx = _get_link_id(device, namespace)
            return ip.addr(command, index=idx, **kwargs)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def add_ip_address(ip_version, ip, prefixlen, device, namespace, scope,
                   broadcast=None):
    family = _IP_VERSION_FAMILY_MAP[ip_version]
    _run_iproute_addr('add',
                      device,
                      namespace,
                      address=ip,
                      mask=prefixlen,
                      family=family,
                      broadcast=broadcast,
                      scope=_get_scope_name(scope))


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
        with _get_iproute(namespace) as ip:
            idx = _get_link_id(device, namespace)
            ip.flush_addr(index=idx, family=family)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def open_namespace(namespace):
    """Open namespace to test if the namespace is ready to be manipulated"""
    with pyroute2.NetNS(namespace, flags=0):
        pass


@privileged.default.entrypoint
def create_interface(ifname, namespace, kind, **kwargs):
    ifname = ifname[:constants.DEVICE_NAME_MAX_LEN]
    try:
        with _get_iproute(namespace) as ip:
            physical_interface = kwargs.pop("physical_interface", None)
            if physical_interface:
                link_key = "vxlan_link" if kind == "vxlan" else "link"
                kwargs[link_key] = _get_link_id(physical_interface, namespace)
            return ip.link("add", ifname=ifname, kind=kind, **kwargs)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise NetworkNamespaceNotFound(netns_name=namespace)
        raise


@privileged.default.entrypoint
def delete_interface(ifname, namespace, **kwargs):
    _run_iproute_link("del", ifname, namespace, **kwargs)


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
        netns.remove(name, **kwargs)
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
