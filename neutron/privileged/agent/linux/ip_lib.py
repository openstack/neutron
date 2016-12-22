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

import pyroute2
from pyroute2.netlink import rtnl

from neutron._i18n import _
from neutron import privileged


_IP_VERSION_FAMILY_MAP = {4: socket.AF_INET, 6: socket.AF_INET6}


def _get_scope_name(scope):
    """Return the name of the scope (given as a number), or the scope number
    if the name is unknown.
    """
    return rtnl.rt_scope.get(scope, scope)


class NetworkNamespaceNotFound(RuntimeError):
    message = _("Network namespace %(netns_name)s could not be found.")

    def __init__(self, netns_name):
        super(NetworkNamespaceNotFound, self).__init__(
            self.message % {'netns_name': netns_name})


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
    with pyroute2.IPDB(nl=netns) as ipdb:
        ipdb_routes = ipdb.routes
        ipdb_interfaces = ipdb.interfaces
        routes = [{'destination': route['dst'],
                   'nexthop': route.get('gateway'),
                   'device': ipdb_interfaces[route['oif']]['ifname'],
                   'scope': _get_scope_name(route['scope'])}
                  for route in ipdb_routes if route['family'] == family]
    return routes
