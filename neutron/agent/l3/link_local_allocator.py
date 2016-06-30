# Copyright 2014 Hewlett-Packard Development Company, L.P.
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

import netaddr

from neutron.agent.l3.item_allocator import ItemAllocator


class LinkLocalAddressPair(netaddr.IPNetwork):
    def __init__(self, addr):
        super(LinkLocalAddressPair, self).__init__(addr)

    def get_pair(self):
        """Builds an address pair from the first and last addresses. """
        # TODO(kevinbenton): the callers of this seem only interested in an IP,
        # so we should just return two IPAddresses.
        return (netaddr.IPNetwork("%s/%s" % (self.network, self.prefixlen)),
                netaddr.IPNetwork("%s/%s" % (self[-1], self.prefixlen)))


class LinkLocalAllocator(ItemAllocator):
    """Manages allocation of link local IP addresses.

    These link local addresses are used for routing inside the fip namespaces.
    The associations need to persist across agent restarts to maintain
    consistency.  Without this, there is disruption in network connectivity
    as the agent rewires the connections with the new IP address associations.

    Persisting these in the database is unnecessary and would degrade
    performance.
    """
    def __init__(self, data_store_path, subnet):
        """Create the necessary pool and item allocator
            using ',' as the delimiter and LinkLocalAllocator as the
            class type
        """
        subnet = netaddr.IPNetwork(subnet)
        pool = set(LinkLocalAddressPair(s) for s in subnet.subnet(31))
        super(LinkLocalAllocator, self).__init__(data_store_path,
                                                 LinkLocalAddressPair,
                                                 pool)
