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
import os


class LinkLocalAddressPair(netaddr.IPNetwork):
    def __init__(self, addr):
        super(LinkLocalAddressPair, self).__init__(addr)

    def get_pair(self):
        """Builds an address pair from the first and last addresses. """
        # TODO(kevinbenton): the callers of this seem only interested in an IP,
        # so we should just return two IPAddresses.
        return (netaddr.IPNetwork("%s/%s" % (self.network, self.prefixlen)),
                netaddr.IPNetwork("%s/%s" % (self[-1], self.prefixlen)))


class LinkLocalAllocator(object):
    """Manages allocation of link local IP addresses.

    These link local addresses are used for routing inside the fip namespaces.
    The associations need to persist across agent restarts to maintain
    consistency.  Without this, there is disruption in network connectivity
    as the agent rewires the connections with the new IP address assocations.

    Persisting these in the database is unnecessary and would degrade
    performance.
    """
    def __init__(self, state_file, subnet):
        """Read the file with previous allocations recorded.

        See the note in the allocate method for more detail.
        """
        self.state_file = state_file
        subnet = netaddr.IPNetwork(subnet)

        self.allocations = {}

        self.remembered = {}
        for line in self._read():
            key, cidr = line.strip().split(',')
            self.remembered[key] = LinkLocalAddressPair(cidr)

        self.pool = set(LinkLocalAddressPair(s) for s in subnet.subnet(31))
        self.pool.difference_update(self.remembered.values())

    def allocate(self, key):
        """Try to allocate a link local address pair.

        I expect this to work in all cases because I expect the pool size to be
        large enough for any situation.  Nonetheless, there is some defensive
        programming in here.

        Since the allocations are persisted, there is the chance to leak
        allocations which should have been released but were not.  This leak
        could eventually exhaust the pool.

        So, if a new allocation is needed, the code first checks to see if
        there are any remembered allocations for the key.  If not, it checks
        the free pool.  If the free pool is empty then it dumps the remembered
        allocations to free the pool.  This final desperate step will not
        happen often in practice.
        """
        if key in self.remembered:
            self.allocations[key] = self.remembered.pop(key)
            return self.allocations[key]

        if not self.pool:
            # Desperate times.  Try to get more in the pool.
            self.pool.update(self.remembered.values())
            self.remembered.clear()
            if not self.pool:
                # More than 256 routers on a compute node!
                raise RuntimeError(_("Cannot allocate link local address"))

        self.allocations[key] = self.pool.pop()
        self._write_allocations()
        return self.allocations[key]

    def release(self, key):
        self.pool.add(self.allocations.pop(key))
        self._write_allocations()

    def _write_allocations(self):
        current = ["%s,%s\n" % (k, v) for k, v in self.allocations.items()]
        remembered = ["%s,%s\n" % (k, v) for k, v in self.remembered.items()]
        current.extend(remembered)
        self._write(current)

    def _write(self, lines):
        with open(self.state_file, "w") as f:
            f.writelines(lines)

    def _read(self):
        if not os.path.exists(self.state_file):
            return []
        with open(self.state_file) as f:
            return f.readlines()
