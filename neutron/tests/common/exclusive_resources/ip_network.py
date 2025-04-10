# Copyright 2016 Red Hat, Inc.
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

import functools

import netaddr

from neutron.tests.common.exclusive_resources import ip_address
from neutron.tests.common.exclusive_resources import resource_allocator


def _get_random_network(low, high, netmask):
    ip = ip_address.get_random_ip(low, high)
    return str(netaddr.IPNetwork(f"{ip}/{netmask}").cidr)


class ExclusiveIPNetwork(resource_allocator.ExclusiveResource):
    """Allocate a non-overlapping ip network.

    :ivar network: allocated ip network
    :type network: netaddr.IPNetwork
    """

    def __init__(self, low, high, netmask):
        super().__init__(
            'ip_networks',
            functools.partial(_get_random_network, low, high, netmask),
            self.is_valid)

    def _setUp(self):
        super()._setUp()
        self.network = netaddr.IPNetwork(self.resource)

    def is_valid(self, new_resource, allocated_resources):
        new_ipset = netaddr.IPSet([new_resource])
        allocated_ipset = netaddr.IPSet(allocated_resources)
        return new_ipset.isdisjoint(allocated_ipset)
