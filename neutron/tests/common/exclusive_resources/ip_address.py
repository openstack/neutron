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
import random

import netaddr

from neutron.tests.common.exclusive_resources import resource_allocator

TEST_NET_RANGE = {
    1: ('192.0.2.1', '192.0.2.254'),
    2: ('198.51.100.1', '198.51.100.254'),
    3: ('203.0.113.1', '203.0.113.254'),
}


def get_test_net_address_fixture(test_net_number):
    """Return exclusive ip address on the system based on RFC 5737.

    :param block: One of following constants: 1, 2, 3

    https://tools.ietf.org/html/rfc5737
    """
    try:
        net_range = TEST_NET_RANGE[test_net_number]
    except KeyError:
        raise ValueError("Unknown constant for TEST-NET: %d" % test_net_number)

    return ExclusiveIPAddress(*net_range)


def get_random_ip(low, high):
    parent_range = netaddr.IPRange(low, high)
    return str(random.choice(parent_range))


class ExclusiveIPAddress(resource_allocator.ExclusiveResource):
    """Allocate a unique ip address.

    :ivar address: allocated ip address
    :type address: netaddr.IPAddress
    """

    def __init__(self, low, high):
        super(ExclusiveIPAddress, self).__init__(
            'ip_addresses', functools.partial(get_random_ip, low, high))

    def _setUp(self):
        super(ExclusiveIPAddress, self)._setUp()
        self.address = netaddr.IPAddress(self.resource)
