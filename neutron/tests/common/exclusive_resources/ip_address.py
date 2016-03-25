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
