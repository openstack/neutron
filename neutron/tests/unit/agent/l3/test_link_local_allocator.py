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

from neutron.agent.l3 import link_local_allocator as lla
from neutron.tests import base


class TestLinkLocalAddrAllocator(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.subnet = netaddr.IPNetwork('169.254.31.0/24')

    def test__init__(self):
        a = lla.LinkLocalAllocator('/file', self.subnet.cidr)
        self.assertEqual('/file', a.state_file)
        self.assertEqual({}, a.allocations)
