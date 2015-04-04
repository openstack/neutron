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

import mock
import netaddr

from neutron.agent.l3 import link_local_allocator as lla
from neutron.tests import base


class TestLinkLocalAddrAllocator(base.BaseTestCase):
    def setUp(self):
        super(TestLinkLocalAddrAllocator, self).setUp()
        self.subnet = netaddr.IPNetwork('169.254.31.0/24')

    def test__init__(self):
        a = lla.LinkLocalAllocator('/file', self.subnet.cidr)
        self.assertEqual('/file', a.state_file)
        self.assertEqual({}, a.allocations)

    def test__init__readfile(self):
        with mock.patch.object(lla.LinkLocalAllocator, '_read') as read:
            read.return_value = ["da873ca2,169.254.31.28/31\n"]
            a = lla.LinkLocalAllocator('/file', self.subnet.cidr)

        self.assertTrue('da873ca2' in a.remembered)
        self.assertEqual({}, a.allocations)

    def test_allocate(self):
        a = lla.LinkLocalAllocator('/file', self.subnet.cidr)
        with mock.patch.object(lla.LinkLocalAllocator, '_write') as write:
            subnet = a.allocate('deadbeef')

        self.assertTrue('deadbeef' in a.allocations)
        self.assertTrue(subnet not in a.pool)
        self._check_allocations(a.allocations)
        write.assert_called_once_with(['deadbeef,%s\n' % subnet.cidr])

    def test_allocate_from_file(self):
        with mock.patch.object(lla.LinkLocalAllocator, '_read') as read:
            read.return_value = ["deadbeef,169.254.31.88/31\n"]
            a = lla.LinkLocalAllocator('/file', self.subnet.cidr)

        with mock.patch.object(lla.LinkLocalAllocator, '_write') as write:
            subnet = a.allocate('deadbeef')

        self.assertEqual(netaddr.IPNetwork('169.254.31.88/31'), subnet)
        self.assertTrue(subnet not in a.pool)
        self._check_allocations(a.allocations)
        self.assertFalse(write.called)

    def test_allocate_exhausted_pool(self):
        subnet = netaddr.IPNetwork('169.254.31.0/31')
        with mock.patch.object(lla.LinkLocalAllocator, '_read') as read:
            read.return_value = ["deadbeef,169.254.31.0/31\n"]
            a = lla.LinkLocalAllocator('/file', subnet.cidr)

        with mock.patch.object(lla.LinkLocalAllocator, '_write') as write:
            allocation = a.allocate('abcdef12')

        self.assertEqual(subnet, allocation)
        self.assertFalse('deadbeef' in a.allocations)
        self.assertTrue('abcdef12' in a.allocations)
        self.assertTrue(allocation not in a.pool)
        self._check_allocations(a.allocations)
        write.assert_called_once_with(['abcdef12,%s\n' % allocation.cidr])

        self.assertRaises(RuntimeError, a.allocate, 'deadbeef')

    def test_release(self):
        with mock.patch.object(lla.LinkLocalAllocator, '_write') as write:
            a = lla.LinkLocalAllocator('/file', self.subnet.cidr)
            subnet = a.allocate('deadbeef')
            write.reset_mock()
            a.release('deadbeef')

        self.assertTrue('deadbeef' not in a.allocations)
        self.assertTrue(subnet in a.pool)
        self.assertEqual({}, a.allocations)
        write.assert_called_once_with([])

    def _check_allocations(self, allocations):
        for key, subnet in allocations.items():
            self.assertTrue(subnet in self.subnet)
            self.assertEqual(subnet.prefixlen, 31)
