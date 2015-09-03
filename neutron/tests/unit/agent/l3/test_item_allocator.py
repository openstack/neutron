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

from neutron.agent.l3 import item_allocator as ia
from neutron.tests import base


class TestObject(object):
    def __init__(self, value):
        super(TestObject, self).__init__()
        self._value = value

    def __str__(self):
        return str(self._value)


class TestItemAllocator(base.BaseTestCase):
    def setUp(self):
        super(TestItemAllocator, self).setUp()

    def test__init__(self):
        test_pool = set(TestObject(s) for s in range(32768, 40000))
        with mock.patch.object(ia.ItemAllocator, '_write') as write:
            a = ia.ItemAllocator('/file', TestObject, test_pool)
            test_object = a.allocate('test')

        self.assertTrue('test' in a.allocations)
        self.assertTrue(test_object in a.allocations.values())
        self.assertTrue(test_object not in a.pool)
        self.assertTrue(write.called)

    def test__init__readfile(self):
        test_pool = set(TestObject(s) for s in range(32768, 40000))
        with mock.patch.object(ia.ItemAllocator, '_read') as read:
            read.return_value = ["da873ca2,10\n"]
            a = ia.ItemAllocator('/file', TestObject, test_pool)

        self.assertTrue('da873ca2' in a.remembered)
        self.assertEqual({}, a.allocations)

    def test_allocate(self):
        test_pool = set([TestObject(33000), TestObject(33001)])
        a = ia.ItemAllocator('/file', TestObject, test_pool)
        with mock.patch.object(ia.ItemAllocator, '_write') as write:
            test_object = a.allocate('test')

        self.assertTrue('test' in a.allocations)
        self.assertTrue(test_object in a.allocations.values())
        self.assertTrue(test_object not in a.pool)
        self.assertTrue(write.called)

    def test_allocate_from_file(self):
        test_pool = set([TestObject(33000), TestObject(33001)])
        with mock.patch.object(ia.ItemAllocator, '_read') as read:
            read.return_value = ["deadbeef,33000\n"]
            a = ia.ItemAllocator('/file', TestObject, test_pool)

        with mock.patch.object(ia.ItemAllocator, '_write') as write:
            t_obj = a.allocate('deadbeef')

        self.assertEqual('33000', t_obj._value)
        self.assertTrue('deadbeef' in a.allocations)
        self.assertTrue(t_obj in a.allocations.values())
        self.assertTrue(33000 not in a.pool)
        self.assertFalse(write.called)

    def test_allocate_exhausted_pool(self):
        test_pool = set([TestObject(33000)])
        with mock.patch.object(ia.ItemAllocator, '_read') as read:
            read.return_value = ["deadbeef,33000\n"]
            a = ia.ItemAllocator('/file', TestObject, test_pool)

        with mock.patch.object(ia.ItemAllocator, '_write') as write:
            allocation = a.allocate('abcdef12')

        self.assertFalse('deadbeef' in a.allocations)
        self.assertTrue(allocation not in a.pool)
        self.assertTrue(write.called)

    def test_release(self):
        test_pool = set([TestObject(33000), TestObject(33001)])
        with mock.patch.object(ia.ItemAllocator, '_write') as write:
            a = ia.ItemAllocator('/file', TestObject, test_pool)
            allocation = a.allocate('deadbeef')
            write.reset_mock()
            a.release('deadbeef')

        self.assertTrue('deadbeef' not in a.allocations)
        self.assertTrue(allocation in a.pool)
        self.assertEqual({}, a.allocations)
        write.assert_called_once_with([])
