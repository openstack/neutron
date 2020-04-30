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

from unittest import mock

from neutron.agent.l3 import item_allocator as ia
from neutron.tests import base


class TestObject(object):
    def __init__(self, value):
        super(TestObject, self).__init__()
        self._value = value

    def __str__(self):
        return str(self._value)


class TestItemAllocator(base.BaseTestCase):

    def test__init__(self):
        test_pool = set(TestObject(s) for s in range(32768, 40000))
        with mock.patch.object(ia.ItemAllocator, '_write') as write:
            a = ia.ItemAllocator('/file', TestObject, test_pool)
            test_object = a.allocate('test')

        self.assertIn('test', a.allocations)
        self.assertIn(test_object, a.allocations.values())
        self.assertNotIn(test_object, a.pool)
        self.assertTrue(write.called)

    def test__init__readfile(self):
        test_pool = set(TestObject(s) for s in range(32768, 40000))
        with mock.patch.object(ia.ItemAllocator, '_read') as read:
            read.return_value = ["da873ca2,10\n"]
            a = ia.ItemAllocator('/file', TestObject, test_pool)

        self.assertIn('da873ca2', a.remembered)
        self.assertEqual({}, a.allocations)

    def test__init__readfile_error(self):
        test_pool = set(TestObject(s) for s in range(32768, 40000))
        with mock.patch.object(ia.ItemAllocator, '_read') as read,\
                mock.patch.object(ia.ItemAllocator, '_write') as write:
            read.return_value = ["da873ca2,10\n",
                                 "corrupt_entry_no_delimiter\n",
                                 "42c9daf7,11\n"]
            a = ia.ItemAllocator('/file', TestObject, test_pool)

        self.assertIn('da873ca2', a.remembered)
        self.assertIn('42c9daf7', a.remembered)
        self.assertNotIn('corrupt_entry_no_delimiter', a.remembered)
        self.assertEqual({}, a.allocations)
        self.assertTrue(write.called)

    def test_allocate_and_lookup(self):
        test_pool = set([TestObject(33000), TestObject(33001)])
        a = ia.ItemAllocator('/file', TestObject, test_pool)
        with mock.patch.object(ia.ItemAllocator, '_write') as write:
            test_object = a.allocate('test')

        # a lookup should find the same object
        lookup_object = a.lookup('test')

        self.assertIn('test', a.allocations)
        self.assertIn(test_object, a.allocations.values())
        self.assertNotIn(test_object, a.pool)
        self.assertTrue(write.called)
        self.assertEqual(test_object, lookup_object)

    def test_allocate_repeated_call_with_same_key(self):
        test_pool = set([TestObject(33000), TestObject(33001),
                         TestObject(33002), TestObject(33003),
                         TestObject(33004), TestObject(33005)])
        a = ia.ItemAllocator('/file', TestObject, test_pool)
        with mock.patch.object(ia.ItemAllocator, '_write'):
            test_object = a.allocate('test')
            test_object1 = a.allocate('test')
            test_object2 = a.allocate('test')
            test_object3 = a.allocate('test1')

        # same value for same key on repeated calls
        self.assertEqual(test_object, test_object1)
        self.assertEqual(test_object1, test_object2)
        # values for different keys should be diffent
        self.assertNotEqual(test_object, test_object3)

    def test_allocate_from_file(self):
        test_pool = set([TestObject(33000), TestObject(33001)])
        with mock.patch.object(ia.ItemAllocator, '_read') as read:
            read.return_value = ["deadbeef,33000\n"]
            a = ia.ItemAllocator('/file', TestObject, test_pool)

        with mock.patch.object(ia.ItemAllocator, '_write') as write:
            t_obj = a.allocate('deadbeef')

        self.assertEqual('33000', t_obj._value)
        self.assertIn('deadbeef', a.allocations)
        self.assertIn(t_obj, a.allocations.values())
        self.assertNotIn(33000, a.pool)
        self.assertFalse(write.called)

    def test_allocate_exhausted_pool(self):
        test_pool = set([TestObject(33000)])
        with mock.patch.object(ia.ItemAllocator, '_read') as read:
            read.return_value = ["deadbeef,33000\n"]
            a = ia.ItemAllocator('/file', TestObject, test_pool)

        with mock.patch.object(ia.ItemAllocator, '_write') as write:
            allocation = a.allocate('abcdef12')

        self.assertNotIn('deadbeef', a.allocations)
        self.assertNotIn(allocation, a.pool)
        self.assertTrue(write.called)

    def test_release(self):
        test_pool = set([TestObject(33000), TestObject(33001)])
        with mock.patch.object(ia.ItemAllocator, '_write') as write:
            a = ia.ItemAllocator('/file', TestObject, test_pool)
            allocation = a.allocate('deadbeef')
            write.reset_mock()
            a.release('deadbeef')
            # Just try to release the item again to see if it
            # throws any error
            a.release('deadbeef')

        self.assertNotIn('deadbeef', a.allocations)
        self.assertIn(allocation, a.pool)
        self.assertEqual({}, a.allocations)
        write.assert_called_once_with([])
