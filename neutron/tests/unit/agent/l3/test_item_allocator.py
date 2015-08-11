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

from neutron.agent.l3 import item_allocator as ia
from neutron.tests import base


class TestItemAllocator(base.BaseTestCase):
    def setUp(self):
        super(TestItemAllocator, self).setUp()

    def test__init__(self):
        test_pool = set(s for s in range(32768, 40000))
        a = ia.ItemAllocator('/file', object, test_pool)
        self.assertEqual('/file', a.state_file)
        self.assertEqual({}, a.allocations)
        self.assertEqual(object, a.ItemClass)
        self.assertEqual(test_pool, a.pool)
