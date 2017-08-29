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

from neutron.agent.l3 import fip_rule_priority_allocator as frpa
from neutron.tests import base


class TestFipPriority(base.BaseTestCase):
    def test__init__(self):
        test_pr = frpa.FipPriority(10)
        self.assertEqual(10, test_pr.index)

    def test__repr__(self):
        test_pr = frpa.FipPriority(20)
        self.assertEqual("20", str(test_pr))

    def test__eq__(self):
        left_pr = frpa.FipPriority(10)
        right_pr = frpa.FipPriority(10)
        other_pr = frpa.FipPriority(20)
        self.assertEqual(left_pr, right_pr)
        self.assertNotEqual(left_pr, other_pr)
        self.assertNotEqual(right_pr, other_pr)

    def test__hash__(self):
        left_pr = frpa.FipPriority(10)
        right_pr = frpa.FipPriority(10)
        other_pr = frpa.FipPriority(20)
        self.assertEqual(hash(left_pr), hash(right_pr))
        self.assertNotEqual(hash(left_pr), hash(other_pr))
        self.assertNotEqual(hash(other_pr), hash(right_pr))


class TestFipRulePriorityAllocator(base.BaseTestCase):
    def setUp(self):
        super(TestFipRulePriorityAllocator, self).setUp()
        self.priority_rule_start = 100
        self.priority_rule_end = 200
        self.data_store_path = '/data_store_path_test'

    def test__init__(self):
        _frpa = frpa.FipRulePriorityAllocator(self.data_store_path,
                                              self.priority_rule_start,
                                              self.priority_rule_end)
        self.assertEqual(self.data_store_path, _frpa.state_file)
        self.assertEqual(frpa.FipPriority, _frpa.ItemClass)
        self.assertEqual(100, len(_frpa.pool))
