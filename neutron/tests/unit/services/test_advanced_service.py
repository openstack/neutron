# Copyright 2014 OpenStack Foundation.
# All Rights Reserved.
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

from neutron.agent.l3 import event_observers
from neutron.services import advanced_service
from neutron.tests import base


class FakeServiceA(advanced_service.AdvancedService):
    pass


class FakeServiceB(advanced_service.AdvancedService):
    pass


class TestAdvancedService(base.BaseTestCase):

    def setUp(self):
        super(TestAdvancedService, self).setUp()
        self.agent = mock.Mock()
        self.test_observers = event_observers.L3EventObservers()

    def test_create_service(self):
        """Test agent saved and service added to observer list."""
        my_service = FakeServiceA(self.agent)
        self.test_observers.add(my_service)
        self.assertIn(my_service, self.test_observers.observers)
        self.assertEqual(self.agent, my_service.l3_agent)

    def test_shared_observers_for_different_services(self):
        """Test different service type instances created.

        The services are unique instances, with different agents, but
        sharing the same observer list.
        """
        a = FakeServiceA(self.agent)
        self.test_observers.add(a)
        self.assertEqual(self.agent, a.l3_agent)
        self.assertIn(a, self.test_observers.observers)

        another_agent = mock.Mock()
        b = FakeServiceB(another_agent)
        self.test_observers.add(b)
        self.assertNotEqual(a, b)
        self.assertEqual(another_agent, b.l3_agent)
        self.assertIn(b, self.test_observers.observers)
        self.assertEqual(2, len(self.test_observers.observers))

    def test_unique_observers_for_different_services(self):
        """Test different service types with different observer lists.

        The services are unique instances, shared the same agent, but
        are using different observer lists.
        """
        a = FakeServiceA(self.agent)
        self.test_observers.add(a)
        other_observers = event_observers.L3EventObservers()
        b = FakeServiceB(self.agent)
        other_observers.add(b)

        self.assertNotEqual(a, b)
        self.assertEqual(self.agent, a.l3_agent)
        self.assertIn(a, self.test_observers.observers)
        self.assertEqual(1, len(self.test_observers.observers))

        self.assertEqual(self.agent, b.l3_agent)
        self.assertIn(b, other_observers.observers)
        self.assertEqual(1, len(other_observers.observers))
