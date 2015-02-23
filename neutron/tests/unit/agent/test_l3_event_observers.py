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
import testtools

from neutron.agent.l3 import event_observers
from neutron.services import advanced_service as adv_svc
from neutron.tests import base


class DummyService1(adv_svc.AdvancedService):
    def before_router_added(self, ri):
        pass

    def after_router_added(self, ri):
        pass


class DummyService2(adv_svc.AdvancedService):
    def before_router_added(self, ri):
        pass


class TestL3EventObservers(base.BaseTestCase):

    def setUp(self):
        super(TestL3EventObservers, self).setUp()
        self.event_observers = event_observers.L3EventObservers()

    def test_add_observer(self):
        observer = object()
        self.assertNotIn(observer, self.event_observers.observers)
        self.event_observers.add(observer)
        self.assertIn(observer, self.event_observers.observers)

    def test_add_duplicate_observer_type_raises(self):
        agent = mock.Mock()
        observer = DummyService1(agent)
        self.event_observers.add(observer)

        observer2 = DummyService1(agent)
        with testtools.ExpectedException(ValueError):
            self.event_observers.add(observer2)

        self.assertEqual(1, len(self.event_observers.observers))

    def test_observers_in_service_notified(self):
        """Test that correct handlers for multiple services are called."""
        l3_agent = mock.Mock()
        router_info = mock.Mock()
        observer1 = DummyService1(l3_agent)
        observer2 = DummyService2(l3_agent)
        observer1_before_add = mock.patch.object(
            DummyService1, 'before_router_added').start()
        observer2_before_add = mock.patch.object(
            DummyService2, 'before_router_added').start()

        self.event_observers.add(observer1)
        self.event_observers.add(observer2)
        self.event_observers.notify(
            adv_svc.AdvancedService.before_router_added, router_info)

        observer1_before_add.assert_called_with(router_info)
        observer2_before_add.assert_called_with(router_info)
