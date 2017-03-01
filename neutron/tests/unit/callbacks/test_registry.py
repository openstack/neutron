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

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.tests import base


@registry.has_registry_receivers
class ObjectWithDecoratedCallback(object):

    def __init__(self):
        self.counter = 0

    @registry.receives(resources.PORT, [events.AFTER_CREATE,
                                        events.AFTER_UPDATE])
    @registry.receives(resources.NETWORK, [events.AFTER_DELETE])
    def callback(self, *args, **kwargs):
        self.counter += 1


class MixinWithNew(object):
    def __new__(cls):
        i = super(MixinWithNew, cls).__new__(cls)
        i.new_called = True
        return i


@registry.has_registry_receivers
class AnotherObjectWithDecoratedCallback(ObjectWithDecoratedCallback,
                                         MixinWithNew):

    def __init__(self):
        super(AnotherObjectWithDecoratedCallback, self).__init__()
        self.counter2 = 0

    @registry.receives(resources.NETWORK, [events.AFTER_DELETE])
    def callback2(self, *args, **kwargs):
        self.counter2 += 1


@registry.has_registry_receivers
class CallbackClassWithParameters(object):

    def __init__(self, dummy):
        pass


class CallBacksManagerTestCase(base.BaseTestCase):

    def test_decorated_inst_method_receives(self):
        i1 = ObjectWithDecoratedCallback()
        registry.notify(resources.PORT, events.BEFORE_CREATE, self)
        self.assertEqual(0, i1.counter)
        registry.notify(resources.PORT, events.AFTER_CREATE, self)
        self.assertEqual(1, i1.counter)
        registry.notify(resources.PORT, events.AFTER_UPDATE, self)
        self.assertEqual(2, i1.counter)
        registry.notify(resources.NETWORK, events.AFTER_UPDATE, self)
        self.assertEqual(2, i1.counter)
        registry.notify(resources.NETWORK, events.AFTER_DELETE, self)
        self.assertEqual(3, i1.counter)
        i2 = ObjectWithDecoratedCallback()
        self.assertEqual(0, i2.counter)
        registry.notify(resources.NETWORK, events.AFTER_DELETE, self)
        self.assertEqual(4, i1.counter)
        self.assertEqual(1, i2.counter)

    def test_object_inheriting_others_no_double_subscribe(self):
        with mock.patch.object(registry, 'subscribe') as sub:
            AnotherObjectWithDecoratedCallback()
            # there are 3 methods (2 in parent and one in child) and 1
            # subscribes to 2 events, so we expect 4 subscribes
            self.assertEqual(4, len(sub.mock_calls))

    def test_new_inheritance_not_broken(self):
        self.assertTrue(AnotherObjectWithDecoratedCallback().new_called)

    def test_object_new_not_broken(self):
        CallbackClassWithParameters('dummy')
