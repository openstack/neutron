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
