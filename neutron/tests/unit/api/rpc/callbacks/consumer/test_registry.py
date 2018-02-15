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

from neutron.api.rpc.callbacks.consumer import registry
from neutron.tests import base


class ConsumerRegistryTestCase(base.BaseTestCase):

    def test__get_manager_is_singleton(self):
        self.assertIs(registry._get_manager(), registry._get_manager())

    @mock.patch.object(registry, '_get_manager')
    def test_register(self, manager_mock):
        callback = lambda: None
        registry.register(callback, 'TYPE')
        manager_mock().register.assert_called_with(callback, 'TYPE')

    @mock.patch.object(registry, '_get_manager')
    def test_unsubscribe(self, manager_mock):
        callback = lambda: None
        registry.unsubscribe(callback, 'TYPE')
        manager_mock().unregister.assert_called_with(callback, 'TYPE')

    @mock.patch.object(registry, '_get_manager')
    def test_clear(self, manager_mock):
        registry.clear()
        manager_mock().clear.assert_called_with()

    @mock.patch.object(registry, '_get_manager')
    def test_push(self, manager_mock):
        resource_type_ = object()
        resource_ = object()
        event_type_ = object()

        context = mock.Mock()
        callback1 = mock.Mock()
        callback2 = mock.Mock()
        registry.register(callback1, 'x')
        registry.register(callback2, 'x')
        callbacks = {callback1, callback2}
        manager_mock().get_callbacks.return_value = callbacks
        registry.push(context, resource_type_, [resource_], event_type_)
        for callback in (callback1, callback2):
            callback.assert_called_with(context, resource_type_,
                                        [resource_], event_type_)
