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

from neutron_lib.callbacks import exceptions

from neutron.api.rpc.callbacks import exceptions as rpc_exc
from neutron.api.rpc.callbacks import resource_manager
from neutron.tests.unit.services.qos import base

IS_VALID_RESOURCE_TYPE = (
    'neutron.api.rpc.callbacks.resources.is_valid_resource_type')


class ResourceCallbacksManagerTestCaseMixin(object):

    def test_register_fails_on_invalid_type(self):
        self.assertRaises(
            exceptions.Invalid,
            self.mgr.register, lambda: None, 'TYPE')

    @mock.patch(IS_VALID_RESOURCE_TYPE, return_value=True)
    def test_clear_unregisters_all_callbacks(self, *mocks):
        self.mgr.register(lambda: None, 'TYPE1')
        self.mgr.register(lambda: None, 'TYPE2')
        self.mgr.clear()
        self.assertEqual([], self.mgr.get_subscribed_types())

    def test_unregister_fails_on_invalid_type(self):
        self.assertRaises(
            exceptions.Invalid,
            self.mgr.unregister, lambda: None, 'TYPE')

    @mock.patch(IS_VALID_RESOURCE_TYPE, return_value=True)
    def test_unregister_fails_on_unregistered_callback(self, *mocks):
        self.assertRaises(
            rpc_exc.CallbackNotFound,
            self.mgr.unregister, lambda: None, 'TYPE')

    @mock.patch(IS_VALID_RESOURCE_TYPE, return_value=True)
    def test_unregister_unregisters_callback(self, *mocks):
        callback = lambda: None
        self.mgr.register(callback, 'TYPE')
        self.mgr.unregister(callback, 'TYPE')
        self.assertEqual([], self.mgr.get_subscribed_types())

    @mock.patch(IS_VALID_RESOURCE_TYPE, return_value=True)
    def test___init___does_not_reset_callbacks(self, *mocks):
        callback = lambda: None
        self.mgr.register(callback, 'TYPE')
        resource_manager.ProducerResourceCallbacksManager()
        self.assertEqual(['TYPE'], self.mgr.get_subscribed_types())


class ProducerResourceCallbacksManagerTestCase(
    base.BaseQosTestCase, ResourceCallbacksManagerTestCaseMixin):

    def setUp(self):
        super(ProducerResourceCallbacksManagerTestCase, self).setUp()
        self.mgr = self.prod_mgr

    @mock.patch(IS_VALID_RESOURCE_TYPE, return_value=True)
    def test_register_registers_callback(self, *mocks):
        callback = lambda: None
        self.mgr.register(callback, 'TYPE')
        self.assertEqual(callback, self.mgr.get_callback('TYPE'))

    @mock.patch(IS_VALID_RESOURCE_TYPE, return_value=True)
    def test_register_fails_on_multiple_calls(self, *mocks):
        self.mgr.register(lambda: None, 'TYPE')
        self.assertRaises(
            rpc_exc.CallbacksMaxLimitReached,
            self.mgr.register, lambda: None, 'TYPE')

    def test_get_callback_fails_on_invalid_type(self):
        self.assertRaises(
            exceptions.Invalid,
            self.mgr.get_callback, 'TYPE')

    @mock.patch(IS_VALID_RESOURCE_TYPE, return_value=True)
    def test_get_callback_fails_on_unregistered_callback(
            self, *mocks):
        self.assertRaises(
            rpc_exc.CallbackNotFound,
            self.mgr.get_callback, 'TYPE')

    @mock.patch(IS_VALID_RESOURCE_TYPE, return_value=True)
    def test_get_callback_returns_proper_callback(self, *mocks):
        callback1 = lambda: None
        callback2 = lambda: None
        self.mgr.register(callback1, 'TYPE1')
        self.mgr.register(callback2, 'TYPE2')
        self.assertEqual(callback1, self.mgr.get_callback('TYPE1'))
        self.assertEqual(callback2, self.mgr.get_callback('TYPE2'))


class ConsumerResourceCallbacksManagerTestCase(
    base.BaseQosTestCase, ResourceCallbacksManagerTestCaseMixin):

    def setUp(self):
        super(ConsumerResourceCallbacksManagerTestCase, self).setUp()
        self.mgr = self.cons_mgr

    @mock.patch(IS_VALID_RESOURCE_TYPE, return_value=True)
    def test_register_registers_callback(self, *mocks):
        callback = lambda: None
        self.mgr.register(callback, 'TYPE')
        self.assertEqual({callback}, self.mgr.get_callbacks('TYPE'))

    @mock.patch(IS_VALID_RESOURCE_TYPE, return_value=True)
    def test_register_succeeds_on_multiple_calls(self, *mocks):
        callback1 = lambda: None
        callback2 = lambda: None
        self.mgr.register(callback1, 'TYPE')
        self.mgr.register(callback2, 'TYPE')

    @mock.patch(IS_VALID_RESOURCE_TYPE, return_value=True)
    def test_get_callbacks_fails_on_unregistered_callback(
        self, *mocks):
        self.assertRaises(
            rpc_exc.CallbackNotFound,
            self.mgr.get_callbacks, 'TYPE')

    @mock.patch(IS_VALID_RESOURCE_TYPE, return_value=True)
    def test_get_callbacks_returns_proper_callbacks(self, *mocks):
        callback1 = lambda: None
        callback2 = lambda: None
        self.mgr.register(callback1, 'TYPE1')
        self.mgr.register(callback2, 'TYPE2')
        self.assertEqual(set([callback1]), self.mgr.get_callbacks('TYPE1'))
        self.assertEqual(set([callback2]), self.mgr.get_callbacks('TYPE2'))
