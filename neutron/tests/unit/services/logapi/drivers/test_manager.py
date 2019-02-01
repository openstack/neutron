# Copyright (c) 2017 Fujitsu Limited
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
from neutron_lib.callbacks import events
from neutron_lib import exceptions
from neutron_lib import fixture

from neutron.services.logapi.common import constants as log_const
from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.drivers import base as log_driver_base
from neutron.services.logapi.drivers import manager as driver_mgr
from neutron.tests import tools
from neutron.tests.unit.services.logapi import base


class TestGetParameter(base.BaseLogTestCase):

    def test__get_param_missing_parameter(self):
        kwargs = {'context': mock.sentinel.context}
        self.assertRaises(log_exc.LogapiDriverException,
                          driver_mgr._get_param,
                          args=[], kwargs=kwargs,
                          name='log_obj', index=1)
        self.assertRaises(log_exc.LogapiDriverException,
                          driver_mgr._get_param,
                          args=[mock.sentinel.context], kwargs={},
                          name='log_obj', index=1)
        self.assertRaises(log_exc.LogapiDriverException,
                          driver_mgr._get_param,
                          args=[], kwargs={'log_obj': mock.sentinel.log_obj},
                          name='context', index=0)


class TestLogDriversManagerBase(base.BaseLogTestCase):

    def setUp(self):
        super(TestLogDriversManagerBase, self).setUp()
        self.config_parse()
        self.setup_coreplugin(load_plugins=False)

    @staticmethod
    def _create_manager_with_drivers(drivers_details):
        for name, driver_details in drivers_details.items():
            class LogDriver(log_driver_base.DriverBase):
                @property
                def is_loaded(self):
                    return driver_details['is_loaded']

            LogDriver(name,
                      driver_details.get('vif_types', []),
                      driver_details.get('vnic_types', []),
                      driver_details.get('supported_logging_types', []))

        return driver_mgr.LoggingServiceDriverManager()


class TestLogDriversManagerMulti(TestLogDriversManagerBase):
    """Test calls happen to all drivers"""
    def test_driver_manager_empty_with_no_drivers(self):
        driver_manager = self._create_manager_with_drivers({})
        self.assertEqual(0, len(driver_manager.drivers))

    def test_driver_manager_empty_with_no_loaded_drivers(self):
        driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': False}})
        self.assertEqual(0, len(driver_manager.drivers))

    def test_driver_manager_with_one_loaded_driver(self):
        driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': True}})
        self.assertEqual(1, len(driver_manager.drivers))

    def test_driver_manager_with_two_loaded_drivers(self):
        driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': True},
             'driver-B': {'is_loaded': True}})
        self.assertEqual(2, len(driver_manager.drivers))


class TestLogDriversManagerLoggingTypes(TestLogDriversManagerBase):
    """Test supported logging types"""
    def test_available_logging_types(self):
        driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': True,
                          'supported_logging_types': ['security_group']},
             'driver-B': {'is_loaded': True,
                          'supported_logging_types':
                              ['security_group', 'firewall']}
             })
        self.assertEqual(set(['security_group', 'firewall']),
                         driver_manager.supported_logging_types)


class TestLogDriversCalls(TestLogDriversManagerBase):
    """Test log driver calls"""

    def setUp(self):
        super(TestLogDriversCalls, self).setUp()
        self.driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': True}})

    def test_implemented_call_methods(self):
        for method in log_const.LOG_CALL_METHODS:
            with mock.patch.object(log_driver_base.DriverBase, method) as \
                    method_fnc:
                context = mock.sentinel.context
                log_obj = mock.sentinel.log_obj
                self.driver_manager.call(
                    method, context=context, log_objs=[log_obj])
                method_fnc.assert_called_once_with(
                    context=context, log_objs=[log_obj])

    def test_not_implemented_call_methods(self):
        context = mock.sentinel.context
        log_obj = mock.sentinel.log_obj
        self.assertRaises(exceptions.DriverCallError, self.driver_manager.call,
                          'wrong_method', context=context, log_objs=[log_obj])


class TestHandleResourceCallback(TestLogDriversManagerBase):
    """Test handle resource callback"""

    def setUp(self):
        super(TestHandleResourceCallback, self).setUp()
        self._cb_mgr = mock.Mock()
        self.useFixture(fixture.CallbackRegistryFixture(
            callback_manager=self._cb_mgr))
        self.driver_manager = driver_mgr.LoggingServiceDriverManager()

    def test_subscribe_resources_cb(self):

        class FakeResourceCB1(driver_mgr.ResourceCallBackBase):
            def handle_event(self, resource, event, trigger, **kwargs):
                pass

        class FakeResourceCB2(driver_mgr.ResourceCallBackBase):
            def handle_event(self, resource, event, trigger, **kwargs):
                pass

        driver_mgr.RESOURCE_CB_CLASS_MAP = {'fake_resource1': FakeResourceCB1,
                                            'fake_resource2': FakeResourceCB2}

        self.driver_manager._setup_resources_cb_handle()

        fake_resource_cb1 = FakeResourceCB1(
            'fake_resource1', self.driver_manager.call)
        fake_resource_cb2 = FakeResourceCB2(
            'fake_resource2', self.driver_manager.call)
        assert_calls = [
            mock.call(
                *tools.get_subscribe_args(
                    fake_resource_cb1.handle_event,
                    'fake_resource1', events.AFTER_CREATE)),
            mock.call(
                *tools.get_subscribe_args(
                    fake_resource_cb1.handle_event,
                    'fake_resource1', events.AFTER_UPDATE)),
            mock.call(
                *tools.get_subscribe_args(
                    fake_resource_cb1.handle_event,
                    'fake_resource1', events.AFTER_DELETE)),
            mock.call(
                *tools.get_subscribe_args(
                    fake_resource_cb2.handle_event,
                    'fake_resource2', events.AFTER_CREATE)),
            mock.call(
                *tools.get_subscribe_args(
                    fake_resource_cb2.handle_event,
                    'fake_resource2', events.AFTER_UPDATE)),
            mock.call(
                *tools.get_subscribe_args(
                    fake_resource_cb2.handle_event,
                    'fake_resource2', events.AFTER_DELETE)),
        ]
        self._cb_mgr.subscribe.assert_has_calls(assert_calls)
