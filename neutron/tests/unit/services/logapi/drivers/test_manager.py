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

from neutron.services.logapi.drivers import base as log_driver_base
from neutron.services.logapi.drivers import manager as driver_mgr
from neutron.tests.unit.services.logapi import base


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
