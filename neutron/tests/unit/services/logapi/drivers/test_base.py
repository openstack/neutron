# Copyright (C) 2017 Fujitsu Limited
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

from neutron_lib.api.definitions import portbindings

from neutron.services.logapi.drivers import base as log_base_driver
from neutron.tests import base

SUPPORTED_LOGGING_TYPES = ('security_group',)


class FakeDriver(log_base_driver.DriverBase):

    @staticmethod
    def create():
        return FakeDriver(
            name='fake_driver',
            vif_types=[portbindings.VIF_TYPE_OVS],
            vnic_types=[portbindings.VNIC_NORMAL],
            supported_logging_types=SUPPORTED_LOGGING_TYPES,
            requires_rpc=False
        )


class TestDriverBase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.driver = FakeDriver.create()

    def test_is_vif_type_compatible(self):
        self.assertFalse(
            self.driver.is_vif_type_compatible(portbindings.VIF_TYPE_OTHER))
        self.assertTrue(
            self.driver.is_vif_type_compatible(portbindings.VIF_TYPE_OVS))

    def test_is_vnic_compatible(self):
        self.assertFalse(
            self.driver.is_vnic_compatible(portbindings.VNIC_BAREMETAL))
        self.assertTrue(
            self.driver.is_vnic_compatible(portbindings.VNIC_NORMAL))

    def test_is_logging_type_supported(self):
        self.assertTrue(
            self.driver.is_logging_type_supported('security_group'))
        self.assertFalse(self.driver.is_logging_type_supported('firewall'))
