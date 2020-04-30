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

from unittest import mock

from neutron.tests import base

from neutron.services.qos.drivers.ovn import driver


context = 'context'


class TestOVNQosDriver(base.BaseTestCase):

    def setUp(self):
        super(TestOVNQosDriver, self).setUp()
        self.mech_driver = mock.Mock()
        self.mech_driver._ovn_client = mock.Mock()
        self.mech_driver._ovn_client._qos_driver = mock.Mock()
        self.driver = driver.OVNQosDriver.create(self.mech_driver)
        self.policy = "policy"

    def test_create_policy(self):
        self.driver.create_policy(context, self.policy)
        self.driver._driver._ovn_client._qos_driver.create_policy.\
            assert_not_called()

    def test_update_policy(self):
        self.driver.update_policy(context, self.policy)
        self.driver._driver._ovn_client._qos_driver.update_policy.\
            assert_called_once_with(context, self.policy)

    def test_delete_policy(self):
        self.driver.delete_policy(context, self.policy)
        self.driver._driver._ovn_client._qos_driver.delete_policy.\
            assert_not_called()
