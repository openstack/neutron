# Copyright 2016 Red Hat, Inc.
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

import netaddr

from neutron.tests.common.exclusive_resources import ip_address
from neutron.tests.functional import base


class TestExclusiveIPAddress(base.BaseLoggingTestCase):
    def test_ip_address(self):
        address_1 = self.useFixture(
            ip_address.ExclusiveIPAddress('10.0.0.1', '10.0.0.2')).address
        address_2 = self.useFixture(
            ip_address.ExclusiveIPAddress('10.0.0.1', '10.0.0.2')).address

        self.assertIsInstance(address_1, netaddr.IPAddress)
        self.assertNotEqual(address_1, address_2)
