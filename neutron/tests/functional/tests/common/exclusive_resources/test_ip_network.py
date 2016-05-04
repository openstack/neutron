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

from neutron.tests.common.exclusive_resources import ip_network
from neutron.tests.functional import base


class TestExclusiveIPNetwork(base.BaseLoggingTestCase):
    def test_ip_network(self):
        network_1 = self.useFixture(
            ip_network.ExclusiveIPNetwork(
                '240.0.0.1', '240.255.255.254', '24')).network
        network_2 = self.useFixture(
            ip_network.ExclusiveIPNetwork(
                '240.0.0.1', '240.255.255.254', '24')).network

        self.assertIsInstance(network_1, netaddr.IPNetwork)
        self.assertEqual(network_1.cidr, network_1)
        self.assertNotEqual(network_1, network_2)
