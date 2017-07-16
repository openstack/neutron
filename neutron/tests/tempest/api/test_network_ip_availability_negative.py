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

from oslo_utils import uuidutils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron.tests.tempest.api import test_network_ip_availability as net_ip


class NetworksIpAvailabilityNegativeTest(net_ip.NetworksIpAvailabilityTest):

    @decorators.attr(type='negative')
    @decorators.idempotent_id('3b8693eb-6c57-4ea1-ab84-3730c9ee9c84')
    def test_network_availability_nonexistent_network_id(self):
        self.assertRaises(lib_exc.NotFound,
                          self.admin_client.show_network_ip_availability,
                          uuidutils.generate_uuid())
