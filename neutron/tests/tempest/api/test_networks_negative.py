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

from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
import testtools

from neutron.tests.tempest.api import base


class NetworksNegativeTest(base.BaseNetworkTest):

    @classmethod
    def resource_setup(cls):
        super(NetworksNegativeTest, cls).resource_setup()
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('9f80f25b-5d1b-4f26-9f6b-774b9b270819')
    def test_delete_network_in_use(self):
        port = self.client.create_port(network_id=self.network['id'])
        self.addCleanup(self.client.delete_port, port['port']['id'])
        with testtools.ExpectedException(lib_exc.Conflict):
            self.client.delete_subnet(self.subnet['id'])
        with testtools.ExpectedException(lib_exc.Conflict):
            self.client.delete_network(self.network['id'])
