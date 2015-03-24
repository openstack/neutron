# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License. You may
# obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

import testtools

from neutron.tests import base as tests_base
from neutron.tests.retargetable import base


class TestExample(base.RetargetableApiTest):
    """This class is an example of how to write a retargetable api test.

    See the parent class for details about how the 'client' attribute
    is configured via testscenarios.
    """

    def test_network_lifecycle(self):
        net = self.client.create_network(name=tests_base.get_rand_name())
        listed_networks = {x.id: x.name for x in self.client.get_networks()}
        self.assertIn(net.id, listed_networks)
        self.assertEqual(listed_networks[net.id], net.name,
                         'Listed network name is not as expected.')
        updated_name = 'new %s' % net.name
        updated_net = self.client.update_network(net.id, name=updated_name)
        self.assertEqual(updated_name, updated_net.name,
                         'Updated network name is not as expected.')
        self.client.delete_network(net.id)
        with testtools.ExpectedException(self.client.NotFound,
                                         msg='Network was not deleted'):
            self.client.get_network(net.id)
