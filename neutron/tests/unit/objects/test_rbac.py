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

from neutron.objects import network
from neutron.objects.qos import policy
from neutron.objects import rbac
from neutron.tests import base as neutron_test_base


class RBACBaseObjectTestCase(neutron_test_base.BaseTestCase):

    def test_get_type_class_map(self):
        class_map = {'qos_policy': policy.QosPolicyRBAC,
                     'network': network.NetworkRBAC}
        self.assertEqual(class_map, rbac.RBACBaseObject.get_type_class_map())
