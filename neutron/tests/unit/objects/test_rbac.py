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

from neutron.objects import network
from neutron.objects.qos import policy
from neutron.objects import rbac
from neutron.objects import securitygroup
from neutron.tests import base as neutron_test_base
from neutron.tests.unit.objects import test_base


class RBACBaseObjectTestCase(neutron_test_base.BaseTestCase):

    def test_get_type_class_map(self):
        class_map = {'qos_policy': policy.QosPolicyRBAC,
                     'network': network.NetworkRBAC,
                     'security_group': securitygroup.SecurityGroupRBAC}
        self.assertEqual(class_map, rbac.RBACBaseObject.get_type_class_map())


class RBACBaseObjectIfaceTestCase(test_base.BaseObjectIfaceTestCase):

    def test_get_object(self, context=None):
        super(RBACBaseObjectIfaceTestCase,
              self).test_get_object(context=mock.ANY)

    def test_get_objects(self, context=None):
        super(RBACBaseObjectIfaceTestCase,
              self).test_get_objects(context=mock.ANY)
