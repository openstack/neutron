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

from oslo_versionedobjects import base as obj_base

from neutron.api.rpc.callbacks import resources
from neutron.objects.qos import policy
from neutron.tests import base


class GetResourceTypeTestCase(base.BaseTestCase):

    def test_get_resource_type_none(self):
        self.assertIsNone(resources.get_resource_type(None))

    def test_get_resource_type_wrong_type(self):
        self.assertIsNone(resources.get_resource_type(object()))

    def test_get_resource_type(self):
        # we could use any other registered NeutronObject type here
        self.assertEqual(policy.QosPolicy.obj_name(),
                         resources.get_resource_type(policy.QosPolicy()))


class IsValidResourceTypeTestCase(base.BaseTestCase):

    def test_known_type(self):
        # it could be any other NeutronObject, assuming it's known to RPC
        # callbacks
        self.assertTrue(resources.is_valid_resource_type(
            policy.QosPolicy.obj_name()))

    def test_unknown_type(self):
        self.assertFalse(
            resources.is_valid_resource_type('unknown-resource-type'))


class GetResourceClsTestCase(base.BaseTestCase):

    def test_known_type(self):
        # it could be any other NeutronObject, assuming it's known to RPC
        # callbacks
        self.assertEqual(policy.QosPolicy,
                         resources.get_resource_cls(resources.QOS_POLICY))

    def test_unknown_type(self):
        self.assertIsNone(resources.get_resource_cls('unknown-resource-type'))


class RegisterResourceClass(base.BaseTestCase):

    def test_register_resource_class(self):
        class DummyOVO(obj_base.VersionedObject):
            pass

        self.assertFalse(
            resources.is_valid_resource_type('DummyOVO'))
        resources.register_resource_class(DummyOVO)
        self.assertTrue(
            resources.is_valid_resource_type('DummyOVO'))

    def test_register_bogus_resource_class(self):
        class DummyOVO:
            pass

        self.assertRaises(ValueError,
                          resources.register_resource_class, DummyOVO)
