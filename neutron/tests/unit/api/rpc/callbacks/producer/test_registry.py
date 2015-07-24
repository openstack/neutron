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

from neutron.api.rpc.callbacks import exceptions
from neutron.api.rpc.callbacks.producer import registry
from neutron.api.rpc.callbacks import resources
from neutron.objects.qos import policy
from neutron.tests.unit.services.qos import base


class ProducerRegistryTestCase(base.BaseQosTestCase):

    def test_pull_returns_callback_result(self):
        policy_obj = policy.QosPolicy(context=None)

        def _fake_policy_cb(*args, **kwargs):
            return policy_obj

        registry.provide(_fake_policy_cb, resources.QOS_POLICY)

        self.assertEqual(
            policy_obj,
            registry.pull(resources.QOS_POLICY, 'fake_id'))

    def test_pull_does_not_raise_on_none(self):
        def _none_cb(*args, **kwargs):
            pass

        registry.provide(_none_cb, resources.QOS_POLICY)

        obj = registry.pull(resources.QOS_POLICY, 'fake_id')
        self.assertIsNone(obj)

    def test_pull_raises_on_wrong_object_type(self):
        def _wrong_type_cb(*args, **kwargs):
            return object()

        registry.provide(_wrong_type_cb, resources.QOS_POLICY)

        self.assertRaises(
            exceptions.CallbackWrongResourceType,
            registry.pull, resources.QOS_POLICY, 'fake_id')

    def test_pull_raises_on_callback_not_found(self):
        self.assertRaises(
            exceptions.CallbackNotFound,
            registry.pull, resources.QOS_POLICY, 'fake_id')

    def test__get_manager_is_singleton(self):
        self.assertIs(registry._get_manager(), registry._get_manager())

    def test_unprovide(self):
        def _fake_policy_cb(*args, **kwargs):
            pass

        registry.provide(_fake_policy_cb, resources.QOS_POLICY)
        registry.unprovide(_fake_policy_cb, resources.QOS_POLICY)

        self.assertRaises(
            exceptions.CallbackNotFound,
            registry.pull, resources.QOS_POLICY, 'fake_id')

    def test_clear_unprovides_all_producers(self):
        def _fake_policy_cb(*args, **kwargs):
            pass

        registry.provide(_fake_policy_cb, resources.QOS_POLICY)
        registry.clear()

        self.assertRaises(
            exceptions.CallbackNotFound,
            registry.pull, resources.QOS_POLICY, 'fake_id')
