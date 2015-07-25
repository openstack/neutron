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

from neutron.api.rpc.callbacks import registry
from neutron.api.rpc.callbacks import resource_manager
from neutron.api.rpc.callbacks import resources
from neutron.objects.qos import policy
from neutron.tests import base


class GetInfoTestCase(base.BaseTestCase):
    def setUp(self):
        super(GetInfoTestCase, self).setUp()
        mgr = resource_manager.ResourcesCallbacksManager()
        mgr_p = mock.patch.object(
            registry, '_get_resources_callback_manager', return_value=mgr)
        mgr_p.start()

    def test_returns_callback_result(self):
        policy_obj = policy.QosPolicy(context=None)

        def _fake_policy_cb(*args, **kwargs):
            return policy_obj

        registry.register_provider(_fake_policy_cb, resources.QOS_POLICY)

        self.assertEqual(policy_obj,
                         registry.get_info(resources.QOS_POLICY, 'fake_id'))

    def test_does_not_raise_on_none(self):
        def _wrong_type_cb(*args, **kwargs):
            pass

        registry.register_provider(_wrong_type_cb, resources.QOS_POLICY)

        obj = registry.get_info(resources.QOS_POLICY, 'fake_id')
        self.assertIsNone(obj)

    def test_raises_on_wrong_object_type(self):
        def _wrong_type_cb(*args, **kwargs):
            return object()

        registry.register_provider(_wrong_type_cb, resources.QOS_POLICY)

        self.assertRaises(
            registry.CallbackReturnedWrongObjectType,
            registry.get_info, resources.QOS_POLICY, 'fake_id')
