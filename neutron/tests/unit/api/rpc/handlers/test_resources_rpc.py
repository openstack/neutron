# Copyright (c) 2015 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
from oslo_utils import uuidutils

from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron import context
from neutron.objects.qos import policy
from neutron.tests import base


class ResourcesRpcBaseTestCase(base.BaseTestCase):

    def setUp(self):
        super(ResourcesRpcBaseTestCase, self).setUp()
        self.context = context.get_admin_context()

    def _create_test_policy_dict(self):
        return {'id': uuidutils.generate_uuid(),
                'tenant_id': uuidutils.generate_uuid(),
                'name': 'test',
                'description': 'test',
                'shared': False}

    def _create_test_policy(self, policy_dict):
        policy_obj = policy.QosPolicy(self.context, **policy_dict)
        policy_obj.obj_reset_changes()
        return policy_obj


class ResourcesPullRpcApiTestCase(ResourcesRpcBaseTestCase):

    def setUp(self):
        super(ResourcesPullRpcApiTestCase, self).setUp()
        self.client_p = mock.patch.object(resources_rpc.n_rpc, 'get_client')
        self.client = self.client_p.start()
        self.rpc = resources_rpc.ResourcesPullRpcApi()
        self.mock_cctxt = self.rpc.client.prepare.return_value

    def test_is_singleton(self):
        self.assertEqual(id(self.rpc),
                         id(resources_rpc.ResourcesPullRpcApi()))

    def test_pull(self):
        policy_dict = self._create_test_policy_dict()
        expected_policy_obj = self._create_test_policy(policy_dict)
        qos_policy_id = policy_dict['id']
        self.mock_cctxt.call.return_value = (
            expected_policy_obj.obj_to_primitive())
        pull_result = self.rpc.pull(
            self.context, resources.QOS_POLICY, qos_policy_id)
        self.mock_cctxt.call.assert_called_once_with(
            self.context, 'pull', resource_type=resources.QOS_POLICY,
            version=policy.QosPolicy.VERSION, resource_id=qos_policy_id)
        self.assertEqual(expected_policy_obj, pull_result)

    def test_pull_invalid_resource_type_cls(self):
        self.assertRaises(
            resources_rpc.InvalidResourceTypeClass, self.rpc.pull,
            self.context, 'foo_type', 'foo_id')

    def test_pull_resource_not_found(self):
        policy_dict = self._create_test_policy_dict()
        qos_policy_id = policy_dict['id']
        self.mock_cctxt.call.return_value = None
        self.assertRaises(
            resources_rpc.ResourceNotFound, self.rpc.pull,
            self.context, resources.QOS_POLICY, qos_policy_id)


class ResourcesPullRpcCallbackTestCase(ResourcesRpcBaseTestCase):

    def setUp(self):
        super(ResourcesPullRpcCallbackTestCase, self).setUp()
        self.callbacks = resources_rpc.ResourcesPullRpcCallback()

    def test_pull(self):
        policy_dict = self._create_test_policy_dict()
        policy_obj = self._create_test_policy(policy_dict)
        qos_policy_id = policy_dict['id']
        with mock.patch.object(resources_rpc.registry, 'pull',
                               return_value=policy_obj) as registry_mock:
            primitive = self.callbacks.pull(
                self.context, resource_type=resources.QOS_POLICY,
                version=policy.QosPolicy.VERSION,
                resource_id=qos_policy_id)
            registry_mock.assert_called_once_with(
                resources.QOS_POLICY,
                qos_policy_id, context=self.context)
        self.assertEqual(policy_dict, primitive['versioned_object.data'])
        self.assertEqual(policy_obj.obj_to_primitive(), primitive)

    @mock.patch.object(policy.QosPolicy, 'obj_to_primitive')
    def test_pull_no_backport_for_latest_version(self, to_prim_mock):
        policy_dict = self._create_test_policy_dict()
        policy_obj = self._create_test_policy(policy_dict)
        qos_policy_id = policy_dict['id']
        with mock.patch.object(resources_rpc.registry, 'pull',
                               return_value=policy_obj):
            self.callbacks.pull(
                self.context, resource_type=resources.QOS_POLICY,
                version=policy.QosPolicy.VERSION,
                resource_id=qos_policy_id)
            to_prim_mock.assert_called_with(target_version=None)

    @mock.patch.object(policy.QosPolicy, 'obj_to_primitive')
    def test_pull_backports_to_older_version(self, to_prim_mock):
        policy_dict = self._create_test_policy_dict()
        policy_obj = self._create_test_policy(policy_dict)
        qos_policy_id = policy_dict['id']
        with mock.patch.object(resources_rpc.registry, 'pull',
                               return_value=policy_obj):
            self.callbacks.pull(
                self.context, resource_type=resources.QOS_POLICY,
                version='0.9',  # less than initial version 1.0
                resource_id=qos_policy_id)
            to_prim_mock.assert_called_with(target_version='0.9')
