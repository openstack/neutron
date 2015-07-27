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


class ResourcesServerRpcApiTestCase(ResourcesRpcBaseTestCase):

    def setUp(self):
        super(ResourcesServerRpcApiTestCase, self).setUp()
        self.client_p = mock.patch.object(resources_rpc.n_rpc, 'get_client')
        self.client = self.client_p.start()
        self.rpc = resources_rpc.ResourcesServerRpcApi()
        self.mock_cctxt = self.rpc.client.prepare.return_value

    def test_get_info(self):
        policy_dict = self._create_test_policy_dict()
        expected_policy_obj = self._create_test_policy(policy_dict)
        qos_policy_id = policy_dict['id']
        self.mock_cctxt.call.return_value = (
            expected_policy_obj.obj_to_primitive())
        get_info_result = self.rpc.get_info(
            self.context, resources.QOS_POLICY, qos_policy_id)
        self.mock_cctxt.call.assert_called_once_with(
            self.context, 'get_info', resource_type=resources.QOS_POLICY,
            version=policy.QosPolicy.VERSION, resource_id=qos_policy_id)
        self.assertEqual(expected_policy_obj, get_info_result)

    def test_get_info_invalid_resource_type_cls(self):
        self.assertRaises(
            resources_rpc.InvalidResourceTypeClass, self.rpc.get_info,
            self.context, 'foo_type', 'foo_id')

    def test_get_info_resource_not_found(self):
        policy_dict = self._create_test_policy_dict()
        qos_policy_id = policy_dict['id']
        self.mock_cctxt.call.return_value = None
        self.assertRaises(
            resources_rpc.ResourceNotFound, self.rpc.get_info, self.context,
            resources.QOS_POLICY, qos_policy_id)


class ResourcesServerRpcCallbackTestCase(ResourcesRpcBaseTestCase):

    def setUp(self):
        super(ResourcesServerRpcCallbackTestCase, self).setUp()
        self.callbacks = resources_rpc.ResourcesServerRpcCallback()

    def test_get_info(self):
        policy_dict = self._create_test_policy_dict()
        policy_obj = self._create_test_policy(policy_dict)
        qos_policy_id = policy_dict['id']
        with mock.patch.object(resources_rpc.registry, 'get_info',
                               return_value=policy_obj) as registry_mock:
            primitive = self.callbacks.get_info(
                self.context, resource_type=resources.QOS_POLICY,
                version=policy.QosPolicy.VERSION,
                resource_id=qos_policy_id)
            registry_mock.assert_called_once_with(
                resources.QOS_POLICY,
                qos_policy_id, context=self.context)
        self.assertEqual(policy_dict, primitive['versioned_object.data'])
        self.assertEqual(policy_obj.obj_to_primitive(), primitive)

    @mock.patch.object(policy.QosPolicy, 'obj_to_primitive')
    def test_get_info_no_backport_for_latest_version(self, to_prim_mock):
        policy_dict = self._create_test_policy_dict()
        policy_obj = self._create_test_policy(policy_dict)
        qos_policy_id = policy_dict['id']
        with mock.patch.object(resources_rpc.registry, 'get_info',
                               return_value=policy_obj):
            self.callbacks.get_info(
                self.context, resource_type=resources.QOS_POLICY,
                version=policy.QosPolicy.VERSION,
                resource_id=qos_policy_id)
            to_prim_mock.assert_called_with(target_version=None)

    @mock.patch.object(policy.QosPolicy, 'obj_to_primitive')
    def test_get_info_backports_to_older_version(self, to_prim_mock):
        policy_dict = self._create_test_policy_dict()
        policy_obj = self._create_test_policy(policy_dict)
        qos_policy_id = policy_dict['id']
        with mock.patch.object(resources_rpc.registry, 'get_info',
                               return_value=policy_obj):
            self.callbacks.get_info(
                self.context, resource_type=resources.QOS_POLICY,
                version='0.9',  # less than initial version 1.0
                resource_id=qos_policy_id)
            to_prim_mock.assert_called_with(target_version='0.9')
