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

import copy

import mock
from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields
import testtools

from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.common import topics
from neutron import context
from neutron.objects import base as objects_base
from neutron.tests import base


def _create_test_dict():
    return {'id': 'uuid',
            'field': 'foo'}


def _create_test_resource(context=None):
    resource_dict = _create_test_dict()
    resource = FakeResource(context, **resource_dict)
    resource.obj_reset_changes()
    return resource


class FakeResource(objects_base.NeutronObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    fields = {
        'id': obj_fields.UUIDField(),
        'field': obj_fields.StringField()
    }

    @classmethod
    def get_objects(cls, context, **kwargs):
        return list()


class ResourcesRpcBaseTestCase(base.BaseTestCase):

    def setUp(self):
        super(ResourcesRpcBaseTestCase, self).setUp()

        # TODO(mhickey) This is using temp registry pattern. The
        # pattern solution is to backup the object registry, register
        # a class locally, and then restore the original registry.
        # Refer to https://review.openstack.org/#/c/263800/ for more
        # details. This code should be updated when the patch is merged.
        self._base_test_backup = copy.copy(
            obj_base.VersionedObjectRegistry._registry._obj_classes)
        self.addCleanup(self._restore_obj_registry)

        self.context = context.get_admin_context()

    def _restore_obj_registry(self):
        obj_base.VersionedObjectRegistry._registry._obj_classes = (
            self._base_test_backup)


class _ValidateResourceTypeTestCase(base.BaseTestCase):
    def setUp(self):
        super(_ValidateResourceTypeTestCase, self).setUp()
        self.is_valid_mock = mock.patch.object(
            resources_rpc.resources, 'is_valid_resource_type').start()

    def test_valid_type(self):
        self.is_valid_mock.return_value = True
        resources_rpc._validate_resource_type('foo')

    def test_invalid_type(self):
        self.is_valid_mock.return_value = False
        with testtools.ExpectedException(
                resources_rpc.InvalidResourceTypeClass):
            resources_rpc._validate_resource_type('foo')


class _ResourceTypeVersionedTopicTestCase(base.BaseTestCase):

    @mock.patch.object(resources_rpc, '_validate_resource_type')
    def test_resource_type_versioned_topic(self, validate_mock):
        obj_name = FakeResource.obj_name()
        expected = topics.RESOURCE_TOPIC_PATTERN % {
            'resource_type': 'FakeResource', 'version': '1.0'}
        with mock.patch.object(resources_rpc.resources, 'get_resource_cls',
                return_value=FakeResource):
            observed = resources_rpc.resource_type_versioned_topic(obj_name)
        self.assertEqual(expected, observed)


class ResourcesPullRpcApiTestCase(ResourcesRpcBaseTestCase):

    def setUp(self):
        super(ResourcesPullRpcApiTestCase, self).setUp()
        mock.patch.object(resources_rpc, '_validate_resource_type').start()
        mock.patch('neutron.api.rpc.callbacks.resources.get_resource_cls',
                   return_value=FakeResource).start()
        self.rpc = resources_rpc.ResourcesPullRpcApi()
        mock.patch.object(self.rpc, 'client').start()
        self.cctxt_mock = self.rpc.client.prepare.return_value

    def test_is_singleton(self):
        self.assertIs(self.rpc, resources_rpc.ResourcesPullRpcApi())

    def test_pull(self):
        obj_base.VersionedObjectRegistry.register(FakeResource)
        expected_obj = _create_test_resource(self.context)
        resource_id = expected_obj.id
        self.cctxt_mock.call.return_value = expected_obj.obj_to_primitive()

        result = self.rpc.pull(
            self.context, FakeResource.obj_name(), resource_id)

        self.cctxt_mock.call.assert_called_once_with(
            self.context, 'pull', resource_type='FakeResource',
            version=FakeResource.VERSION, resource_id=resource_id)
        self.assertEqual(expected_obj, result)

    def test_pull_resource_not_found(self):
        resource_dict = _create_test_dict()
        resource_id = resource_dict['id']
        self.cctxt_mock.call.return_value = None
        with testtools.ExpectedException(resources_rpc.ResourceNotFound):
            self.rpc.pull(self.context, FakeResource.obj_name(),
                          resource_id)


class ResourcesPullRpcCallbackTestCase(ResourcesRpcBaseTestCase):

    def setUp(self):
        super(ResourcesPullRpcCallbackTestCase, self).setUp()
        obj_base.VersionedObjectRegistry.register(FakeResource)
        self.callbacks = resources_rpc.ResourcesPullRpcCallback()
        self.resource_obj = _create_test_resource(self.context)

    def test_pull(self):
        resource_dict = _create_test_dict()
        with mock.patch.object(
                resources_rpc.prod_registry, 'pull',
                return_value=self.resource_obj) as registry_mock:
            primitive = self.callbacks.pull(
                self.context, resource_type=FakeResource.obj_name(),
                version=FakeResource.VERSION,
                resource_id=self.resource_obj.id)
        registry_mock.assert_called_once_with(
            'FakeResource', self.resource_obj.id, context=self.context)
        self.assertEqual(resource_dict,
                         primitive['versioned_object.data'])
        self.assertEqual(self.resource_obj.obj_to_primitive(), primitive)

    @mock.patch.object(FakeResource, 'obj_to_primitive')
    def test_pull_backports_to_older_version(self, to_prim_mock):
        with mock.patch.object(resources_rpc.prod_registry, 'pull',
                               return_value=self.resource_obj):
            self.callbacks.pull(
                self.context, resource_type=FakeResource.obj_name(),
                version='0.9',  # less than initial version 1.0
                resource_id=self.resource_obj.id)
            to_prim_mock.assert_called_with(target_version='0.9')


class ResourcesPushRpcApiTestCase(ResourcesRpcBaseTestCase):

    def setUp(self):
        super(ResourcesPushRpcApiTestCase, self).setUp()
        mock.patch.object(resources_rpc.n_rpc, 'get_client').start()
        mock.patch.object(resources_rpc, '_validate_resource_type').start()
        self.rpc = resources_rpc.ResourcesPushRpcApi()
        self.cctxt_mock = self.rpc.client.prepare.return_value
        self.resource_obj = _create_test_resource(self.context)

    def test__prepare_object_fanout_context(self):
        expected_topic = topics.RESOURCE_TOPIC_PATTERN % {
            'resource_type': resources.get_resource_type(self.resource_obj),
            'version': self.resource_obj.VERSION}

        with mock.patch.object(resources_rpc.resources, 'get_resource_cls',
                return_value=FakeResource):
            observed = self.rpc._prepare_object_fanout_context(
                self.resource_obj)

        self.rpc.client.prepare.assert_called_once_with(
            fanout=True, topic=expected_topic)
        self.assertEqual(self.cctxt_mock, observed)

    def test_pushy(self):
        with mock.patch.object(resources_rpc.resources, 'get_resource_cls',
                return_value=FakeResource):
            self.rpc.push(
                self.context, self.resource_obj, 'TYPE')

        self.cctxt_mock.cast.assert_called_once_with(
            self.context, 'push',
            resource=self.resource_obj.obj_to_primitive(),
            event_type='TYPE')


class ResourcesPushRpcCallbackTestCase(ResourcesRpcBaseTestCase):

    def setUp(self):
        super(ResourcesPushRpcCallbackTestCase, self).setUp()
        mock.patch.object(resources_rpc, '_validate_resource_type').start()
        mock.patch.object(
            resources_rpc.resources,
            'get_resource_cls', return_value=FakeResource).start()
        self.resource_obj = _create_test_resource(self.context)
        self.resource_prim = self.resource_obj.obj_to_primitive()
        self.callbacks = resources_rpc.ResourcesPushRpcCallback()

    @mock.patch.object(resources_rpc.cons_registry, 'push')
    def test_push(self, reg_push_mock):
        obj_base.VersionedObjectRegistry.register(FakeResource)
        self.callbacks.push(self.context, self.resource_prim, 'TYPE')
        reg_push_mock.assert_called_once_with(self.resource_obj.obj_name(),
                                              self.resource_obj, 'TYPE')
