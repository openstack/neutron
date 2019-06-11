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
from neutron_lib.agent import topics
from neutron_lib import context
from neutron_lib.objects import common_types
from oslo_utils import uuidutils
from oslo_versionedobjects import fields as obj_fields
import testtools

from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.callbacks import version_manager
from neutron.api.rpc.handlers import resources_rpc
from neutron.objects import base as objects_base
from neutron.tests import base
from neutron.tests.unit.objects import test_base as objects_test_base


TEST_EVENT = 'test_event'
TEST_VERSION = '1.0'


def _create_test_dict(uuid=None):
    return {'id': uuid or uuidutils.generate_uuid(),
            'field': 'foo'}


def _create_test_resource(context=None, resource_cls=None):
    resource_cls = resource_cls or FakeResource
    resource_dict = _create_test_dict()
    resource = resource_cls(context, **resource_dict)
    resource.obj_reset_changes()
    return resource


class BaseFakeResource(objects_base.NeutronObject):
    @classmethod
    def get_objects(cls, context, **kwargs):
        return list()


class FakeResource(BaseFakeResource):
    VERSION = TEST_VERSION

    fields = {
        'id': common_types.UUIDField(),
        'field': obj_fields.StringField()
    }


class FakeResource2(BaseFakeResource):
    VERSION = TEST_VERSION

    fields = {
        'id': common_types.UUIDField(),
        'field': obj_fields.StringField()
    }


class ResourcesRpcBaseTestCase(base.BaseTestCase):

    def setUp(self):
        super(ResourcesRpcBaseTestCase, self).setUp()

        self.obj_registry = self.useFixture(
            objects_test_base.NeutronObjectRegistryFixture())

        self.context = context.get_admin_context()
        mock.patch.object(resources_rpc.resources,
                          'is_valid_resource_type').start()
        mock.patch.object(resources_rpc.resources, 'get_resource_cls',
                          side_effect=self._get_resource_cls).start()

        self.resource_objs = [_create_test_resource(self.context)
                              for _ in range(2)]
        self.resource_objs2 = [_create_test_resource(self.context,
                                                     FakeResource2)
                               for _ in range(2)]

    @staticmethod
    def _get_resource_cls(resource_type):
        return {FakeResource.obj_name(): FakeResource,
                FakeResource2.obj_name(): FakeResource2}.get(resource_type)


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
        self.rpc = resources_rpc.ResourcesPullRpcApi()
        mock.patch.object(self.rpc, 'client').start()
        self.cctxt_mock = self.rpc.client.prepare.return_value

    def test_is_singleton(self):
        self.assertIs(self.rpc, resources_rpc.ResourcesPullRpcApi())

    def test_pull(self):
        self.obj_registry.register(FakeResource)
        expected_obj = _create_test_resource(self.context)
        resource_id = expected_obj.id
        self.cctxt_mock.call.return_value = expected_obj.obj_to_primitive()

        result = self.rpc.pull(
            self.context, FakeResource.obj_name(), resource_id)

        self.cctxt_mock.call.assert_called_once_with(
            self.context, 'pull', resource_type='FakeResource',
            version=TEST_VERSION, resource_id=resource_id)
        self.assertEqual(expected_obj, result)

    def test_bulk_pull(self):
        self.obj_registry.register(FakeResource)
        expected_objs = [_create_test_resource(self.context),
                         _create_test_resource(self.context)]
        self.cctxt_mock.call.return_value = [
            e.obj_to_primitive() for e in expected_objs]

        filter_kwargs = {'a': 'b', 'c': 'd'}
        result = self.rpc.bulk_pull(
            self.context, FakeResource.obj_name(),
            filter_kwargs=filter_kwargs)

        self.cctxt_mock.call.assert_called_once_with(
            self.context, 'bulk_pull', resource_type='FakeResource',
            version=TEST_VERSION, filter_kwargs=filter_kwargs)
        self.assertEqual(expected_objs, result)

    def test_pull_resource_not_found(self):
        resource_dict = _create_test_dict()
        resource_id = resource_dict['id']
        self.cctxt_mock.call.return_value = None
        with testtools.ExpectedException(resources_rpc.ResourceNotFound):
            self.rpc.pull(self.context, FakeResource.obj_name(),
                          resource_id)


class ResourcesPushToServerRpcCallbackTestCase(ResourcesRpcBaseTestCase):

    def test_report_versions(self):
        callbacks = resources_rpc.ResourcesPushToServerRpcCallback()
        with mock.patch('neutron.api.rpc.callbacks.version_manager'
                        '.update_versions') as update_versions:
            version_map = {'A': '1.0'}
            callbacks.report_agent_resource_versions(context=mock.ANY,
                                      agent_type='DHCP Agent',
                                      agent_host='fake-host',
                                      version_map=version_map)
            update_versions.assert_called_once_with(mock.ANY,
                                                    version_map)


class ResourcesPullRpcCallbackTestCase(ResourcesRpcBaseTestCase):

    def setUp(self):
        super(ResourcesPullRpcCallbackTestCase, self).setUp()
        self.obj_registry.register(FakeResource)
        self.callbacks = resources_rpc.ResourcesPullRpcCallback()
        self.resource_obj = _create_test_resource(self.context)

    def test_pull(self):
        resource_dict = _create_test_dict(uuid=self.resource_obj.id)
        with mock.patch.object(
                resources_rpc.prod_registry, 'pull',
                return_value=self.resource_obj) as registry_mock:
            primitive = self.callbacks.pull(
                self.context, resource_type=FakeResource.obj_name(),
                version=TEST_VERSION,
                resource_id=self.resource_obj.id)
        registry_mock.assert_called_once_with(
            'FakeResource', self.resource_obj.id, context=self.context)
        self.assertEqual(resource_dict,
                         primitive['versioned_object.data'])
        self.assertEqual(self.resource_obj.obj_to_primitive(), primitive)

    def test_bulk_pull(self):
        r1 = self.resource_obj
        r2 = _create_test_resource(self.context)

        @classmethod
        def get_objs(*args, **kwargs):
            if 'id' not in kwargs:
                return [r1, r2]
            return [r for r in [r1, r2] if r.id == kwargs['id']]

        # the bulk interface currently retrieves directly from the registry
        with mock.patch.object(FakeResource, 'get_objects', new=get_objs):
            objs = self.callbacks.bulk_pull(
                self.context, resource_type=FakeResource.obj_name(),
                version=TEST_VERSION)
            self.assertItemsEqual([r1.obj_to_primitive(),
                                   r2.obj_to_primitive()],
                                  objs)
            objs = self.callbacks.bulk_pull(
                self.context, resource_type=FakeResource.obj_name(),
                version=TEST_VERSION, filter_kwargs={'id': r1.id})
            self.assertEqual([r1.obj_to_primitive()], objs)

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
    """Tests the neutron server side of the RPC interface."""

    def setUp(self):
        super(ResourcesPushRpcApiTestCase, self).setUp()
        mock.patch.object(resources_rpc.n_rpc, 'get_client').start()
        self.rpc = resources_rpc.ResourcesPushRpcApi()
        self.cctxt_mock = self.rpc.client.prepare.return_value
        mock.patch.object(version_manager, 'get_resource_versions',
                         return_value=set([TEST_VERSION])).start()

    def test__prepare_object_fanout_context(self):
        expected_topic = topics.RESOURCE_TOPIC_PATTERN % {
            'resource_type': resources.get_resource_type(
                self.resource_objs[0]),
            'version': TEST_VERSION}

        observed = self.rpc._prepare_object_fanout_context(
            self.resource_objs[0], self.resource_objs[0].VERSION, '1.0')

        self.rpc.client.prepare.assert_called_once_with(
            fanout=True, topic=expected_topic, version='1.0')
        self.assertEqual(self.cctxt_mock, observed)

    def test_push_single_type(self):
        self.rpc.push(
            self.context, self.resource_objs, TEST_EVENT)

        self.cctxt_mock.cast.assert_called_once_with(
            self.context, 'push',
            resource_list=[resource.obj_to_primitive()
                           for resource in self.resource_objs],
            event_type=TEST_EVENT)

    def test_push_mixed(self):
        self.rpc.push(
            self.context, self.resource_objs + self.resource_objs2,
            event_type=TEST_EVENT)

        self.cctxt_mock.cast.assert_any_call(
            self.context, 'push',
            resource_list=[resource.obj_to_primitive()
                           for resource in self.resource_objs],
            event_type=TEST_EVENT)

        self.cctxt_mock.cast.assert_any_call(
            self.context, 'push',
            resource_list=[resource.obj_to_primitive()
                           for resource in self.resource_objs2],
            event_type=TEST_EVENT)


class ResourcesPushRpcCallbackTestCase(ResourcesRpcBaseTestCase):
    """Tests the agent-side of the RPC interface."""

    def setUp(self):
        super(ResourcesPushRpcCallbackTestCase, self).setUp()
        self.callbacks = resources_rpc.ResourcesPushRpcCallback()

    @mock.patch.object(resources_rpc.cons_registry, 'push')
    def test_push(self, reg_push_mock):
        self.obj_registry.register(FakeResource)
        self.callbacks.push(self.context,
                            resource_list=[resource.obj_to_primitive()
                                           for resource in self.resource_objs],
                            event_type=TEST_EVENT)
        reg_push_mock.assert_called_once_with(self.context,
                                              self.resource_objs[0].obj_name(),
                                              self.resource_objs,
                                              TEST_EVENT)
