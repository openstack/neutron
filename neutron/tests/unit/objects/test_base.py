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

import copy

import mock
from oslo_db import exception as obj_exc
from oslo_utils import uuidutils
from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields

from neutron.common import exceptions as n_exc
from neutron.common import utils as common_utils
from neutron import context
from neutron.db import api as db_api
from neutron.db import models_v2
from neutron.objects import base
from neutron.tests import base as test_base
from neutron.tests import tools


SQLALCHEMY_COMMIT = 'sqlalchemy.engine.Connection._commit_impl'
OBJECTS_BASE_OBJ_FROM_PRIMITIVE = ('oslo_versionedobjects.base.'
                                   'VersionedObject.obj_from_primitive')


class FakeModel(object):
    def __init__(self, *args, **kwargs):
        pass


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObject(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = FakeModel

    fields = {
        'id': obj_fields.UUIDField(),
        'field1': obj_fields.StringField(),
        'field2': obj_fields.StringField()
    }

    fields_no_update = ['id']

    synthetic_fields = ['field2']


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObjectNonStandardPrimaryKey(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = FakeModel

    primary_key = 'weird_key'

    fields = {
        'weird_key': obj_fields.UUIDField(),
        'field1': obj_fields.StringField(),
        'field2': obj_fields.StringField()
    }

    synthetic_fields = ['field2']


FIELD_TYPE_VALUE_GENERATOR_MAP = {
    obj_fields.BooleanField: tools.get_random_boolean,
    obj_fields.IntegerField: tools.get_random_integer,
    obj_fields.StringField: tools.get_random_string,
    obj_fields.UUIDField: uuidutils.generate_uuid,
    obj_fields.ListOfObjectsField: lambda: []
}


def get_obj_db_fields(obj):
    return {field: getattr(obj, field) for field in obj.fields
            if field not in obj.synthetic_fields}


class _BaseObjectTestCase(object):

    _test_class = FakeNeutronObject

    def setUp(self):
        super(_BaseObjectTestCase, self).setUp()
        self.context = context.get_admin_context()
        self.db_objs = list(self.get_random_fields() for _ in range(3))
        self.db_obj = self.db_objs[0]

        valid_field = [f for f in self._test_class.fields
                       if f not in self._test_class.synthetic_fields][0]
        self.valid_field_filter = {valid_field: self.db_obj[valid_field]}

    @classmethod
    def get_random_fields(cls, obj_cls=None):
        obj_cls = obj_cls or cls._test_class
        fields = {}
        for field, field_obj in obj_cls.fields.items():
            if field not in obj_cls.synthetic_fields:
                generator = FIELD_TYPE_VALUE_GENERATOR_MAP[type(field_obj)]
                fields[field] = generator()
        return fields

    def get_updatable_fields(self, fields):
        return base.get_updatable_fields(self._test_class, fields)

    @classmethod
    def _is_test_class(cls, obj):
        return isinstance(obj, cls._test_class)


class BaseObjectIfaceTestCase(_BaseObjectTestCase, test_base.BaseTestCase):

    def test_get_by_id(self):
        with mock.patch.object(db_api, 'get_object',
                               return_value=self.db_obj) as get_object_mock:
            obj = self._test_class.get_by_id(self.context, id='fake_id')
            self.assertTrue(self._is_test_class(obj))
            self.assertEqual(self.db_obj, get_obj_db_fields(obj))
            get_object_mock.assert_called_once_with(
                self.context, self._test_class.db_model,
                **{self._test_class.primary_key: 'fake_id'})

    def test_get_by_id_missing_object(self):
        with mock.patch.object(db_api, 'get_object', return_value=None):
            obj = self._test_class.get_by_id(self.context, id='fake_id')
            self.assertIsNone(obj)

    def test_get_objects(self):
        with mock.patch.object(db_api, 'get_objects',
                               return_value=self.db_objs) as get_objects_mock:
            objs = self._test_class.get_objects(self.context)
            self._validate_objects(self.db_objs, objs)
        get_objects_mock.assert_called_once_with(
            self.context, self._test_class.db_model)

    def test_get_objects_valid_fields(self):
        with mock.patch.object(
            db_api, 'get_objects',
            return_value=[self.db_obj]) as get_objects_mock:

            objs = self._test_class.get_objects(self.context,
                                                **self.valid_field_filter)
            self._validate_objects([self.db_obj], objs)

        get_objects_mock.assert_called_with(
            self.context, self._test_class.db_model,
            **self.valid_field_filter)

    def test_get_objects_mixed_fields(self):
        synthetic_fields = self._test_class.synthetic_fields
        if not synthetic_fields:
            self.skipTest('No synthetic fields found in test class %r' %
                          self._test_class)

        filters = copy.copy(self.valid_field_filter)
        filters[synthetic_fields[0]] = 'xxx'

        with mock.patch.object(db_api, 'get_objects',
                               return_value=self.db_objs):
            self.assertRaises(base.exceptions.InvalidInput,
                              self._test_class.get_objects, self.context,
                              **filters)

    def test_get_objects_synthetic_fields(self):
        synthetic_fields = self._test_class.synthetic_fields
        if not synthetic_fields:
            self.skipTest('No synthetic fields found in test class %r' %
                          self._test_class)

        with mock.patch.object(db_api, 'get_objects',
                               return_value=self.db_objs):
            self.assertRaises(base.exceptions.InvalidInput,
                              self._test_class.get_objects, self.context,
                              **{synthetic_fields[0]: 'xxx'})

    def test_get_objects_invalid_fields(self):
        with mock.patch.object(db_api, 'get_objects',
                               return_value=self.db_objs):
            self.assertRaises(base.exceptions.InvalidInput,
                              self._test_class.get_objects, self.context,
                              fake_field='xxx')

    def _validate_objects(self, expected, observed):
        self.assertTrue(all(self._is_test_class(obj) for obj in observed))
        self.assertEqual(
            sorted(expected,
                   key=common_utils.safe_sort_key),
            sorted([get_obj_db_fields(obj) for obj in observed],
                   key=common_utils.safe_sort_key))

    def _check_equal(self, obj, db_obj):
        self.assertEqual(
            sorted(db_obj),
            sorted(get_obj_db_fields(obj)))

    def test_create(self):
        with mock.patch.object(db_api, 'create_object',
                               return_value=self.db_obj) as create_mock:
            obj = self._test_class(self.context, **self.db_obj)
            self._check_equal(obj, self.db_obj)
            obj.create()
            self._check_equal(obj, self.db_obj)
            create_mock.assert_called_once_with(
                self.context, self._test_class.db_model, self.db_obj)

    def test_create_updates_from_db_object(self):
        with mock.patch.object(db_api, 'create_object',
                               return_value=self.db_obj):
            obj = self._test_class(self.context, **self.db_objs[1])
            self._check_equal(obj, self.db_objs[1])
            obj.create()
            self._check_equal(obj, self.db_obj)

    def test_create_duplicates(self):
        with mock.patch.object(db_api, 'create_object',
                               side_effect=obj_exc.DBDuplicateEntry):
            obj = self._test_class(self.context, **self.db_obj)
            self.assertRaises(base.NeutronDbObjectDuplicateEntry, obj.create)

    @mock.patch.object(db_api, 'update_object')
    def test_update_no_changes(self, update_mock):
        with mock.patch.object(base.NeutronDbObject,
                               '_get_changed_persistent_fields',
                               return_value={}):
            obj = self._test_class(self.context, id=7777)
            obj.update()
            self.assertFalse(update_mock.called)

    @mock.patch.object(db_api, 'update_object')
    def test_update_changes(self, update_mock):
        fields_to_update = self.get_updatable_fields(self.db_obj)
        with mock.patch.object(base.NeutronDbObject,
                               '_get_changed_persistent_fields',
                               return_value=fields_to_update):
            obj = self._test_class(self.context, **self.db_obj)
            obj.update()
            update_mock.assert_called_once_with(
                self.context, self._test_class.db_model,
                self.db_obj[self._test_class.primary_key],
                fields_to_update,
                key=self._test_class.primary_key)

    @mock.patch.object(base.NeutronDbObject,
                       '_get_changed_persistent_fields',
                       return_value={'a': 'a', 'b': 'b', 'c': 'c'})
    def test_update_changes_forbidden(self, *mocks):
        with mock.patch.object(
            self._test_class,
            'fields_no_update',
            new_callable=mock.PropertyMock(return_value=['a', 'c']),
            create=True):
            obj = self._test_class(self.context, **self.db_obj)
            self.assertRaises(base.NeutronObjectUpdateForbidden, obj.update)

    def test_update_updates_from_db_object(self):
        with mock.patch.object(db_api, 'update_object',
                               return_value=self.db_obj):
            obj = self._test_class(self.context, **self.db_objs[1])
            fields_to_update = self.get_updatable_fields(self.db_objs[1])
            with mock.patch.object(base.NeutronDbObject,
                                   '_get_changed_persistent_fields',
                                   return_value=fields_to_update):
                obj.update()
            self._check_equal(obj, self.db_obj)

    @mock.patch.object(db_api, 'delete_object')
    def test_delete(self, delete_mock):
        obj = self._test_class(self.context, **self.db_obj)
        self._check_equal(obj, self.db_obj)
        obj.delete()
        self._check_equal(obj, self.db_obj)
        delete_mock.assert_called_once_with(
            self.context, self._test_class.db_model,
            self.db_obj[self._test_class.primary_key],
            key=self._test_class.primary_key)

    @mock.patch(OBJECTS_BASE_OBJ_FROM_PRIMITIVE)
    def test_clean_obj_from_primitive(self, get_prim_m):
        expected_obj = get_prim_m.return_value
        observed_obj = self._test_class.clean_obj_from_primitive('foo', 'bar')
        self.assertIs(expected_obj, observed_obj)
        self.assertTrue(observed_obj.obj_reset_changes.called)


class BaseDbObjectNonStandardPrimaryKeyTestCase(BaseObjectIfaceTestCase):

    _test_class = FakeNeutronObjectNonStandardPrimaryKey


class BaseDbObjectTestCase(_BaseObjectTestCase):

    def _create_test_network(self):
        # TODO(ihrachys): replace with network.create() once we get an object
        # implementation for networks
        self._network = db_api.create_object(self.context, models_v2.Network,
                                             {'name': 'test-network1'})

    def _create_test_port(self, network):
        # TODO(ihrachys): replace with port.create() once we get an object
        # implementation for ports
        self._port = db_api.create_object(self.context, models_v2.Port,
                                          {'tenant_id': 'fake_tenant_id',
                                           'name': 'test-port1',
                                           'network_id': network['id'],
                                           'mac_address': 'fake_mac',
                                           'admin_state_up': True,
                                           'status': 'ACTIVE',
                                           'device_id': 'fake_device',
                                           'device_owner': 'fake_owner'})

    def test_get_by_id_create_update_delete(self):
        obj = self._test_class(self.context, **self.db_obj)
        obj.create()

        new = self._test_class.get_by_id(self.context,
                                         id=getattr(obj, obj.primary_key))
        self.assertEqual(obj, new)

        obj = new

        for key, val in self.get_updatable_fields(self.db_objs[1]).items():
            setattr(obj, key, val)
        obj.update()

        new = self._test_class.get_by_id(self.context,
                                         getattr(obj, obj.primary_key))
        self.assertEqual(obj, new)

        obj = new
        new.delete()

        new = self._test_class.get_by_id(self.context,
                                         getattr(obj, obj.primary_key))
        self.assertIsNone(new)

    def test_update_non_existent_object_raises_not_found(self):
        obj = self._test_class(self.context, **self.db_obj)
        obj.obj_reset_changes()

        for key, val in self.get_updatable_fields(self.db_obj).items():
            setattr(obj, key, val)

        self.assertRaises(n_exc.ObjectNotFound, obj.update)

    def test_delete_non_existent_object_raises_not_found(self):
        obj = self._test_class(self.context, **self.db_obj)
        self.assertRaises(n_exc.ObjectNotFound, obj.delete)

    @mock.patch(SQLALCHEMY_COMMIT)
    def test_create_single_transaction(self, mock_commit):
        obj = self._test_class(self.context, **self.db_obj)
        obj.create()
        self.assertEqual(1, mock_commit.call_count)

    def test_update_single_transaction(self):
        obj = self._test_class(self.context, **self.db_obj)
        obj.create()

        for key, val in self.get_updatable_fields(self.db_obj).items():
            setattr(obj, key, val)

        with mock.patch(SQLALCHEMY_COMMIT) as mock_commit:
            obj.update()
        self.assertEqual(1, mock_commit.call_count)

    def test_delete_single_transaction(self):
        obj = self._test_class(self.context, **self.db_obj)
        obj.create()

        with mock.patch(SQLALCHEMY_COMMIT) as mock_commit:
            obj.delete()
        self.assertEqual(1, mock_commit.call_count)

    @mock.patch(SQLALCHEMY_COMMIT)
    def test_get_objects_single_transaction(self, mock_commit):
        self._test_class.get_objects(self.context)
        self.assertEqual(1, mock_commit.call_count)

    @mock.patch(SQLALCHEMY_COMMIT)
    def test_get_by_id_single_transaction(self, mock_commit):
        obj = self._test_class(self.context, **self.db_obj)
        obj.create()

        obj = self._test_class.get_by_id(self.context,
                                         getattr(obj, obj.primary_key))
        self.assertEqual(2, mock_commit.call_count)
