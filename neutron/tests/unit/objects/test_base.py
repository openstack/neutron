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
from neutron.db import models_v2
from neutron.objects import base
from neutron.objects.db import api as obj_db_api
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

    primary_keys = ['id']

    fields_no_update = ['field1']

    synthetic_fields = ['field2']


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObjectNonStandardPrimaryKey(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = FakeModel

    primary_keys = ['weird_key']

    fields = {
        'weird_key': obj_fields.UUIDField(),
        'field1': obj_fields.StringField(),
        'field2': obj_fields.StringField()
    }

    synthetic_fields = ['field2']


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObjectCompositePrimaryKey(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = FakeModel

    primary_keys = ['weird_key', 'field1']

    fields = {
        'weird_key': obj_fields.UUIDField(),
        'field1': obj_fields.StringField(),
        'field2': obj_fields.StringField()
    }

    synthetic_fields = ['field2']


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObjectRenamedField(base.NeutronDbObject):
    """
    Testing renaming the parameter from DB to NeutronDbObject
    For tests:
        - db fields: id, field_db, field2
        - object: id, field_ovo, field2
    """
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = FakeModel

    primary_keys = ['id']

    fields = {
        'id': obj_fields.UUIDField(),
        'field_ovo': obj_fields.StringField(),
        'field2': obj_fields.StringField()
    }

    synthetic_fields = ['field2']

    fields_need_translation = {'field_ovo': 'field_db'}


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObjectCompositePrimaryKeyWithId(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = FakeModel

    primary_keys = ['id', 'field1']

    fields = {
        'id': obj_fields.UUIDField(),
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

        self.obj_fields = []
        for db_obj in self.db_objs:
            self.obj_fields.append(
                self._test_class.modify_fields_from_db(db_obj))

        valid_field = [f for f in self._test_class.fields
                       if f not in self._test_class.synthetic_fields][0]
        self.valid_field_filter = {valid_field:
                                   self.obj_fields[0][valid_field]}

    @classmethod
    def get_random_fields(cls, obj_cls=None):
        obj_cls = obj_cls or cls._test_class
        fields = {}
        for field, field_obj in obj_cls.fields.items():
            if field not in obj_cls.synthetic_fields:
                generator = FIELD_TYPE_VALUE_GENERATOR_MAP[type(field_obj)]
                fields[field] = generator()
        return obj_cls.modify_fields_to_db(fields)

    @classmethod
    def generate_object_keys(cls, obj_cls):
        keys = {}
        for field, field_obj in obj_cls.fields.items():
            if field in obj_cls.primary_keys:
                generator = FIELD_TYPE_VALUE_GENERATOR_MAP[type(field_obj)]
                keys[field] = generator()
        return keys

    def get_updatable_fields(self, fields):
        return base.get_updatable_fields(self._test_class, fields)

    @classmethod
    def _is_test_class(cls, obj):
        return isinstance(obj, cls._test_class)


class BaseObjectIfaceTestCase(_BaseObjectTestCase, test_base.BaseTestCase):

    def test_get_object(self):
        with mock.patch.object(obj_db_api, 'get_object',
                               return_value=self.db_obj) as get_object_mock:
            obj_keys = self.generate_object_keys(self._test_class)
            obj = self._test_class.get_object(self.context, **obj_keys)
            self.assertTrue(self._is_test_class(obj))
            self.assertEqual(self.obj_fields[0],
                             get_obj_db_fields(obj))
            get_object_mock.assert_called_once_with(
                self.context, self._test_class.db_model, **obj_keys)

    def test_get_object_missing_object(self):
        with mock.patch.object(obj_db_api, 'get_object', return_value=None):
            obj_keys = self.generate_object_keys(self._test_class)
            obj = self._test_class.get_object(self.context, **obj_keys)
            self.assertIsNone(obj)

    def test_get_object_missing_primary_key(self):
        obj_keys = self.generate_object_keys(self._test_class)
        obj_keys.popitem()
        self.assertRaises(base.NeutronPrimaryKeyMissing,
                          self._test_class.get_object,
                          self.context, **obj_keys)

    def test_get_objects(self):
        with mock.patch.object(obj_db_api, 'get_objects',
                               return_value=self.db_objs) as get_objects_mock:
            objs = self._test_class.get_objects(self.context)
            self._validate_objects(self.db_objs, objs)
        get_objects_mock.assert_called_once_with(
            self.context, self._test_class.db_model)

    def test_get_objects_valid_fields(self):
        with mock.patch.object(
            obj_db_api, 'get_objects',
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

        with mock.patch.object(obj_db_api, 'get_objects',
                               return_value=self.db_objs):
            self.assertRaises(base.exceptions.InvalidInput,
                              self._test_class.get_objects, self.context,
                              **filters)

    def test_get_objects_synthetic_fields(self):
        synthetic_fields = self._test_class.synthetic_fields
        if not synthetic_fields:
            self.skipTest('No synthetic fields found in test class %r' %
                          self._test_class)

        with mock.patch.object(obj_db_api, 'get_objects',
                               return_value=self.db_objs):
            self.assertRaises(base.exceptions.InvalidInput,
                              self._test_class.get_objects, self.context,
                              **{synthetic_fields[0]: 'xxx'})

    def test_get_objects_invalid_fields(self):
        with mock.patch.object(obj_db_api, 'get_objects',
                               return_value=self.db_objs):
            self.assertRaises(base.exceptions.InvalidInput,
                              self._test_class.get_objects, self.context,
                              fake_field='xxx')

    def _validate_objects(self, expected, observed):
        self.assertTrue(all(self._is_test_class(obj) for obj in observed))
        self.assertEqual(
            sorted([self._test_class.modify_fields_from_db(db_obj)
                    for db_obj in expected],
                   key=common_utils.safe_sort_key),
            sorted([get_obj_db_fields(obj) for obj in observed],
                   key=common_utils.safe_sort_key))

    def _check_equal(self, obj, db_obj):
        self.assertEqual(
            sorted(db_obj),
            sorted(get_obj_db_fields(obj)))

    def test_create(self):
        with mock.patch.object(obj_db_api, 'create_object',
                               return_value=self.db_obj) as create_mock:
            obj = self._test_class(self.context, **self.obj_fields[0])
            self._check_equal(obj, self.obj_fields[0])
            obj.create()
            self._check_equal(obj, self.obj_fields[0])
            create_mock.assert_called_once_with(
                self.context, self._test_class.db_model, self.db_obj)

    def test_create_updates_from_db_object(self):
        with mock.patch.object(obj_db_api, 'create_object',
                               return_value=self.db_obj):
            obj = self._test_class(self.context, **self.obj_fields[1])
            self._check_equal(obj, self.obj_fields[1])
            obj.create()
            self._check_equal(obj, self.obj_fields[0])

    def test_create_duplicates(self):
        with mock.patch.object(obj_db_api, 'create_object',
                               side_effect=obj_exc.DBDuplicateEntry):
            obj = self._test_class(self.context, **self.obj_fields[0])
            self.assertRaises(base.NeutronDbObjectDuplicateEntry, obj.create)

    @mock.patch.object(obj_db_api, 'update_object')
    def test_update_no_changes(self, update_mock):
        with mock.patch.object(base.NeutronDbObject,
                               '_get_changed_persistent_fields',
                               return_value={}):
            obj_keys = self.generate_object_keys(self._test_class)
            obj = self._test_class(self.context, **obj_keys)
            obj.update()
            self.assertFalse(update_mock.called)

    @mock.patch.object(obj_db_api, 'update_object')
    def test_update_changes(self, update_mock):
        fields_to_update = self.get_updatable_fields(self.db_obj)
        if not fields_to_update:
            self.skipTest('No updatable fields found in test class %r' %
                          self._test_class)

        with mock.patch.object(base.NeutronDbObject,
                               '_get_changed_persistent_fields',
                               return_value=fields_to_update):
            obj = self._test_class(self.context, **self.obj_fields[0])
            obj.update()
            update_mock.assert_called_once_with(
                self.context, self._test_class.db_model,
                fields_to_update,
                **obj._get_composite_keys())

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
        with mock.patch.object(obj_db_api, 'update_object',
                               return_value=self.db_obj):
            obj = self._test_class(self.context, **self.obj_fields[1])
            fields_to_update = self.get_updatable_fields(self.obj_fields[1])
            if not fields_to_update:
                self.skipTest('No updatable fields found in test class %r' %
                              self._test_class)
            with mock.patch.object(base.NeutronDbObject,
                                   '_get_changed_persistent_fields',
                                   return_value=fields_to_update):
                obj.update()
            self._check_equal(obj, self.obj_fields[0])

    @mock.patch.object(obj_db_api, 'delete_object')
    def test_delete(self, delete_mock):
        obj = self._test_class(self.context, **self.obj_fields[0])
        self._check_equal(obj, self.obj_fields[0])
        obj.delete()
        self._check_equal(obj, self.obj_fields[0])
        delete_mock.assert_called_once_with(
            self.context, self._test_class.db_model,
            **obj._get_composite_keys())

    @mock.patch(OBJECTS_BASE_OBJ_FROM_PRIMITIVE)
    def test_clean_obj_from_primitive(self, get_prim_m):
        expected_obj = get_prim_m.return_value
        observed_obj = self._test_class.clean_obj_from_primitive('foo', 'bar')
        self.assertIs(expected_obj, observed_obj)
        self.assertTrue(observed_obj.obj_reset_changes.called)

    def test_update_primary_key_forbidden_fail(self):
        obj = self._test_class(self.context, **self.db_obj)
        obj.obj_reset_changes()

        if not self._test_class.primary_keys:
            self.skipTest(
                'All non-updatable fields found in test class %r '
                'are primary keys' % self._test_class)

        for key, val in self.db_obj.items():
            if key in self._test_class.primary_keys:
                setattr(obj, key, val)

        self.assertRaises(base.NeutronObjectUpdateForbidden, obj.update)


class BaseDbObjectNonStandardPrimaryKeyTestCase(BaseObjectIfaceTestCase):

    _test_class = FakeNeutronObjectNonStandardPrimaryKey


class BaseDbObjectCompositePrimaryKeyTestCase(BaseObjectIfaceTestCase):

    _test_class = FakeNeutronObjectCompositePrimaryKey


class BaseDbObjectCompositePrimaryKeyWithIdTestCase(BaseObjectIfaceTestCase):

    _test_class = FakeNeutronObjectCompositePrimaryKeyWithId


class BaseDbObjectRenamedFieldTestCase(BaseObjectIfaceTestCase):

    _test_class = FakeNeutronObjectRenamedField


class BaseDbObjectTestCase(_BaseObjectTestCase):

    def _create_test_network(self):
        # TODO(ihrachys): replace with network.create() once we get an object
        # implementation for networks
        self._network = obj_db_api.create_object(self.context,
                                                 models_v2.Network,
                                                 {'name': 'test-network1'})

    def _create_test_port(self, network):
        # TODO(ihrachys): replace with port.create() once we get an object
        # implementation for ports
        self._port = obj_db_api.create_object(self.context, models_v2.Port,
                                              {'tenant_id': 'fake_tenant_id',
                                               'name': 'test-port1',
                                               'network_id': network['id'],
                                               'mac_address': 'fake_mac',
                                               'admin_state_up': True,
                                               'status': 'ACTIVE',
                                               'device_id': 'fake_device',
                                               'device_owner': 'fake_owner'})

    def test_get_object_create_update_delete(self):
        obj = self._test_class(self.context, **self.obj_fields[0])
        obj.create()

        new = self._test_class.get_object(self.context,
            **obj._get_composite_keys())
        self.assertEqual(obj, new)

        obj = new

        for key, val in self.get_updatable_fields(self.obj_fields[1]).items():
            setattr(obj, key, val)
        obj.update()

        new = self._test_class.get_object(self.context,
            **obj._get_composite_keys())
        self.assertEqual(obj, new)

        obj = new
        new.delete()

        new = self._test_class.get_object(self.context,
                                          **obj._get_composite_keys())
        self.assertIsNone(new)

    def test_update_non_existent_object_raises_not_found(self):
        obj = self._test_class(self.context, **self.obj_fields[0])
        obj.obj_reset_changes()

        fields_to_update = self.get_updatable_fields(self.obj_fields[0])
        if not fields_to_update:
            self.skipTest('No updatable fields found in test class %r' %
                          self._test_class)
        for key, val in fields_to_update.items():
            setattr(obj, key, val)

        self.assertRaises(n_exc.ObjectNotFound, obj.update)

    def test_delete_non_existent_object_raises_not_found(self):
        obj = self._test_class(self.context, **self.obj_fields[0])
        self.assertRaises(n_exc.ObjectNotFound, obj.delete)

    @mock.patch(SQLALCHEMY_COMMIT)
    def test_create_single_transaction(self, mock_commit):
        obj = self._test_class(self.context, **self.obj_fields[0])
        obj.create()
        self.assertEqual(1, mock_commit.call_count)

    def test_update_single_transaction(self):
        obj = self._test_class(self.context, **self.obj_fields[0])
        obj.create()

        fields_to_update = self.get_updatable_fields(self.obj_fields[1])
        if not fields_to_update:
            self.skipTest('No updatable fields found in test class %r' %
                          self._test_class)
        for key, val in fields_to_update.items():
            setattr(obj, key, val)

        with mock.patch(SQLALCHEMY_COMMIT) as mock_commit:
            obj.update()
        self.assertEqual(1, mock_commit.call_count)

    def test_delete_single_transaction(self):
        obj = self._test_class(self.context, **self.obj_fields[0])
        obj.create()

        with mock.patch(SQLALCHEMY_COMMIT) as mock_commit:
            obj.delete()
        self.assertEqual(1, mock_commit.call_count)

    @mock.patch(SQLALCHEMY_COMMIT)
    def test_get_objects_single_transaction(self, mock_commit):
        self._test_class.get_objects(self.context)
        self.assertEqual(1, mock_commit.call_count)

    @mock.patch(SQLALCHEMY_COMMIT)
    def test_get_object_single_transaction(self, mock_commit):
        obj = self._test_class(self.context, **self.obj_fields[0])
        obj.create()

        obj = self._test_class.get_object(self.context,
                                          **obj._get_composite_keys())
        self.assertEqual(2, mock_commit.call_count)
