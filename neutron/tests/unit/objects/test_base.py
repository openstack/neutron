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

import random
import string

import mock
from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields

from neutron import context
from neutron.db import api as db_api
from neutron.objects import base
from neutron.tests import base as test_base


@obj_base.VersionedObjectRegistry.register
class FakeNeutronObject(base.NeutronObject):

    db_model = 'fake_model'

    fields = {
        'id': obj_fields.UUIDField(),
        'field1': obj_fields.StringField(),
        'field2': obj_fields.StringField()
    }


def _random_string(n=10):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))


def _random_boolean():
    return bool(random.getrandbits(1))


def _random_integer():
    return random.randint(0, 1000)


FIELD_TYPE_VALUE_GENERATOR_MAP = {
    obj_fields.BooleanField: _random_boolean,
    obj_fields.IntegerField: _random_integer,
    obj_fields.StringField: _random_string,
    obj_fields.UUIDField: _random_string,
}


def get_obj_fields(obj):
    return {field: getattr(obj, field) for field in obj.fields}


class BaseObjectTestCase(test_base.BaseTestCase):

    test_class = FakeNeutronObject

    def setUp(self):
        super(BaseObjectTestCase, self).setUp()
        self.context = context.get_admin_context()
        self.db_objs = list(self._get_random_fields() for _ in range(3))
        self.db_obj = self.db_objs[0]

    @classmethod
    def _get_random_fields(cls):
        fields = {}
        for field in cls.test_class.fields:
            field_obj = cls.test_class.fields[field]
            fields[field] = FIELD_TYPE_VALUE_GENERATOR_MAP[type(field_obj)]()
        return fields

    @classmethod
    def _is_test_class(cls, obj):
        return isinstance(obj, cls.test_class)

    def test_get_by_id(self):
        with mock.patch.object(db_api, 'get_object',
                               return_value=self.db_obj) as get_object_mock:
            obj = self.test_class.get_by_id(self.context, id='fake_id')
            self.assertTrue(self._is_test_class(obj))
            self.assertEqual(self.db_obj, get_obj_fields(obj))
            get_object_mock.assert_called_once_with(
                self.context, self.test_class.db_model, 'fake_id')

    def test_get_objects(self):
        with mock.patch.object(db_api, 'get_objects',
                               return_value=self.db_objs) as get_objects_mock:
            objs = self.test_class.get_objects(self.context)
            self.assertFalse(
                filter(lambda obj: not self._is_test_class(obj), objs))
            self.assertEqual(
                sorted(self.db_objs),
                sorted(get_obj_fields(obj) for obj in objs))
            get_objects_mock.assert_called_once_with(
                self.context, self.test_class.db_model)

    def _check_equal(self, obj, db_obj):
        self.assertEqual(
            sorted(db_obj),
            sorted(get_obj_fields(obj)))

    def test_create(self):
        with mock.patch.object(db_api, 'create_object',
                               return_value=self.db_obj) as create_mock:
            obj = self.test_class(self.context, **self.db_obj)
            self._check_equal(obj, self.db_obj)
            obj.create()
            self._check_equal(obj, self.db_obj)
            create_mock.assert_called_once_with(
                self.context, self.test_class.db_model, self.db_obj)

    def test_create_updates_from_db_object(self):
        with mock.patch.object(db_api, 'create_object',
                               return_value=self.db_obj):
            obj = self.test_class(self.context, **self.db_objs[1])
            self._check_equal(obj, self.db_objs[1])
            obj.create()
            self._check_equal(obj, self.db_obj)

    def test_update_no_changes(self):
        with mock.patch.object(db_api, 'update_object',
                               return_value=self.db_obj) as update_mock:
            obj = self.test_class(self.context, **self.db_obj)
            self._check_equal(obj, self.db_obj)
            obj.update()
            self.assertTrue(update_mock.called)

            # consequent call to update does not try to update database
            update_mock.reset_mock()
            obj.update()
            self._check_equal(obj, self.db_obj)
            self.assertFalse(update_mock.called)

    def test_update_changes(self):
        with mock.patch.object(db_api, 'update_object',
                               return_value=self.db_obj) as update_mock:
            obj = self.test_class(self.context, **self.db_obj)
            self._check_equal(obj, self.db_obj)
            obj.update()
            self._check_equal(obj, self.db_obj)
            update_mock.assert_called_once_with(
                self.context, self.test_class.db_model,
                self.db_obj['id'], self.db_obj)

    def test_update_updates_from_db_object(self):
        with mock.patch.object(db_api, 'update_object',
                               return_value=self.db_obj):
            obj = self.test_class(self.context, **self.db_objs[1])
            self._check_equal(obj, self.db_objs[1])
            obj.update()
            self._check_equal(obj, self.db_obj)

    @mock.patch.object(db_api, 'delete_object')
    def test_delete(self, delete_mock):
        obj = self.test_class(self.context, **self.db_obj)
        self._check_equal(obj, self.db_obj)
        obj.delete()
        self._check_equal(obj, self.db_obj)
        delete_mock.assert_called_once_with(
            self.context, self.test_class.db_model, self.db_obj['id'])
