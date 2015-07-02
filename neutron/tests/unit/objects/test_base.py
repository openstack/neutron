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


db_objs = ({'id': 'id1', 'field1': 'value1', 'field2': 'value2'},
           {'id': 'id2', 'field1': 'value3', 'field2': 'value4'},
           {'id': 'id3', 'field1': 'value5', 'field2': 'value6'})
db_obj = db_objs[0]


def get_obj_fields(obj):
    return {field: getattr(obj, field) for field in obj.fields}


def _is_fake(obj):
    return isinstance(obj, FakeNeutronObject)


class BaseObjectTestCase(test_base.BaseTestCase):

    def setUp(self):
        super(BaseObjectTestCase, self).setUp()
        self.context = context.get_admin_context()

    @mock.patch.object(db_api, 'get_object', return_value=db_obj)
    def test_get_by_id(self, get_object_mock):
        obj = FakeNeutronObject.get_by_id(self.context, id='fake_id')
        self.assertTrue(_is_fake(obj))
        self.assertEqual(db_obj, get_obj_fields(obj))
        get_object_mock.assert_called_once_with(
            self.context, FakeNeutronObject.db_model, 'fake_id')

    @mock.patch.object(db_api, 'get_objects', return_value=db_objs)
    def test_get_objects(self, get_objects_mock):
        objs = FakeNeutronObject.get_objects(self.context)
        self.assertFalse(
            filter(lambda obj: not _is_fake(obj), objs))
        self.assertEqual(
            sorted(db_objs),
            sorted(get_obj_fields(obj) for obj in objs))
        get_objects_mock.assert_called_once_with(
            self.context, FakeNeutronObject.db_model)

    def _check_equal(self, obj, db_obj):
        self.assertEqual(
            sorted(db_obj),
            sorted(get_obj_fields(obj)))

    @mock.patch.object(db_api, 'create_object', return_value=db_obj)
    def test_create(self, create_mock):
        obj = FakeNeutronObject(self.context, **db_obj)
        self._check_equal(obj, db_obj)
        obj.create()
        self._check_equal(obj, db_obj)
        create_mock.assert_called_once_with(
            self.context, FakeNeutronObject.db_model, db_obj)

    @mock.patch.object(db_api, 'create_object', return_value=db_obj)
    def test_create_updates_from_db_object(self, *args):
        obj = FakeNeutronObject(self.context, **db_objs[1])
        self._check_equal(obj, db_objs[1])
        obj.create()
        self._check_equal(obj, db_obj)

    @mock.patch.object(db_api, 'update_object', return_value=db_obj)
    def test_update_no_changes(self, update_mock):
        obj = FakeNeutronObject(self.context, **db_obj)
        self._check_equal(obj, db_obj)
        obj.update()
        self.assertTrue(update_mock.called)

        # consequent call to update does not try to update database
        update_mock.reset_mock()
        obj.update()
        self._check_equal(obj, db_obj)
        self.assertFalse(update_mock.called)

    @mock.patch.object(db_api, 'update_object', return_value=db_obj)
    def test_update_changes(self, update_mock):
        obj = FakeNeutronObject(self.context, **db_obj)
        self._check_equal(obj, db_obj)
        obj.update()
        self._check_equal(obj, db_obj)
        update_mock.assert_called_once_with(
            self.context, FakeNeutronObject.db_model, db_obj['id'], db_obj)

    @mock.patch.object(db_api, 'update_object', return_value=db_obj)
    def test_update_updates_from_db_object(self, *args):
        obj = FakeNeutronObject(self.context, **db_objs[1])
        self._check_equal(obj, db_objs[1])
        obj.update()
        self._check_equal(obj, db_obj)

    @mock.patch.object(db_api, 'delete_object')
    def test_delete(self, delete_mock):
        obj = FakeNeutronObject(self.context, **db_obj)
        self._check_equal(obj, db_obj)
        obj.delete()
        self._check_equal(obj, db_obj)
        delete_mock.assert_called_once_with(
            self.context, FakeNeutronObject.db_model, db_obj['id'])
