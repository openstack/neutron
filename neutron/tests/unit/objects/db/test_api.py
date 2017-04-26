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
from neutron_lib import context
from neutron_lib import exceptions as n_exc

from neutron.db import _model_query as model_query
from neutron.db import models_v2
from neutron.objects import base
from neutron.objects.db import api
from neutron.tests import base as test_base
from neutron.tests.unit import testlib_api


PLUGIN_NAME = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class GetObjectsTestCase(test_base.BaseTestCase):

    def setUp(self):
        super(GetObjectsTestCase, self).setUp()
        # TODO(ihrachys): revisit plugin setup once we decouple
        # objects.db.objects.api from core plugin instance
        self.setup_coreplugin(PLUGIN_NAME)

    def test_get_objects_pass_marker_obj_when_limit_and_marker_passed(self):
        ctxt = context.get_admin_context()
        model = mock.sentinel.model
        marker = mock.sentinel.marker
        limit = mock.sentinel.limit
        pager = base.Pager(marker=marker, limit=limit)

        with mock.patch.object(
                model_query, 'get_collection') as get_collection:
            with mock.patch.object(api, 'get_object') as get_object:
                api.get_objects(ctxt, model, _pager=pager)
        get_object.assert_called_with(ctxt, model, id=marker)
        get_collection.assert_called_with(
            ctxt, model, dict_func=None,
            filters={},
            limit=limit,
            marker_obj=get_object.return_value)


class CreateObjectTestCase(test_base.BaseTestCase):
    def test_populate_id(self, populate_id=True):
        ctxt = context.get_admin_context()
        model_cls = mock.Mock()
        values = {'x': 1, 'y': 2, 'z': 3}
        with mock.patch.object(ctxt.__class__, 'session'):
            api.create_object(ctxt, model_cls, values,
                              populate_id=populate_id)
        expected = copy.copy(values)
        if populate_id:
            expected['id'] = mock.ANY
        model_cls.assert_called_with(**expected)

    def test_populate_id_False(self):
        self.test_populate_id(populate_id=False)


class CRUDScenarioTestCase(testlib_api.SqlTestCase):

    CORE_PLUGIN = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'

    def setUp(self):
        super(CRUDScenarioTestCase, self).setUp()
        # TODO(ihrachys): revisit plugin setup once we decouple
        # neutron.objects.db.api from core plugin instance
        self.setup_coreplugin(self.CORE_PLUGIN)
        # NOTE(ihrachys): nothing specific to networks in this test case, but
        # we needed to pick some real model, so we picked the network. Any
        # other model would work as well for our needs here.
        self.model = models_v2.Network
        self.ctxt = context.get_admin_context()

    def test_get_object_create_update_delete(self):
        obj = api.create_object(self.ctxt, self.model, {'name': 'foo'})

        new_obj = api.get_object(self.ctxt, self.model, id=obj.id)
        self.assertEqual(obj, new_obj)

        obj = new_obj
        api.update_object(self.ctxt, self.model, {'name': 'bar'}, id=obj.id)

        new_obj = api.get_object(self.ctxt, self.model, id=obj.id)
        self.assertEqual(obj, new_obj)

        obj = new_obj
        api.delete_object(self.ctxt, self.model, id=obj.id)

        new_obj = api.get_object(self.ctxt, self.model, id=obj.id)
        self.assertIsNone(new_obj)

        # delete_object raises an exception on missing object
        self.assertRaises(
            n_exc.ObjectNotFound,
            api.delete_object, self.ctxt, self.model, id=obj.id)

        # but delete_objects does not not
        api.delete_objects(self.ctxt, self.model, id=obj.id)

    def test_delete_objects_removes_all_matching_objects(self):
        # create some objects with identical description
        for i in range(10):
            api.create_object(
                self.ctxt, self.model,
                {'name': 'foo%d' % i, 'description': 'bar'})
        # create some more objects with a different description
        descriptions = set()
        for i in range(10, 20):
            desc = 'bar%d' % i
            descriptions.add(desc)
            api.create_object(
                self.ctxt, self.model,
                {'name': 'foo%d' % i, 'description': desc})
        # make sure that all objects are in the database
        self.assertEqual(20, api.count(self.ctxt, self.model))
        # now delete just those with the 'bar' description
        api.delete_objects(self.ctxt, self.model, description='bar')

        # check that half of objects are gone, and remaining have expected
        # descriptions
        objs = api.get_objects(self.ctxt, self.model)
        self.assertEqual(10, len(objs))
        self.assertEqual(
            descriptions,
            {obj.description for obj in objs})
