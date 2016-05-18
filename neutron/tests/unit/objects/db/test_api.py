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

from neutron import context
from neutron import manager
from neutron.objects import base
from neutron.objects.db import api
from neutron.tests import base as test_base


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

        plugin = manager.NeutronManager.get_plugin()
        with mock.patch.object(plugin, '_get_collection') as get_collection:
            with mock.patch.object(api, 'get_object') as get_object:
                api.get_objects(ctxt, model, _pager=pager)
        get_object.assert_called_with(ctxt, model, id=marker)
        get_collection.assert_called_with(
            ctxt, model, mock.ANY,
            filters={},
            limit=limit,
            marker_obj=get_object.return_value)
