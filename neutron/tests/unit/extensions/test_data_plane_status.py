# Copyright (c) 2017 NEC Corporation.  All rights reserved.
#
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

from webob import exc as web_exc

from neutron_lib.api.definitions import data_plane_status as dps_lib
from neutron_lib.api.definitions import port as port_def
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib.tests.unit import fake_notifier

from neutron.db import data_plane_status_db as dps_db
from neutron.db import db_base_plugin_v2
from neutron.extensions import data_plane_status as dps_ext
from neutron.tests.unit.db import test_db_base_plugin_v2


class DataPlaneStatusTestExtensionManager(object):

    def get_resources(self):
        return []

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []

    def get_extended_resources(self, version):
        return dps_ext.Data_plane_status.get_extended_resources(version)


@resource_extend.has_resource_extenders
class DataPlaneStatusExtensionTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                                         dps_db.DataPlaneStatusMixin):

    supported_extension_aliases = [dps_lib.ALIAS]

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _extend_port_data_plane_status(port_res, port_db):
        return dps_db.DataPlaneStatusMixin._extend_port_data_plane_status(
            port_res, port_db)

    def update_port(self, context, id, port):
        with db_api.CONTEXT_WRITER.using(context):
            ret_port = super(DataPlaneStatusExtensionTestPlugin,
                             self).update_port(context, id, port)
            if dps_lib.DATA_PLANE_STATUS in port['port']:
                self._process_update_port_data_plane_status(context,
                                                            port['port'],
                                                            ret_port)
        return ret_port


class DataPlaneStatusExtensionTestCase(
        test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self):
        plugin = ('neutron.tests.unit.extensions.test_data_plane_status.'
                  'DataPlaneStatusExtensionTestPlugin')
        ext_mgr = DataPlaneStatusTestExtensionManager()
        super(DataPlaneStatusExtensionTestCase, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr)

    def test_update_port_data_plane_status(self):
        with self.port() as port:
            data = {'port': {'data_plane_status': constants.ACTIVE}}
            req = self.new_update_request(port_def.COLLECTION_NAME,
                                          data,
                                          port['port']['id'],
                                          as_admin=True)
            res = req.get_response(self.api)
            p = self.deserialize(self.fmt, res)['port']
            self.assertEqual(200, res.status_code)
            self.assertEqual(p[dps_lib.DATA_PLANE_STATUS], constants.ACTIVE)

    def test_port_create_data_plane_status_default_none(self):
        with self.port(name='port1') as port:
            req = self.new_show_request(
                port_def.COLLECTION_NAME, port['port']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertIsNone(res['port'][dps_lib.DATA_PLANE_STATUS])

    def test_port_create_invalid_attr_data_plane_status(self):
        kwargs = {dps_lib.DATA_PLANE_STATUS: constants.ACTIVE}
        with self.network() as network:
            with self.subnet(network=network):
                res = self._create_port(self.fmt, network['network']['id'],
                                        arg_list=(dps_lib.DATA_PLANE_STATUS,),
                                        **kwargs)
                self.assertEqual(400, res.status_code)

    def test_port_update_preserves_data_plane_status(self):
        with self.port(name='port1') as port:
            res = self._update(port_def.COLLECTION_NAME, port['port']['id'],
                               {'port': {dps_lib.DATA_PLANE_STATUS:
                                         constants.ACTIVE}},
                               as_admin=True)
            res = self._update(port_def.COLLECTION_NAME, port['port']['id'],
                               {'port': {'name': 'port2'}},
                               as_admin=True)
            self.assertEqual(res['port']['name'], 'port2')
            self.assertEqual(res['port'][dps_lib.DATA_PLANE_STATUS],
                             constants.ACTIVE)

    def test_port_update_with_invalid_data_plane_status(self):
        with self.port(name='port1') as port:
            self._update(port_def.COLLECTION_NAME, port['port']['id'],
                         {'port': {dps_lib.DATA_PLANE_STATUS: "abc"}},
                         web_exc.HTTPBadRequest.code)

    def test_port_update_event_on_data_plane_status(self):
        expect_notify = set(['port.update.start',
                             'port.update.end'])
        with self.port(name='port1') as port:
            self._update(port_def.COLLECTION_NAME, port['port']['id'],
                         {'port': {dps_lib.DATA_PLANE_STATUS:
                                   constants.ACTIVE}},
                         as_admin=True)
            notify = set(n['event_type'] for n in fake_notifier.NOTIFICATIONS)
            duplicated_notify = expect_notify & notify
            self.assertEqual(expect_notify, duplicated_notify)
            fake_notifier.reset()
