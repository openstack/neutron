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

import mock

from neutron_lib.api.definitions import data_plane_status as dps_lib
from neutron_lib.api.definitions import port as port_def
from neutron_lib import constants
from neutron_lib import context
from neutron_lib.plugins import directory
from oslo_config import cfg

from neutron.plugins.ml2.extensions import data_plane_status
from neutron.tests.unit.plugins.ml2 import test_plugin


class DataPlaneStatusSML2ExtDriverTestCase(test_plugin.Ml2PluginV2TestCase):

    _extension_drivers = ['data_plane_status']

    def setUp(self):
        cfg.CONF.set_override('extension_drivers',
                              self._extension_drivers,
                              group='ml2')
        super(DataPlaneStatusSML2ExtDriverTestCase, self).setUp()
        self.plugin = directory.get_plugin()

    def test_extend_port_dict_no_data_plane_status(self):
        for db_data in ({'data_plane_status': None}, {}):
            response_data = {}
            session = mock.Mock()

            driver = data_plane_status.DataPlaneStatusExtensionDriver()
            driver.extend_port_dict(session, db_data, response_data)
            self.assertIsNone(response_data['data_plane_status'])

    def test_show_port_has_data_plane_status(self):
        with self.port() as port:
            req = self.new_show_request(port_def.COLLECTION_NAME,
                                        port['port']['id'],
                                        self.fmt)
            p = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertIsNone(p['port'][dps_lib.DATA_PLANE_STATUS])

    def test_port_update_data_plane_status(self):
        with self.port() as port:
            admin_ctx = context.get_admin_context()
            p = {'port': {dps_lib.DATA_PLANE_STATUS: constants.ACTIVE}}
            self.plugin.update_port(admin_ctx, port['port']['id'], p)
            req = self.new_show_request(
                port_def.COLLECTION_NAME, port['port']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(res['port'][dps_lib.DATA_PLANE_STATUS],
                             constants.ACTIVE)
