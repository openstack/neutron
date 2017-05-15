# Copyright 2015, Red Hat, Inc.
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

from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.agent.ovsdb.native import connection as native_conn
from neutron.agent.ovsdb.native import helpers
from neutron.tests import base


class TestOVSNativeConnection(base.BaseTestCase):
    @mock.patch.object(connection, 'threading')
    @mock.patch.object(idlutils, 'wait_for_change')
    @mock.patch.object(native_conn, 'idl')
    @mock.patch.object(helpers, 'enable_connection_uri')
    @mock.patch.object(idlutils, 'get_schema_helper')
    def test_do_get_schema_helper_retry(self, mock_get_schema_helper,
                                        mock_enable_conn,
                                        mock_idl,
                                        mock_wait_for_change,
                                        mock_threading):
        mock_helper = mock.Mock()
        # raise until 3rd retry attempt
        mock_get_schema_helper.side_effect = [Exception(), Exception(),
                                              mock_helper]
        try:
            conn = connection.Connection(idl_factory=native_conn.idl_factory,
                                         timeout=mock.Mock())
        except TypeError:
            conn = connection.Connection(idl=native_conn.idl_factory(),
                                         timeout=mock.Mock())
        conn.start()
        self.assertEqual(3, len(mock_get_schema_helper.mock_calls))
        mock_helper.register_all.assert_called_once_with()
