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
from neutron.agent.ovsdb.native import exceptions as ovsdb_exc
from neutron.agent.ovsdb.native import helpers
from neutron.tests import base

SSL_KEY_FILE = '/tmp/dummy.pem'
SSL_CERT_FILE = '/tmp/dummy.crt'
SSL_CA_FILE = '/tmp/ca.crt'


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

    @mock.patch.object(native_conn, 'Stream')
    @mock.patch.object(connection, 'threading')
    @mock.patch.object(native_conn, 'idl')
    @mock.patch.object(idlutils, 'get_schema_helper')
    @mock.patch.object(native_conn, 'os')
    @mock.patch.object(native_conn, 'cfg')
    def test_ssl_connection(self, mock_cfg, mock_os, mock_get_schema_helper,
                            mock_idl, mock_threading, mock_stream):
        mock_os.path.isfile.return_value = True
        mock_cfg.CONF.OVS.ovsdb_connection = 'ssl:127.0.0.1:6640'
        mock_cfg.CONF.OVS.ssl_key_file = SSL_KEY_FILE
        mock_cfg.CONF.OVS.ssl_cert_file = SSL_CERT_FILE
        mock_cfg.CONF.OVS.ssl_ca_cert_file = SSL_CA_FILE

        conn = connection.Connection(idl=native_conn.idl_factory(),
                                     timeout=1)
        conn.start()
        mock_stream.ssl_set_private_key_file.assert_called_once_with(
            SSL_KEY_FILE
        )
        mock_stream.ssl_set_certificate_file.assert_called_once_with(
            SSL_CERT_FILE
        )
        mock_stream.ssl_set_ca_cert_file.assert_called_once_with(
            SSL_CA_FILE
        )

    @mock.patch.object(native_conn, 'Stream')
    @mock.patch.object(connection, 'threading')
    @mock.patch.object(native_conn, 'idl')
    @mock.patch.object(idlutils, 'get_schema_helper')
    @mock.patch.object(native_conn, 'cfg')
    def test_ssl_conn_file_missing(self, mock_cfg, mock_get_schema_helper,
                                   mock_idl, mock_threading, mock_stream):
        mock_cfg.CONF.OVS.ovsdb_connection = 'ssl:127.0.0.1:6640'
        mock_cfg.CONF.OVS.ssl_key_file = SSL_KEY_FILE
        mock_cfg.CONF.OVS.ssl_cert_file = SSL_CERT_FILE
        mock_cfg.CONF.OVS.ssl_ca_cert_file = SSL_CA_FILE

        self.assertRaises(ovsdb_exc.OvsdbSslConfigNotFound,
                          native_conn.idl_factory)

    @mock.patch.object(native_conn, 'Stream')
    @mock.patch.object(connection, 'threading')
    @mock.patch.object(native_conn, 'idl')
    @mock.patch.object(idlutils, 'get_schema_helper')
    @mock.patch.object(native_conn, 'cfg')
    def test_ssl_conn_cfg_missing(self, mock_cfg, mock_get_schema_helper,
                                  mock_idl, mock_threading, mock_stream):
        mock_cfg.CONF.OVS.ovsdb_connection = 'ssl:127.0.0.1:6640'
        mock_cfg.CONF.OVS.ssl_key_file = None
        mock_cfg.CONF.OVS.ssl_cert_file = None
        mock_cfg.CONF.OVS.ssl_ca_cert_file = None
        self.assertRaises(ovsdb_exc.OvsdbSslRequiredOptError,
                          native_conn.idl_factory)
