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

from ovs.db import idl
from ovs import jsonrpc
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp import event as ovsdb_event

from neutron.agent.ovsdb.native import connection as native_conn
from neutron.agent.ovsdb.native import exceptions as ovsdb_exc
from neutron.tests import base


SSL_KEY_FILE = '/tmp/dummy.pem'
SSL_CERT_FILE = '/tmp/dummy.crt'
SSL_CA_FILE = '/tmp/ca.crt'

COLUMN_NAME = {'name': {'mutable': False, 'type': 'string'}}
SCHEMA = {'tables': {'Bridge': {'columns': COLUMN_NAME},
                     'Open_vSwitch': {'columns': COLUMN_NAME},
                     'Port': {'columns': COLUMN_NAME},
                     'Interface': {'columns': COLUMN_NAME}},
          'version': '7.15.1', 'name': 'Open_vSwitch',
          'cksum': '3682332033 23608'}


class ConfigureSslConnTestCase(base.BaseTestCase):

    def setUp(self):
        super(ConfigureSslConnTestCase, self).setUp()
        self._mock_cfg = mock.patch.object(native_conn, 'cfg')
        self.mock_cfg = self._mock_cfg.start()
        self._mock_os = mock.patch.object(native_conn, 'os')
        self.mock_os = self._mock_os.start()
        self._mock_stream = mock.patch.object(native_conn, 'Stream')
        self.mock_stream = self._mock_stream.start()
        self._mock_has_ever_connected = mock.patch.object(
            idl.Idl, 'has_ever_connected')
        self.mock_has_ever_connected = self._mock_has_ever_connected.start()
        self.addCleanup(self._clean_mocks)

    def _get_ovs_idl_monitor(self):
        with mock.patch.object(ovsdb_event, 'RowEventHandler'), \
                mock.patch.object(
                    native_conn.OvsIdl, '_get_ovsdb_helper',
                    return_value=idl.SchemaHelper(None, SCHEMA)), \
                mock.patch.object(jsonrpc.Session, 'open'), \
                mock.patch.object(connection.OvsdbIdl, '__init__'):
            return native_conn.OvsIdlMonitor()

    def _clean_mocks(self):
        self._mock_cfg.stop()
        self._mock_os.stop()
        self._mock_stream.stop()
        self._mock_has_ever_connected.stop()

    def test_ssl_connection(self):
        self.mock_os.path.isfile.return_value = True
        self.mock_cfg.CONF.OVS.ovsdb_connection = 'ssl:127.0.0.1:6640'
        self.mock_cfg.CONF.OVS.ssl_key_file = SSL_KEY_FILE
        self.mock_cfg.CONF.OVS.ssl_cert_file = SSL_CERT_FILE
        self.mock_cfg.CONF.OVS.ssl_ca_cert_file = SSL_CA_FILE
        ovs_idl_monitor = self._get_ovs_idl_monitor()
        conn = connection.Connection(idl=ovs_idl_monitor,
                                 timeout=1)
        conn.start()
        self.mock_stream.ssl_set_private_key_file.assert_called_once_with(
            SSL_KEY_FILE)
        self.mock_stream.ssl_set_certificate_file.assert_called_once_with(
            SSL_CERT_FILE)
        self.mock_stream.ssl_set_ca_cert_file.assert_called_once_with(
            SSL_CA_FILE)

    def test_ssl_conn_file_missing(self):
        self.mock_cfg.CONF.OVS.ovsdb_connection = 'ssl:127.0.0.1:6640'
        self.mock_cfg.CONF.OVS.ssl_key_file = SSL_KEY_FILE
        self.mock_cfg.CONF.OVS.ssl_cert_file = SSL_CERT_FILE
        self.mock_cfg.CONF.OVS.ssl_ca_cert_file = SSL_CA_FILE
        self.mock_os.path.exists.return_value = False
        self.assertRaises(ovsdb_exc.OvsdbSslConfigNotFound,
                          self._get_ovs_idl_monitor)

    def test_ssl_conn_cfg_missing(self):
        self.mock_cfg.CONF.OVS.ovsdb_connection = 'ssl:127.0.0.1:6640'
        self.mock_cfg.CONF.OVS.ssl_key_file = None
        self.mock_cfg.CONF.OVS.ssl_cert_file = None
        self.mock_cfg.CONF.OVS.ssl_ca_cert_file = None
        self.assertRaises(ovsdb_exc.OvsdbSslRequiredOptError,
                          self._get_ovs_idl_monitor)


class BridgeCreateEventTestCase(base.BaseTestCase):

    class MetadataAgent(object):

        bridges = []

        def add_bridge(self, row_name):
            self.bridges.append(row_name)

    def test_run(self):
        agent = self.MetadataAgent()
        mock_row = mock.Mock()
        mock_row.name = 'row_name'
        bridge_create_event = native_conn.BridgeCreateEvent(agent)
        bridge_create_event.run(mock.ANY, mock_row, mock.ANY)
        self.assertEqual([mock_row.name], agent.bridges)


class OvsIdlMonitorTestCase(base.BaseTestCase):

    def setUp(self):
        super(OvsIdlMonitorTestCase, self).setUp()
        self._mock_get_ovsdb_helper = mock.patch.object(
            native_conn.OvsIdl, '_get_ovsdb_helper')
        self._mock_get_ovsdb_helper.start()
        self._mock_row_event_handler = mock.patch.object(ovsdb_event,
                                                         'RowEventHandler')
        self._mock_row_event_handler.start()
        self._mock_idl = mock.patch.object(idl.Idl, '__init__')
        self._mock_idl.start()
        self.addCleanup(self._stop_mocks)
        self.ovs_idl_monitor = native_conn.OvsIdlMonitor()

    def _stop_mocks(self):
        self._mock_get_ovsdb_helper.stop()
        self._mock_row_event_handler.stop()
        self._mock_idl.stop()

    @mock.patch.object(native_conn, 'BridgeCreateEvent')
    def test_start_bridge_monitor(self, mock_bridge_event):
        mock_bridge_event.return_value = 'bridge_event'
        self.ovs_idl_monitor.start_bridge_monitor(['br01', 'br02'])
        self.assertEqual(['br01', 'br02'],
                         self.ovs_idl_monitor._bridges_to_monitor)
        self.ovs_idl_monitor.notify_handler.\
            watch_event.assert_called_once_with('bridge_event')

    def test_add_bridge(self):
        self.ovs_idl_monitor.start_bridge_monitor(['br01', 'br02'])
        self.ovs_idl_monitor.add_bridge('br01')
        self.ovs_idl_monitor.add_bridge('br02')
        self.ovs_idl_monitor.add_bridge('br03')
        self.assertEqual(['br01', 'br02'],
                         self.ovs_idl_monitor._bridges_added_list)

    def test_bridged_added(self):
        self.ovs_idl_monitor.start_bridge_monitor(['br01', 'br02'])
        self.ovs_idl_monitor.add_bridge('br01')
        self.ovs_idl_monitor.add_bridge('br02')
        self.assertEqual(['br01', 'br02'], self.ovs_idl_monitor.bridges_added)
        self.assertEqual([], self.ovs_idl_monitor.bridges_added)
