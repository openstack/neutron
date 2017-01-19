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

import eventlet
import mock
from ovs.db import idl
from ovs import poller

from neutron.agent.ovsdb.native import connection
from neutron.agent.ovsdb.native import idlutils
from neutron.tests import base


class TestOVSNativeConnection(base.BaseTestCase):

    def setUp(self):
        super(TestOVSNativeConnection, self).setUp()

    @mock.patch.object(connection, 'TransactionQueue')
    @mock.patch.object(idlutils, 'get_schema_helper')
    @mock.patch.object(idl, 'Idl')
    @mock.patch.object(idlutils, 'wait_for_change')
    def _test_start(self, wfc, idl, gsh, tq, table_name_list=None):
        gsh.return_value = helper = mock.Mock()
        self.connection = connection.Connection(
            mock.Mock(), mock.Mock(), mock.Mock())
        with mock.patch.object(poller, 'Poller') as poller_mock,\
                mock.patch('threading.Thread'):
            poller_mock.return_value.block.side_effect = eventlet.sleep
            self.connection.start(table_name_list=table_name_list)
        reg_all_called = table_name_list is None
        reg_table_called = table_name_list is not None
        self.assertEqual(reg_all_called, helper.register_all.called)
        self.assertEqual(reg_table_called, helper.register_table.called)

    def test_start_without_table_name_list(self):
        self._test_start()

    def test_start_with_table_name_list(self):
        self._test_start(table_name_list=['fake-table1', 'fake-table2'])

    @mock.patch.object(connection, 'TransactionQueue')
    @mock.patch.object(idl, 'Idl')
    @mock.patch.object(idlutils, 'wait_for_change')
    def test_start_call_graph(self, wait_for_change, idl, transaction_queue):
        self.connection = connection.Connection(
            mock.sentinel, mock.sentinel, mock.sentinel)
        self.connection.get_schema_helper = mock.Mock()
        helper = self.connection.get_schema_helper.return_value
        self.connection.update_schema_helper = mock.Mock()
        with mock.patch.object(poller, 'Poller') as poller_mock,\
                mock.patch('threading.Thread'):
            poller_mock.return_value.block.side_effect = eventlet.sleep
            self.connection.start()
        self.connection.get_schema_helper.assert_called_once_with()
        self.connection.update_schema_helper.assert_called_once_with(helper)

    def test_transaction_queue_init(self):
        # a test to cover py34 failure during initialization (LP Bug #1580270)
        # make sure no ValueError: can't have unbuffered text I/O is raised
        connection.TransactionQueue()

    @mock.patch.object(connection, 'TransactionQueue')
    @mock.patch.object(idlutils, 'get_schema_helper')
    @mock.patch.object(idlutils, 'wait_for_change')
    def test_start_with_idl_class(self, wait_for_change, get_schema_helper,
                                  transaction_queue):
        idl_class = mock.Mock()
        self.connection = connection.Connection(
            mock.sentinel, mock.sentinel, mock.sentinel, idl_class=idl_class)
        idl_instance = idl_class.return_value
        self.connection.start()
        self.assertEqual(idl_instance, self.connection.idl)

    @mock.patch.object(connection, 'threading')
    @mock.patch.object(connection.idlutils, 'wait_for_change')
    @mock.patch.object(connection, 'idl')
    @mock.patch.object(idlutils.helpers, 'enable_connection_uri')
    @mock.patch.object(connection.idlutils, '_get_schema_helper')
    def test_do_get_schema_helper_retry(self, mock_get_schema_helper,
                                        mock_enable_conn,
                                        mock_idl,
                                        mock_wait_for_change,
                                        mock_threading):
        mock_helper = mock.Mock()
        # raise until 3rd retry attempt
        mock_get_schema_helper.side_effect = [Exception(), Exception(),
                                              mock_helper]
        conn = connection.Connection(
            mock.Mock(), mock.Mock(), mock.Mock())
        conn.start()
        self.assertEqual(3, len(mock_get_schema_helper.mock_calls))
        mock_helper.register_all.assert_called_once_with()
