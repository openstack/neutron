# Copyright 2016 Red Hat, Inc.
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

import copy
import datetime
import os
from unittest import mock

from neutron_lib.plugins import constants as n_const
from neutron_lib.plugins import directory
from oslo_utils import timeutils
from oslo_utils import uuidutils
from ovs.db import idl as ovs_idl
from ovs import poller
from ovs.stream import Stream
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import hash_ring_manager
from neutron.common.ovn import utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.db import ovn_hash_ring_db
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import impl_idl_ovn
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovsdb_monitor
from neutron.services.ovn_l3 import plugin  # noqa
from neutron.tests import base
from neutron.tests.unit import fake_resources as fakes
from neutron.tests.unit.plugins.ml2.drivers.ovn.mech_driver import \
    test_mech_driver


basedir = os.path.dirname(os.path.abspath(__file__))
schema_files = {
    'OVN_Northbound': os.path.join(basedir, 'schemas', 'ovn-nb.ovsschema'),
    'OVN_Southbound': os.path.join(basedir, 'schemas', 'ovn-sb.ovsschema'),
}

OVN_NB_SCHEMA = {
    "name": "OVN_Northbound", "version": "3.0.0",
    "tables": {
        "Logical_Switch_Port": {
            "columns": {
                "name": {"type": "string"},
                "type": {"type": "string"},
                "addresses": {"type": {"key": "string",
                                       "min": 0,
                                       "max": "unlimited"}},
                "port_security": {"type": {"key": "string",
                                           "min": 0,
                                           "max": "unlimited"}},
                "up": {"type": {"key": "boolean", "min": 0, "max": 1}}},
            "indexes": [["name"]],
            "isRoot": False,
        },
        "Logical_Switch": {
            "columns": {"name": {"type": "string"}},
            "indexes": [["name"]],
            "isRoot": True,
        }
    }
}


OVN_SB_SCHEMA = {
    "name": "OVN_Southbound", "version": "1.3.0",
    "tables": {
        "Chassis": {
            "columns": {
                "name": {"type": "string"},
                "hostname": {"type": "string"},
                "external_ids": {
                    "type": {"key": "string", "value": "string",
                             "min": 0, "max": "unlimited"}},
                "other_config": {
                    "type": {"key": "string", "value": "string",
                             "min": 0, "max": "unlimited"}}},
            "isRoot": True,
            "indexes": [["name"]]
        }
    }
}


ROW_CREATE = ovsdb_monitor.BaseEvent.ROW_CREATE
ROW_UPDATE = ovsdb_monitor.BaseEvent.ROW_UPDATE


class TestOvnDbNotifyHandler(base.BaseTestCase):

    def setUp(self):
        super(TestOvnDbNotifyHandler, self).setUp()
        self.handler = ovsdb_monitor.OvnDbNotifyHandler(mock.ANY)

    def test_watch_and_unwatch_events(self):
        expected_events = set()
        networking_event = mock.Mock(priority=1)
        ovn_event = mock.Mock(priority=2)
        unknown_event = mock.Mock(priority=3)

        self.assertCountEqual(set(), set(self.handler._watched_events))

        expected_events.add(networking_event)
        self.handler.watch_event(networking_event)
        self.assertCountEqual(expected_events,
                              set(self.handler._watched_events))

        expected_events.add(ovn_event)
        self.handler.watch_events([ovn_event])
        self.assertCountEqual(expected_events,
                              set(self.handler._watched_events))

        self.handler.unwatch_events([networking_event, ovn_event])
        self.handler.unwatch_event(unknown_event)
        self.handler.unwatch_events([unknown_event])
        self.assertCountEqual(set(), set(self.handler._watched_events))

    def test_shutdown(self):
        self.handler.shutdown()


# class TestOvnBaseConnection(base.TestCase):
#
# Each test is being deleted, but for reviewers sake I wanted to explain why:
#
#     @mock.patch.object(idlutils, 'get_schema_helper')
#     def testget_schema_helper_success(self, mock_gsh):
#
# 1. OvnBaseConnection and OvnConnection no longer exist
# 2. get_schema_helper is no longer a part of the Connection class
#
#     @mock.patch.object(idlutils, 'get_schema_helper')
#     def testget_schema_helper_initial_exception(self, mock_gsh):
#
#     @mock.patch.object(idlutils, 'get_schema_helper')
#     def testget_schema_helper_all_exception(self, mock_gsh):
#
# 3. The only reason get_schema_helper had a retry loop was for Neutron's
#    use case of trying to set the Manager to listen on ptcp:127.0.0.1:6640
#    if it wasn't already set up. Since that code being removed was the whole
#    reason to re-implement get_schema_helper here,the exception retry is not
#    needed and therefor is not a part of ovsdbapp's implementation of
#    idlutils.get_schema_helper which we now use directly in from_server()
# 4. These tests now would be testing the various from_server() calls, but
#    there is almost nothing to test in those except maybe SSL being set up
#    but that was done below.

class TestOvnConnection(base.BaseTestCase):

    def setUp(self):
        ovn_conf.register_opts()
        super(TestOvnConnection, self).setUp()

    @mock.patch.object(idlutils, 'get_schema_helper')
    @mock.patch.object(idlutils, 'wait_for_change')
    def _test_connection_start(self, mock_wfc, mock_gsh,
                               idl_class, schema):
        mock_gsh.return_value = ovs_idl.SchemaHelper(
            location=schema_files[schema])
        impl_idl_ovn.Backend.schema = schema
        helper = impl_idl_ovn.OvsdbNbOvnIdl.schema_helper
        _idl = idl_class.from_server('punix:/fake', helper, mock.Mock())
        self.ovn_connection = connection.Connection(_idl, mock.Mock())
        with mock.patch.object(poller, 'Poller'), \
                mock.patch('threading.Thread'):
            self.ovn_connection.start()
            # A second start attempt shouldn't re-register.
            self.ovn_connection.start()

        self.ovn_connection.thread.start.assert_called_once_with()

    def test_connection_nb_start(self):
        ovn_conf.cfg.CONF.set_override('ovn_nb_private_key', 'foo-key', 'ovn')
        Stream.ssl_set_private_key_file = mock.Mock()
        Stream.ssl_set_certificate_file = mock.Mock()
        Stream.ssl_set_ca_cert_file = mock.Mock()

        self._test_connection_start(idl_class=ovsdb_monitor.OvnNbIdl,
                                    schema='OVN_Northbound')

        Stream.ssl_set_private_key_file.assert_called_once_with('foo-key')
        Stream.ssl_set_certificate_file.assert_not_called()
        Stream.ssl_set_ca_cert_file.assert_not_called()

    def test_connection_sb_start(self):
        self._test_connection_start(idl_class=ovsdb_monitor.OvnSbIdl,
                                    schema='OVN_Southbound')


class TestOvnIdlDistributedLock(base.BaseTestCase):

    def setUp(self):
        ovn_conf.register_opts()
        super(TestOvnIdlDistributedLock, self).setUp()
        self.node_uuid = uuidutils.generate_uuid()
        self.fake_driver = mock.Mock()
        self.fake_driver.node_uuid = self.node_uuid
        self.fake_event = 'fake-event'
        self.fake_row = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'_table': mock.Mock(name='FakeTable')})
        helper = ovs_idl.SchemaHelper(schema_json=OVN_NB_SCHEMA)
        helper.register_all()

        with mock.patch.object(ovsdb_monitor, 'OvnDbNotifyHandler'):
            self.idl = ovsdb_monitor.OvnIdlDistributedLock(
                self.fake_driver, 'punix:/tmp/fake', helper)

        self.mock_get_node = mock.patch.object(
            hash_ring_manager.HashRingManager,
            'get_node', return_value=self.node_uuid).start()
        self.mock_update_tables = mock.patch.object(
            self.idl, 'update_tables').start()

    def _assert_has_notify_calls(self):
        self.idl.notify_handler.notify.assert_has_calls([
            mock.call(self.fake_event, self.fake_row, None, global_=True),
            mock.call(self.fake_event, self.fake_row, None)])
        self.assertEqual(2, len(self.idl.notify_handler.mock_calls))

    @mock.patch.object(ovn_hash_ring_db, 'touch_node')
    def test_notify(self, mock_touch_node):
        self.idl.notify(self.fake_event, self.fake_row)

        mock_touch_node.assert_called_once_with(mock.ANY, self.node_uuid)
        self._assert_has_notify_calls()

    @mock.patch.object(ovn_hash_ring_db, 'touch_node')
    def test_notify_skip_touch_node(self, mock_touch_node):
        # Set a time for last touch
        self.idl._last_touch = timeutils.utcnow()
        self.idl.notify(self.fake_event, self.fake_row)

        # Assert that touch_node() wasn't called
        self.assertFalse(mock_touch_node.called)
        self._assert_has_notify_calls()

    @mock.patch.object(ovn_hash_ring_db, 'touch_node')
    def test_notify_last_touch_expired(self, mock_touch_node):
        # Set a time for last touch
        self.idl._last_touch = timeutils.utcnow()

        # Let's expire the touch node interval for the next utcnow()
        with mock.patch.object(timeutils, 'utcnow') as mock_utcnow:
            mock_utcnow.return_value = (
                self.idl._last_touch + datetime.timedelta(
                    seconds=ovn_const.HASH_RING_TOUCH_INTERVAL + 1))
            self.idl.notify(self.fake_event, self.fake_row)

        # Assert that touch_node() was invoked
        mock_touch_node.assert_called_once_with(mock.ANY, self.node_uuid)
        self._assert_has_notify_calls()

    @mock.patch.object(ovsdb_monitor.LOG, 'exception')
    @mock.patch.object(ovn_hash_ring_db, 'touch_node')
    def test_notify_touch_node_exception(self, mock_touch_node, mock_log):
        mock_touch_node.side_effect = Exception('BoOooOmmMmmMm')
        self.idl.notify(self.fake_event, self.fake_row)

        # Assert that in an eventual failure on touch_node() the event
        # will continue to be processed by notify_handler.notify()
        mock_touch_node.assert_called_once_with(mock.ANY, self.node_uuid)
        # Assert we are logging the exception
        self.assertTrue(mock_log.called)
        self._assert_has_notify_calls()

    def test_notify_different_node(self):
        self.mock_get_node.return_value = 'different-node-uuid'
        self.idl.notify('fake-event', self.fake_row)
        # Assert that notify() wasn't called for a different node uuid
        self.idl.notify_handler.notify.assert_called_once_with(
            self.fake_event, self.fake_row, None, global_=True)

    @staticmethod
    def _create_fake_row(table_name):
        # name is a parameter in Mock() so it can't be passed to constructor
        table = mock.Mock()
        table.name = table_name
        return fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'_table': table, 'schema': ['foo']})

    def test_handle_db_schema_changes_no_match_events(self):
        other_table_row = self._create_fake_row('other')
        database_table_row = self._create_fake_row('Database')

        self.idl.handle_db_schema_changes(
            ovsdb_monitor.BaseEvent.ROW_UPDATE, other_table_row)
        self.idl.handle_db_schema_changes(
            ovsdb_monitor.BaseEvent.ROW_CREATE, other_table_row)
        self.idl.handle_db_schema_changes(
            ovsdb_monitor.BaseEvent.ROW_UPDATE, database_table_row)

        self.assertFalse(self.mock_update_tables.called)

    def _test_handle_db_schema(self, agent_table, chassis_private_present):
        database_table_row = self._create_fake_row('Database')
        self.idl._tables_to_register[database_table_row.name] = 'foo'

        self.fake_driver.agent_chassis_table = agent_table
        if chassis_private_present:
            self.idl.tables['Chassis_Private'] = 'foo'
        else:
            try:
                del self.idl.tables['Chassis_Private']
            except KeyError:
                pass

        self.idl.handle_db_schema_changes(
            ovsdb_monitor.BaseEvent.ROW_CREATE, database_table_row)

    def test_handle_db_schema_changes_old_schema_to_old_schema(self):
        """Agents use Chassis and should keep using Chassis table"""
        self._test_handle_db_schema('Chassis', chassis_private_present=False)
        self.assertEqual('Chassis', self.fake_driver.agent_chassis_table)

    def test_handle_db_schema_changes_old_schema_to_new_schema(self):
        """Agents use Chassis and should start using Chassis_Private table"""
        self._test_handle_db_schema('Chassis', chassis_private_present=True)
        self.assertEqual('Chassis_Private',
                         self.fake_driver.agent_chassis_table)

    def test_handle_db_schema_changes_new_schema_to_old_schema(self):
        """Agents use Chassis_Private and should start using Chassis table"""
        self._test_handle_db_schema('Chassis_Private',
                                    chassis_private_present=False)
        self.assertEqual('Chassis', self.fake_driver.agent_chassis_table)

    def test_handle_db_schema_changes_new_schema_to_new_schema(self):
        """Agents use Chassis_Private and should keep using Chassis_Private
           table.
        """
        self._test_handle_db_schema('Chassis_Private',
                                    chassis_private_present=True)
        self.assertEqual('Chassis_Private',
                         self.fake_driver.agent_chassis_table)


class TestPortBindingChassisUpdateEvent(base.BaseTestCase):
    def setUp(self):
        super(TestPortBindingChassisUpdateEvent, self).setUp()
        self.driver = mock.Mock()
        self.event = ovsdb_monitor.PortBindingChassisUpdateEvent(self.driver)

    def _test_event(self, event, row, old):
        if self.event.matches(event, row, old):
            self.event.run(event, row, old)
            self.driver.set_port_status_up.assert_called()
        else:
            self.driver.set_port_status_up.assert_not_called()

    def test_event_matches(self):
        # NOTE(twilson) This primarily tests implementation details. If a
        # scenario test is written that handles shutting down a compute
        # node uncleanly and performing a 'host-evacuate', this can be removed
        pbtable = fakes.FakeOvsdbTable.create_one_ovsdb_table(
            attrs={'name': 'Port_Binding'})
        ovsdb_row = fakes.FakeOvsdbRow.create_one_ovsdb_row
        self.driver.nb_ovn.lookup.return_value = ovsdb_row(attrs={'up': True})
        self._test_event(
            self.event.ROW_UPDATE,
            ovsdb_row(attrs={'_table': pbtable, 'chassis': 'one',
                             'type': '_fake_', 'logical_port': 'foo'}),
            ovsdb_row(attrs={'_table': pbtable, 'chassis': 'two',
                             'type': '_fake_'}))


class TestOvnNbIdlNotifyHandler(test_mech_driver.OVNMechanismDriverTestCase):

    def setUp(self):
        super(TestOvnNbIdlNotifyHandler, self).setUp()
        helper = ovs_idl.SchemaHelper(schema_json=OVN_NB_SCHEMA)
        helper.register_all()
        self.idl = ovsdb_monitor.OvnNbIdl(self.mech_driver, "remote", helper)
        self.lp_table = self.idl.tables.get('Logical_Switch_Port')
        self.mech_driver.set_port_status_up = mock.Mock()
        self.mech_driver.set_port_status_down = mock.Mock()
        mock.patch.object(self.idl, 'handle_db_schema_changes').start()
        self._mock_hash_ring = mock.patch.object(
            self.idl._hash_ring, 'get_node', return_value=self.idl._node_uuid)
        self._mock_hash_ring.start()

    def _test_lsp_helper(self, event, new_row_json, old_row_json=None,
                         table=None):
        row_uuid = uuidutils.generate_uuid()
        if not table:
            table = self.lp_table
        lp_row = ovs_idl.Row.from_json(self.idl, table,
                                       row_uuid, new_row_json)
        if old_row_json:
            old_row = ovs_idl.Row.from_json(self.idl, table,
                                            row_uuid, old_row_json)
        else:
            old_row = None
        self.idl.notify(event, lp_row, updates=old_row)
        # Add a STOP EVENT to the queue
        self.idl.notify_handler.shutdown()
        # Execute the notifications queued
        self.idl.notify_handler.notify_loop()

    def test_lsp_up_create_event(self):
        row_data = {"up": True, "name": "foo-name"}
        self._test_lsp_helper('create', row_data)
        self.mech_driver.set_port_status_up.assert_called_once_with("foo-name")
        self.assertFalse(self.mech_driver.set_port_status_down.called)

    def test_lsp_down_create_event(self):
        row_data = {"up": False, "name": "foo-name"}
        self._test_lsp_helper('create', row_data)
        self.mech_driver.set_port_status_down.assert_called_once_with(
            "foo-name")
        self.assertFalse(self.mech_driver.set_port_status_up.called)

    def test_lsp_up_not_set_event(self):
        row_data = {"up": ['set', []], "name": "foo-name"}
        self._test_lsp_helper('create', row_data)
        self.assertFalse(self.mech_driver.set_port_status_up.called)
        self.assertFalse(self.mech_driver.set_port_status_down.called)

    def test_unwatch_logical_switch_port_create_events(self):
        self.idl.unwatch_logical_switch_port_create_events()
        row_data = {"up": True, "name": "foo-name"}
        self._test_lsp_helper('create', row_data)
        self.assertFalse(self.mech_driver.set_port_status_up.called)
        self.assertFalse(self.mech_driver.set_port_status_down.called)

        row_data["up"] = False
        self._test_lsp_helper('create', row_data)
        self.assertFalse(self.mech_driver.set_port_status_up.called)
        self.assertFalse(self.mech_driver.set_port_status_down.called)

    def test_post_connect(self):
        self.idl.post_connect()
        self.assertIsNone(self.idl._lsp_create_up_event)
        self.assertIsNone(self.idl._lsp_create_down_event)

    def test_lsp_up_update_event(self):
        new_row_json = {"up": True, "name": "foo-name"}
        old_row_json = {"up": False}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=old_row_json)
        self.mech_driver.set_port_status_up.assert_called_once_with("foo-name")
        self.assertFalse(self.mech_driver.set_port_status_down.called)

    def test_lsp_down_update_event(self):
        new_row_json = {"up": False, "name": "foo-name"}
        old_row_json = {"up": True}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=old_row_json)
        self.mech_driver.set_port_status_down.assert_called_once_with(
            "foo-name")
        self.assertFalse(self.mech_driver.set_port_status_up.called)

    def test_lsp_up_update_event_no_old_data(self):
        new_row_json = {"up": True, "name": "foo-name"}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=None)
        self.assertFalse(self.mech_driver.set_port_status_up.called)
        self.assertFalse(self.mech_driver.set_port_status_down.called)

    def test_lsp_down_update_event_no_old_data(self):
        new_row_json = {"up": False, "name": "foo-name"}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=None)
        self.assertFalse(self.mech_driver.set_port_status_up.called)
        self.assertFalse(self.mech_driver.set_port_status_down.called)

    def test_lsp_other_column_update_event(self):
        new_row_json = {"up": False, "name": "foo-name",
                        "addresses": ["10.0.0.2"]}
        old_row_json = {"addresses": ["10.0.0.3"]}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=old_row_json)
        self.assertFalse(self.mech_driver.set_port_status_up.called)
        self.assertFalse(self.mech_driver.set_port_status_down.called)

    def test_notify_other_table(self):
        new_row_json = {"name": "foo-name"}
        self._test_lsp_helper('create', new_row_json,
                              table=self.idl.tables.get("Logical_Switch"))
        self.assertFalse(self.mech_driver.set_port_status_up.called)
        self.assertFalse(self.mech_driver.set_port_status_down.called)

    @mock.patch.object(hash_ring_manager.HashRingManager, 'get_node')
    def test_notify_different_target_node(self, mock_get_node):
        self._mock_hash_ring.stop()
        mock_get_node.return_value = 'this-is-a-different-node'
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        row._table = mock.Mock(name='table-name')
        self.idl.notify_handler.notify = mock.Mock()
        self.idl.notify("create", row)
        # Assert that if the target_node returned by the ring is different
        # than this driver's node_uuid, only global notify() won't be called
        self.idl.notify_handler.notify.assert_called_once_with(
            "create", row, None, global_=True)


class TestOvnSbIdlNotifyHandler(test_mech_driver.OVNMechanismDriverTestCase):

    l3_plugin = 'ovn-router'

    def setUp(self):
        super(TestOvnSbIdlNotifyHandler, self).setUp()
        sb_helper = ovs_idl.SchemaHelper(schema_json=OVN_SB_SCHEMA)
        sb_helper.register_table('Chassis')
        self.driver.agent_chassis_table = 'Chassis'
        self.sb_idl = ovsdb_monitor.OvnSbIdl(self.mech_driver, "remote",
                                             sb_helper)
        self.sb_idl.post_connect()
        self.chassis_table = self.sb_idl.tables.get('Chassis')
        self.mech_driver.update_segment_host_mapping = mock.Mock()
        self.l3_plugin = directory.get_plugin(n_const.L3)
        self.l3_plugin.schedule_unhosted_gateways = mock.Mock()

        self.row_json = {
            "name": "fake-name",
            "hostname": "fake-hostname",
            "other_config": ['map', [["ovn-bridge-mappings",
                                      "fake-phynet1:fake-br1"]]]
        }
        self._mock_hash_ring = mock.patch.object(
            self.sb_idl._hash_ring, 'get_node',
            return_value=self.sb_idl._node_uuid)
        self._mock_hash_ring.start()

    def _test_chassis_helper(self, event, new_row_json, old_row_json=None):
        row_uuid = uuidutils.generate_uuid()
        table = self.chassis_table
        row = ovs_idl.Row.from_json(self.sb_idl, table, row_uuid, new_row_json)
        if old_row_json:
            old_row = ovs_idl.Row.from_json(self.sb_idl, table,
                                            row_uuid, old_row_json)
        else:
            old_row = None
        self.sb_idl.notify(event, row, updates=old_row)
        # Add a STOP EVENT to the queue
        self.sb_idl.notify_handler.shutdown()
        # Execute the notifications queued
        self.sb_idl.notify_handler.notify_loop()

    def test_chassis_create_event(self):
        old_row_json = {'other_config': ['map', []]}
        self._test_chassis_helper('create', self.row_json,
                                  old_row_json=old_row_json)
        self.mech_driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', ['fake-phynet1'])
        self.l3_plugin.schedule_unhosted_gateways.assert_called_once_with(
            event_from_chassis=None)

    def test_chassis_delete_event(self):
        old_row_json = {'other_config': ['map', []]}
        self._test_chassis_helper('delete', self.row_json,
                                  old_row_json=old_row_json)
        self.mech_driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', [])
        self.l3_plugin.schedule_unhosted_gateways.assert_called_once_with(
            event_from_chassis='fake-name')

    def test_chassis_update_event(self):
        old_row_json = copy.deepcopy(self.row_json)
        old_row_json['other_config'][1][0][1] = (
            "fake-phynet2:fake-br2")
        self._test_chassis_helper('update', self.row_json, old_row_json)
        self.mech_driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', ['fake-phynet1'])
        self.l3_plugin.schedule_unhosted_gateways.assert_called_once_with(
            event_from_chassis=None)

    def test_chassis_update_event_reschedule_not_needed(self):
        self.row_json['other_config'][1].append(['foo_field', 'foo_value_new'])
        old_row_json = copy.deepcopy(self.row_json)
        old_row_json['other_config'][1][1][1] = (
            "foo_value")
        self._test_chassis_helper('update', self.row_json, old_row_json)
        self.mech_driver.update_segment_host_mapping.assert_not_called()
        self.l3_plugin.schedule_unhosted_gateways.assert_not_called()

    def test_chassis_update_event_reschedule_lost_physnet(self):
        old_row_json = copy.deepcopy(self.row_json)
        self.row_json['other_config'][1][0][1] = ''
        self._test_chassis_helper('update', self.row_json, old_row_json)
        self.l3_plugin.schedule_unhosted_gateways.assert_called_once_with(
            event_from_chassis='fake-name')

    def test_chassis_update_event_reschedule_add_physnet(self):
        old_row_json = copy.deepcopy(self.row_json)
        self.row_json['other_config'][1][0][1] += ',foo_physnet:foo_br'
        self._test_chassis_helper('update', self.row_json, old_row_json)
        self.mech_driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', ['fake-phynet1', 'foo_physnet'])
        self.l3_plugin.schedule_unhosted_gateways.assert_called_once_with(
            event_from_chassis=None)

    def test_chassis_update_event_reschedule_add_and_remove_physnet(self):
        old_row_json = copy.deepcopy(self.row_json)
        self.row_json['other_config'][1][0][1] = 'foo_physnet:foo_br'
        self._test_chassis_helper('update', self.row_json, old_row_json)
        self.mech_driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', ['foo_physnet'])
        self.l3_plugin.schedule_unhosted_gateways.assert_called_once_with(
            event_from_chassis=None)

    def test_chassis_update_empty_no_external_ids(self):
        old_row_json = copy.deepcopy(self.row_json)
        old_row_json.pop('other_config')
        with mock.patch(
            'neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.'
            'ovsdb_monitor.ChassisEvent.'
                'handle_ha_chassis_group_changes') as mock_ha:
            self._test_chassis_helper('update', self.row_json, old_row_json)
            self.mech_driver.update_segment_host_mapping.assert_not_called()
            self.l3_plugin.schedule_unhosted_gateways.assert_not_called()
            mock_ha.assert_not_called()


class TestChassisEvent(base.BaseTestCase):

    def setUp(self):
        super(TestChassisEvent, self).setUp()
        self.driver = mock.MagicMock()
        self.nb_ovn = self.driver.nb_ovn
        self.driver._ovn_client.is_external_ports_supported.return_value = True
        self.event = ovsdb_monitor.ChassisEvent(self.driver)
        self.is_gw_ch_mock = mock.patch.object(
            utils, 'is_gateway_chassis').start()
        self.is_gw_ch_mock.return_value = True

    def test_handle_ha_chassis_group_changes_create_not_gw(self):
        self.is_gw_ch_mock.return_value = False
        # Assert chassis is ignored because it's not a gateway chassis
        self.assertIsNone(self.event.handle_ha_chassis_group_changes(
            self.event.ROW_CREATE, mock.Mock(), mock.Mock()))
        self.assertFalse(self.nb_ovn.ha_chassis_group_add_chassis.called)
        self.assertFalse(self.nb_ovn.ha_chassis_group_del_chassis.called)

    def _test_handle_ha_chassis_group_changes_create(self, event):
        # Chassis
        other_config = {
            'ovn-cms-options': 'enable-chassis-as-gw,availability-zones=az-0'}
        row = fakes.FakeOvsdbTable.create_one_ovsdb_table(
            attrs={'name': 'SpongeBob', 'other_config': other_config})
        # HA Chassis
        ch0 = fakes.FakeOvsdbTable.create_one_ovsdb_table(
            attrs={'priority': 10})
        ch1 = fakes.FakeOvsdbTable.create_one_ovsdb_table(
            attrs={'priority': 9})
        ch2 = fakes.FakeOvsdbTable.create_one_ovsdb_table(
            attrs={'priority': 10})
        # HA Chassis Groups
        ha_ch_grp0 = fakes.FakeOvsdbTable.create_one_ovsdb_table(
            attrs={'ha_chassis': [ch0, ch1], 'name': 'neutron-ha-ch-grp0',
                   'external_ids': {
                        ovn_const.OVN_AZ_HINTS_EXT_ID_KEY: 'az-0,az-1'}})
        ha_ch_grp1 = fakes.FakeOvsdbTable.create_one_ovsdb_table(
            attrs={'ha_chassis': [ch2], 'name': 'neutron-ha-ch-grp1',
                   'external_ids': {
                        ovn_const.OVN_AZ_HINTS_EXT_ID_KEY: 'az-2'}})

        self.nb_ovn.db_list_rows.return_value.execute.return_value = [
            ha_ch_grp0, ha_ch_grp1]
        self.event.handle_ha_chassis_group_changes(event, row, mock.Mock())
        # Assert the new chassis has been added to "neutron-ha-ch-grp0"
        # HA Chassis Group with the lowest priority
        self.nb_ovn.ha_chassis_group_add_chassis.assert_called_once_with(
            'neutron-ha-ch-grp0', 'SpongeBob', priority=8)

    def test_handle_ha_chassis_group_changes_create(self):
        self._test_handle_ha_chassis_group_changes_create(
            self.event.ROW_CREATE)

    def _test_handle_ha_chassis_group_changes_delete(self, event):
        # Chassis
        other_config = {
            'ovn-cms-options': 'enable-chassis-as-gw,availability-zones=az-0'}
        row = fakes.FakeOvsdbTable.create_one_ovsdb_table(
            attrs={'name': 'SpongeBob', 'other_config': other_config})
        # HA Chassis
        ha_ch = fakes.FakeOvsdbTable.create_one_ovsdb_table(
            attrs={'priority': 10})
        # HA Chassis Group
        ha_ch_grp = fakes.FakeOvsdbTable.create_one_ovsdb_table(
            attrs={'ha_chassis': [ha_ch], 'name': 'neutron-ha-ch-grp',
                   'external_ids': {
                        ovn_const.OVN_AZ_HINTS_EXT_ID_KEY: 'az-0'}})
        self.nb_ovn.db_list_rows.return_value.execute.return_value = [
            ha_ch_grp]

        self.event.handle_ha_chassis_group_changes(event, row, mock.Mock())
        # Assert chassis was removed from the default group
        self.nb_ovn.ha_chassis_group_del_chassis.assert_called_once_with(
            'neutron-ha-ch-grp', 'SpongeBob', if_exists=True)

    def test_handle_ha_chassis_group_changes_delete(self):
        self._test_handle_ha_chassis_group_changes_delete(
            self.event.ROW_DELETE)

    def test_handle_ha_chassis_group_changes_update_no_changes(self):
        # Assert nothing was done because the update didn't
        # change the gateway chassis status or the availability zones
        other_config = {
            'ovn-cms-options': 'enable-chassis-as-gw,availability-zones=az-0'}
        new = fakes.FakeOvsdbTable.create_one_ovsdb_table(
            attrs={'name': 'SpongeBob', 'other_config': other_config})
        old = new
        self.assertIsNone(self.event.handle_ha_chassis_group_changes(
            self.event.ROW_UPDATE, new, old))
        self.assertFalse(self.nb_ovn.ha_chassis_group_add_chassis.called)
        self.assertFalse(self.nb_ovn.ha_chassis_group_del_chassis.called)

    def test_handle_ha_chassis_group_changes_update_no_longer_gw(self):
        self.is_gw_ch_mock.side_effect = (False, True)
        # Assert that the chassis was removed from the default group
        # after it's no longer being a Gateway chassis
        self._test_handle_ha_chassis_group_changes_delete(
            self.event.ROW_UPDATE)

    def test_handle_ha_chassis_group_changes_update_new_gw(self):
        self.is_gw_ch_mock.side_effect = (True, False)
        # Assert that the chassis was added to the default group
        # after it became a Gateway chassis
        self._test_handle_ha_chassis_group_changes_create(
            self.event.ROW_UPDATE)
