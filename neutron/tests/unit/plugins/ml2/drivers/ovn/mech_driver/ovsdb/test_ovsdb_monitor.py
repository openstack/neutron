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

import mock
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
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.db import ovn_hash_ring_db
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
        self.watched_events = self.handler._RowEventHandler__watched_events

    def test_watch_and_unwatch_events(self):
        expected_events = set()
        networking_event = mock.Mock()
        ovn_event = mock.Mock()
        unknown_event = mock.Mock()

        self.assertItemsEqual(set(), self.watched_events)

        expected_events.add(networking_event)
        self.handler.watch_event(networking_event)
        self.assertItemsEqual(expected_events, self.watched_events)

        expected_events.add(ovn_event)
        self.handler.watch_events([ovn_event])
        self.assertItemsEqual(expected_events, self.watched_events)

        self.handler.unwatch_events([networking_event, ovn_event])
        self.handler.unwatch_event(unknown_event)
        self.handler.unwatch_events([unknown_event])
        self.assertItemsEqual(set(), self.watched_events)

    def test_shutdown(self):
        self.handler.shutdown()


# class TestOvnBaseConnection(base.TestCase):
#
# Each test is being deleted, but for reviewers sake I wanted to exaplain why:
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
        super(TestOvnConnection, self).setUp()

    @mock.patch.object(idlutils, 'get_schema_helper')
    @mock.patch.object(idlutils, 'wait_for_change')
    def _test_connection_start(self, mock_wfc, mock_gsh,
                               idl_class, schema):
        mock_gsh.return_value = ovs_idl.SchemaHelper(
            location=schema_files[schema])
        _idl = idl_class.from_server('punix:/tmp/fake', schema, mock.Mock())
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

    @mock.patch.object(ovn_hash_ring_db, 'touch_node')
    def test_notify(self, mock_touch_node):
        self.idl.notify(self.fake_event, self.fake_row)

        mock_touch_node.assert_called_once_with(mock.ANY, self.node_uuid)
        self.idl.notify_handler.notify.assert_called_once_with(
            self.fake_event, self.fake_row, None)

    @mock.patch.object(ovn_hash_ring_db, 'touch_node')
    def test_notify_skip_touch_node(self, mock_touch_node):
        # Set a time for last touch
        self.idl._last_touch = timeutils.utcnow()
        self.idl.notify(self.fake_event, self.fake_row)

        # Assert that touch_node() wasn't called
        self.assertFalse(mock_touch_node.called)
        self.idl.notify_handler.notify.assert_called_once_with(
            self.fake_event, self.fake_row, None)

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
        self.idl.notify_handler.notify.assert_called_once_with(
            self.fake_event, self.fake_row, None)

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
        self.idl.notify_handler.notify.assert_called_once_with(
            self.fake_event, self.fake_row, None)

    def test_notify_different_node(self):
        self.mock_get_node.return_value = 'different-node-uuid'
        self.idl.notify('fake-event', self.fake_row)
        # Assert that notify() wasn't called for a different node uuid
        self.assertFalse(self.idl.notify_handler.notify.called)


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
        self.driver._nb_ovn.lookup.return_value = ovsdb_row(attrs={'up': True})
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
        self.idl = ovsdb_monitor.OvnNbIdl(self.driver, "remote", helper)
        self.lp_table = self.idl.tables.get('Logical_Switch_Port')
        self.driver.set_port_status_up = mock.Mock()
        self.driver.set_port_status_down = mock.Mock()

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
        self.driver.set_port_status_up.assert_called_once_with("foo-name")
        self.assertFalse(self.driver.set_port_status_down.called)

    def test_lsp_down_create_event(self):
        row_data = {"up": False, "name": "foo-name"}
        self._test_lsp_helper('create', row_data)
        self.driver.set_port_status_down.assert_called_once_with("foo-name")
        self.assertFalse(self.driver.set_port_status_up.called)

    def test_lsp_up_not_set_event(self):
        row_data = {"up": ['set', []], "name": "foo-name"}
        self._test_lsp_helper('create', row_data)
        self.assertFalse(self.driver.set_port_status_up.called)
        self.assertFalse(self.driver.set_port_status_down.called)

    def test_unwatch_logical_switch_port_create_events(self):
        self.idl.unwatch_logical_switch_port_create_events()
        row_data = {"up": True, "name": "foo-name"}
        self._test_lsp_helper('create', row_data)
        self.assertFalse(self.driver.set_port_status_up.called)
        self.assertFalse(self.driver.set_port_status_down.called)

        row_data["up"] = False
        self._test_lsp_helper('create', row_data)
        self.assertFalse(self.driver.set_port_status_up.called)
        self.assertFalse(self.driver.set_port_status_down.called)

    def test_post_connect(self):
        self.idl.post_connect()
        self.assertIsNone(self.idl._lsp_create_up_event)
        self.assertIsNone(self.idl._lsp_create_down_event)

    def test_lsp_up_update_event(self):
        new_row_json = {"up": True, "name": "foo-name"}
        old_row_json = {"up": False}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=old_row_json)
        self.driver.set_port_status_up.assert_called_once_with("foo-name")
        self.assertFalse(self.driver.set_port_status_down.called)

    def test_lsp_down_update_event(self):
        new_row_json = {"up": False, "name": "foo-name"}
        old_row_json = {"up": True}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=old_row_json)
        self.driver.set_port_status_down.assert_called_once_with("foo-name")
        self.assertFalse(self.driver.set_port_status_up.called)

    def test_lsp_up_update_event_no_old_data(self):
        new_row_json = {"up": True, "name": "foo-name"}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=None)
        self.assertFalse(self.driver.set_port_status_up.called)
        self.assertFalse(self.driver.set_port_status_down.called)

    def test_lsp_down_update_event_no_old_data(self):
        new_row_json = {"up": False, "name": "foo-name"}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=None)
        self.assertFalse(self.driver.set_port_status_up.called)
        self.assertFalse(self.driver.set_port_status_down.called)

    def test_lsp_other_column_update_event(self):
        new_row_json = {"up": False, "name": "foo-name",
                        "addresses": ["10.0.0.2"]}
        old_row_json = {"addresses": ["10.0.0.3"]}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=old_row_json)
        self.assertFalse(self.driver.set_port_status_up.called)
        self.assertFalse(self.driver.set_port_status_down.called)

    def test_notify_other_table(self):
        new_row_json = {"name": "foo-name"}
        self._test_lsp_helper('create', new_row_json,
                              table=self.idl.tables.get("Logical_Switch"))
        self.assertFalse(self.driver.set_port_status_up.called)
        self.assertFalse(self.driver.set_port_status_down.called)

    @mock.patch.object(hash_ring_manager.HashRingManager, 'get_node')
    def test_notify_different_target_node(self, mock_get_node):
        mock_get_node.return_value = 'this-is-a-different-node'
        row = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        self.idl.notify_handler.notify = mock.Mock()
        self.idl.notify("create", row)
        # Assert that if the target_node returned by the ring is different
        # than this driver's node_uuid, notify() won't be called
        self.assertFalse(self.idl.notify_handler.notify.called)


class TestOvnSbIdlNotifyHandler(test_mech_driver.OVNMechanismDriverTestCase):

    l3_plugin = 'ovn-router'

    def setUp(self):
        super(TestOvnSbIdlNotifyHandler, self).setUp()
        sb_helper = ovs_idl.SchemaHelper(schema_json=OVN_SB_SCHEMA)
        sb_helper.register_table('Chassis')
        self.sb_idl = ovsdb_monitor.OvnSbIdl(self.driver, "remote", sb_helper)
        self.sb_idl.post_connect()
        self.chassis_table = self.sb_idl.tables.get('Chassis')
        self.driver.update_segment_host_mapping = mock.Mock()
        self.l3_plugin = directory.get_plugin(n_const.L3)
        self.l3_plugin.schedule_unhosted_gateways = mock.Mock()

        self.row_json = {
            "name": "fake-name",
            "hostname": "fake-hostname",
            "external_ids": ['map', [["ovn-bridge-mappings",
                                      "fake-phynet1:fake-br1"]]]
        }

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
        self._test_chassis_helper('create', self.row_json)
        self.driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', ['fake-phynet1'])
        self.assertEqual(
            1,
            self.l3_plugin.schedule_unhosted_gateways.call_count)

    def test_chassis_delete_event(self):
        self._test_chassis_helper('delete', self.row_json)
        self.driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', [])
        self.assertEqual(
            1,
            self.l3_plugin.schedule_unhosted_gateways.call_count)

    def test_chassis_update_event(self):
        old_row_json = copy.deepcopy(self.row_json)
        old_row_json['external_ids'][1][0][1] = (
            "fake-phynet2:fake-br2")
        self._test_chassis_helper('update', self.row_json, old_row_json)
        self.driver.update_segment_host_mapping.assert_called_once_with(
            'fake-hostname', ['fake-phynet1'])
        self.assertEqual(
            1,
            self.l3_plugin.schedule_unhosted_gateways.call_count)
