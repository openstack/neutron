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
from neutron.common import utils as n_utils
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
                "up": {"type": {"key": "boolean", "min": 0, "max": 1}},
                "enabled": {"type": {"key": "boolean", "min": 0, "max": 1}},
                "external_ids": {
                    "type": {"key": "string", "value": "string",
                             "min": 0, "max": "unlimited"}},
            },
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
        super().setUp()
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
        super().setUp()

    @mock.patch.object(idlutils, 'get_schema_helper')
    @mock.patch.object(idlutils, 'wait_for_change')
    def _test_connection_start(self, mock_wfc, mock_gsh,
                               idl_class, schema):
        mock_gsh.return_value = ovs_idl.SchemaHelper(
            location=schema_files[schema])
        impl_idl_ovn.Backend.schema = schema
        helper = impl_idl_ovn.OvsdbNbOvnIdl.schema_helper
        _idl = idl_class.from_server('punix:/fake', helper, mock.Mock())
        with mock.patch.object(connection, 'TransactionQueue'):
            self.ovn_connection = connection.Connection(_idl, mock.Mock())
        with mock.patch.object(poller, 'Poller'), \
                mock.patch('threading.Thread'):
            self.ovn_connection.start()
            # A second start attempt shouldn't re-register.
            self.ovn_connection.start()

        self.ovn_connection.thread.start.assert_called_once_with()

    def test_connection_nb_start(self):
        ovn_conf.cfg.CONF.set_override('ovn_nb_private_key', 'foo-key', 'ovn')
        mock.patch.object(Stream, 'ssl_set_private_key_file').start()
        mock.patch.object(Stream, 'ssl_set_certificate_file').start()
        mock.patch.object(Stream, 'ssl_set_ca_cert_file').start()

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
        super().setUp()
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
            'get_node',
            return_value=(self.node_uuid, timeutils.utcnow())).start()
        self.mock_update_tables = mock.patch.object(
            self.idl, 'update_tables').start()

    def _assert_has_notify_calls(self):
        self.idl.notify_handler.notify.assert_has_calls([
            mock.call(self.fake_event, self.fake_row, None, global_=True),
            mock.call(self.fake_event, self.fake_row, None)])
        self.assertEqual(2, len(self.idl.notify_handler.mock_calls))

    @mock.patch.object(ovn_hash_ring_db, 'touch_node')
    def test_notify_updated_node(self, mock_touch_node):
        self.idl.notify(self.fake_event, self.fake_row)
        mock_touch_node.assert_not_called()
        self._assert_has_notify_calls()

    @mock.patch.object(ovn_hash_ring_db, 'touch_node')
    def test_notify_not_updated_node(self, mock_touch_node):
        updated_at = timeutils.utcnow() - datetime.timedelta(
            seconds=ovn_const.HASH_RING_CACHE_TIMEOUT + 10)
        self.mock_get_node.return_value = (self.node_uuid, updated_at)
        self.idl.notify(self.fake_event, self.fake_row)
        mock_touch_node.assert_called_once_with(mock.ANY, self.node_uuid)
        self._assert_has_notify_calls()

    @mock.patch.object(ovn_hash_ring_db, 'touch_node')
    def test_notify_skip_touch_node(self, mock_touch_node):
        self.idl.notify(self.fake_event, self.fake_row)

        # Assert that touch_node() wasn't called
        self.assertFalse(mock_touch_node.called)
        self._assert_has_notify_calls()

    @mock.patch.object(ovn_hash_ring_db, 'touch_node')
    def test_notify_last_touch_expired(self, mock_touch_node):
        # make the node old enough to require a touch
        updated_at = timeutils.utcnow() - datetime.timedelta(
            seconds=ovn_const.HASH_RING_TOUCH_INTERVAL + 1)
        self.mock_get_node.return_value = (self.node_uuid, updated_at)

        self.idl.notify(self.fake_event, self.fake_row)

        # Assert that touch_node() was invoked
        mock_touch_node.assert_called_once_with(mock.ANY, self.node_uuid)
        self._assert_has_notify_calls()

    @mock.patch.object(ovsdb_monitor.LOG, 'exception')
    @mock.patch.object(ovn_hash_ring_db, 'touch_node')
    def test_notify_touch_node_exception(self, mock_touch_node, mock_log):
        updated_at = timeutils.utcnow() - datetime.timedelta(
            seconds=ovn_const.HASH_RING_CACHE_TIMEOUT + 10)
        self.mock_get_node.return_value = (self.node_uuid, updated_at)
        mock_touch_node.side_effect = Exception('BoOooOmmMmmMm')
        self.idl.notify(self.fake_event, self.fake_row)

        # Assert that in an eventual failure on touch_node() the event
        # will continue to be processed by notify_handler.notify()
        mock_touch_node.assert_called_once_with(mock.ANY, self.node_uuid)
        # Assert we are logging the exception
        self.assertTrue(mock_log.called)
        self._assert_has_notify_calls()

    def test_notify_different_node(self):
        self.mock_get_node.return_value = ('different-node-uuid',
                                           timeutils.utcnow())
        self.idl.notify('fake-event', self.fake_row)
        # Assert that notify() wasn't called for a different node uuid
        self.idl.notify_handler.notify.assert_called_once_with(
            self.fake_event, self.fake_row, None, global_=True)


class TestPortBindingChassisUpdateEvent(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.driver = mock.Mock()
        self.event = ovsdb_monitor.PortBindingChassisUpdateEvent(self.driver)

    def _test_event(self, event, row, old):
        if self.event.matches(event, row, old):
            self.event.run(event, row, old)
            self.driver.set_port_status_up.assert_called()
        else:
            self.driver.set_port_status_up.assert_not_called()
        self.driver.set_port_status_up.reset_mock()

    def test_event_matches(self):
        # NOTE(twilson) This primarily tests implementation details. If a
        # scenario test is written that handles shutting down a compute
        # node uncleanly and performing a 'host-evacuate', this can be removed
        pbtable = fakes.FakeOvsdbTable.create_one_ovsdb_table(
            attrs={'name': 'Port_Binding'})
        ovsdb_row = fakes.FakeOvsdbRow.create_one_ovsdb_row
        self.driver.nb_ovn.lookup.return_value = ovsdb_row(
            attrs={'up': True, 'enabled': True})

        # Port binding change.
        self._test_event(
            self.event.ROW_UPDATE,
            ovsdb_row(attrs={'_table': pbtable, 'chassis': 'one',
                             'type': '_fake_', 'logical_port': 'foo',
                             'options': {}}),
            ovsdb_row(attrs={'_table': pbtable, 'chassis': 'two',
                             'type': '_fake_'}))

        # Port binding change because of a live migration in progress.
        options = {
            ovn_const.LSP_OPTIONS_REQUESTED_CHASSIS_KEY: 'chassis1,chassis2'}
        self._test_event(
            self.event.ROW_UPDATE,
            ovsdb_row(attrs={'_table': pbtable, 'chassis': 'one',
                             'type': '_fake_', 'logical_port': 'foo',
                             'options': options}),
            ovsdb_row(attrs={'_table': pbtable, 'chassis': 'two',
                             'type': '_fake_'}))


class TestPortBindingUpdateVirtualPortsEvent(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.event = ovsdb_monitor.PortBindingUpdateVirtualPortsEvent(None)

        self.pbtable = fakes.FakeOvsdbTable.create_one_ovsdb_table(
            attrs={'name': 'Port_Binding'})
        self.ovsdb_row = fakes.FakeOvsdbRow.create_one_ovsdb_row

        self.row = self.ovsdb_row(
            attrs={'_table': self.pbtable,
                   'chassis': 'newchassis',
                   'options': {
                       'virtual-parents': 'uuid1,uuid2'}})

    def test_delete_event_matches(self):
        # Delete event (only type virtual).
        self.assertFalse(self.event.match_fn(
            self.event.ROW_DELETE,
            self.ovsdb_row(attrs={'_table': self.pbtable, 'type': '_fake_'}),
            None))
        self.assertTrue(self.event.match_fn(
            self.event.ROW_DELETE,
            self.ovsdb_row(attrs={'_table': self.pbtable, 'type': 'virtual'}),
            None))

    def test_event_no_match_no_options(self):
        # Unrelated portbind change (no options in old, so no virtual parents)
        self.assertFalse(self.event.match_fn(
            self.event.ROW_UPDATE, self.row,
            self.ovsdb_row(attrs={'_table': self.pbtable,
                                  'name': 'somename'})))

    def test_event_no_match_other_options_change(self):
        # Non-virtual parent change, no chassis has changed
        old = self.ovsdb_row(
            attrs={'_table': self.pbtable,
                   'options': {
                       'virtual-parents': 'uuid1,uuid2',
                       'other-opt': '_fake_'}})

        self.assertFalse(self.event.match_fn(self.event.ROW_UPDATE,
                                             self.row, old))

    def test_event_match_chassis_change(self):
        # Port binding change (chassis changed, and marked in old)
        self.assertTrue(self.event.match_fn(
            self.event.ROW_UPDATE, self.row,
            self.ovsdb_row(attrs={'_table': self.pbtable,
                                  'chassis': 'fakechassis'})))

    def test_event_match_virtual_parent_change(self):
        # Virtual parent change
        old = self.ovsdb_row(attrs={'_table': self.pbtable,
                                    'options': {
                                        'virtual-parents': 'uuid1,uuid3'}})
        self.assertTrue(self.event.match_fn(self.event.ROW_UPDATE,
                                            self.row, old))


class TestOvnNbIdlNotifyHandler(test_mech_driver.OVNMechanismDriverTestCase):

    def setUp(self):
        super().setUp()
        helper = ovs_idl.SchemaHelper(schema_json=OVN_NB_SCHEMA)
        helper.register_all()
        self.idl = ovsdb_monitor.OvnNbIdl(self.mech_driver, "remote", helper)
        self.lp_table = self.idl.tables.get('Logical_Switch_Port')
        self.mech_driver.set_port_status_up = mock.Mock()
        self.mech_driver.set_port_status_down = mock.Mock()
        self._mock_hash_ring = mock.patch.object(
            self.idl._hash_ring, 'get_node',
            return_value=(self.idl._node_uuid, timeutils.utcnow()))
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

    def test_lsp_create_event(self):
        row_data = {'name': 'foo'}

        # up and enabled
        row_data.update({'up': True, 'enabled': True})
        self._test_lsp_helper('create', row_data)
        self.mech_driver.set_port_status_up.assert_called_once_with('foo')
        self.assertFalse(self.mech_driver.set_port_status_down.called)
        self.mech_driver.set_port_status_up.reset_mock()

        # up and disabled
        row_data.update({'up': True, 'enabled': False})
        self._test_lsp_helper('create', row_data)
        self.assertFalse(self.mech_driver.set_port_status_up.called)
        self.mech_driver.set_port_status_down.assert_called_once_with('foo')
        self.mech_driver.set_port_status_down.reset_mock()

        # down and enabled
        row_data.update({'up': False, 'enabled': True})
        self._test_lsp_helper('create', row_data)
        self.assertFalse(self.mech_driver.set_port_status_up.called)
        self.mech_driver.set_port_status_down.assert_called_once_with('foo')
        self.mech_driver.set_port_status_down.reset_mock()

        # down and disabled
        row_data.update({'up': False, 'enabled': False})
        self._test_lsp_helper('create', row_data)
        self.assertFalse(self.mech_driver.set_port_status_up.called)
        self.mech_driver.set_port_status_down.assert_called_once_with('foo')
        self.mech_driver.set_port_status_down.reset_mock()

        # Not set to up
        row_data.update({'up': ['set', []], 'enabled': True})
        self._test_lsp_helper('create', row_data)
        self.assertFalse(self.mech_driver.set_port_status_up.called)
        self.mech_driver.set_port_status_down.assert_called_once_with('foo')

    def test_lsp_up_update_event(self):
        new_row_json = {'up': True, 'enabled': True, 'name': 'foo-name'}
        old_row_json = {"up": False}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=old_row_json)
        self.mech_driver.set_port_status_up.assert_called_once_with("foo-name")
        self.assertFalse(self.mech_driver.set_port_status_down.called)

    def test_lsp_down_update_event(self):
        new_row_json = {'up': False, 'enabled': False, 'name': 'foo-name'}
        old_row_json = {"up": True}
        self._test_lsp_helper('update', new_row_json,
                              old_row_json=old_row_json)
        self.mech_driver.set_port_status_down.assert_called_once_with(
            "foo-name")
        self.assertFalse(self.mech_driver.set_port_status_up.called)

    def test_lsp_up_update_event_no_old_data(self):
        new_row_json = {'up': True, 'enabled': True, 'name': 'foo-name'}
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
        super().setUp()
        sb_helper = ovs_idl.SchemaHelper(schema_json=OVN_SB_SCHEMA)
        sb_helper.register_table('Chassis')
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
                                      "fake-phynet1:fake-br1"]]],
            "external_ids": ['map', []],
        }
        self._mock_hash_ring = mock.patch.object(
            self.sb_idl._hash_ring, 'get_node',
            return_value=(self.sb_idl._node_uuid, timeutils.utcnow()))
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
        # The ``notify_handler.notify_loop()`` call is done by the
        # ``notify_handler.start()`` method, that is a ``OvnDbNotifyHandler``
        # instance class, inheriting from ``ovsdbapp.event.RowEventHandler``.

    def _wait_update_segment_host_mapping(self, *args):
        def called():
            try:
                (self.mech_driver.update_segment_host_mapping.
                 assert_called_once_with(*args))
                return True
            except AssertionError:
                return False

        n_utils.wait_until_true(called, timeout=10)

    def _wait_schedule_unhosted_gateways(self, *args, **kwargs):
        def called():
            try:
                (self.l3_plugin.schedule_unhosted_gateways.
                 assert_called_once_with(*args, **kwargs))
                return True
            except AssertionError:
                return False

        n_utils.wait_until_true(called, timeout=10)

    def test_chassis_create_event(self):
        old_row_json = {'other_config': ['map', []]}
        self._test_chassis_helper('create', self.row_json,
                                  old_row_json=old_row_json)
        self._wait_update_segment_host_mapping(
            'fake-hostname', ['fake-phynet1'])
        self._wait_schedule_unhosted_gateways(event_from_chassis=None)

    def test_chassis_delete_event(self):
        old_row_json = {'other_config': ['map', []]}
        self._test_chassis_helper('delete', self.row_json,
                                  old_row_json=old_row_json)
        self._wait_update_segment_host_mapping('fake-hostname', [])
        self._wait_schedule_unhosted_gateways(event_from_chassis='fake-name')

    def test_chassis_update_event(self):
        old_row_json = copy.deepcopy(self.row_json)
        old_row_json['other_config'][1][0][1] = (
            "fake-phynet2:fake-br2")
        self._test_chassis_helper('update', self.row_json, old_row_json)
        self._wait_update_segment_host_mapping(
            'fake-hostname', ['fake-phynet1'])
        self._wait_schedule_unhosted_gateways(event_from_chassis=None)

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
        self._wait_schedule_unhosted_gateways(event_from_chassis='fake-name')

    def test_chassis_update_event_reschedule_add_physnet(self):
        old_row_json = copy.deepcopy(self.row_json)
        self.row_json['other_config'][1][0][1] += ',foo_physnet:foo_br'
        self._test_chassis_helper('update', self.row_json, old_row_json)
        self._wait_update_segment_host_mapping(
            'fake-hostname', ['fake-phynet1', 'foo_physnet'])
        self._wait_schedule_unhosted_gateways(event_from_chassis=None)

    def test_chassis_update_event_reschedule_add_and_remove_physnet(self):
        old_row_json = copy.deepcopy(self.row_json)
        self.row_json['other_config'][1][0][1] = 'foo_physnet:foo_br'
        self._test_chassis_helper('update', self.row_json, old_row_json)
        self._wait_update_segment_host_mapping(
            'fake-hostname', ['foo_physnet'])
        self._wait_schedule_unhosted_gateways(event_from_chassis=None)

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
        super().setUp()
        self.driver = mock.MagicMock()
        self.nb_ovn = self.driver.nb_ovn
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


class TestChassisOVNAgentWriteEvent(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.driver = mock.MagicMock()
        self.event = ovsdb_monitor.ChassisOVNAgentWriteEvent(self.driver)

        self.chassis_private_table = fakes.FakeOvsdbTable.create_one_ovsdb_table(
            attrs={'name': 'Chassis_Private'})
        self.ovsdb_row = fakes.FakeOvsdbRow.create_one_ovsdb_row

    def test_match_fn_no_agent_id(self):
        # Should not match if no agent ID
        row = self.ovsdb_row(attrs={'external_ids': {}})
        self.assertFalse(self.event.match_fn(self.event.ROW_CREATE, row))

    def test_match_fn_create_event(self):
        # Should match CREATE events with valid agent ID
        row = self.ovsdb_row(
            attrs={'external_ids': {
                ovn_const.OVN_AGENT_NEUTRON_ID_KEY: 'neutron-123'}})
        self.assertTrue(self.event.match_fn(self.event.ROW_CREATE, row))

    def test_match_fn_update_no_chassis(self):
        # Should not match UPDATE events if no chassis
        row = self.ovsdb_row(
            attrs={'external_ids': {
                ovn_const.OVN_AGENT_NEUTRON_ID_KEY: 'neutron-123'},
                   'chassis': None})
        old = self.ovsdb_row(attrs={'external_ids': {}})
        self.assertFalse(self.event.match_fn(self.event.ROW_UPDATE, row, old))

    def test_match_fn_update_no_old_external_ids(self):
        # Should not match UPDATE events if old row has no external_ids
        row = self.ovsdb_row(
            attrs={'external_ids': {
                ovn_const.OVN_AGENT_NEUTRON_ID_KEY: 'neutron-123'},
                   'chassis': 'chassis-1'})
        old = self.ovsdb_row(attrs={})
        self.assertFalse(self.event.match_fn(self.event.ROW_UPDATE, row, old))

    def test_match_fn_update_sb_cfg_changed(self):
        # Should match UPDATE events when sb_cfg changes
        row = self.ovsdb_row(
            attrs={'external_ids': {
                ovn_const.OVN_AGENT_NEUTRON_ID_KEY: 'neutron-123',
                ovn_const.OVN_AGENT_NEUTRON_SB_CFG_KEY: '456'},
                   'chassis': 'chassis-1'})
        old = self.ovsdb_row(
            attrs={'external_ids': {
                ovn_const.OVN_AGENT_NEUTRON_ID_KEY: 'neutron-123',
                ovn_const.OVN_AGENT_NEUTRON_SB_CFG_KEY: '123'}})
        self.assertTrue(self.event.match_fn(self.event.ROW_UPDATE, row, old))

    def test_match_fn_update_sb_cfg_unchanged(self):
        # Should not match UPDATE events when sb_cfg is unchanged
        row = self.ovsdb_row(
            attrs={'external_ids': {
                ovn_const.OVN_AGENT_NEUTRON_ID_KEY: 'neutron-123',
                ovn_const.OVN_AGENT_NEUTRON_SB_CFG_KEY: '123'},
                   'chassis': 'chassis-1'})
        old = self.ovsdb_row(
            attrs={'external_ids': {
                ovn_const.OVN_AGENT_NEUTRON_ID_KEY: 'neutron-123',
                ovn_const.OVN_AGENT_NEUTRON_SB_CFG_KEY: '123'}})
        self.assertFalse(self.event.match_fn(self.event.ROW_UPDATE, row, old))

    def test_run_ovn_neutron_agent(self):
        # Test run method with neutron agent
        row = self.ovsdb_row(
            attrs={'external_ids': {
                ovn_const.OVN_AGENT_NEUTRON_ID_KEY: 'neutron-123'}})

        with mock.patch('neutron.plugins.ml2.drivers.ovn.agent.neutron_agent.'
                        'AgentCache') as agent_cache:
            self.event.run(self.event.ROW_CREATE, row, None)
            agent_cache.assert_has_calls([
                mock.call().update(
                    ovn_const.OVN_NEUTRON_AGENT, row, clear_down=True)])

    def test_run_metadata_agent(self):
        # Test run method with metadata agent
        row = self.ovsdb_row(
            attrs={'external_ids': {
                ovn_const.OVN_AGENT_METADATA_ID_KEY: 'metadata-456'}})

        with mock.patch('neutron.plugins.ml2.drivers.ovn.agent.neutron_agent.'
                        'AgentCache') as agent_cache:
            self.event.run(self.event.ROW_CREATE, row, None)
            agent_cache.assert_has_calls([
                mock.call().update(
                    ovn_const.OVN_METADATA_AGENT, row, clear_down=True)])
