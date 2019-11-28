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

import datetime
import os

import mock
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
from neutron.tests import base
from neutron.tests.unit import fake_resources as fakes


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


# NOTE(ralonsoh): once the OVN mech driver is implemented, we'll be able to
# test OvnNbIdl and OvnSbIdl properly.
