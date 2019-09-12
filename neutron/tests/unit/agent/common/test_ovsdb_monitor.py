# Copyright 2013 Red Hat, Inc.
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
from oslo_serialization import jsonutils

from neutron.agent.common import async_process
from neutron.agent.common import ovs_lib
from neutron.agent.common import ovsdb_monitor
from neutron.agent.ovsdb.native import helpers
from neutron.tests import base


class TestOvsdbMonitor(base.BaseTestCase):

    def setUp(self):
        super(TestOvsdbMonitor, self).setUp()
        mock.patch.object(helpers, 'enable_connection_uri').start()

    def test___init__(self):
        ovsdb_monitor.OvsdbMonitor('Interface')

    @mock.patch.object(async_process.AsyncProcess, '__init__')
    def test___init___with_columns(self, init):
        columns = ['col1', 'col2']

        ovsdb_monitor.OvsdbMonitor('Interface', columns=columns)
        cmd = init.call_args_list[0][0][0]
        self.assertEqual('col1,col2', cmd[-1])

    @mock.patch.object(async_process.AsyncProcess, '__init__')
    def test___init___with_format(self, init):
        ovsdb_monitor.OvsdbMonitor('Interface', format='blob')
        cmd = init.call_args_list[0][0][0]
        self.assertEqual('--format=blob', cmd[-1])

    @mock.patch.object(async_process.AsyncProcess, '__init__')
    def test__init__with_connection_columns(self, init):
        conn_info = 'tcp:10.10.10.10:6640'
        columns = ['col1', 'col2']

        ovsdb_monitor.OvsdbMonitor('Interface', columns=columns,
                                   ovsdb_connection=conn_info)
        cmd_all = init.call_args_list[0][0][0]
        cmd_expect = ['ovsdb-client', 'monitor', 'tcp:10.10.10.10:6640',
                      'Interface', 'col1,col2']
        self.assertEqual(cmd_expect, cmd_all)


class TestSimpleInterfaceMonitor(base.BaseTestCase):

    def setUp(self):
        super(TestSimpleInterfaceMonitor, self).setUp()
        self.monitor = ovsdb_monitor.SimpleInterfaceMonitor()

    def test_has_updates_is_false_if_active_with_no_output(self):
        with mock.patch.object(self.monitor, 'is_active', return_value=True):
            self.assertFalse(self.monitor.has_updates)

    def test_has_updates_after_calling_get_events_is_false(self):
        with mock.patch.object(
                self.monitor, 'process_events') as process_events:
            self.monitor.new_events = {'added': ['foo'], 'removed': ['foo1'],
                                       'modified': []}
            self.assertTrue(self.monitor.has_updates)
            self.monitor.get_events()
            self.assertTrue(process_events.called)
            self.assertFalse(self.monitor.has_updates)

    def _get_event(self, ovs_id='e040fbec-0579-4990-8324-d338da33ae88',
                   action="insert", name="fake_dev", ofport=10,
                   external_ids=None, as_string=True):
        event = {"data": [[ovs_id, action, name, ["set", [ofport]],
                          ["map", external_ids or []]]]}
        if as_string:
            event = jsonutils.dumps(event)
        return event

    def process_event_unassigned_of_port(self):
        output = self._get_event()
        with mock.patch.object(
                self.monitor, 'iter_stdout', return_value=[output]):
            self.monitor.process_events()
            self.assertEqual(self.monitor.new_events['added'][0]['ofport'],
                             ovs_lib.UNASSIGNED_OFPORT)

    def test_process_changed_of_port(self):
        event0 = self._get_event(action="old", ofport=-1)
        event1 = self._get_event(action="new", ofport=10)

        expected_dev = {
            'name': 'fake_dev',
            'ofport': [10],
            'external_ids': {}
        }

        with mock.patch.object(
                self.monitor, 'iter_stdout', return_value=[event0, event1]):
            self.monitor.process_events()
            self.assertIn(expected_dev,
                          self.monitor.new_events['modified'])
