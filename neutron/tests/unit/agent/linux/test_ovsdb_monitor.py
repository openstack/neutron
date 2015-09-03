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

from neutron.agent.common import ovs_lib
from neutron.agent.linux import ovsdb_monitor
from neutron.tests import base


class TestOvsdbMonitor(base.BaseTestCase):

    def setUp(self):
        super(TestOvsdbMonitor, self).setUp()
        self.monitor = ovsdb_monitor.OvsdbMonitor('Interface')

    def read_output_queues_and_returns_result(self, output_type, output):
        with mock.patch.object(self.monitor, '_process') as mock_process:
            with mock.patch.object(mock_process, output_type) as mock_file:
                with mock.patch.object(mock_file, 'readline') as mock_readline:
                    mock_readline.return_value = output
                    func = getattr(self.monitor,
                                   '_read_%s' % output_type,
                                   None)
                    return func()

    def test__read_stdout_returns_none_for_empty_read(self):
        result = self.read_output_queues_and_returns_result('stdout', '')
        self.assertIsNone(result)

    def test__read_stdout_queues_normal_output_to_stdout_queue(self):
        output = 'foo'
        result = self.read_output_queues_and_returns_result('stdout', output)
        self.assertEqual(result, output)
        self.assertEqual(self.monitor._stdout_lines.get_nowait(), output)

    def test__read_stderr_returns_none(self):
        result = self.read_output_queues_and_returns_result('stderr', '')
        self.assertIsNone(result)


class TestSimpleInterfaceMonitor(base.BaseTestCase):

    def setUp(self):
        super(TestSimpleInterfaceMonitor, self).setUp()
        self.monitor = ovsdb_monitor.SimpleInterfaceMonitor()

    def test_has_updates_is_false_if_active_with_no_output(self):
        target = ('neutron.agent.linux.ovsdb_monitor.SimpleInterfaceMonitor'
                  '.is_active')
        with mock.patch(target, return_value=True):
            self.assertFalse(self.monitor.has_updates)

    def test__kill_sets_data_received_to_false(self):
        self.monitor.data_received = True
        with mock.patch(
                'neutron.agent.linux.ovsdb_monitor.OvsdbMonitor._kill'):
            self.monitor._kill()
        self.assertFalse(self.monitor.data_received)

    def test__read_stdout_sets_data_received_and_returns_output(self):
        output = 'foo'
        with mock.patch(
                'neutron.agent.linux.ovsdb_monitor.OvsdbMonitor._read_stdout',
                return_value=output):
            result = self.monitor._read_stdout()
        self.assertTrue(self.monitor.data_received)
        self.assertEqual(result, output)

    def test__read_stdout_does_not_set_data_received_for_empty_ouput(self):
        output = None
        with mock.patch(
                'neutron.agent.linux.ovsdb_monitor.OvsdbMonitor._read_stdout',
                return_value=output):
            self.monitor._read_stdout()
        self.assertFalse(self.monitor.data_received)

    def test_has_updates_after_calling_get_events_is_false(self):
        with mock.patch.object(
                self.monitor, 'process_events') as process_events:
            self.monitor.new_events = {'added': ['foo'], 'removed': ['foo1']}
            self.assertTrue(self.monitor.has_updates)
            self.monitor.get_events()
            self.assertTrue(process_events.called)
            self.assertFalse(self.monitor.has_updates)

    def process_event_unassigned_of_port(self):
        output = '{"data":[["e040fbec-0579-4990-8324-d338da33ae88","insert",'
        output += '"m50",["set",[]],["map",[]]]],"headings":["row","action",'
        output += '"name","ofport","external_ids"]}'
        with mock.patch.object(
                self.monitor, 'iter_stdout', return_value=[output]):
            self.monitor.process_events()
            self.assertEqual(self.monitor.new_events['added'][0]['ofport'],
                             ovs_lib.UNASSIGNED_OFPORT)
