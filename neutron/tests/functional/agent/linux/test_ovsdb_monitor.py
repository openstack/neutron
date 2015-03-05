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

"""
Tests in this module will be skipped unless:

 - ovsdb-client is installed

 - ovsdb-client can be invoked password-less via the configured root helper

 - sudo testing is enabled (see neutron.tests.functional.base for details)
"""

import eventlet
from oslo_config import cfg

from neutron.agent.linux import ovsdb_monitor
from neutron.agent.linux import utils
from neutron.tests import base as tests_base
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.linux import base as linux_base
from neutron.tests.functional import base as functional_base


class BaseMonitorTest(linux_base.BaseOVSLinuxTestCase):

    def setUp(self):
        super(BaseMonitorTest, self).setUp()

        rootwrap_not_configured = (cfg.CONF.AGENT.root_helper ==
                                   functional_base.SUDO_CMD)
        if rootwrap_not_configured:
            # The monitor tests require a nested invocation that has
            # to be emulated by double sudo if rootwrap is not
            # configured.
            self.config(group='AGENT',
                        root_helper=" ".join([functional_base.SUDO_CMD] * 2))

        self._check_test_requirements()
        # ovsdb-client monitor needs to have a bridge to make any output
        self.useFixture(net_helpers.OVSBridgeFixture())

    def _check_test_requirements(self):
        self.check_command(['ovsdb-client', 'list-dbs'],
                           'Exit code: 1',
                           'password-less sudo not granted for ovsdb-client',
                           run_as_root=True)


class TestOvsdbMonitor(BaseMonitorTest):

    def setUp(self):
        super(TestOvsdbMonitor, self).setUp()

        self.monitor = ovsdb_monitor.OvsdbMonitor('Bridge')
        self.addCleanup(self.monitor.stop)
        self.monitor.start()

    def collect_initial_output(self):
        while True:
            output = list(self.monitor.iter_stdout())
            if output:
                # Output[0] is header row with spaces for column separation.
                # The column widths can vary depending on the data in the
                # columns, so compress multiple spaces to one for testing.
                return ' '.join(output[0].split())
            eventlet.sleep(0.01)

    def test_killed_monitor_respawns(self):
        self.monitor.respawn_interval = 0
        old_pid = self.monitor._process.pid
        output1 = self.collect_initial_output()
        pid = utils.get_root_helper_child_pid(old_pid, run_as_root=True)
        self.monitor._kill_process(pid)
        self.monitor._reset_queues()
        while (self.monitor._process.pid == old_pid):
            eventlet.sleep(0.01)
        output2 = self.collect_initial_output()
        # Initial output should appear twice
        self.assertEqual(output1, output2)


class TestSimpleInterfaceMonitor(BaseMonitorTest):

    def setUp(self):
        super(TestSimpleInterfaceMonitor, self).setUp()

        self.monitor = ovsdb_monitor.SimpleInterfaceMonitor()
        self.addCleanup(self.monitor.stop)
        # In case a global test timeout isn't set or disabled, use a
        # value that will ensure the monitor has time to start.
        timeout = max(tests_base.get_test_timeout(), 60)
        self.monitor.start(block=True, timeout=timeout)

    def test_has_updates(self):
        utils.wait_until_true(lambda: self.monitor.data_received is True)
        self.assertTrue(self.monitor.has_updates,
                        'Initial call should always be true')
        # clear the event list
        self.monitor.get_events()
        self.useFixture(net_helpers.OVSPortFixture())
        # has_updates after port addition should become True
        utils.wait_until_true(lambda: self.monitor.has_updates is True)

    def _expected_devices_events(self, devices, state):
        """Helper to check that events are received for expected devices.

        :param devices: The list of expected devices. WARNING: This list
          is modified by this method
        :param state: The state of the devices (added or removed)
        """
        events = self.monitor.get_events()
        event_devices = [
            (dev['name'], dev['external_ids']) for dev in events.get(state)]
        for dev in event_devices:
            if dev[0] in devices:
                devices.remove(dev[0])
                self.assertEqual(dev[1].get('iface-status'), 'active')
            if not devices:
                return True

    def test_get_events(self):
        utils.wait_until_true(lambda: self.monitor.data_received is True)
        devices = self.monitor.get_events()
        self.assertTrue(devices.get('added'),
                        'Initial call should always be true')
        p_attrs = [('external_ids', {'iface-status': 'active'})]
        br = self.useFixture(net_helpers.OVSBridgeFixture())
        p1 = self.useFixture(net_helpers.OVSPortFixture(
            br.bridge, None, p_attrs))
        p2 = self.useFixture(net_helpers.OVSPortFixture(
            br.bridge, None, p_attrs))
        added_devices = [p1.port.name, p2.port.name]
        utils.wait_until_true(
            lambda: self._expected_devices_events(added_devices, 'added'))
        br.bridge.delete_port(p1.port.name)
        br.bridge.delete_port(p2.port.name)
        removed_devices = [p1.port.name, p2.port.name]
        utils.wait_until_true(
            lambda: self._expected_devices_events(removed_devices, 'removed'))
        # restart
        self.monitor.stop(block=True)
        self.monitor.start(block=True, timeout=60)
        devices = self.monitor.get_events()
        self.assertTrue(devices.get('added'),
                        'Initial call should always be true')
