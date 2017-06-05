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

from oslo_config import cfg

from neutron.agent.common import ovs_lib
from neutron.agent.linux import ovsdb_monitor
from neutron.common import utils
from neutron.tests import base
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.linux import base as linux_base


class BaseMonitorTest(linux_base.BaseOVSLinuxTestCase):

    def setUp(self):
        super(BaseMonitorTest, self).setUp()

        rootwrap_not_configured = (cfg.CONF.AGENT.root_helper == base.SUDO_CMD)
        if rootwrap_not_configured:
            # The monitor tests require a nested invocation that has
            # to be emulated by double sudo if rootwrap is not
            # configured.
            self.config(group='AGENT',
                        root_helper=" ".join([base.SUDO_CMD] * 2))

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

    def collect_monitor_output(self):
        output = list(self.monitor.iter_stdout())
        if output:
            # Output[0] is header row with spaces for column separation.
            # Use 'other_config' as an indication of the table header.
            self.assertIn('other_config', output[0])
            return True

    def test_monitor_generates_initial_output(self):
        utils.wait_until_true(self.collect_monitor_output, timeout=30)


class TestSimpleInterfaceMonitor(BaseMonitorTest):

    def setUp(self):
        super(TestSimpleInterfaceMonitor, self).setUp()

        self.monitor = ovsdb_monitor.SimpleInterfaceMonitor()
        self.addCleanup(self.monitor.stop)
        self.monitor.start(block=True, timeout=60)

    def test_has_updates(self):
        utils.wait_until_true(lambda: self.monitor.has_updates)
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
        utils.wait_until_true(lambda: self.monitor.has_updates)
        devices = self.monitor.get_events()
        self.assertTrue(devices.get('added'),
                        'Initial call should always be true')
        br = self.useFixture(net_helpers.OVSBridgeFixture())
        p1 = self.useFixture(net_helpers.OVSPortFixture(br.bridge))
        p2 = self.useFixture(net_helpers.OVSPortFixture(br.bridge))
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
        try:
            utils.wait_until_true(
                lambda: self.monitor.get_events().get('added'))
        except utils.WaitTimeout:
            raise AssertionError('Initial call should always be true')

    def test_get_events_includes_ofport(self):
        utils.wait_until_true(lambda: self.monitor.has_updates)
        self.monitor.get_events()  # clear initial events
        br = self.useFixture(net_helpers.OVSBridgeFixture())
        p1 = self.useFixture(net_helpers.OVSPortFixture(br.bridge))

        def p1_event_has_ofport():
            if not self.monitor.has_updates:
                return
            for e in self.monitor.new_events['added']:
                if (e['name'] == p1.port.name and
                        e['ofport'] != ovs_lib.UNASSIGNED_OFPORT):
                    return True
        utils.wait_until_true(p1_event_has_ofport)
