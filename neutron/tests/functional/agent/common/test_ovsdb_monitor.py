# Copyright (c) 2020 Red Hat, Inc.
# All Rights Reserved.
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

from oslo_config import cfg

from neutron.agent.common import ovsdb_monitor
from neutron.common import utils as common_utils
from neutron.tests.common import net_helpers
from neutron.tests.functional import base


class SimpleInterfaceMonitorTestCase(base.BaseSudoTestCase):

    def _stop_monitors(self, monitors):
        for monitor in monitors:
            monitor.stop()

    def _check_port_events(self, monitor, ports_expected=None,
                           ports_not_expected=None):
        ports_expected = ports_expected or set()
        ports_not_expected = ports_not_expected or set()
        added_events = monitor.get_events().get('added', [])
        added_port_names = {port['name'] for port in added_events}
        intersection = ports_not_expected & added_port_names
        if intersection:
            self.fail('Interface monitor filtering events for bridges %s '
                      'received an event for those ports %s' %
                      (monitor._bridge_names, intersection))
        return ports_expected - added_port_names

    def test_interface_monitor_filtering(self):
        br_1 = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        br_2 = self.useFixture(net_helpers.OVSBridgeFixture()).bridge

        mon_no_filter = ovsdb_monitor.SimpleInterfaceMonitor(
            respawn_interval=30,
            ovsdb_connection=cfg.CONF.OVS.ovsdb_connection)
        mon_no_filter.start(block=True)
        mon_br_1 = ovsdb_monitor.SimpleInterfaceMonitor(
            respawn_interval=30,
            ovsdb_connection=cfg.CONF.OVS.ovsdb_connection,
            bridge_names=[br_1.br_name], ovs=br_1)
        mon_br_1.start(block=True)
        mon_br_2 = ovsdb_monitor.SimpleInterfaceMonitor(
            respawn_interval=30,
            ovsdb_connection=cfg.CONF.OVS.ovsdb_connection,
            bridge_names=[br_2.br_name], ovs=br_1)
        mon_br_2.start(block=True)
        self.addCleanup(self._stop_monitors,
                        [mon_no_filter, mon_br_1, mon_br_2])

        p1 = self.useFixture(net_helpers.OVSPortFixture(br_1))
        p2 = self.useFixture(net_helpers.OVSPortFixture(br_2))

        ports_expected = {p1.port.name, p2.port.name}

        def process_new_events(mon, ports_expected):
            remaining = self._check_port_events(
                mon, ports_expected=ports_expected)

            # Next time check only the ports not seen yet
            ports_expected.clear()  # Python doesn't support {:} syntax
            ports_expected.update(remaining)

            return bool(ports_expected)  # True if there are remaining ports

        try:
            common_utils.wait_until_true(
                lambda: not process_new_events(mon_no_filter, ports_expected),
                timeout=5)
        except common_utils.WaitTimeout:
            self.fail('Interface monitor not filtered did not received an '
                      'event for ports %s' % ports_expected)

        self.assertIs(0, len(self._check_port_events(
            mon_br_1, ports_expected={p1.port.name},
            ports_not_expected={p2.port.name})))
        self.assertIs(0, len(self._check_port_events(
            mon_br_2, ports_expected={p2.port.name},
            ports_not_expected={p1.port.name})))
