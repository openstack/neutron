# Copyright (c) 2015 Red Hat Inc.
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

import functools
import os

import eventlet
import mock
import netaddr
from oslo_config import fixture as fixture_config
from oslo_utils import uuidutils

from neutron.agent.l3 import keepalived_state_change
from neutron.agent.linux import ip_lib
from neutron.common import utils
from neutron.conf.agent.l3 import keepalived as kd
from neutron.tests.common import machine_fixtures as mf
from neutron.tests.common import net_helpers
from neutron.tests.functional import base


def has_expected_arp_entry(device_name, namespace, ip, mac):
    ip_version = utils.get_ip_version(ip)
    entry = ip_lib.dump_neigh_entries(ip_version, device_name, namespace,
                                      dst=ip, lladdr=mac)
    return entry != []


class TestKeepalivedStateChange(base.BaseSudoTestCase):
    def setUp(self):
        super(TestKeepalivedStateChange, self).setUp()
        self.conf_fixture = self.useFixture(fixture_config.Config())
        kd.register_l3_agent_keepalived_opts(self.conf_fixture)
        self.router_id = uuidutils.generate_uuid()
        self.conf_dir = self.get_default_temp_dir().path
        self.cidr = '169.254.128.1/24'
        self.interface_name = utils.get_rand_name()
        self.monitor = keepalived_state_change.MonitorDaemon(
            self.get_temp_file_path('monitor.pid'),
            self.router_id,
            1,
            2,
            utils.get_rand_name(),
            self.conf_dir,
            self.interface_name,
            self.cidr)
        mock.patch.object(self.monitor, 'notify_agent').start()
        self.line = '1: %s    inet %s' % (self.interface_name, self.cidr)

    def test_parse_and_handle_event_wrong_device_completes_without_error(self):
        self.monitor.parse_and_handle_event(
            '1: wrong_device    inet wrong_cidr')

    def _get_state(self):
        with open(os.path.join(self.monitor.conf_dir, 'state')) as state_file:
            return state_file.read()

    def test_parse_and_handle_event_writes_to_file(self):
        self.monitor.parse_and_handle_event('Deleted %s' % self.line)
        self.assertEqual('backup', self._get_state())

        self.monitor.parse_and_handle_event(self.line)
        self.assertEqual('master', self._get_state())

    def test_parse_and_handle_event_fails_writing_state(self):
        with mock.patch.object(
                self.monitor, 'write_state_change', side_effect=OSError):
            self.monitor.parse_and_handle_event(self.line)

    def test_parse_and_handle_event_fails_notifying_agent(self):
        with mock.patch.object(
                self.monitor, 'notify_agent', side_effect=Exception):
            self.monitor.parse_and_handle_event(self.line)

    def test_handle_initial_state_backup(self):
        ip = ip_lib.IPWrapper(namespace=self.monitor.namespace)
        ip.netns.add(self.monitor.namespace)
        self.addCleanup(ip.netns.delete, self.monitor.namespace)
        ip.add_dummy(self.interface_name)

        with mock.patch.object(
                self.monitor, 'write_state_change') as write_state_change,\
                mock.patch.object(
                    self.monitor, 'notify_agent') as notify_agent:

            self.monitor.handle_initial_state()
            write_state_change.assert_not_called()
            notify_agent.assert_not_called()

    def test_handle_initial_state_master(self):
        ip = ip_lib.IPWrapper(namespace=self.monitor.namespace)
        ip.netns.add(self.monitor.namespace)
        self.addCleanup(ip.netns.delete, self.monitor.namespace)
        ha_interface = ip.add_dummy(self.interface_name)

        ha_interface.addr.add(self.cidr)

        self.monitor.handle_initial_state()
        self.assertEqual('master', self._get_state())


class TestMonitorDaemon(base.BaseSudoTestCase):
    def setUp(self):
        super(TestMonitorDaemon, self).setUp()
        bridge = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        self.machines = self.useFixture(mf.PeerMachines(bridge))
        self.router, self.peer = self.machines.machines[:2]

        conf_dir = self.get_default_temp_dir().path
        monitor = keepalived_state_change.MonitorDaemon(
            self.get_temp_file_path('monitor.pid'),
            uuidutils.generate_uuid(),
            1,
            2,
            self.router.namespace,
            conf_dir,
            'foo-iface',
            self.machines.ip_cidr
        )
        eventlet.spawn_n(monitor.run, run_as_root=True)
        monitor_started = functools.partial(
            lambda mon: mon.monitor is not None, monitor)
        utils.wait_until_true(monitor_started)
        self.addCleanup(monitor.monitor.stop)

    def test_new_fip_sends_garp(self):
        next_ip_cidr = net_helpers.increment_ip_cidr(self.machines.ip_cidr, 2)
        expected_ip = str(netaddr.IPNetwork(next_ip_cidr).ip)
        # Create incomplete ARP entry
        self.peer.assert_no_ping(expected_ip)
        has_entry = has_expected_arp_entry(
            self.peer.port.name,
            self.peer.namespace,
            expected_ip,
            self.router.port.link.address)
        self.assertFalse(has_entry)
        self.router.port.addr.add(next_ip_cidr)
        has_arp_entry_predicate = functools.partial(
            has_expected_arp_entry,
            self.peer.port.name,
            self.peer.namespace,
            expected_ip,
            self.router.port.link.address,
        )
        exc = RuntimeError(
            "No ARP entry in %s namespace containing IP address %s and MAC "
            "address %s" % (
                self.peer.namespace,
                expected_ip,
                self.router.port.link.address))
        utils.wait_until_true(
            has_arp_entry_predicate,
            exception=exc)
