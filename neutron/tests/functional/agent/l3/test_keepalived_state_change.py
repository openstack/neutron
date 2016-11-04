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
import re

import eventlet
import mock
import netaddr
from oslo_config import cfg
from oslo_config import fixture as fixture_config
from oslo_utils import uuidutils

from neutron._i18n import _
from neutron.agent.l3 import keepalived_state_change
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.tests.common import machine_fixtures as mf
from neutron.tests.common import net_helpers
from neutron.tests.functional import base

IPV4_NEIGH_REGEXP = re.compile(
    r'(?P<ip>(\d{1,3}\.){3}\d{1,3}) '
    '.*(?P<mac>([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]){2}).*')


def get_arp_ip_mac_pairs(device_name, namespace):
    """Generate (ip, mac) pairs from device's ip neigh.

    Each neigh entry has following format:
    192.168.0.1 lladdr fa:16:3e:01:ba:d3 STALE
    """
    device = ip_lib.IPDevice(device_name, namespace)
    for entry in device.neigh.show(ip_version=4).splitlines():
        match = IPV4_NEIGH_REGEXP.match(entry)
        if match:
            yield match.group('ip'), match.group('mac')


def has_expected_arp_entry(device_name, namespace, ip, mac):
    return (ip, mac) in get_arp_ip_mac_pairs(device_name, namespace)


class TestKeepalivedStateChange(base.BaseSudoTestCase):
    def setUp(self):
        super(TestKeepalivedStateChange, self).setUp()
        self.conf_fixture = self.useFixture(fixture_config.Config())
        self.conf_fixture.register_opt(
            cfg.StrOpt('metadata_proxy_socket',
                       default='$state_path/metadata_proxy',
                       help=_('Location of Metadata Proxy UNIX domain '
                              'socket')))

        self.router_id = uuidutils.generate_uuid()
        self.conf_dir = self.get_default_temp_dir().path
        self.cidr = '169.254.128.1/24'
        self.interface_name = 'interface'
        self.monitor = keepalived_state_change.MonitorDaemon(
            self.get_temp_file_path('monitor.pid'),
            self.router_id,
            1,
            2,
            'namespace',
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
