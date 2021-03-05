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
from unittest import mock

import eventlet
import netaddr
from oslo_utils import uuidutils

from neutron.agent.l3 import ha
from neutron.agent.l3 import ha_router
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as linux_utils
from neutron.common import utils
from neutron.tests.common import machine_fixtures as mf
from neutron.tests.common import net_helpers
from neutron.tests.functional import base


def has_expected_arp_entry(device_name, namespace, ip, mac):
    ip_version = utils.get_ip_version(ip)
    entry = ip_lib.dump_neigh_entries(ip_version, device_name, namespace,
                                      dst=ip, lladdr=mac)
    return entry != []


class TestMonitorDaemon(base.BaseLoggingTestCase):
    def setUp(self):
        super(TestMonitorDaemon, self).setUp()
        self.conf_dir = self.get_default_temp_dir().path
        self.pid_file = os.path.join(self.conf_dir, 'pid_file')
        self.log_file = os.path.join(self.conf_dir, 'log_file')
        self.state_file = os.path.join(self.conf_dir,
                                       'keepalived-state-change')
        self.cidr = '169.254.151.1/24'
        bridge = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        self.machines = self.useFixture(mf.PeerMachines(bridge))
        self.router, self.peer = self.machines.machines[:2]
        self.router_id = uuidutils.generate_uuid()

        self._generate_cmd_opts()
        self.ext_process = external_process.ProcessManager(
            conf=None, uuid=self.router_id, namespace=self.router.namespace,
            service='test_ip_mon', pids_path=self.conf_dir,
            default_cmd_callback=self._callback, run_as_root=True,
            pid_file=self.pid_file)

        server = linux_utils.UnixDomainWSGIServer(
            'neutron-keepalived-state-change', num_threads=1)
        server.start(ha.KeepalivedStateChangeHandler(mock.Mock()),
                     self.state_file, workers=0,
                     backlog=ha.KEEPALIVED_STATE_CHANGE_SERVER_BACKLOG)
        self.addCleanup(server.stop)

    def _run_monitor(self):
        self.ext_process.enable()
        self.addCleanup(self.ext_process.disable)
        eventlet.sleep(5)

    def _callback(self, *args):
        return self.cmd_opts

    def _generate_cmd_opts(self, monitor_interface=None, cidr=None):
        monitor_interface = monitor_interface or self.router.port.name
        cidr = cidr or self.cidr
        self.cmd_opts = [
            ha_router.STATE_CHANGE_PROC_NAME,
            '--router_id=%s' % self.router_id,
            '--namespace=%s' % self.router.namespace,
            '--conf_dir=%s' % self.conf_dir,
            '--log-file=%s' % self.log_file,
            '--monitor_interface=%s' % monitor_interface,
            '--monitor_cidr=%s' % cidr,
            '--pid_file=%s' % self.pid_file,
            '--state_path=%s' % self.conf_dir,
            '--user=%s' % os.geteuid(),
            '--group=%s' % os.getegid()]

    def _search_in_file(self, file_name, text):
        def text_in_file():
            try:
                return text in open(file_name).read()
            except FileNotFoundError:
                return False
        try:
            utils.wait_until_true(text_in_file, timeout=15)
        except utils.WaitTimeout:
            devices = {}
            for dev in ip_lib.IPWrapper(
                    namespace=self.router.namespace).get_devices():
                devices[dev.name] = [addr['cidr'] for addr in dev.addr.list()]
            # NOTE: we need to read here the content of the file.
            self.fail(
                'Text not found in file %(file_name)s: "%(text)s".\nDevice '
                'addresses: %(devices)s.\nFile content:\n%(file_content)s' %
                {'file_name': file_name, 'text': text, 'devices': devices,
                 'file_content': open(file_name).read()})

    def test_new_fip_sends_garp(self):
        ns_ip_wrapper = ip_lib.IPWrapper(self.router.namespace)
        new_interface = ns_ip_wrapper.add_dummy('new_interface')
        new_interface_cidr = '169.254.152.1/24'
        new_interface.link.set_up()
        new_interface.addr.add(new_interface_cidr)
        self._generate_cmd_opts(monitor_interface='new_interface',
                                cidr=new_interface_cidr)

        self._run_monitor()

        next_ip_cidr = net_helpers.increment_ip_cidr(self.machines.ip_cidr, 2)
        expected_ip = str(netaddr.IPNetwork(next_ip_cidr).ip)
        # Create incomplete ARP entry
        self.peer.assert_no_ping(expected_ip)
        # Wait for ping expiration
        eventlet.sleep(1)
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
        utils.wait_until_true(has_arp_entry_predicate, timeout=15,
                              exception=exc)
        msg = ('Sent GARP to %(cidr)s from %(device)s' %
               {'cidr': expected_ip, 'device': self.router.port.name})
        self._search_in_file(self.log_file, msg)

    def test_read_queue_change_state(self):
        self._run_monitor()
        msg = 'Wrote router %s state %s'
        self.router.port.addr.add(self.cidr)
        self._search_in_file(self.log_file, msg % (self.router_id, 'primary'))
        self.router.port.addr.delete(self.cidr)
        self._search_in_file(self.log_file, msg % (self.router_id, 'backup'))

    def test_read_queue_send_garp(self):
        self._run_monitor()
        dev_dummy = 'dev_dummy'
        ip_wrapper = ip_lib.IPWrapper(namespace=self.router.namespace)
        ip_wrapper.add_dummy(dev_dummy)
        ip_device = ip_lib.IPDevice(dev_dummy, namespace=self.router.namespace)
        ip_device.link.set_up()
        msg = 'Sent GARP to %(ip_address)s from %(device_name)s'
        for idx in range(2, 20):
            next_cidr = net_helpers.increment_ip_cidr(self.cidr, idx)
            ip_device.addr.add(next_cidr)
            msg_args = {'ip_address': str(netaddr.IPNetwork(next_cidr).ip),
                        'device_name': dev_dummy}
            self._search_in_file(self.log_file, msg % msg_args)
            ip_device.addr.delete(next_cidr)

    def test_handle_initial_state_backup(self):
        # No tracked IP (self.cidr) is configured in the monitored interface
        # (self.router.port)
        self._run_monitor()
        msg = 'Initial status of router %s is %s' % (self.router_id, 'backup')
        self._search_in_file(self.log_file, msg)

    def test_handle_initial_state_primary(self):
        self.router.port.addr.add(self.cidr)
        self._run_monitor()
        msg = 'Initial status of router %s is %s' % (self.router_id, 'primary')
        self._search_in_file(self.log_file, msg)

    def test_handle_initial_state_backup_error_reading_initial_status(self):
        # By passing this wrong IP address, the thread "_thread_initial_state"
        # will fail generating an exception (caught inside the called method).
        # The main thread will timeout waiting for an initial state and
        # "backup" will be set.
        self.router.port.addr.add(self.cidr)
        self._generate_cmd_opts(cidr='failed_IP_address')
        self.ext_process = external_process.ProcessManager(
            conf=None, uuid=self.router_id, namespace=self.router.namespace,
            service='test_ip_mon', pids_path=self.conf_dir,
            default_cmd_callback=self._callback, run_as_root=True,
            pid_file=self.pid_file)
        self._run_monitor()
        msg = ('Timeout reading the initial status of router %s' %
               self.router_id)
        self._search_in_file(self.log_file, msg)
        msg = 'Initial status of router %s is %s' % (self.router_id, 'backup')
        self._search_in_file(self.log_file, msg)
