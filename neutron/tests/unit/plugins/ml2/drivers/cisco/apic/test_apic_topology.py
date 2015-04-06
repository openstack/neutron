# Copyright (c) 2014 Cisco Systems
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

import sys

import mock

sys.modules["apicapi"] = mock.Mock()

from neutron.plugins.ml2.drivers.cisco.apic import apic_topology
from neutron.tests import base
from neutron.tests.unit.plugins.ml2.drivers.cisco.apic import (
    base as mocked)

NOTIFIER = ('neutron.plugins.ml2.drivers.cisco.apic.'
            'apic_topology.ApicTopologyServiceNotifierApi')
RPC_CONNECTION = 'neutron.common.rpc.Connection'
AGENTS_DB = 'neutron.db.agents_db'
PERIODIC_TASK = 'neutron.openstack.common.periodic_task'
DEV_EXISTS = 'neutron.agent.linux.ip_lib.device_exists'
IP_DEVICE = 'neutron.agent.linux.ip_lib.IPDevice'
EXECUTE = 'neutron.agent.linux.utils.execute'

LLDP_CMD = ['lldpctl', '-f', 'keyvalue']
ETH0 = mocked.SERVICE_HOST_IFACE

LLDPCTL_RES = (
    'lldp.' + ETH0 + '.via=LLDP\n'
    'lldp.' + ETH0 + '.rid=1\n'
    'lldp.' + ETH0 + '.age=0 day, 20:55:54\n'
    'lldp.' + ETH0 + '.chassis.mac=' + mocked.SERVICE_HOST_MAC + '\n'
    'lldp.' + ETH0 + '.chassis.name=' + mocked.SERVICE_PEER_CHASSIS_NAME + '\n'
    'lldp.' + ETH0 + '.chassis.descr=' + mocked.SERVICE_PEER_CHASSIS + '\n'
    'lldp.' + ETH0 + '.chassis.Bridge.enabled=on\n'
    'lldp.' + ETH0 + '.chassis.Router.enabled=on\n'
    'lldp.' + ETH0 + '.port.local=' + mocked.SERVICE_PEER_PORT_LOCAL + '\n'
    'lldp.' + ETH0 + '.port.descr=' + mocked.SERVICE_PEER_PORT_DESC)


class TestCiscoApicTopologyService(base.BaseTestCase,
                                  mocked.ControllerMixin,
                                  mocked.ConfigMixin):

    def setUp(self):
        super(TestCiscoApicTopologyService, self).setUp()
        mocked.ControllerMixin.set_up_mocks(self)
        mocked.ConfigMixin.set_up_mocks(self)
        # Patch notifier
        notifier_c = mock.patch(NOTIFIER).start()
        self.notifier = mock.Mock()
        notifier_c.return_value = self.notifier
        # Patch Connection
        connection_c = mock.patch(RPC_CONNECTION).start()
        self.connection = mock.Mock()
        connection_c.return_value = self.connection
        # Patch agents db
        self.agents_db = mock.patch(AGENTS_DB).start()
        self.service = apic_topology.ApicTopologyService()
        self.service.apic_manager = mock.Mock()

    def test_init_host(self):
        self.service.init_host()
        self.connection.create_consumer.ensure_called_once()
        self.connection.consume_in_threads.ensure_called_once()

    def test_update_link_add_nopeers(self):
        self.service.peers = {}
        args = (mocked.SERVICE_HOST, mocked.SERVICE_HOST_IFACE,
                mocked.SERVICE_HOST_MAC, mocked.APIC_EXT_SWITCH,
                mocked.APIC_EXT_MODULE, mocked.APIC_EXT_PORT)
        self.service.update_link(None, *args)
        self.service.apic_manager.add_hostlink.assert_called_once_with(*args)
        self.assertEqual(args,
                         self.service.peers[(mocked.SERVICE_HOST,
                                             mocked.SERVICE_HOST_IFACE)])

    def test_update_link_add_with_peers_diff(self):
        args = (mocked.SERVICE_HOST, mocked.SERVICE_HOST_IFACE,
                mocked.SERVICE_HOST_MAC, mocked.APIC_EXT_SWITCH,
                mocked.APIC_EXT_MODULE, mocked.APIC_EXT_PORT)
        args_prime = args[:2] + tuple(x + '1' for x in args[2:])
        self.service.peers = {args_prime[:2]: args_prime}
        self.service.update_link(None, *args)
        self.service.apic_manager.remove_hostlink.assert_called_once_with(
            *args_prime)
        self.service.apic_manager.add_hostlink.assert_called_once_with(*args)
        self.assertEqual(
            args, self.service.peers[
                (mocked.SERVICE_HOST, mocked.SERVICE_HOST_IFACE)])

    def test_update_link_add_with_peers_eq(self):
        args = (mocked.SERVICE_HOST, mocked.SERVICE_HOST_IFACE,
                mocked.SERVICE_HOST_MAC,
                mocked.APIC_EXT_SWITCH,
                mocked.APIC_EXT_MODULE, mocked.APIC_EXT_PORT)
        self.service.peers = {args[:2]: args}
        self.service.update_link(None, *args)

    def test_update_link_rem_with_peers(self):
        args = (mocked.SERVICE_HOST, mocked.SERVICE_HOST_IFACE,
                mocked.SERVICE_HOST_MAC, 0,
                mocked.APIC_EXT_MODULE, mocked.APIC_EXT_PORT)
        self.service.peers = {args[:2]: args}
        self.service.update_link(None, *args)
        self.service.apic_manager.remove_hostlink.assert_called_once_with(
            *args)
        self.assertFalse(bool(self.service.peers))

    def test_update_link_rem_no_peers(self):
        args = (mocked.SERVICE_HOST, mocked.SERVICE_HOST_IFACE,
                mocked.SERVICE_HOST_MAC, 0,
                mocked.APIC_EXT_MODULE, mocked.APIC_EXT_PORT)
        self.service.update_link(None, *args)


class TestCiscoApicTopologyAgent(base.BaseTestCase,
                                 mocked.ControllerMixin,
                                 mocked.ConfigMixin):

        def setUp(self):
            super(TestCiscoApicTopologyAgent, self).setUp()
            mocked.ControllerMixin.set_up_mocks(self)
            mocked.ConfigMixin.set_up_mocks(self)
            # Patch notifier
            notifier_c = mock.patch(NOTIFIER).start()
            self.notifier = mock.Mock()
            notifier_c.return_value = self.notifier
            # Patch device_exists
            self.dev_exists = mock.patch(DEV_EXISTS).start()
            # Patch IPDevice
            ipdev_c = mock.patch(IP_DEVICE).start()
            self.ipdev = mock.Mock()
            ipdev_c.return_value = self.ipdev
            self.ipdev.link.address = mocked.SERVICE_HOST_MAC
            # Patch execute
            self.execute = mock.patch(EXECUTE).start()
            self.execute.return_value = LLDPCTL_RES
            # Patch tasks
            self.periodic_task = mock.patch(PERIODIC_TASK).start()
            self.agent = apic_topology.ApicTopologyAgent()
            self.agent.host = mocked.SERVICE_HOST
            self.agent.service_agent = mock.Mock()
            self.agent.lldpcmd = LLDP_CMD

        def test_init_host_device_exists(self):
            self.agent.lldpcmd = None
            self.dev_exists.return_value = True
            self.agent.init_host()
            self.assertEqual(LLDP_CMD + mocked.APIC_UPLINK_PORTS,
                             self.agent.lldpcmd)

        def test_init_host_device_not_exist(self):
            self.agent.lldpcmd = None
            self.dev_exists.return_value = False
            self.agent.init_host()
            self.assertEqual(LLDP_CMD, self.agent.lldpcmd)

        def test_get_peers(self):
            self.agent.peers = {}
            peers = self.agent._get_peers()
            expected = [(mocked.SERVICE_HOST, mocked.SERVICE_HOST_IFACE,
                         mocked.SERVICE_HOST_MAC, mocked.APIC_EXT_SWITCH,
                         mocked.APIC_EXT_MODULE, mocked.APIC_EXT_PORT)]
            self.assertEqual(expected,
                             peers[mocked.SERVICE_HOST_IFACE])

        def test_check_for_new_peers_no_peers(self):
            self.agent.peers = {}
            expected = (mocked.SERVICE_HOST, mocked.SERVICE_HOST_IFACE,
                        mocked.SERVICE_HOST_MAC, mocked.APIC_EXT_SWITCH,
                        mocked.APIC_EXT_MODULE, mocked.APIC_EXT_PORT)
            peers = {mocked.SERVICE_HOST_IFACE: [expected]}
            context = mock.Mock()
            with mock.patch.object(self.agent, '_get_peers',
                                   return_value=peers):
                self.agent._check_for_new_peers(context)
                self.assertEqual(expected,
                                 self.agent.peers[mocked.SERVICE_HOST_IFACE])
                self.agent.service_agent.update_link.assert_called_once_with(
                    context, *expected)

        def test_check_for_new_peers_with_peers(self):
            expected = (mocked.SERVICE_HOST, mocked.SERVICE_HOST_IFACE,
                        mocked.SERVICE_HOST_MAC, mocked.APIC_EXT_SWITCH,
                        mocked.APIC_EXT_MODULE, mocked.APIC_EXT_PORT)
            peers = {mocked.SERVICE_HOST_IFACE: [expected]}
            self.agent.peers = {mocked.SERVICE_HOST_IFACE:
                                [tuple(x + '1' for x in expected)]}
            context = mock.Mock()
            with mock.patch.object(self.agent, '_get_peers',
                                   return_value=peers):
                self.agent._check_for_new_peers(context)
                self.agent.service_agent.update_link.assert_called_with(
                    context, *expected)
