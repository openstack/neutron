# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack Foundation.
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

import contextlib

import mock
from oslo.config import cfg
import testtools

from quantum.agent.linux import ip_lib
from quantum.plugins.linuxbridge.agent import linuxbridge_quantum_agent
from quantum.plugins.linuxbridge.common import constants as lconst
from quantum.tests import base


class TestLinuxBridge(base.BaseTestCase):

    def setUp(self):
        super(TestLinuxBridge, self).setUp()
        self.addCleanup(cfg.CONF.reset)
        interface_mappings = {'physnet1': 'eth1'}
        root_helper = cfg.CONF.AGENT.root_helper

        self.linux_bridge = linuxbridge_quantum_agent.LinuxBridgeManager(
            interface_mappings, root_helper)

    def test_ensure_physical_in_bridge_invalid(self):
        result = self.linux_bridge.ensure_physical_in_bridge('network_id',
                                                             'physnetx',
                                                             7)
        self.assertFalse(result)

    def test_ensure_physical_in_bridge_flat(self):
        with mock.patch.object(self.linux_bridge,
                               'ensure_flat_bridge') as flat_bridge_func:
            self.linux_bridge.ensure_physical_in_bridge(
                'network_id', 'physnet1', lconst.FLAT_VLAN_ID)
        self.assertTrue(flat_bridge_func.called)

    def test_ensure_physical_in_bridge_vlan(self):
        with mock.patch.object(self.linux_bridge,
                               'ensure_vlan_bridge') as vlan_bridge_func:
            self.linux_bridge.ensure_physical_in_bridge(
                'network_id', 'physnet1', 7)
        self.assertTrue(vlan_bridge_func.called)


class TestLinuxBridgeAgent(base.BaseTestCase):

    LINK_SAMPLE = [
        '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue \\'
        'state UNKNOWN \\'
        'link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00',
        '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 \\'
        'qdisc mq state UP qlen 1000\    link/ether \\'
        'cc:dd:ee:ff:ab:cd brd ff:ff:ff:ff:ff:ff']

    def setUp(self):
        super(TestLinuxBridgeAgent, self).setUp()
        cfg.CONF.set_override('rpc_backend',
                              'quantum.openstack.common.rpc.impl_fake')
        self.lbmgr_patcher = mock.patch('quantum.plugins.linuxbridge.agent.'
                                        'linuxbridge_quantum_agent.'
                                        'LinuxBridgeManager')
        self.lbmgr_mock = self.lbmgr_patcher.start()
        self.addCleanup(self.lbmgr_patcher.stop)
        self.execute_p = mock.patch.object(ip_lib.IPWrapper, '_execute')
        self.execute = self.execute_p.start()
        self.addCleanup(self.execute_p.stop)
        self.execute.return_value = '\n'.join(self.LINK_SAMPLE)

    def test_update_devices_failed(self):
        lbmgr_instance = self.lbmgr_mock.return_value
        lbmgr_instance.update_devices.side_effect = RuntimeError
        agent = linuxbridge_quantum_agent.LinuxBridgeQuantumAgentRPC({},
                                                                     0,
                                                                     None)
        raise_exception = [0]

        def info_mock(msg):
            if raise_exception[0] < 2:
                raise_exception[0] += 1
            else:
                raise RuntimeError()

        with mock.patch.object(linuxbridge_quantum_agent.LOG, 'info') as log:
            log.side_effect = info_mock
            with testtools.ExpectedException(RuntimeError):
                agent.daemon_loop()
            self.assertEqual(3, log.call_count)

    def test_process_network_devices_failed(self):
        device_info = {'current': [1, 2, 3]}
        lbmgr_instance = self.lbmgr_mock.return_value
        lbmgr_instance.update_devices.return_value = device_info
        agent = linuxbridge_quantum_agent.LinuxBridgeQuantumAgentRPC({},
                                                                     0,
                                                                     None)
        raise_exception = [0]

        def info_mock(msg):
            if raise_exception[0] < 2:
                raise_exception[0] += 1
            else:
                raise RuntimeError()

        with contextlib.nested(
            mock.patch.object(linuxbridge_quantum_agent.LOG, 'info'),
            mock.patch.object(agent, 'process_network_devices')
        ) as (log, process_network_devices):
            log.side_effect = info_mock
            process_network_devices.side_effect = RuntimeError
            with testtools.ExpectedException(RuntimeError):
                agent.daemon_loop()
            self.assertEqual(3, log.call_count)
