# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira, Inc.
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

import copy
import time
import unittest

import mock

from quantum.agent.common import config
from quantum.agent import l3_agent
from quantum.agent.linux import interface
from quantum.db import l3_db
from quantum.openstack.common import uuidutils


_uuid = uuidutils.generate_uuid


class TestBasicRouterOperations(unittest.TestCase):

    def setUp(self):
        self.conf = config.setup_conf()
        self.conf.register_opts(l3_agent.L3NATAgent.OPTS)
        self.conf.register_opts(interface.OPTS)
        self.conf.set_override('interface_driver',
                               'quantum.agent.linux.interface.NullDriver')
        self.conf.root_helper = 'sudo'

        self.device_exists_p = mock.patch(
            'quantum.agent.linux.ip_lib.device_exists')
        self.device_exists = self.device_exists_p.start()

        self.utils_exec_p = mock.patch(
            'quantum.agent.linux.utils.execute')
        self.utils_exec = self.utils_exec_p.start()

        self.external_process_p = mock.patch(
            'quantum.agent.linux.external_process.ProcessManager')
        self.external_process = self.external_process_p.start()

        self.dvr_cls_p = mock.patch('quantum.agent.linux.interface.NullDriver')
        driver_cls = self.dvr_cls_p.start()
        self.mock_driver = mock.MagicMock()
        self.mock_driver.DEV_NAME_LEN = (
            interface.LinuxInterfaceDriver.DEV_NAME_LEN)
        driver_cls.return_value = self.mock_driver

        self.ip_cls_p = mock.patch('quantum.agent.linux.ip_lib.IPWrapper')
        ip_cls = self.ip_cls_p.start()
        self.mock_ip = mock.MagicMock()
        ip_cls.return_value = self.mock_ip

        self.client_cls_p = mock.patch('quantumclient.v2_0.client.Client')
        client_cls = self.client_cls_p.start()
        self.client_inst = mock.Mock()
        client_cls.return_value = self.client_inst

    def tearDown(self):
        self.device_exists_p.stop()
        self.client_cls_p.stop()
        self.ip_cls_p.stop()
        self.dvr_cls_p.stop()
        self.utils_exec_p.stop()
        self.external_process_p.stop()

    def testRouterInfoCreate(self):
        id = _uuid()
        ri = l3_agent.RouterInfo(id, self.conf.root_helper,
                                 self.conf.use_namespaces)

        self.assertTrue(ri.ns_name().endswith(id))

    def testAgentCreate(self):
        agent = l3_agent.L3NATAgent(self.conf)

    def _test_internal_network_action(self, action):
        port_id = _uuid()
        router_id = _uuid()
        network_id = _uuid()
        ri = l3_agent.RouterInfo(router_id, self.conf.root_helper,
                                 self.conf.use_namespaces)
        agent = l3_agent.L3NATAgent(self.conf)
        interface_name = agent.get_internal_device_name(port_id)
        cidr = '99.0.1.9/24'
        mac = 'ca:fe:de:ad:be:ef'
        ex_gw_port = {'fixed_ips': [{'ip_address': '20.0.0.30'}]}

        if action == 'add':
            self.device_exists.return_value = False
            agent.internal_network_added(ri, ex_gw_port, network_id,
                                         port_id, cidr, mac)
            self.assertEquals(self.mock_driver.plug.call_count, 1)
            self.assertEquals(self.mock_driver.init_l3.call_count, 1)
        elif action == 'remove':
            self.device_exists.return_value = True
            agent.internal_network_removed(ri, ex_gw_port, port_id, cidr)
            self.assertEquals(self.mock_driver.unplug.call_count, 1)
        else:
            raise Exception("Invalid action %s" % action)

    def testAgentAddInternalNetwork(self):
        self._test_internal_network_action('add')

    def testAgentRemoveInternalNetwork(self):
        self._test_internal_network_action('remove')

    def _test_external_gateway_action(self, action):
        router_id = _uuid()
        ri = l3_agent.RouterInfo(router_id, self.conf.root_helper,
                                 self.conf.use_namespaces)
        agent = l3_agent.L3NATAgent(self.conf)
        internal_cidrs = ['100.0.1.0/24', '200.74.0.0/16']
        ex_gw_port = {'fixed_ips': [{'ip_address': '20.0.0.30',
                                     'subnet_id': _uuid()}],
                      'subnet': {'gateway_ip': '20.0.0.1'},
                      'id': _uuid(),
                      'network_id': _uuid(),
                      'mac_address': 'ca:fe:de:ad:be:ef',
                      'ip_cidr': '20.0.0.30/24'}
        interface_name = agent.get_external_device_name(ex_gw_port['id'])

        if action == 'add':
            self.device_exists.return_value = False
            agent.external_gateway_added(ri, ex_gw_port, internal_cidrs)
            self.assertEquals(self.mock_driver.plug.call_count, 1)
            self.assertEquals(self.mock_driver.init_l3.call_count, 1)
            arping_cmd = ['arping', '-A', '-U',
                          '-I', interface_name,
                          '-c', self.conf.send_arp_for_ha,
                          '20.0.0.30']
            if self.conf.use_namespaces:
                self.mock_ip.netns.execute.assert_any_call(
                    arping_cmd, check_exit_code=True)
            else:
                self.utils_exec.assert_any_call(
                    check_exit_code=True, root_helper=self.conf.root_helper)

        elif action == 'remove':
            self.device_exists.return_value = True
            agent.external_gateway_removed(ri, ex_gw_port, internal_cidrs)
            self.assertEquals(self.mock_driver.unplug.call_count, 1)
        else:
            raise Exception("Invalid action %s" % action)

    def testAgentAddExternalGateway(self):
        self._test_external_gateway_action('add')

    def testAgentRemoveExternalGateway(self):
        self._test_external_gateway_action('remove')

    def _test_floating_ip_action(self, action):
        router_id = _uuid()
        ri = l3_agent.RouterInfo(router_id, self.conf.root_helper,
                                 self.conf.use_namespaces)
        agent = l3_agent.L3NATAgent(self.conf)
        floating_ip = '20.0.0.100'
        fixed_ip = '10.0.0.23'
        ex_gw_port = {'fixed_ips': [{'ip_address': '20.0.0.30',
                                     'subnet_id': _uuid()}],
                      'subnet': {'gateway_ip': '20.0.0.1'},
                      'id': _uuid(),
                      'mac_address': 'ca:fe:de:ad:be:ef',
                      'ip_cidr': '20.0.0.30/24'}
        interface_name = agent.get_external_device_name(ex_gw_port['id'])

        if action == 'add':
            self.device_exists.return_value = False
            agent.floating_ip_added(ri, ex_gw_port, floating_ip, fixed_ip)
            arping_cmd = ['arping', '-A', '-U',
                          '-I', interface_name,
                          '-c', self.conf.send_arp_for_ha,
                          floating_ip]
            if self.conf.use_namespaces:
                self.mock_ip.netns.execute.assert_any_call(
                    arping_cmd, check_exit_code=True)
            else:
                self.utils_exec.assert_any_call(
                    check_exit_code=True, root_helper=self.conf.root_helper)

        elif action == 'remove':
            self.device_exists.return_value = True
            agent.floating_ip_removed(ri, ex_gw_port, floating_ip, fixed_ip)
        else:
            raise Exception("Invalid action %s" % action)

    def testAgentAddFloatingIP(self):
        self._test_floating_ip_action('add')

    def testAgentRemoveFloatingIP(self):
        self._test_floating_ip_action('remove')

    def testProcessRouter(self):

        agent = l3_agent.L3NATAgent(self.conf)
        router_id = _uuid()
        ri = l3_agent.RouterInfo(router_id, self.conf.root_helper,
                                 self.conf.use_namespaces)

        # return data so that state is built up
        ex_gw_port = {'id': _uuid(),
                      'network_id': _uuid(),
                      'fixed_ips': [{'ip_address': '19.4.4.4',
                                     'subnet_id': _uuid()}]}
        internal_port = {'id': _uuid(),
                         'network_id': _uuid(),
                         'admin_state_up': True,
                         'fixed_ips': [{'ip_address': '35.4.4.4',
                                        'subnet_id': _uuid()}],
                         'mac_address': 'ca:fe:de:ad:be:ef'}

        def fake_list_ports1(**kwargs):
            if kwargs['device_owner'] == l3_db.DEVICE_OWNER_ROUTER_GW:
                return {'ports': [ex_gw_port]}
            elif kwargs['device_owner'] == l3_db.DEVICE_OWNER_ROUTER_INTF:
                return {'ports': [internal_port]}

        fake_subnet = {'subnet': {'cidr': '19.4.4.0/24',
                                  'gateway_ip': '19.4.4.1'}}

        fake_floatingips1 = {'floatingips': [
            {'id': _uuid(),
             'floating_ip_address': '8.8.8.8',
             'fixed_ip_address': '7.7.7.7',
             'port_id': _uuid()}]}

        self.client_inst.list_ports.side_effect = fake_list_ports1
        self.client_inst.show_subnet.return_value = fake_subnet
        self.client_inst.list_floatingips.return_value = fake_floatingips1
        agent.process_router(ri)

        # remap floating IP to a new fixed ip
        fake_floatingips2 = copy.deepcopy(fake_floatingips1)
        fake_floatingips2['floatingips'][0]['fixed_ip_address'] = '7.7.7.8'
        self.client_inst.list_floatingips.return_value = fake_floatingips2
        agent.process_router(ri)

        # remove just the floating ips
        self.client_inst.list_floatingips.return_value = {'floatingips': []}
        agent.process_router(ri)

        # now return no ports so state is torn down
        self.client_inst.list_ports.return_value = {'ports': []}
        agent.process_router(ri)

    def testSingleLoopRouterRemoval(self):
        agent = l3_agent.L3NATAgent(self.conf)
        router_id = _uuid()

        self.client_inst.list_ports.return_value = {'ports': []}

        self.client_inst.list_networks.return_value = {'networks': []}

        self.client_inst.list_routers.return_value = {'routers': [
            {'id': router_id,
             'admin_state_up': True,
             'external_gateway_info': {}}]}
        agent.do_single_loop()

        self.client_inst.list_routers.return_value = {'routers': []}
        agent.do_single_loop()
        self.external_process.assert_has_calls(
            [mock.call(agent.conf, router_id, 'sudo', 'qrouter-' + router_id),
             mock.call().enable(mock.ANY),
             mock.call(agent.conf, router_id, 'sudo', 'qrouter-' + router_id),
             mock.call().disable()])

        # verify that remove is called
        self.assertEquals(self.mock_ip.get_devices.call_count, 1)

        self.device_exists.assert_has_calls(
            [mock.call(self.conf.external_network_bridge)])

    def testDaemonLoop(self):

        # just take a pass through the loop, then raise on time.sleep()
        time_sleep_p = mock.patch('time.sleep')
        time_sleep = time_sleep_p.start()

        class ExpectedException(Exception):
            pass

        time_sleep.side_effect = ExpectedException()

        agent = l3_agent.L3NATAgent(self.conf)
        self.assertRaises(ExpectedException, agent.daemon_loop)

        time_sleep_p.stop()

    def testDestroyNamespace(self):

        class FakeDev(object):
            def __init__(self, name):
                self.name = name

        self.mock_ip.get_namespaces.return_value = ['qrouter-foo']
        self.mock_ip.get_devices.return_value = [FakeDev('qr-aaaa'),
                                                 FakeDev('qgw-aaaa')]

        agent = l3_agent.L3NATAgent(self.conf)
        agent._destroy_all_router_namespaces()

    def testMain(self):
        agent_mock_p = mock.patch('quantum.agent.l3_agent.L3NATAgent')
        agent_mock = agent_mock_p.start()
        agent_mock.daemon_loop.return_value = None
        with mock.patch('quantum.agent.common.config.setup_logging'):
            with mock.patch('quantum.agent.l3_agent.sys') as mock_sys:
                mock_sys.argv = []
                l3_agent.main()

        agent_mock_p.stop()
