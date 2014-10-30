# Copyright 2012 VMware, Inc.
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

import contextlib
import copy

import mock
import netaddr
from oslo.config import cfg
from testtools import matchers

from neutron.agent.common import config as agent_config
from neutron.agent import l3_agent
from neutron.agent.linux import interface
from neutron.common import config as base_config
from neutron.common import constants as l3_constants
from neutron.common import exceptions as n_exc
from neutron.openstack.common import processutils
from neutron.openstack.common import uuidutils
from neutron.tests import base


_uuid = uuidutils.generate_uuid
HOSTNAME = 'myhost'
FAKE_ID = _uuid()


class TestBasicRouterOperations(base.BaseTestCase):

    def setUp(self):
        super(TestBasicRouterOperations, self).setUp()
        self.conf = cfg.ConfigOpts()
        self.conf.register_opts(base_config.core_opts)
        self.conf.register_opts(l3_agent.L3NATAgent.OPTS)
        agent_config.register_interface_driver_opts_helper(self.conf)
        agent_config.register_use_namespaces_opts_helper(self.conf)
        agent_config.register_root_helper(self.conf)
        self.conf.register_opts(interface.OPTS)
        self.conf.set_override('router_id', 'fake_id')
        self.conf.set_override('interface_driver',
                               'neutron.agent.linux.interface.NullDriver')
        self.conf.set_override('send_arp_for_ha', 1)
        self.conf.root_helper = 'sudo'

        self.device_exists_p = mock.patch(
            'neutron.agent.linux.ip_lib.device_exists')
        self.device_exists = self.device_exists_p.start()

        self.utils_exec_p = mock.patch(
            'neutron.agent.linux.utils.execute')
        self.utils_exec = self.utils_exec_p.start()

        self.external_process_p = mock.patch(
            'neutron.agent.linux.external_process.ProcessManager')
        self.external_process = self.external_process_p.start()

        self.send_arp_p = mock.patch(
            'neutron.agent.l3_agent.L3NATAgent._send_gratuitous_arp_packet')
        self.send_arp = self.send_arp_p.start()

        self.dvr_cls_p = mock.patch('neutron.agent.linux.interface.NullDriver')
        driver_cls = self.dvr_cls_p.start()
        self.mock_driver = mock.MagicMock()
        self.mock_driver.DEV_NAME_LEN = (
            interface.LinuxInterfaceDriver.DEV_NAME_LEN)
        driver_cls.return_value = self.mock_driver

        self.ip_cls_p = mock.patch('neutron.agent.linux.ip_lib.IPWrapper')
        ip_cls = self.ip_cls_p.start()
        self.mock_ip = mock.MagicMock()
        ip_cls.return_value = self.mock_ip

        self.l3pluginApi_cls_p = mock.patch(
            'neutron.agent.l3_agent.L3PluginApi')
        l3pluginApi_cls = self.l3pluginApi_cls_p.start()
        self.plugin_api = mock.Mock()
        l3pluginApi_cls.return_value = self.plugin_api

        self.looping_call_p = mock.patch(
            'neutron.openstack.common.loopingcall.FixedIntervalLoopingCall')
        self.looping_call_p.start()

    def test_router_info_create(self):
        id = _uuid()
        ri = l3_agent.RouterInfo(id, self.conf.root_helper,
                                 self.conf.use_namespaces, None)

        self.assertTrue(ri.ns_name.endswith(id))

    def test_router_info_create_with_router(self):
        id = _uuid()
        ex_gw_port = {'id': _uuid(),
                      'network_id': _uuid(),
                      'fixed_ips': [{'ip_address': '19.4.4.4',
                                     'subnet_id': _uuid()}],
                      'subnet': {'cidr': '19.4.4.0/24',
                                 'gateway_ip': '19.4.4.1'}}
        router = {
            'id': _uuid(),
            'enable_snat': True,
            'routes': [],
            'gw_port': ex_gw_port}
        ri = l3_agent.RouterInfo(id, self.conf.root_helper,
                                 self.conf.use_namespaces, router)
        self.assertTrue(ri.ns_name.endswith(id))
        self.assertEqual(ri.router, router)

    def test_agent_create(self):
        l3_agent.L3NATAgent(HOSTNAME, self.conf)

    def _test_internal_network_action(self, action):
        port_id = _uuid()
        router_id = _uuid()
        network_id = _uuid()
        ri = l3_agent.RouterInfo(router_id, self.conf.root_helper,
                                 self.conf.use_namespaces, None)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        cidr = '99.0.1.9/24'
        mac = 'ca:fe:de:ad:be:ef'
        interface_name = agent.get_internal_device_name(port_id)

        if action == 'add':
            self.device_exists.return_value = False
            agent.internal_network_added(ri, network_id,
                                         port_id, cidr, mac)
            self.assertEqual(self.mock_driver.plug.call_count, 1)
            self.assertEqual(self.mock_driver.init_l3.call_count, 1)
            self.send_arp.assert_called_once_with(ri, interface_name,
                                                  '99.0.1.9')
        elif action == 'remove':
            self.device_exists.return_value = True
            agent.internal_network_removed(ri, port_id, cidr)
            self.assertEqual(self.mock_driver.unplug.call_count, 1)
        else:
            raise Exception("Invalid action %s" % action)

    def test_agent_add_internal_network(self):
        self._test_internal_network_action('add')

    def test_agent_remove_internal_network(self):
        self._test_internal_network_action('remove')

    def _test_external_gateway_action(self, action):
        router_id = _uuid()
        ri = l3_agent.RouterInfo(router_id, self.conf.root_helper,
                                 self.conf.use_namespaces, None)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
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
            ri.router = mock.Mock()
            ri.router.get.return_value = [{'floating_ip_address':
                                           '192.168.1.34'}]
            agent.external_gateway_added(ri, ex_gw_port,
                                         interface_name, internal_cidrs)
            self.assertEqual(self.mock_driver.plug.call_count, 1)
            self.assertEqual(self.mock_driver.init_l3.call_count, 1)
            self.send_arp.assert_called_once_with(ri, interface_name,
                                                  '20.0.0.30')
            kwargs = {'preserve_ips': ['192.168.1.34/32'],
                      'namespace': 'qrouter-' + router_id}
            self.mock_driver.init_l3.assert_called_with(interface_name,
                                                        ['20.0.0.30/24'],
                                                        **kwargs)

        elif action == 'remove':
            self.device_exists.return_value = True
            agent.external_gateway_removed(ri, ex_gw_port,
                                           interface_name, internal_cidrs)
            self.assertEqual(self.mock_driver.unplug.call_count, 1)
        else:
            raise Exception("Invalid action %s" % action)

    def test_agent_add_external_gateway(self):
        self._test_external_gateway_action('add')

    def _test_arping(self, namespace):
        if not namespace:
            self.conf.set_override('use_namespaces', False)

        router_id = _uuid()
        ri = l3_agent.RouterInfo(router_id, self.conf.root_helper,
                                 self.conf.use_namespaces, None)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        floating_ip = '20.0.0.101'
        interface_name = agent.get_external_device_name(router_id)
        agent._arping(ri, interface_name, floating_ip)

        arping_cmd = ['arping', '-A',
                      '-I', interface_name,
                      '-c', self.conf.send_arp_for_ha,
                      floating_ip]
        self.mock_ip.netns.execute.assert_any_call(
            arping_cmd, check_exit_code=True)

    def test_arping_namespace(self):
        self._test_arping(namespace=True)

    def test_arping_no_namespace(self):
        self._test_arping(namespace=False)

    def test_agent_remove_external_gateway(self):
        self._test_external_gateway_action('remove')

    def _check_agent_method_called(self, agent, calls, namespace):
        self.mock_ip.netns.execute.assert_has_calls(
            [mock.call(call, check_exit_code=False) for call in calls],
            any_order=True)

    def _test_routing_table_update(self, namespace):
        if not namespace:
            self.conf.set_override('use_namespaces', False)

        router_id = _uuid()
        ri = l3_agent.RouterInfo(router_id, self.conf.root_helper,
                                 self.conf.use_namespaces,
                                 None)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        fake_route1 = {'destination': '135.207.0.0/16',
                       'nexthop': '1.2.3.4'}
        fake_route2 = {'destination': '135.207.111.111/32',
                       'nexthop': '1.2.3.4'}

        agent._update_routing_table(ri, 'replace', fake_route1)
        expected = [['ip', 'route', 'replace', 'to', '135.207.0.0/16',
                     'via', '1.2.3.4']]
        self._check_agent_method_called(agent, expected, namespace)

        agent._update_routing_table(ri, 'delete', fake_route1)
        expected = [['ip', 'route', 'delete', 'to', '135.207.0.0/16',
                     'via', '1.2.3.4']]
        self._check_agent_method_called(agent, expected, namespace)

        agent._update_routing_table(ri, 'replace', fake_route2)
        expected = [['ip', 'route', 'replace', 'to', '135.207.111.111/32',
                     'via', '1.2.3.4']]
        self._check_agent_method_called(agent, expected, namespace)

        agent._update_routing_table(ri, 'delete', fake_route2)
        expected = [['ip', 'route', 'delete', 'to', '135.207.111.111/32',
                     'via', '1.2.3.4']]
        self._check_agent_method_called(agent, expected, namespace)

    def test_agent_routing_table_updated(self):
        self._test_routing_table_update(namespace=True)

    def test_agent_routing_table_updated_no_namespace(self):
        self._test_routing_table_update(namespace=False)

    def test_routes_updated(self):
        self._test_routes_updated(namespace=True)

    def test_routes_updated_no_namespace(self):
        self._test_routes_updated(namespace=False)

    def _test_routes_updated(self, namespace=True):
        if not namespace:
            self.conf.set_override('use_namespaces', False)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router_id = _uuid()

        ri = l3_agent.RouterInfo(router_id, self.conf.root_helper,
                                 self.conf.use_namespaces,
                                 None)
        ri.router = {}

        fake_old_routes = []
        fake_new_routes = [{'destination': "110.100.31.0/24",
                            'nexthop': "10.100.10.30"},
                           {'destination': "110.100.30.0/24",
                            'nexthop': "10.100.10.30"}]
        ri.routes = fake_old_routes
        ri.router['routes'] = fake_new_routes
        agent.routes_updated(ri)

        expected = [['ip', 'route', 'replace', 'to', '110.100.30.0/24',
                    'via', '10.100.10.30'],
                    ['ip', 'route', 'replace', 'to', '110.100.31.0/24',
                     'via', '10.100.10.30']]

        self._check_agent_method_called(agent, expected, namespace)

        fake_new_routes = [{'destination': "110.100.30.0/24",
                            'nexthop': "10.100.10.30"}]
        ri.router['routes'] = fake_new_routes
        agent.routes_updated(ri)
        expected = [['ip', 'route', 'delete', 'to', '110.100.31.0/24',
                    'via', '10.100.10.30']]

        self._check_agent_method_called(agent, expected, namespace)
        fake_new_routes = []
        ri.router['routes'] = fake_new_routes
        agent.routes_updated(ri)

        expected = [['ip', 'route', 'delete', 'to', '110.100.30.0/24',
                    'via', '10.100.10.30']]
        self._check_agent_method_called(agent, expected, namespace)

    def _verify_snat_rules(self, rules, router, negate=False):
        interfaces = router[l3_constants.INTERFACE_KEY]
        source_cidrs = []
        for interface in interfaces:
            prefix = interface['subnet']['cidr'].split('/')[1]
            source_cidr = "%s/%s" % (interface['fixed_ips'][0]['ip_address'],
                                     prefix)
            source_cidrs.append(source_cidr)
        source_nat_ip = router['gw_port']['fixed_ips'][0]['ip_address']
        interface_name = ('qg-%s' % router['gw_port']['id'])[:14]
        expected_rules = [
            '! -i %s ! -o %s -m conntrack ! --ctstate DNAT -j ACCEPT' %
            (interface_name, interface_name)]
        for source_cidr in source_cidrs:
            # Create SNAT rules for IPv4 only
            if (netaddr.IPNetwork(source_cidr).version == 4 and
                netaddr.IPNetwork(source_nat_ip).version == 4):
                value_dict = {'source_cidr': source_cidr,
                              'source_nat_ip': source_nat_ip}
                expected_rules.append('-s %(source_cidr)s -j SNAT --to-source '
                                      '%(source_nat_ip)s' % value_dict)
        for r in rules:
            if negate:
                self.assertNotIn(r.rule, expected_rules)
            else:
                self.assertIn(r.rule, expected_rules)

    def _prepare_router_data(self, ip_version=4,
                             enable_snat=None, num_internal_ports=1):
        if ip_version == 4:
            ip_addr = '19.4.4.4'
            cidr = '19.4.4.0/24'
            gateway_ip = '19.4.4.1'
        elif ip_version == 6:
            ip_addr = 'fd00::4'
            cidr = 'fd00::/64'
            gateway_ip = 'fd00::1'

        router_id = _uuid()
        ex_gw_port = {'id': _uuid(),
                      'network_id': _uuid(),
                      'fixed_ips': [{'ip_address': ip_addr,
                                     'subnet_id': _uuid()}],
                      'subnet': {'cidr': cidr,
                                 'gateway_ip': gateway_ip}}
        int_ports = []
        for i in range(num_internal_ports):
            int_ports.append({'id': _uuid(),
                              'network_id': _uuid(),
                              'admin_state_up': True,
                              'fixed_ips': [{'ip_address': '35.4.%s.4' % i,
                                             'subnet_id': _uuid()}],
                              'mac_address': 'ca:fe:de:ad:be:ef',
                              'subnet': {'cidr': '35.4.%s.0/24' % i,
                                         'gateway_ip': '35.4.%s.1' % i}})

        router = {
            'id': router_id,
            l3_constants.INTERFACE_KEY: int_ports,
            'routes': [],
            'gw_port': ex_gw_port}
        if enable_snat is not None:
            router['enable_snat'] = enable_snat
        return router

    def test_process_router(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        fake_fip_id = 'fake_fip_id'
        agent.process_router_floating_ip_addresses = mock.Mock()
        agent.process_router_floating_ip_nat_rules = mock.Mock()
        agent.process_router_floating_ip_addresses.return_value = {
            fake_fip_id: 'ACTIVE'}
        agent.external_gateway_added = mock.Mock()
        router = self._prepare_router_data()
        fake_floatingips1 = {'floatingips': [
            {'id': fake_fip_id,
             'floating_ip_address': '8.8.8.8',
             'fixed_ip_address': '7.7.7.7',
             'port_id': _uuid()}]}
        ri = l3_agent.RouterInfo(router['id'], self.conf.root_helper,
                                 self.conf.use_namespaces, router=router)
        agent.process_router(ri)
        ex_gw_port = agent._get_ex_gw_port(ri)
        agent.process_router_floating_ip_addresses.assert_called_with(
            ri, ex_gw_port)
        agent.process_router_floating_ip_addresses.reset_mock()
        agent.process_router_floating_ip_nat_rules.assert_called_with(ri)
        agent.process_router_floating_ip_nat_rules.reset_mock()

        # remap floating IP to a new fixed ip
        fake_floatingips2 = copy.deepcopy(fake_floatingips1)
        fake_floatingips2['floatingips'][0]['fixed_ip_address'] = '7.7.7.8'

        router[l3_constants.FLOATINGIP_KEY] = fake_floatingips2['floatingips']
        agent.process_router(ri)
        ex_gw_port = agent._get_ex_gw_port(ri)
        agent.process_router_floating_ip_addresses.assert_called_with(
            ri, ex_gw_port)
        agent.process_router_floating_ip_addresses.reset_mock()
        agent.process_router_floating_ip_nat_rules.assert_called_with(ri)
        agent.process_router_floating_ip_nat_rules.reset_mock()

        # remove just the floating ips
        del router[l3_constants.FLOATINGIP_KEY]
        agent.process_router(ri)
        ex_gw_port = agent._get_ex_gw_port(ri)
        agent.process_router_floating_ip_addresses.assert_called_with(
            ri, ex_gw_port)
        agent.process_router_floating_ip_addresses.reset_mock()
        agent.process_router_floating_ip_nat_rules.assert_called_with(ri)
        agent.process_router_floating_ip_nat_rules.reset_mock()

        # now no ports so state is torn down
        del router[l3_constants.INTERFACE_KEY]
        del router['gw_port']
        agent.process_router(ri)
        self.send_arp.assert_called_once()
        self.assertFalse(agent.process_router_floating_ip_addresses.called)
        self.assertFalse(agent.process_router_floating_ip_nat_rules.called)

    @mock.patch('neutron.agent.linux.ip_lib.IPDevice')
    def test_process_router_floating_ip_addresses_add(self, IPDevice):
        fip_id = _uuid()
        fip = {
            'id': fip_id, 'port_id': _uuid(),
            'floating_ip_address': '15.1.2.3',
            'fixed_ip_address': '192.168.0.1'
        }

        IPDevice.return_value = device = mock.Mock()
        device.addr.list.return_value = []

        ri = mock.MagicMock()
        ri.router.get.return_value = [fip]

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        fip_statuses = agent.process_router_floating_ip_addresses(
            ri, {'id': _uuid()})
        self.assertEqual({fip_id: l3_constants.FLOATINGIP_STATUS_ACTIVE},
                         fip_statuses)
        device.addr.add.assert_called_once_with(4, '15.1.2.3/32', '15.1.2.3')

    def test_process_router_floating_ip_nat_rules_add(self):
        fip = {
            'id': _uuid(), 'port_id': _uuid(),
            'floating_ip_address': '15.1.2.3',
            'fixed_ip_address': '192.168.0.1'
        }

        ri = mock.MagicMock()
        ri.router.get.return_value = [fip]

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        agent.process_router_floating_ip_nat_rules(ri)

        nat = ri.iptables_manager.ipv4['nat']
        nat.clear_rules_by_tag.assert_called_once_with('floating_ip')
        rules = agent.floating_forward_rules('15.1.2.3', '192.168.0.1')
        for chain, rule in rules:
            nat.add_rule.assert_any_call(chain, rule, tag='floating_ip')

    @mock.patch('neutron.agent.linux.ip_lib.IPDevice')
    def test_process_router_floating_ip_addresses_remove(self, IPDevice):
        IPDevice.return_value = device = mock.Mock()
        device.addr.list.return_value = [{'cidr': '15.1.2.3/32'}]

        ri = mock.MagicMock()
        ri.router.get.return_value = []

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        fip_statuses = agent.process_router_floating_ip_addresses(
            ri, {'id': _uuid()})
        self.assertEqual({}, fip_statuses)
        device.addr.delete.assert_called_once_with(4, '15.1.2.3/32')

    def test_process_router_floating_ip_nat_rules_remove(self):
        ri = mock.MagicMock()
        ri.router.get.return_value = []

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        agent.process_router_floating_ip_nat_rules(ri)

        nat = ri.iptables_manager.ipv4['nat']
        nat = ri.iptables_manager.ipv4['nat`']
        nat.clear_rules_by_tag.assert_called_once_with('floating_ip')

    @mock.patch('neutron.agent.linux.ip_lib.IPDevice')
    def test_process_router_floating_ip_addresses_remap(self, IPDevice):
        fip_id = _uuid()
        fip = {
            'id': fip_id, 'port_id': _uuid(),
            'floating_ip_address': '15.1.2.3',
            'fixed_ip_address': '192.168.0.2'
        }

        IPDevice.return_value = device = mock.Mock()
        device.addr.list.return_value = [{'cidr': '15.1.2.3/32'}]
        ri = mock.MagicMock()

        ri.router.get.return_value = [fip]

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        fip_statuses = agent.process_router_floating_ip_addresses(
            ri, {'id': _uuid()})
        self.assertEqual({fip_id: l3_constants.FLOATINGIP_STATUS_ACTIVE},
                         fip_statuses)

        self.assertFalse(device.addr.add.called)
        self.assertFalse(device.addr.delete.called)

    @mock.patch('neutron.agent.linux.ip_lib.IPDevice')
    def test_process_router_with_disabled_floating_ip(self, IPDevice):
        fip_id = _uuid()
        fip = {
            'id': fip_id, 'port_id': _uuid(),
            'floating_ip_address': '15.1.2.3',
            'fixed_ip_address': '192.168.0.2'
        }

        ri = mock.MagicMock()
        ri.floating_ips = [fip]
        ri.router.get.return_value = []

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        fip_statuses = agent.process_router_floating_ip_addresses(
            ri, {'id': _uuid()})

        self.assertIsNone(fip_statuses.get(fip_id))

    @mock.patch('neutron.agent.linux.ip_lib.IPDevice')
    def test_process_router_floating_ip_with_device_add_error(self, IPDevice):
        IPDevice.return_value = device = mock.Mock()
        device.addr.add.side_effect = processutils.ProcessExecutionError
        device.addr.list.return_value = []
        fip_id = _uuid()
        fip = {
            'id': fip_id, 'port_id': _uuid(),
            'floating_ip_address': '15.1.2.3',
            'fixed_ip_address': '192.168.0.2'
        }
        ri = mock.MagicMock()
        ri.router.get.return_value = [fip]

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        fip_statuses = agent.process_router_floating_ip_addresses(
            ri, {'id': _uuid()})

        self.assertEqual({fip_id: l3_constants.FLOATINGIP_STATUS_ERROR},
                         fip_statuses)

    def test_process_router_snat_disabled(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = self._prepare_router_data(enable_snat=True)
        ri = l3_agent.RouterInfo(router['id'], self.conf.root_helper,
                                 self.conf.use_namespaces, router=router)
        agent.external_gateway_added = mock.Mock()
        # Process with NAT
        agent.process_router(ri)
        orig_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]
        # Reprocess without NAT
        router['enable_snat'] = False
        # Reassign the router object to RouterInfo
        ri.router = router
        agent.process_router(ri)
        # For some reason set logic does not work well with
        # IpTablesRule instances
        nat_rules_delta = [r for r in orig_nat_rules
                           if r not in ri.iptables_manager.ipv4['nat'].rules]
        self.assertEqual(len(nat_rules_delta), 2)
        self._verify_snat_rules(nat_rules_delta, router)
        self.send_arp.assert_called_once()

    def test_process_router_snat_enabled(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = self._prepare_router_data(enable_snat=False)
        ri = l3_agent.RouterInfo(router['id'], self.conf.root_helper,
                                 self.conf.use_namespaces, router=router)
        agent.external_gateway_added = mock.Mock()
        # Process without NAT
        agent.process_router(ri)
        orig_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]
        # Reprocess with NAT
        router['enable_snat'] = True
        # Reassign the router object to RouterInfo
        ri.router = router
        agent.process_router(ri)
        # For some reason set logic does not work well with
        # IpTablesRule instances
        nat_rules_delta = [r for r in ri.iptables_manager.ipv4['nat'].rules
                           if r not in orig_nat_rules]
        self.assertEqual(len(nat_rules_delta), 2)
        self._verify_snat_rules(nat_rules_delta, router)
        self.send_arp.assert_called_once()

    def test_process_router_interface_added(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = self._prepare_router_data()
        ri = l3_agent.RouterInfo(router['id'], self.conf.root_helper,
                                 self.conf.use_namespaces, router=router)
        agent.external_gateway_added = mock.Mock()
        # Process with NAT
        agent.process_router(ri)
        orig_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]
        # Add an interface and reprocess
        router[l3_constants.INTERFACE_KEY].append(
            {'id': _uuid(),
             'network_id': _uuid(),
             'admin_state_up': True,
             'fixed_ips': [{'ip_address': '35.4.1.4',
                            'subnet_id': _uuid()}],
             'mac_address': 'ca:fe:de:ad:be:ef',
             'subnet': {'cidr': '35.4.1.0/24',
                        'gateway_ip': '35.4.1.1'}})
        # Reassign the router object to RouterInfo
        ri.router = router
        agent.process_router(ri)
        # For some reason set logic does not work well with
        # IpTablesRule instances
        nat_rules_delta = [r for r in ri.iptables_manager.ipv4['nat'].rules
                           if r not in orig_nat_rules]
        self.assertEqual(len(nat_rules_delta), 1)
        self._verify_snat_rules(nat_rules_delta, router)
        self.send_arp.assert_called_once()

    def test_process_ipv6_only_gw(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = self._prepare_router_data(ip_version=6)
        # Get NAT rules without the gw_port
        gw_port = router['gw_port']
        router['gw_port'] = None
        ri = l3_agent.RouterInfo(router['id'], self.conf.root_helper,
                                 self.conf.use_namespaces, router=router)
        agent.external_gateway_added = mock.Mock()
        agent.process_router(ri)
        orig_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]

        # Get NAT rules with the gw_port
        router['gw_port'] = gw_port
        ri = l3_agent.RouterInfo(router['id'], self.conf.root_helper,
                                 self.conf.use_namespaces, router=router)
        with mock.patch.object(
                agent,
                'external_gateway_nat_rules') as external_gateway_nat_rules:
            agent.process_router(ri)
            new_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]

            # There should be no change with the NAT rules
            self.assertFalse(external_gateway_nat_rules.called)
            self.assertEqual(orig_nat_rules, new_nat_rules)

    def test_process_router_ipv6_interface_added(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = self._prepare_router_data()
        ri = l3_agent.RouterInfo(router['id'], self.conf.root_helper,
                                 self.conf.use_namespaces, router=router)
        agent.external_gateway_added = mock.Mock()
        # Process with NAT
        agent.process_router(ri)
        orig_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]
        # Add an IPv6 interface and reprocess
        router[l3_constants.INTERFACE_KEY].append(
            {'id': _uuid(),
             'network_id': _uuid(),
             'admin_state_up': True,
             'fixed_ips': [{'ip_address': 'fd00::2',
                            'subnet_id': _uuid()}],
             'mac_address': 'ca:fe:de:ad:be:ef',
             'subnet': {'cidr': 'fd00::/64',
                        'gateway_ip': 'fd00::1'}})
        # Reassign the router object to RouterInfo
        ri.router = router
        agent.process_router(ri)
        # For some reason set logic does not work well with
        # IpTablesRule instances
        nat_rules_delta = [r for r in ri.iptables_manager.ipv4['nat'].rules
                           if r not in orig_nat_rules]
        self.assertFalse(nat_rules_delta)

    def test_process_router_ipv6v4_interface_added(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = self._prepare_router_data()
        ri = l3_agent.RouterInfo(router['id'], self.conf.root_helper,
                                 self.conf.use_namespaces, router=router)
        agent.external_gateway_added = mock.Mock()
        # Process with NAT
        agent.process_router(ri)
        orig_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]
        # Add an IPv4 and IPv6 interface and reprocess
        router[l3_constants.INTERFACE_KEY].append(
            {'id': _uuid(),
             'network_id': _uuid(),
             'admin_state_up': True,
             'fixed_ips': [{'ip_address': '35.4.1.4',
                            'subnet_id': _uuid()}],
             'mac_address': 'ca:fe:de:ad:be:ef',
             'subnet': {'cidr': '35.4.1.0/24',
                        'gateway_ip': '35.4.1.1'}})

        router[l3_constants.INTERFACE_KEY].append(
            {'id': _uuid(),
             'network_id': _uuid(),
             'admin_state_up': True,
             'fixed_ips': [{'ip_address': 'fd00::2',
                            'subnet_id': _uuid()}],
             'mac_address': 'ca:fe:de:ad:be:ef',
             'subnet': {'cidr': 'fd00::/64',
                        'gateway_ip': 'fd00::1'}})
        # Reassign the router object to RouterInfo
        ri.router = router
        agent.process_router(ri)
        # For some reason set logic does not work well with
        # IpTablesRule instances
        nat_rules_delta = [r for r in ri.iptables_manager.ipv4['nat'].rules
                           if r not in orig_nat_rules]
        self.assertEqual(1, len(nat_rules_delta))
        self._verify_snat_rules(nat_rules_delta, router)

    def test_process_router_interface_removed(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = self._prepare_router_data(num_internal_ports=2)
        ri = l3_agent.RouterInfo(router['id'], self.conf.root_helper,
                                 self.conf.use_namespaces, router=router)
        agent.external_gateway_added = mock.Mock()
        # Process with NAT
        agent.process_router(ri)
        orig_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]
        # Add an interface and reprocess
        del router[l3_constants.INTERFACE_KEY][1]
        # Reassign the router object to RouterInfo
        ri.router = router
        agent.process_router(ri)
        # For some reason set logic does not work well with
        # IpTablesRule instances
        nat_rules_delta = [r for r in orig_nat_rules
                           if r not in ri.iptables_manager.ipv4['nat'].rules]
        self.assertEqual(len(nat_rules_delta), 1)
        self._verify_snat_rules(nat_rules_delta, router, negate=True)
        self.send_arp.assert_called_once()

    def test_process_router_internal_network_added_unexpected_error(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = self._prepare_router_data()
        ri = l3_agent.RouterInfo(router['id'], self.conf.root_helper,
                                 self.conf.use_namespaces, router=router)
        agent.external_gateway_added = mock.Mock()
        with mock.patch.object(
                l3_agent.L3NATAgent,
                'internal_network_added') as internal_network_added:
            # raise RuntimeError to simulate that an unexpected exception
            # occurrs
            internal_network_added.side_effect = RuntimeError
            self.assertRaises(RuntimeError, agent.process_router, ri)
            self.assertNotIn(
                router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

            # The unexpected exception has been fixed manually
            internal_network_added.side_effect = None

            # _sync_routers_task finds out that _rpc_loop failed to process the
            # router last time, it will retry in the next run.
            agent.process_router(ri)
            # We were able to add the port to ri.internal_ports
            self.assertIn(
                router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

    def test_process_router_internal_network_removed_unexpected_error(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = self._prepare_router_data()
        ri = l3_agent.RouterInfo(router['id'], self.conf.root_helper,
                                 self.conf.use_namespaces, router=router)
        agent.external_gateway_added = mock.Mock()
        # add an internal port
        agent.process_router(ri)

        with mock.patch.object(
                l3_agent.L3NATAgent,
                'internal_network_removed') as internal_net_removed:
            # raise RuntimeError to simulate that an unexpected exception
            # occurrs
            internal_net_removed.side_effect = RuntimeError
            ri.internal_ports[0]['admin_state_up'] = False
            # The above port is set to down state, remove it.
            self.assertRaises(RuntimeError, agent.process_router, ri)
            self.assertIn(
                router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

            # The unexpected exception has been fixed manually
            internal_net_removed.side_effect = None

            # _sync_routers_task finds out that _rpc_loop failed to process the
            # router last time, it will retry in the next run.
            agent.process_router(ri)
            # We were able to remove the port from ri.internal_ports
            self.assertNotIn(
                router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

    def test_process_router_floatingip_disabled(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        with mock.patch.object(
            agent.plugin_rpc,
            'update_floatingip_statuses') as mock_update_fip_status:
            fip_id = _uuid()
            router = self._prepare_router_data(num_internal_ports=1)
            router[l3_constants.FLOATINGIP_KEY] = [
                {'id': fip_id,
                 'floating_ip_address': '8.8.8.8',
                 'fixed_ip_address': '7.7.7.7',
                 'port_id': router[l3_constants.INTERFACE_KEY][0]['id']}]

            ri = l3_agent.RouterInfo(router['id'], self.conf.root_helper,
                                     self.conf.use_namespaces, router=router)
            agent.external_gateway_added = mock.Mock()
            agent.process_router(ri)
            # Assess the call for putting the floating IP up was performed
            mock_update_fip_status.assert_called_once_with(
                mock.ANY, ri.router_id,
                {fip_id: l3_constants.FLOATINGIP_STATUS_ACTIVE})
            mock_update_fip_status.reset_mock()
            # Process the router again, this time without floating IPs
            router[l3_constants.FLOATINGIP_KEY] = []
            ri.router = router
            agent.process_router(ri)
            # Assess the call for putting the floating IP up was performed
            mock_update_fip_status.assert_called_once_with(
                mock.ANY, ri.router_id,
                {fip_id: l3_constants.FLOATINGIP_STATUS_DOWN})

    def test_process_router_floatingip_exception(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.process_router_floating_ip_addresses = mock.Mock()
        agent.process_router_floating_ip_addresses.side_effect = RuntimeError
        with mock.patch.object(
            agent.plugin_rpc,
            'update_floatingip_statuses') as mock_update_fip_status:
            fip_id = _uuid()
            router = self._prepare_router_data(num_internal_ports=1)
            router[l3_constants.FLOATINGIP_KEY] = [
                {'id': fip_id,
                 'floating_ip_address': '8.8.8.8',
                 'fixed_ip_address': '7.7.7.7',
                 'port_id': router[l3_constants.INTERFACE_KEY][0]['id']}]

            ri = l3_agent.RouterInfo(router['id'], self.conf.root_helper,
                                     self.conf.use_namespaces, router=router)
            agent.external_gateway_added = mock.Mock()
            agent.process_router(ri)
            # Assess the call for putting the floating IP into Error
            # was performed
            mock_update_fip_status.assert_called_once_with(
                mock.ANY, ri.router_id,
                {fip_id: l3_constants.FLOATINGIP_STATUS_ERROR})

    def test_handle_router_snat_rules_add_back_jump(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = mock.MagicMock()
        port = {'fixed_ips': [{'ip_address': '192.168.1.4'}]}

        agent._handle_router_snat_rules(ri, port, [], "iface", "add_rules")

        nat = ri.iptables_manager.ipv4['nat']
        nat.empty_chain.assert_any_call('snat')
        nat.add_rule.assert_any_call('snat', '-j $float-snat')
        for call in nat.mock_calls:
            name, args, kwargs = call
            if name == 'add_rule':
                self.assertEqual(args, ('snat', '-j $float-snat'))
                self.assertEqual(kwargs, {})
                break

    def test_handle_router_snat_rules_add_rules(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = l3_agent.RouterInfo(_uuid(), self.conf.root_helper,
                                 self.conf.use_namespaces, None)
        ex_gw_port = {'fixed_ips': [{'ip_address': '192.168.1.4'}]}
        internal_cidrs = ['10.0.0.0/24']
        agent._handle_router_snat_rules(ri, ex_gw_port, internal_cidrs,
                                        "iface", "add_rules")

        nat_rules = map(str, ri.iptables_manager.ipv4['nat'].rules)
        wrap_name = ri.iptables_manager.wrap_name

        jump_float_rule = "-A %s-snat -j %s-float-snat" % (wrap_name,
                                                           wrap_name)
        internal_net_rule = ("-A %s-snat -s %s -j SNAT --to-source %s") % (
            wrap_name, internal_cidrs[0],
            ex_gw_port['fixed_ips'][0]['ip_address'])

        self.assertIn(jump_float_rule, nat_rules)

        self.assertIn(internal_net_rule, nat_rules)
        self.assertThat(nat_rules.index(jump_float_rule),
                        matchers.LessThan(nat_rules.index(internal_net_rule)))

    def test_process_router_delete_stale_internal_devices(self):
        class FakeDev(object):
            def __init__(self, name):
                self.name = name

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        stale_devlist = [FakeDev('qr-a1b2c3d4-e5'),
                         FakeDev('qr-b2c3d4e5-f6')]
        stale_devnames = [dev.name for dev in stale_devlist]

        get_devices_return = []
        get_devices_return.extend(stale_devlist)
        self.mock_ip.get_devices.return_value = get_devices_return

        router = self._prepare_router_data(enable_snat=True,
                                           num_internal_ports=1)
        ri = l3_agent.RouterInfo(router['id'],
                                 self.conf.root_helper,
                                 self.conf.use_namespaces,
                                 router=router)

        internal_ports = ri.router.get(l3_constants.INTERFACE_KEY, [])
        self.assertEqual(len(internal_ports), 1)
        internal_port = internal_ports[0]

        with contextlib.nested(mock.patch.object(l3_agent.L3NATAgent,
                                                 'internal_network_removed'),
                               mock.patch.object(l3_agent.L3NATAgent,
                                                 'internal_network_added'),
                               mock.patch.object(l3_agent.L3NATAgent,
                                                 'external_gateway_removed'),
                               mock.patch.object(l3_agent.L3NATAgent,
                                                 'external_gateway_added')
                               ) as (internal_network_removed,
                                     internal_network_added,
                                     external_gateway_removed,
                                     external_gateway_added):

            agent.process_router(ri)

            self.assertEqual(external_gateway_added.call_count, 1)
            self.assertFalse(external_gateway_removed.called)
            self.assertFalse(internal_network_removed.called)
            internal_network_added.assert_called_once_with(
                ri,
                internal_port['network_id'],
                internal_port['id'],
                internal_port['ip_cidr'],
                internal_port['mac_address'])
            self.assertEqual(self.mock_driver.unplug.call_count,
                             len(stale_devnames))
            calls = [mock.call(stale_devname,
                               namespace=ri.ns_name,
                               prefix=l3_agent.INTERNAL_DEV_PREFIX)
                     for stale_devname in stale_devnames]
            self.mock_driver.unplug.assert_has_calls(calls, any_order=True)

    def test_process_router_delete_stale_external_devices(self):
        class FakeDev(object):
            def __init__(self, name):
                self.name = name

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        stale_devlist = [FakeDev('qg-a1b2c3d4-e5')]
        stale_devnames = [dev.name for dev in stale_devlist]

        router = self._prepare_router_data(enable_snat=True,
                                           num_internal_ports=1)
        del router['gw_port']
        ri = l3_agent.RouterInfo(router['id'],
                                 self.conf.root_helper,
                                 self.conf.use_namespaces,
                                 router=router)

        self.mock_ip.get_devices.return_value = stale_devlist

        agent.process_router(ri)

        self.mock_driver.unplug.assert_called_with(
            stale_devnames[0],
            bridge="br-ex",
            namespace=ri.ns_name,
            prefix=l3_agent.EXTERNAL_DEV_PREFIX)

    def test_router_deleted(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.router_deleted(None, FAKE_ID)
        # verify that will set fullsync
        self.assertIn(FAKE_ID, agent.removed_routers)

    def test_routers_updated(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.routers_updated(None, [FAKE_ID])
        # verify that will set fullsync
        self.assertIn(FAKE_ID, agent.updated_routers)

    def test_removed_from_agent(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.router_removed_from_agent(None, {'router_id': FAKE_ID})
        # verify that will set fullsync
        self.assertIn(FAKE_ID, agent.removed_routers)

    def test_added_to_agent(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.router_added_to_agent(None, [FAKE_ID])
        # verify that will set fullsync
        self.assertIn(FAKE_ID, agent.updated_routers)

    def test_process_router_delete(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ex_gw_port = {'id': _uuid(),
                      'network_id': _uuid(),
                      'fixed_ips': [{'ip_address': '19.4.4.4',
                                     'subnet_id': _uuid()}],
                      'subnet': {'cidr': '19.4.4.0/24',
                                 'gateway_ip': '19.4.4.1'}}
        router = {
            'id': _uuid(),
            'enable_snat': True,
            'routes': [],
            'gw_port': ex_gw_port}
        agent._router_added(router['id'], router)
        agent.router_deleted(None, router['id'])
        agent._process_router_delete()
        self.assertFalse(list(agent.removed_routers))

    def test_destroy_router_namespace_skips_ns_removal(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._destroy_router_namespace("fakens")
        self.assertEqual(self.mock_ip.netns.delete.call_count, 0)

    def test_destroy_router_namespace_removes_ns(self):
        self.conf.set_override('router_delete_namespaces', True)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._destroy_router_namespace("fakens")
        self.mock_ip.netns.delete.assert_called_once_with("fakens")

    def _configure_metadata_proxy(self, enableflag=True):
        if not enableflag:
            self.conf.set_override('enable_metadata_proxy', False)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router_id = _uuid()
        router = {'id': _uuid(),
                  'external_gateway_info': {},
                  'routes': []}
        with mock.patch.object(
            agent, '_destroy_metadata_proxy') as destroy_proxy:
            with mock.patch.object(
                agent, '_spawn_metadata_proxy') as spawn_proxy:
                agent._router_added(router_id, router)
                if enableflag:
                    spawn_proxy.assert_called_with(mock.ANY, mock.ANY)
                else:
                    self.assertFalse(spawn_proxy.call_count)
                agent._router_removed(router_id)
                if enableflag:
                    destroy_proxy.assert_called_with(mock.ANY, mock.ANY)
                else:
                    self.assertFalse(destroy_proxy.call_count)

    def test_enable_metadata_proxy(self):
        self._configure_metadata_proxy()

    def test_disable_metadata_proxy_spawn(self):
        self._configure_metadata_proxy(enableflag=False)

    def test_metadata_nat_rules(self):
        self.conf.set_override('enable_metadata_proxy', False)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.assertEqual([], agent.metadata_nat_rules())

        self.conf.set_override('metadata_port', '8775')
        self.conf.set_override('enable_metadata_proxy', True)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        rules = ('PREROUTING', '-s 0.0.0.0/0 -d 169.254.169.254/32 '
                 '-p tcp -m tcp --dport 80 -j REDIRECT --to-port 8775')
        self.assertEqual([rules], agent.metadata_nat_rules())

    def test_router_id_specified_in_conf(self):
        self.conf.set_override('use_namespaces', False)
        self.conf.set_override('router_id', '')
        self.assertRaises(SystemExit, l3_agent.L3NATAgent,
                          HOSTNAME, self.conf)

        self.conf.set_override('router_id', '1234')
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.assertEqual(['1234'], agent._router_ids())
        self.assertFalse(agent._delete_stale_namespaces)

    def test_process_routers_with_no_ext_net_in_conf(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.plugin_api.get_external_network_id.return_value = 'aaa'

        routers = [
            {'id': _uuid(),
             'routes': [],
             'admin_state_up': True,
             'external_gateway_info': {'network_id': 'aaa'}}]

        agent._process_routers(routers)
        self.assertIn(routers[0]['id'], agent.router_info)
        self.plugin_api.get_external_network_id.assert_called_with(
            agent.context)

    def test_process_routers_with_cached_ext_net(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.plugin_api.get_external_network_id.return_value = 'aaa'
        agent.target_ex_net_id = 'aaa'

        routers = [
            {'id': _uuid(),
             'routes': [],
             'admin_state_up': True,
             'external_gateway_info': {'network_id': 'aaa'}}]

        agent._process_routers(routers)
        self.assertIn(routers[0]['id'], agent.router_info)
        self.assertFalse(self.plugin_api.get_external_network_id.called)

    def test_process_routers_with_stale_cached_ext_net(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.plugin_api.get_external_network_id.return_value = 'aaa'
        agent.target_ex_net_id = 'bbb'

        routers = [
            {'id': _uuid(),
             'routes': [],
             'admin_state_up': True,
             'external_gateway_info': {'network_id': 'aaa'}}]

        agent._process_routers(routers)
        self.assertIn(routers[0]['id'], agent.router_info)
        self.plugin_api.get_external_network_id.assert_called_with(
            agent.context)

    def test_process_routers_with_no_ext_net_in_conf_and_two_net_plugin(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        routers = [
            {'id': _uuid(),
             'routes': [],
             'admin_state_up': True,
             'external_gateway_info': {'network_id': 'aaa'}}]

        agent.router_info = {}
        self.plugin_api.get_external_network_id.side_effect = (
            n_exc.TooManyExternalNetworks())
        self.assertRaises(n_exc.TooManyExternalNetworks,
                          agent._process_routers,
                          routers)
        self.assertNotIn(routers[0]['id'], agent.router_info)

    def test_process_routers_with_ext_net_in_conf(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.plugin_api.get_external_network_id.return_value = 'aaa'

        routers = [
            {'id': _uuid(),
             'routes': [],
             'admin_state_up': True,
             'external_gateway_info': {'network_id': 'aaa'}},
            {'id': _uuid(),
             'routes': [],
             'admin_state_up': True,
             'external_gateway_info': {'network_id': 'bbb'}}]

        agent.router_info = {}
        self.conf.set_override('gateway_external_network_id', 'aaa')
        agent._process_routers(routers)
        self.assertIn(routers[0]['id'], agent.router_info)
        self.assertNotIn(routers[1]['id'], agent.router_info)

    def test_process_routers_with_no_bridge_no_ext_net_in_conf(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.plugin_api.get_external_network_id.return_value = 'aaa'

        routers = [
            {'id': _uuid(),
             'routes': [],
             'admin_state_up': True,
             'external_gateway_info': {'network_id': 'aaa'}},
            {'id': _uuid(),
             'routes': [],
             'admin_state_up': True,
             'external_gateway_info': {'network_id': 'bbb'}}]

        agent.router_info = {}
        self.conf.set_override('external_network_bridge', '')
        agent._process_routers(routers)
        self.assertIn(routers[0]['id'], agent.router_info)
        self.assertIn(routers[1]['id'], agent.router_info)

    def test_nonexistent_interface_driver(self):
        self.conf.set_override('interface_driver', None)
        with mock.patch.object(l3_agent, 'LOG') as log:
            self.assertRaises(SystemExit, l3_agent.L3NATAgent,
                              HOSTNAME, self.conf)
            msg = 'An interface driver must be specified'
            log.error.assert_called_once_with(msg)

        self.conf.set_override('interface_driver', 'wrong_driver')
        with mock.patch.object(l3_agent, 'LOG') as log:
            self.assertRaises(SystemExit, l3_agent.L3NATAgent,
                              HOSTNAME, self.conf)
            msg = "Error importing interface driver 'wrong_driver'"
            log.error.assert_called_once_with(msg)

    def test_metadata_filter_rules(self):
        self.conf.set_override('enable_metadata_proxy', False)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.assertEqual([], agent.metadata_filter_rules())

        self.conf.set_override('metadata_port', '8775')
        self.conf.set_override('enable_metadata_proxy', True)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        rules = ('INPUT', '-s 0.0.0.0/0 -d 127.0.0.1 '
                 '-p tcp -m tcp --dport 8775 -j ACCEPT')
        self.assertEqual([rules], agent.metadata_filter_rules())

    def _cleanup_namespace_test(self,
                                stale_namespace_list,
                                router_list,
                                other_namespaces):
        self.conf.set_override('router_delete_namespaces', True)

        good_namespace_list = [l3_agent.NS_PREFIX + r['id']
                               for r in router_list]
        self.mock_ip.get_namespaces.return_value = (stale_namespace_list +
                                                    good_namespace_list +
                                                    other_namespaces)

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        self.assertTrue(agent._delete_stale_namespaces)

        pm = self.external_process.return_value
        pm.reset_mock()

        agent._destroy_router_namespace = mock.MagicMock()
        agent._cleanup_namespaces(router_list)

        self.assertEqual(pm.disable.call_count, len(stale_namespace_list))
        self.assertEqual(agent._destroy_router_namespace.call_count,
                         len(stale_namespace_list))
        expected_args = [mock.call(ns) for ns in stale_namespace_list]
        agent._destroy_router_namespace.assert_has_calls(expected_args,
                                                         any_order=True)
        self.assertFalse(agent._delete_stale_namespaces)

    def test_cleanup_namespace(self):
        self.conf.set_override('router_id', None)
        stale_namespaces = [l3_agent.NS_PREFIX + 'foo',
                            l3_agent.NS_PREFIX + 'bar']
        other_namespaces = ['unknown']

        self._cleanup_namespace_test(stale_namespaces,
                                     [],
                                     other_namespaces)

    def test_cleanup_namespace_with_registered_router_ids(self):
        self.conf.set_override('router_id', None)
        stale_namespaces = [l3_agent.NS_PREFIX + 'cccc',
                            l3_agent.NS_PREFIX + 'eeeee']
        router_list = [{'id': 'foo'}, {'id': 'aaaa'}]
        other_namespaces = ['qdhcp-aabbcc', 'unknown']

        self._cleanup_namespace_test(stale_namespaces,
                                     router_list,
                                     other_namespaces)

    def test_cleanup_namespace_with_conf_router_id(self):
        self.conf.set_override('router_id', 'bbbbb')
        stale_namespaces = [l3_agent.NS_PREFIX + 'cccc',
                            l3_agent.NS_PREFIX + 'eeeee',
                            l3_agent.NS_PREFIX + self.conf.router_id]
        router_list = [{'id': 'foo'}, {'id': 'aaaa'}]
        other_namespaces = ['qdhcp-aabbcc', 'unknown']

        self._cleanup_namespace_test(stale_namespaces,
                                     router_list,
                                     other_namespaces)


class TestL3AgentEventHandler(base.BaseTestCase):

    def setUp(self):
        super(TestL3AgentEventHandler, self).setUp()
        cfg.CONF.register_opts(l3_agent.L3NATAgent.OPTS)
        cfg.CONF.set_override(
            'interface_driver', 'neutron.agent.linux.interface.NullDriver'
        )
        cfg.CONF.set_override('use_namespaces', True)
        agent_config.register_root_helper(cfg.CONF)

        device_exists_p = mock.patch(
            'neutron.agent.linux.ip_lib.device_exists')
        device_exists_p.start()

        utils_exec_p = mock.patch(
            'neutron.agent.linux.utils.execute')
        utils_exec_p.start()

        drv_cls_p = mock.patch('neutron.agent.linux.interface.NullDriver')
        driver_cls = drv_cls_p.start()
        mock_driver = mock.MagicMock()
        mock_driver.DEV_NAME_LEN = (
            interface.LinuxInterfaceDriver.DEV_NAME_LEN)
        driver_cls.return_value = mock_driver

        l3_plugin_p = mock.patch(
            'neutron.agent.l3_agent.L3PluginApi')
        l3_plugin_cls = l3_plugin_p.start()
        l3_plugin_cls.return_value = mock.Mock()

        self.external_process_p = mock.patch(
            'neutron.agent.linux.external_process.ProcessManager'
        )
        self.external_process_p.start()
        looping_call_p = mock.patch(
            'neutron.openstack.common.loopingcall.FixedIntervalLoopingCall')
        looping_call_p.start()
        self.agent = l3_agent.L3NATAgent(HOSTNAME)

    def test_spawn_metadata_proxy(self):
        router_id = _uuid()
        metadata_port = 8080
        ip_class_path = 'neutron.agent.linux.ip_lib.IPWrapper'

        cfg.CONF.set_override('metadata_port', metadata_port)
        cfg.CONF.set_override('log_file', 'test.log')
        cfg.CONF.set_override('debug', True)

        self.external_process_p.stop()
        ns = 'qrouter-' + router_id
        try:
            with mock.patch(ip_class_path) as ip_mock:
                self.agent._spawn_metadata_proxy(router_id, ns)
                ip_mock.assert_has_calls([
                    mock.call('sudo', ns),
                    mock.call().netns.execute([
                        'neutron-ns-metadata-proxy',
                        mock.ANY,
                        mock.ANY,
                        '--router_id=%s' % router_id,
                        mock.ANY,
                        '--metadata_port=%s' % metadata_port,
                        '--debug',
                        '--log-file=neutron-ns-metadata-proxy-%s.log' %
                        router_id
                    ])
                ])
        finally:
            self.external_process_p.start()
