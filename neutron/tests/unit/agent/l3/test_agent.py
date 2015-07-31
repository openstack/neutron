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

import copy

import eventlet
from itertools import chain as iter_chain
from itertools import combinations as iter_combinations
import mock
import netaddr
from oslo_log import log
import oslo_messaging
from oslo_utils import uuidutils
from testtools import matchers

from neutron.agent.common import config as agent_config
from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import config as l3_config
from neutron.agent.l3 import dvr_edge_router as dvr_router
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import ha
from neutron.agent.l3 import legacy_router
from neutron.agent.l3 import link_local_allocator as lla
from neutron.agent.l3 import namespaces
from neutron.agent.l3 import router_info as l3router
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent.linux import ra
from neutron.agent.metadata import driver as metadata_driver
from neutron.agent import rpc as agent_rpc
from neutron.common import config as base_config
from neutron.common import constants as l3_constants
from neutron.common import exceptions as n_exc
from neutron.plugins.common import constants as p_const
from neutron.tests import base
from neutron.tests.common import l3_test_common

_uuid = uuidutils.generate_uuid
HOSTNAME = 'myhost'
FAKE_ID = _uuid()
FAKE_ID_2 = _uuid()
FIP_PRI = 32768


class BasicRouterOperationsFramework(base.BaseTestCase):
    def setUp(self):
        super(BasicRouterOperationsFramework, self).setUp()
        mock.patch('eventlet.spawn').start()
        self.conf = agent_config.setup_conf()
        self.conf.register_opts(base_config.core_opts)
        log.register_options(self.conf)
        self.conf.register_opts(agent_config.AGENT_STATE_OPTS, 'AGENT')
        self.conf.register_opts(l3_config.OPTS)
        self.conf.register_opts(ha.OPTS)
        agent_config.register_interface_driver_opts_helper(self.conf)
        agent_config.register_use_namespaces_opts_helper(self.conf)
        agent_config.register_process_monitor_opts(self.conf)
        self.conf.register_opts(interface.OPTS)
        self.conf.register_opts(external_process.OPTS)
        self.conf.set_override('router_id', 'fake_id')
        self.conf.set_override('interface_driver',
                               'neutron.agent.linux.interface.NullDriver')
        self.conf.set_override('send_arp_for_ha', 1)
        self.conf.set_override('state_path', '')

        self.device_exists_p = mock.patch(
            'neutron.agent.linux.ip_lib.device_exists')
        self.device_exists = self.device_exists_p.start()

        self.ensure_dir = mock.patch('neutron.common.utils.ensure_dir').start()

        mock.patch('neutron.agent.linux.keepalived.KeepalivedManager'
                   '.get_full_config_file_path').start()

        self.utils_exec_p = mock.patch(
            'neutron.agent.linux.utils.execute')
        self.utils_exec = self.utils_exec_p.start()

        self.utils_replace_file_p = mock.patch(
            'neutron.agent.linux.utils.replace_file')
        self.utils_replace_file = self.utils_replace_file_p.start()

        self.external_process_p = mock.patch(
            'neutron.agent.linux.external_process.ProcessManager')
        self.external_process = self.external_process_p.start()
        self.process_monitor = mock.patch(
            'neutron.agent.linux.external_process.ProcessMonitor').start()

        self.send_adv_notif_p = mock.patch(
            'neutron.agent.linux.ip_lib.send_ip_addr_adv_notif')
        self.send_adv_notif = self.send_adv_notif_p.start()

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

        ip_rule = mock.patch('neutron.agent.linux.ip_lib.IPRule').start()
        self.mock_rule = mock.MagicMock()
        ip_rule.return_value = self.mock_rule

        ip_dev = mock.patch('neutron.agent.linux.ip_lib.IPDevice').start()
        self.mock_ip_dev = mock.MagicMock()
        ip_dev.return_value = self.mock_ip_dev

        self.l3pluginApi_cls_p = mock.patch(
            'neutron.agent.l3.agent.L3PluginApi')
        l3pluginApi_cls = self.l3pluginApi_cls_p.start()
        self.plugin_api = mock.MagicMock()
        l3pluginApi_cls.return_value = self.plugin_api

        self.looping_call_p = mock.patch(
            'oslo_service.loopingcall.FixedIntervalLoopingCall')
        self.looping_call_p.start()

        subnet_id_1 = _uuid()
        subnet_id_2 = _uuid()
        self.snat_ports = [{'subnets': [{'cidr': '152.2.0.0/16',
                                         'gateway_ip': '152.2.0.1',
                                         'id': subnet_id_1}],
                           'network_id': _uuid(),
                           'device_owner': 'network:router_centralized_snat',
                           'mac_address': 'fa:16:3e:80:8d:80',
                           'fixed_ips': [{'subnet_id': subnet_id_1,
                                          'ip_address': '152.2.0.13',
                                          'prefixlen': 16}],
                           'id': _uuid(), 'device_id': _uuid()},
                          {'subnets': [{'cidr': '152.10.0.0/16',
                                        'gateway_ip': '152.10.0.1',
                                        'id': subnet_id_2}],
                           'network_id': _uuid(),
                           'device_owner': 'network:router_centralized_snat',
                           'mac_address': 'fa:16:3e:80:8d:80',
                           'fixed_ips': [{'subnet_id': subnet_id_2,
                                         'ip_address': '152.10.0.13',
                                         'prefixlen': 16}],
                           'id': _uuid(), 'device_id': _uuid()}]

        self.ri_kwargs = {'agent_conf': self.conf,
                          'interface_driver': self.mock_driver}

    def _process_router_instance_for_agent(self, agent, ri, router):
        ri.router = router
        if not ri.radvd:
            ri.radvd = ra.DaemonMonitor(router['id'],
                                        ri.ns_name,
                                        agent.process_monitor,
                                        ri.get_internal_device_name)
        ri.process(agent)


class TestBasicRouterOperations(BasicRouterOperationsFramework):
    def test_init_ha_conf(self):
        with mock.patch('os.path.dirname', return_value='/etc/ha/'):
            l3_agent.L3NATAgent(HOSTNAME, self.conf)
            self.ensure_dir.assert_called_once_with('/etc/ha/')

    def test_periodic_sync_routers_task_raise_exception(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.plugin_api.get_routers.side_effect = ValueError
        self.assertRaises(ValueError,
                          agent.periodic_sync_routers_task,
                          agent.context)
        self.assertTrue(agent.fullsync)

    def test_l3_initial_full_sync_done(self):
        with mock.patch.object(l3_agent.L3NATAgent,
                               'periodic_sync_routers_task') as router_sync:
            with mock.patch.object(eventlet, 'spawn_n'):
                agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
                agent.after_start()
                router_sync.assert_called_once_with(agent.context)

    def test_l3_initial_report_state_done(self):
        with mock.patch.object(l3_agent.L3NATAgentWithStateReport,
                               'periodic_sync_routers_task'),\
                mock.patch.object(agent_rpc.PluginReportStateAPI,
                                  'report_state') as report_state,\
                mock.patch.object(eventlet, 'spawn_n'):

            agent = l3_agent.L3NATAgentWithStateReport(host=HOSTNAME,
                                                       conf=self.conf)

            self.assertEqual(agent.agent_state['start_flag'], True)
            use_call_arg = agent.use_call
            agent.after_start()
            report_state.assert_called_once_with(agent.context,
                                                 agent.agent_state,
                                                 use_call_arg)
            self.assertTrue(agent.agent_state.get('start_flag') is None)

    def test_periodic_sync_routers_task_call_clean_stale_namespaces(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.plugin_api.get_routers.return_value = []
        agent.periodic_sync_routers_task(agent.context)
        self.assertFalse(agent.namespaces_manager._clean_stale)

    def test_periodic_sync_routers_task_call_clean_stale_meta_proxies(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        stale_router_ids = [_uuid(), _uuid()]
        active_routers = [{'id': _uuid()}, {'id': _uuid()}]
        self.plugin_api.get_routers.return_value = active_routers
        namespace_list = [namespaces.NS_PREFIX + r_id
                          for r_id in stale_router_ids]
        namespace_list += [namespaces.NS_PREFIX + r['id']
                           for r in active_routers]
        self.mock_ip.get_namespaces.return_value = namespace_list
        driver = metadata_driver.MetadataDriver
        with mock.patch.object(
                driver, 'destroy_monitored_metadata_proxy') as destroy_proxy:
            agent.periodic_sync_routers_task(agent.context)

            expected_calls = [mock.call(mock.ANY, r_id, agent.conf)
                              for r_id in stale_router_ids]
            self.assertEqual(len(stale_router_ids), destroy_proxy.call_count)
            destroy_proxy.assert_has_calls(expected_calls, any_order=True)

    def test_router_info_create(self):
        id = _uuid()
        ri = l3router.RouterInfo(id, {}, **self.ri_kwargs)

        self.assertTrue(ri.ns_name.endswith(id))

    def test_router_info_create_with_router(self):
        ns_id = _uuid()
        subnet_id = _uuid()
        ex_gw_port = {'id': _uuid(),
                      'network_id': _uuid(),
                      'fixed_ips': [{'ip_address': '19.4.4.4',
                                     'prefixlen': 24,
                                     'subnet_id': subnet_id}],
                      'subnets': [{'id': subnet_id,
                                   'cidr': '19.4.4.0/24',
                                   'gateway_ip': '19.4.4.1'}]}
        router = {
            'id': _uuid(),
            'enable_snat': True,
            'routes': [],
            'gw_port': ex_gw_port}
        ri = l3router.RouterInfo(ns_id, router, **self.ri_kwargs)
        self.assertTrue(ri.ns_name.endswith(ns_id))
        self.assertEqual(ri.router, router)

    def test_agent_create(self):
        l3_agent.L3NATAgent(HOSTNAME, self.conf)

    def _test_internal_network_action(self, action):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router_id = router['id']
        ri = l3router.RouterInfo(router_id, router, **self.ri_kwargs)
        port = {'network_id': _uuid(),
                'id': _uuid(),
                'mac_address': 'ca:fe:de:ad:be:ef',
                'fixed_ips': [{'subnet_id': _uuid(),
                               'ip_address': '99.0.1.9',
                               'prefixlen': 24}]}

        interface_name = ri.get_internal_device_name(port['id'])

        if action == 'add':
            self.device_exists.return_value = False
            ri.internal_network_added(port)
            self.assertEqual(self.mock_driver.plug.call_count, 1)
            self.assertEqual(self.mock_driver.init_router_port.call_count, 1)
            self.send_adv_notif.assert_called_once_with(ri.ns_name,
                                                        interface_name,
                                                        '99.0.1.9', mock.ANY)
        elif action == 'remove':
            self.device_exists.return_value = True
            ri.internal_network_removed(port)
            self.assertEqual(self.mock_driver.unplug.call_count, 1)
        else:
            raise Exception("Invalid action %s" % action)

    @staticmethod
    def _fixed_ip_cidr(fixed_ip):
        return '%s/%s' % (fixed_ip['ip_address'], fixed_ip['prefixlen'])

    def _test_internal_network_action_dist(self, action):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router_id = router['id']
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = dvr_router.DvrEdgeRouter(
            agent, HOSTNAME, router_id, router, **self.ri_kwargs)
        subnet_id = _uuid()
        port = {'network_id': _uuid(),
                'id': _uuid(),
                'mac_address': 'ca:fe:de:ad:be:ef',
                'fixed_ips': [{'subnet_id': subnet_id,
                               'ip_address': '99.0.1.9',
                               'prefixlen': 24}],
                'subnets': [{'id': subnet_id}]}

        ri.router['gw_port_host'] = HOSTNAME
        agent.host = HOSTNAME
        agent.conf.agent_mode = 'dvr_snat'
        sn_port = {'fixed_ips': [{'ip_address': '20.0.0.31',
                                 'subnet_id': _uuid()}],
                  'subnets': [{'gateway_ip': '20.0.0.1'}],
                  'extra_subnets': [{'cidr': '172.16.0.0/24'}],
                  'id': _uuid(),
                  'network_id': _uuid(),
                  'mac_address': 'ca:fe:de:ad:be:ef'}
        ex_gw_port = {'fixed_ips': [{'ip_address': '20.0.0.30',
                                     'prefixlen': 24,
                                     'subnet_id': _uuid()}],
                      'subnets': [{'gateway_ip': '20.0.0.1'}],
                      'extra_subnets': [{'cidr': '172.16.0.0/24'}],
                      'id': _uuid(),
                      'binding:host_id': HOSTNAME,
                      'network_id': _uuid(),
                      'mac_address': 'ca:fe:de:ad:be:ef'}
        ri.snat_ports = sn_port
        ri.ex_gw_port = ex_gw_port
        ri.snat_namespace = mock.Mock()

        if action == 'add':
            self.device_exists.return_value = False

            ri.get_snat_port_for_internal_port = mock.Mock(
                return_value=sn_port)
            ri._snat_redirect_add = mock.Mock()
            ri._set_subnet_arp_info = mock.Mock()
            ri._internal_network_added = mock.Mock()
            ri._set_subnet_arp_info = mock.Mock()
            ri.internal_network_added(port)
            self.assertEqual(ri._snat_redirect_add.call_count, 1)
            self.assertEqual(ri._internal_network_added.call_count, 2)
            ri._set_subnet_arp_info.assert_called_once_with(subnet_id)
            ri._internal_network_added.assert_called_with(
                dvr_snat_ns.SnatNamespace.get_snat_ns_name(ri.router['id']),
                sn_port['network_id'],
                sn_port['id'],
                sn_port['fixed_ips'],
                sn_port['mac_address'],
                ri.get_snat_int_device_name(sn_port['id']),
                dvr_snat_ns.SNAT_INT_DEV_PREFIX)
        elif action == 'remove':
            self.device_exists.return_value = False
            ri.get_snat_port_for_internal_port = mock.Mock(
                return_value=sn_port)
            ri._snat_redirect_modify = mock.Mock()
            ri.internal_network_removed(port)
            ri._snat_redirect_modify.assert_called_with(
                sn_port, port,
                ri.get_internal_device_name(port['id']),
                is_add=False)

    def test_agent_add_internal_network(self):
        self._test_internal_network_action('add')

    def test_agent_add_internal_network_dist(self):
        self._test_internal_network_action_dist('add')

    def test_agent_remove_internal_network(self):
        self._test_internal_network_action('remove')

    def test_agent_remove_internal_network_dist(self):
        self._test_internal_network_action_dist('remove')

    def _add_external_gateway(self, ri, router, ex_gw_port, interface_name,
                              enable_ra_on_gw=False,
                              use_fake_fip=False,
                              no_subnet=False, no_sub_gw=None,
                              dual_stack=False):
        self.device_exists.return_value = False
        if no_sub_gw is None:
            no_sub_gw = []
        if use_fake_fip:
            fake_fip = {'floatingips': [{'id': _uuid(),
                                         'floating_ip_address': '192.168.1.34',
                                         'fixed_ip_address': '192.168.0.1',
                                         'port_id': _uuid()}]}
            router[l3_constants.FLOATINGIP_KEY] = fake_fip['floatingips']
        ri.external_gateway_added(ex_gw_port, interface_name)
        if not router.get('distributed'):
            self.assertEqual(self.mock_driver.plug.call_count, 1)
            self.assertEqual(self.mock_driver.init_router_port.call_count, 1)
            if no_subnet and not dual_stack:
                self.assertEqual(self.send_adv_notif.call_count, 0)
                ip_cidrs = []
                gateway_ips = []
                if no_sub_gw:
                    gateway_ips.append(no_sub_gw)
                kwargs = {'preserve_ips': [],
                          'gateway_ips': gateway_ips,
                          'namespace': 'qrouter-' + router['id'],
                          'extra_subnets': [],
                          'enable_ra_on_gw': enable_ra_on_gw,
                          'clean_connections': True}
            else:
                exp_arp_calls = [mock.call(ri.ns_name, interface_name,
                                           '20.0.0.30', mock.ANY)]
                if dual_stack and not no_sub_gw:
                    exp_arp_calls += [mock.call(ri.ns_name, interface_name,
                                                '2001:192:168:100::2',
                                                mock.ANY)]
                self.send_adv_notif.assert_has_calls(exp_arp_calls)
                ip_cidrs = ['20.0.0.30/24']
                gateway_ips = ['20.0.0.1']
                if dual_stack:
                    if no_sub_gw:
                        gateway_ips.append(no_sub_gw)
                    else:
                        ip_cidrs.append('2001:192:168:100::2/64')
                        gateway_ips.append('2001:192:168:100::1')
                kwargs = {'preserve_ips': ['192.168.1.34/32'],
                          'gateway_ips': gateway_ips,
                          'namespace': 'qrouter-' + router['id'],
                          'extra_subnets': [{'cidr': '172.16.0.0/24'}],
                          'enable_ra_on_gw': enable_ra_on_gw,
                          'clean_connections': True}
            self.mock_driver.init_router_port.assert_called_with(
                interface_name, ip_cidrs, **kwargs)
        else:
            ri._create_dvr_gateway.assert_called_once_with(
                ex_gw_port, interface_name)

    def _test_external_gateway_action(self, action, router, dual_stack=False):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ex_net_id = _uuid()
        sn_port = self.snat_ports[1]
        # Special setup for dvr routers
        if router.get('distributed'):
            agent.conf.agent_mode = 'dvr_snat'
            agent.host = HOSTNAME
            ri = dvr_router.DvrEdgeRouter(agent,
                                          HOSTNAME,
                                          router['id'],
                                          router,
                                          **self.ri_kwargs)
            ri._create_dvr_gateway = mock.Mock()
            ri.get_snat_interfaces = mock.Mock(return_value=self.snat_ports)
            ri.create_snat_namespace()
            ri.fip_ns = agent.get_fip_ns(ex_net_id)
            ri.internal_ports = self.snat_ports
        else:
            ri = l3router.RouterInfo(
                router['id'], router,
                **self.ri_kwargs)

        ri.use_ipv6 = False
        subnet_id = _uuid()
        fixed_ips = [{'subnet_id': subnet_id,
                      'ip_address': '20.0.0.30',
                      'prefixlen': 24}]
        subnets = [{'id': subnet_id,
                    'cidr': '20.0.0.0/24',
                    'gateway_ip': '20.0.0.1'}]
        if dual_stack:
            ri.use_ipv6 = True
            subnet_id_v6 = _uuid()
            fixed_ips.append({'subnet_id': subnet_id_v6,
                              'ip_address': '2001:192:168:100::2',
                              'prefixlen': 64})
            subnets.append({'id': subnet_id_v6,
                            'cidr': '2001:192:168:100::/64',
                            'gateway_ip': '2001:192:168:100::1'})
        ex_gw_port = {'fixed_ips': fixed_ips,
                      'subnets': subnets,
                      'extra_subnets': [{'cidr': '172.16.0.0/24'}],
                      'id': _uuid(),
                      'network_id': ex_net_id,
                      'mac_address': 'ca:fe:de:ad:be:ef'}
        ex_gw_port_no_sub = {'fixed_ips': [],
                             'id': _uuid(),
                             'network_id': ex_net_id,
                             'mac_address': 'ca:fe:de:ad:be:ef'}
        interface_name = ri.get_external_device_name(ex_gw_port['id'])

        if action == 'add':
            self._add_external_gateway(ri, router, ex_gw_port, interface_name,
                                       use_fake_fip=True,
                                       dual_stack=dual_stack)

        elif action == 'add_no_sub':
            ri.use_ipv6 = True
            self._add_external_gateway(ri, router, ex_gw_port_no_sub,
                                       interface_name, enable_ra_on_gw=True,
                                       no_subnet=True)

        elif action == 'add_no_sub_v6_gw':
            ri.use_ipv6 = True
            self.conf.set_override('ipv6_gateway',
                                   'fe80::f816:3eff:fe2e:1')
            if dual_stack:
                use_fake_fip = True
                # Remove v6 entries
                del ex_gw_port['fixed_ips'][-1]
                del ex_gw_port['subnets'][-1]
            else:
                use_fake_fip = False
                ex_gw_port = ex_gw_port_no_sub
            self._add_external_gateway(ri, router, ex_gw_port,
                                       interface_name, no_subnet=True,
                                       no_sub_gw='fe80::f816:3eff:fe2e:1',
                                       use_fake_fip=use_fake_fip,
                                       dual_stack=dual_stack)

        elif action == 'remove':
            self.device_exists.return_value = True
            ri.get_snat_port_for_internal_port = mock.Mock(
                return_value=sn_port)
            ri._snat_redirect_remove = mock.Mock()
            ri.external_gateway_removed(ex_gw_port, interface_name)
            if not router.get('distributed'):
                self.mock_driver.unplug.assert_called_once_with(
                    interface_name,
                    bridge=agent.conf.external_network_bridge,
                    namespace=mock.ANY,
                    prefix=mock.ANY)
            else:
                ri._snat_redirect_remove.assert_called_with(
                    sn_port, sn_port,
                    ri.get_internal_device_name(sn_port['id']))
        else:
            raise Exception("Invalid action %s" % action)

    def _test_external_gateway_updated(self, dual_stack=False):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        ri.use_ipv6 = False
        interface_name, ex_gw_port = l3_test_common.prepare_ext_gw_test(
            self, ri, dual_stack=dual_stack)

        fake_fip = {'floatingips': [{'id': _uuid(),
                                     'floating_ip_address': '192.168.1.34',
                                     'fixed_ip_address': '192.168.0.1',
                                     'port_id': _uuid()}]}
        router[l3_constants.FLOATINGIP_KEY] = fake_fip['floatingips']
        ri.external_gateway_updated(ex_gw_port, interface_name)
        self.assertEqual(1, self.mock_driver.plug.call_count)
        self.assertEqual(self.mock_driver.init_router_port.call_count, 1)
        exp_arp_calls = [mock.call(ri.ns_name, interface_name,
                                   '20.0.0.30', mock.ANY)]
        if dual_stack:
            ri.use_ipv6 = True
            exp_arp_calls += [mock.call(ri.ns_name, interface_name,
                                        '2001:192:168:100::2', mock.ANY)]
        self.send_adv_notif.assert_has_calls(exp_arp_calls)
        ip_cidrs = ['20.0.0.30/24']
        gateway_ips = ['20.0.0.1']
        if dual_stack:
            ip_cidrs.append('2001:192:168:100::2/64')
            gateway_ips.append('2001:192:168:100::1')
        kwargs = {'preserve_ips': ['192.168.1.34/32'],
                  'gateway_ips': gateway_ips,
                  'namespace': 'qrouter-' + router['id'],
                  'extra_subnets': [{'cidr': '172.16.0.0/24'}],
                  'enable_ra_on_gw': False,
                  'clean_connections': True}
        self.mock_driver.init_router_port.assert_called_with(interface_name,
                                                             ip_cidrs,
                                                             **kwargs)

    def test_external_gateway_updated(self):
        self._test_external_gateway_updated()

    def test_external_gateway_updated_dual_stack(self):
        self._test_external_gateway_updated(dual_stack=True)

    def _test_ext_gw_updated_dvr_agent_mode(self, host,
                                            agent_mode, expected_call_count):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = dvr_router.DvrEdgeRouter(agent,
                                      HOSTNAME,
                                      router['id'],
                                      router,
                                      **self.ri_kwargs)
        ri.create_snat_namespace()
        interface_name, ex_gw_port = l3_test_common.prepare_ext_gw_test(self,
                                                                        ri)
        ri._external_gateway_added = mock.Mock()

        # test agent mode = dvr (compute node)
        router['gw_port_host'] = host
        agent.conf.agent_mode = agent_mode

        ri.external_gateway_updated(ex_gw_port, interface_name)
        # no gateway should be added on dvr node
        self.assertEqual(expected_call_count,
                         ri._external_gateway_added.call_count)

    def test_ext_gw_updated_dvr_agent_mode(self):
        # no gateway should be added on dvr node
        self._test_ext_gw_updated_dvr_agent_mode('any-foo', 'dvr', 0)

    def test_ext_gw_updated_dvr_snat_agent_mode_no_host(self):
        # no gateway should be added on dvr_snat node without host match
        self._test_ext_gw_updated_dvr_agent_mode('any-foo', 'dvr_snat', 0)

    def test_ext_gw_updated_dvr_snat_agent_mode_host(self):
        # gateway should be added on dvr_snat node
        self._test_ext_gw_updated_dvr_agent_mode(HOSTNAME,
                                                 'dvr_snat', 1)

    def test_agent_add_external_gateway(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        self._test_external_gateway_action('add', router)

    def test_agent_add_external_gateway_dual_stack(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        self._test_external_gateway_action('add', router, dual_stack=True)

    def test_agent_add_external_gateway_dist(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        router['gw_port_host'] = HOSTNAME
        self._test_external_gateway_action('add', router)

    def test_agent_add_external_gateway_dist_dual_stack(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        router['gw_port_host'] = HOSTNAME
        self._test_external_gateway_action('add', router, dual_stack=True)

    def test_agent_add_external_gateway_no_subnet(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2,
                                                    v6_ext_gw_with_sub=False)
        self._test_external_gateway_action('add_no_sub', router)

    def test_agent_add_external_gateway_no_subnet_with_ipv6_gw(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2,
                                                    v6_ext_gw_with_sub=False)
        self._test_external_gateway_action('add_no_sub_v6_gw', router)

    def test_agent_add_external_gateway_dual_stack_no_subnet_w_ipv6_gw(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2,
                                                    v6_ext_gw_with_sub=False)
        self._test_external_gateway_action('add_no_sub_v6_gw',
                                           router, dual_stack=True)

    def test_agent_remove_external_gateway(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        self._test_external_gateway_action('remove', router)

    def test_agent_remove_external_gateway_dual_stack(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        self._test_external_gateway_action('remove', router, dual_stack=True)

    def test_agent_remove_external_gateway_dist(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        router['gw_port_host'] = HOSTNAME
        self._test_external_gateway_action('remove', router)

    def test_agent_remove_external_gateway_dist_dual_stack(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        router['gw_port_host'] = HOSTNAME
        self._test_external_gateway_action('remove', router, dual_stack=True)

    def _verify_snat_mangle_rules(self, nat_rules, mangle_rules, router,
                                  negate=False):
        interfaces = router[l3_constants.INTERFACE_KEY]
        source_cidrs = []
        for iface in interfaces:
            for subnet in iface['subnets']:
                prefix = subnet['cidr'].split('/')[1]
                source_cidr = "%s/%s" % (iface['fixed_ips'][0]['ip_address'],
                                         prefix)
                source_cidrs.append(source_cidr)
        source_nat_ip = router['gw_port']['fixed_ips'][0]['ip_address']
        interface_name = ('qg-%s' % router['gw_port']['id'])[:14]
        expected_rules = [
            '! -i %s ! -o %s -m conntrack ! --ctstate DNAT -j ACCEPT' %
            (interface_name, interface_name),
            '-o %s -j SNAT --to-source %s' % (interface_name, source_nat_ip),
            '-m mark ! --mark 0x2/%s -m conntrack --ctstate DNAT '
            '-j SNAT --to-source %s' %
            (l3_constants.ROUTER_MARK_MASK, source_nat_ip)]
        for r in nat_rules:
            if negate:
                self.assertNotIn(r.rule, expected_rules)
            else:
                self.assertIn(r.rule, expected_rules)
        expected_rules = [
            '-i %s -j MARK --set-xmark 0x2/%s' %
            (interface_name, l3_constants.ROUTER_MARK_MASK)]
        for r in mangle_rules:
            if negate:
                self.assertNotIn(r.rule, expected_rules)
            else:
                self.assertIn(r.rule, expected_rules)

    def test_get_snat_port_for_internal_port(self):
        router = l3_test_common.prepare_router_data(num_internal_ports=4)
        ri = dvr_router.DvrEdgeRouter(mock.sentinel.agent,
                                      HOSTNAME,
                                      router['id'],
                                      router,
                                      **self.ri_kwargs)
        test_port = {
            'mac_address': '00:12:23:34:45:56',
            'fixed_ips': [{'subnet_id': l3_test_common.get_subnet_id(
                router[l3_constants.INTERFACE_KEY][0]),
                'ip_address': '101.12.13.14'}]}
        internal_ports = ri.router.get(l3_constants.INTERFACE_KEY, [])
        # test valid case
        with mock.patch.object(ri, 'get_snat_interfaces') as get_interfaces:
            get_interfaces.return_value = [test_port]
            res_port = ri.get_snat_port_for_internal_port(internal_ports[0])
            self.assertEqual(test_port, res_port)
            # test invalid case
            test_port['fixed_ips'][0]['subnet_id'] = 1234
            res_ip = ri.get_snat_port_for_internal_port(internal_ports[0])
            self.assertNotEqual(test_port, res_ip)
            self.assertIsNone(res_ip)

    def test_process_cent_router(self):
        router = l3_test_common.prepare_router_data()
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        self._test_process_router(ri, agent)

    def test_process_dist_router(self):
        router = l3_test_common.prepare_router_data()
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = dvr_router.DvrEdgeRouter(agent,
                                      HOSTNAME,
                                      router['id'],
                                      router,
                                      **self.ri_kwargs)
        subnet_id = l3_test_common.get_subnet_id(
            router[l3_constants.INTERFACE_KEY][0])
        ri.router['distributed'] = True
        ri.router['_snat_router_interfaces'] = [{
            'fixed_ips': [{'subnet_id': subnet_id,
                           'ip_address': '1.2.3.4'}]}]
        ri.router['gw_port_host'] = None
        self._test_process_router(ri, agent)

    def _test_process_router(self, ri, agent):
        router = ri.router
        agent.host = HOSTNAME
        fake_fip_id = 'fake_fip_id'
        ri.create_dvr_fip_interfaces = mock.Mock()
        ri.process_floating_ip_addresses = mock.Mock()
        ri.process_floating_ip_nat_rules = mock.Mock()
        ri.process_floating_ip_addresses.return_value = {
            fake_fip_id: 'ACTIVE'}
        ri.external_gateway_added = mock.Mock()
        ri.external_gateway_updated = mock.Mock()
        fake_floatingips1 = {'floatingips': [
            {'id': fake_fip_id,
             'floating_ip_address': '8.8.8.8',
             'fixed_ip_address': '7.7.7.7',
             'port_id': _uuid(),
             'host': HOSTNAME}]}
        ri.process(agent)
        ri.process_floating_ip_addresses.assert_called_with(mock.ANY)
        ri.process_floating_ip_addresses.reset_mock()
        ri.process_floating_ip_nat_rules.assert_called_with()
        ri.process_floating_ip_nat_rules.reset_mock()
        ri.external_gateway_added.reset_mock()

        # remap floating IP to a new fixed ip
        fake_floatingips2 = copy.deepcopy(fake_floatingips1)
        fake_floatingips2['floatingips'][0]['fixed_ip_address'] = '7.7.7.8'

        router[l3_constants.FLOATINGIP_KEY] = fake_floatingips2['floatingips']
        ri.process(agent)
        ri.process_floating_ip_addresses.assert_called_with(mock.ANY)
        ri.process_floating_ip_addresses.reset_mock()
        ri.process_floating_ip_nat_rules.assert_called_with()
        ri.process_floating_ip_nat_rules.reset_mock()
        self.assertEqual(ri.external_gateway_added.call_count, 0)
        self.assertEqual(ri.external_gateway_updated.call_count, 0)
        ri.external_gateway_added.reset_mock()
        ri.external_gateway_updated.reset_mock()

        # change the ex_gw_port a bit to test gateway update
        new_gw_port = copy.deepcopy(ri.router['gw_port'])
        ri.router['gw_port'] = new_gw_port
        old_ip = (netaddr.IPAddress(ri.router['gw_port']
                                    ['fixed_ips'][0]['ip_address']))
        ri.router['gw_port']['fixed_ips'][0]['ip_address'] = str(old_ip + 1)

        ri.process(agent)
        ri.process_floating_ip_addresses.reset_mock()
        ri.process_floating_ip_nat_rules.reset_mock()
        self.assertEqual(ri.external_gateway_added.call_count, 0)
        self.assertEqual(ri.external_gateway_updated.call_count, 1)

        # remove just the floating ips
        del router[l3_constants.FLOATINGIP_KEY]
        ri.process(agent)
        ri.process_floating_ip_addresses.assert_called_with(mock.ANY)
        ri.process_floating_ip_addresses.reset_mock()
        ri.process_floating_ip_nat_rules.assert_called_with()
        ri.process_floating_ip_nat_rules.reset_mock()

        # now no ports so state is torn down
        del router[l3_constants.INTERFACE_KEY]
        del router['gw_port']
        ri.process(agent)
        self.assertEqual(self.send_adv_notif.call_count, 1)
        distributed = ri.router.get('distributed', False)
        self.assertEqual(ri.process_floating_ip_addresses.called,
                         distributed)
        self.assertEqual(ri.process_floating_ip_nat_rules.called,
                         distributed)

    @mock.patch('neutron.agent.linux.ip_lib.IPDevice')
    def _test_process_floating_ip_addresses_add(self, ri, agent, IPDevice):
        floating_ips = ri.get_floating_ips()
        fip_id = floating_ips[0]['id']
        IPDevice.return_value = device = mock.Mock()
        device.addr.list.return_value = []
        ri.iptables_manager.ipv4['nat'] = mock.MagicMock()
        ex_gw_port = {'id': _uuid(), 'network_id': mock.sentinel.ext_net_id}

        ri.add_floating_ip = mock.Mock(
            return_value=l3_constants.FLOATINGIP_STATUS_ACTIVE)
        with mock.patch.object(lla.LinkLocalAllocator, '_write'):
            if ri.router['distributed']:
                ri.fip_ns = agent.get_fip_ns(ex_gw_port['network_id'])
                ri.create_dvr_fip_interfaces(ex_gw_port)
            fip_statuses = ri.process_floating_ip_addresses(
                mock.sentinel.interface_name)
        self.assertEqual({fip_id: l3_constants.FLOATINGIP_STATUS_ACTIVE},
                         fip_statuses)
        ri.add_floating_ip.assert_called_once_with(
            floating_ips[0], mock.sentinel.interface_name, device)

    @mock.patch.object(lla.LinkLocalAllocator, '_write')
    def test_create_dvr_fip_interfaces_for_late_binding(self, lla_write):
        fake_network_id = _uuid()
        fake_subnet_id = _uuid()
        fake_floatingips = {'floatingips': [
            {'id': _uuid(),
             'floating_ip_address': '20.0.0.3',
             'fixed_ip_address': '192.168.0.1',
             'floating_network_id': _uuid(),
             'port_id': _uuid(),
             'host': HOSTNAME}]}
        agent_gateway_port = (
            {'fixed_ips': [
                {'ip_address': '20.0.0.30',
                 'prefixlen': 24,
                 'subnet_id': fake_subnet_id}],
             'subnets': [
                 {'id': fake_subnet_id,
                  'gateway_ip': '20.0.0.1'}],
             'id': _uuid(),
             'network_id': fake_network_id,
             'mac_address': 'ca:fe:de:ad:be:ef'}
        )

        router = l3_test_common.prepare_router_data(enable_snat=True)
        router[l3_constants.FLOATINGIP_KEY] = fake_floatingips['floatingips']
        router[l3_constants.FLOATINGIP_AGENT_INTF_KEY] = []
        router['distributed'] = True
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = dvr_router.DvrEdgeRouter(
            agent, HOSTNAME, router['id'], router, **self.ri_kwargs)

        ext_gw_port = ri.router.get('gw_port')
        ri.fip_ns = agent.get_fip_ns(ext_gw_port['network_id'])
        ri.dist_fip_count = 0
        ri.fip_ns.subscribe = mock.Mock()
        with mock.patch.object(agent.plugin_rpc,
                               'get_agent_gateway_port') as fip_gw_port:
            fip_gw_port.return_value = agent_gateway_port
            ri.create_dvr_fip_interfaces(ext_gw_port)
            self.assertTrue(fip_gw_port.called)
            self.assertEqual(agent_gateway_port,
                             ri.fip_ns.agent_gateway_port)

    @mock.patch.object(lla.LinkLocalAllocator, '_write')
    def test_create_dvr_fip_interfaces(self, lla_write):
        fake_network_id = _uuid()
        subnet_id = _uuid()
        fake_floatingips = {'floatingips': [
            {'id': _uuid(),
             'floating_ip_address': '20.0.0.3',
             'fixed_ip_address': '192.168.0.1',
             'floating_network_id': _uuid(),
             'port_id': _uuid(),
             'host': HOSTNAME}]}
        agent_gateway_port = (
            [{'fixed_ips': [
                {'ip_address': '20.0.0.30',
                 'prefixlen': 24,
                 'subnet_id': subnet_id}],
             'subnets': [
                 {'id': subnet_id,
                  'gateway_ip': '20.0.0.1'}],
             'id': _uuid(),
             'network_id': fake_network_id,
             'mac_address': 'ca:fe:de:ad:be:ef'}]
        )

        router = l3_test_common.prepare_router_data(enable_snat=True)
        router[l3_constants.FLOATINGIP_KEY] = fake_floatingips['floatingips']
        router[l3_constants.FLOATINGIP_AGENT_INTF_KEY] = agent_gateway_port
        router['distributed'] = True
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = dvr_router.DvrEdgeRouter(
            agent, HOSTNAME, router['id'], router, **self.ri_kwargs)

        ext_gw_port = ri.router.get('gw_port')
        ri.fip_ns = agent.get_fip_ns(ext_gw_port['network_id'])
        ri.dist_fip_count = 0
        ri.fip_ns.subscribe = mock.Mock()
        ri.fip_ns.agent_router_gateway = mock.Mock()

        with mock.patch.object(ri, 'get_floating_ips') as fips, \
                mock.patch.object(ri, 'get_floating_agent_gw_interface'
                                  ) as fip_gw_port:
            fips.return_value = fake_floatingips
            fip_gw_port.return_value = agent_gateway_port[0]
            ri.create_dvr_fip_interfaces(ext_gw_port)
            self.assertTrue(fip_gw_port.called)
            self.assertTrue(fips.called)
            self.assertEqual(ri.fip_ns.agent_gateway_port,
                             agent_gateway_port[0])
            self.assertTrue(ri.rtr_fip_subnet)

    @mock.patch.object(lla.LinkLocalAllocator, '_write')
    def test_create_dvr_fip_interfaces_for_restart_l3agent_case(self,
                                                                lla_write):
        fake_floatingips = {'floatingips': [
            {'id': _uuid(),
             'floating_ip_address': '20.0.0.3',
             'fixed_ip_address': '192.168.0.1',
             'floating_network_id': _uuid(),
             'port_id': _uuid(),
             'host': HOSTNAME}]}
        agent_gateway_port = (
            [{'fixed_ips': [
                {'ip_address': '20.0.0.30',
                 'prefixlen': 24,
                 'subnet_id': 'subnet_id'}],
             'subnets': [
                 {'id': 'subnet_id',
                  'gateway_ip': '20.0.0.1'}],
             'id': _uuid(),
             'network_id': 'fake_network_id',
             'mac_address': 'ca:fe:de:ad:be:ef'}]
        )

        router = l3_test_common.prepare_router_data(enable_snat=True)
        router[l3_constants.FLOATINGIP_KEY] = fake_floatingips['floatingips']
        router[l3_constants.FLOATINGIP_AGENT_INTF_KEY] = agent_gateway_port
        router['distributed'] = True
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = dvr_router.DvrEdgeRouter(
            agent, HOSTNAME, router['id'], router, **self.ri_kwargs)
        ext_gw_port = ri.router.get('gw_port')
        ri.fip_ns = agent.get_fip_ns(ext_gw_port['network_id'])
        ri.fip_ns.subscribe = mock.Mock(return_value=True)
        ri.fip_ns.agent_router_gateway = mock.Mock()
        ri.rtr_fip_subnet = None
        ri.dist_fip_count = 1

        with mock.patch.object(ri, 'get_floating_ips') as fips,\
                mock.patch.object(ri, 'get_floating_agent_gw_interface'
                                  ) as fip_gw_port:
            fips.return_value = fake_floatingips
            fip_gw_port.return_value = agent_gateway_port[0]
            ri.create_dvr_fip_interfaces(ext_gw_port)
            self.assertTrue(fip_gw_port.called)
            self.assertTrue(fips.called)
            self.assertEqual(ri.fip_ns.agent_gateway_port,
                             agent_gateway_port[0])
            self.assertTrue(ri.rtr_fip_subnet)

    def test_process_router_cent_floating_ip_add(self):
        fake_floatingips = {'floatingips': [
            {'id': _uuid(),
             'floating_ip_address': '15.1.2.3',
             'fixed_ip_address': '192.168.0.1',
             'status': 'DOWN',
             'floating_network_id': _uuid(),
             'port_id': _uuid(),
             'host': HOSTNAME}]}

        router = l3_test_common.prepare_router_data(enable_snat=True)
        router[l3_constants.FLOATINGIP_KEY] = fake_floatingips['floatingips']
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        ri.iptables_manager.ipv4['nat'] = mock.MagicMock()
        ri.get_external_device_name = mock.Mock(return_value='exgw')
        self._test_process_floating_ip_addresses_add(ri, agent)

    def test_process_router_snat_disabled(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(enable_snat=True)
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        # Process with NAT
        ri.process(agent)
        orig_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]
        orig_mangle_rules = ri.iptables_manager.ipv4['mangle'].rules[:]
        # Reprocess without NAT
        router['enable_snat'] = False
        # Reassign the router object to RouterInfo
        ri.router = router
        ri.process(agent)
        # For some reason set logic does not work well with
        # IpTablesRule instances
        nat_rules_delta = [r for r in orig_nat_rules
                           if r not in ri.iptables_manager.ipv4['nat'].rules]
        self.assertEqual(len(nat_rules_delta), 3)
        mangle_rules_delta = [
            r for r in orig_mangle_rules
            if r not in ri.iptables_manager.ipv4['mangle'].rules]
        self.assertEqual(len(mangle_rules_delta), 1)
        self._verify_snat_mangle_rules(nat_rules_delta, mangle_rules_delta,
                                       router)
        self.assertEqual(self.send_adv_notif.call_count, 1)

    def test_process_router_snat_enabled(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(enable_snat=False)
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        # Process without NAT
        ri.process(agent)
        orig_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]
        orig_mangle_rules = ri.iptables_manager.ipv4['mangle'].rules[:]
        # Reprocess with NAT
        router['enable_snat'] = True
        # Reassign the router object to RouterInfo
        ri.router = router
        ri.process(agent)
        # For some reason set logic does not work well with
        # IpTablesRule instances
        nat_rules_delta = [r for r in ri.iptables_manager.ipv4['nat'].rules
                           if r not in orig_nat_rules]
        self.assertEqual(len(nat_rules_delta), 3)
        mangle_rules_delta = [
            r for r in ri.iptables_manager.ipv4['mangle'].rules
            if r not in orig_mangle_rules]
        self.assertEqual(len(mangle_rules_delta), 1)
        self._verify_snat_mangle_rules(nat_rules_delta, mangle_rules_delta,
                                       router)
        self.assertEqual(self.send_adv_notif.call_count, 1)

    def test_process_router_interface_added(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        # Process with NAT
        ri.process(agent)
        # Add an interface and reprocess
        l3_test_common.router_append_interface(router)
        # Reassign the router object to RouterInfo
        ri.router = router
        ri.process(agent)
        # send_ip_addr_adv_notif is called both times process is called
        self.assertEqual(self.send_adv_notif.call_count, 2)

    def _test_process_ipv6_only_or_dual_stack_gw(self, dual_stack=False):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(ip_version=6,
                                                    dual_stack=dual_stack)
        # Get NAT rules without the gw_port
        gw_port = router['gw_port']
        router['gw_port'] = None
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        self._process_router_instance_for_agent(agent, ri, router)
        orig_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]

        # Get NAT rules with the gw_port
        router['gw_port'] = gw_port
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        orig_ext_gw_nat_rules = ri.external_gateway_nat_rules
        with mock.patch.object(
                ri,
                'external_gateway_nat_rules') as external_gateway_nat_rules:
            external_gateway_nat_rules.side_effect = orig_ext_gw_nat_rules
            self._process_router_instance_for_agent(agent, ri, router)
            new_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]

            # NAT rules should only change for dual_stack operation
            if dual_stack:
                self.assertTrue(external_gateway_nat_rules.called)
                self.assertNotEqual(orig_nat_rules, new_nat_rules)
            else:
                self.assertFalse(external_gateway_nat_rules.called)
                self.assertEqual(orig_nat_rules, new_nat_rules)

    def test_process_ipv6_only_gw(self):
        self._test_process_ipv6_only_or_dual_stack_gw()

    def test_process_dual_stack_gw(self):
        self._test_process_ipv6_only_or_dual_stack_gw(dual_stack=True)

    def _process_router_ipv6_interface_added(
            self, router, ra_mode=None, addr_mode=None):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        # Process with NAT
        ri.process(agent)
        orig_nat_rules = ri.iptables_manager.ipv4['nat'].rules[:]
        # Add an IPv6 interface and reprocess
        l3_test_common.router_append_interface(router, count=1,
                                               ip_version=6, ra_mode=ra_mode,
                                               addr_mode=addr_mode)
        # Reassign the router object to RouterInfo
        self._process_router_instance_for_agent(agent, ri, router)
        # IPv4 NAT rules should not be changed by adding an IPv6 interface
        nat_rules_delta = [r for r in ri.iptables_manager.ipv4['nat'].rules
                           if r not in orig_nat_rules]
        self.assertFalse(nat_rules_delta)
        return ri

    def _expected_call_lookup_ri_process(self, ri, process):
        """Expected call if a process is looked up in a router instance."""
        return [mock.call(uuid=ri.router['id'],
                          service=process,
                          default_cmd_callback=mock.ANY,
                          namespace=ri.ns_name,
                          conf=mock.ANY,
                          run_as_root=True)]

    def _process_router_ipv6_subnet_added(
            self, router, ipv6_subnet_modes=None):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        agent.external_gateway_added = mock.Mock()
        self._process_router_instance_for_agent(agent, ri, router)
        # Add an IPv6 interface with len(ipv6_subnet_modes) subnets
        # and reprocess
        l3_test_common.router_append_subnet(
            router,
            count=len(ipv6_subnet_modes),
            ip_version=6,
            ipv6_subnet_modes=ipv6_subnet_modes)
        # Reassign the router object to RouterInfo
        self._process_router_instance_for_agent(agent, ri, router)
        return ri

    def _assert_ri_process_enabled(self, ri, process):
        """Verify that process was enabled for a router instance."""
        expected_calls = self._expected_call_lookup_ri_process(
            ri, process)
        expected_calls.append(mock.call().enable(reload_cfg=True))
        self.assertEqual(expected_calls, self.external_process.mock_calls)

    def _assert_ri_process_disabled(self, ri, process):
        """Verify that process was disabled for a router instance."""
        expected_calls = self._expected_call_lookup_ri_process(
            ri, process)
        expected_calls.append(mock.call().disable())
        self.assertEqual(expected_calls, self.external_process.mock_calls)

    def test_process_router_ipv6_interface_added(self):
        router = l3_test_common.prepare_router_data()
        ri = self._process_router_ipv6_interface_added(router)
        self._assert_ri_process_enabled(ri, 'radvd')
        # Expect radvd configured without prefix
        self.assertNotIn('prefix',
                         self.utils_replace_file.call_args[0][1].split())

    def test_process_router_ipv6_slaac_interface_added(self):
        router = l3_test_common.prepare_router_data()
        ri = self._process_router_ipv6_interface_added(
            router, ra_mode=l3_constants.IPV6_SLAAC)
        self._assert_ri_process_enabled(ri, 'radvd')
        # Expect radvd configured with prefix
        self.assertIn('prefix',
                      self.utils_replace_file.call_args[0][1].split())

    def test_process_router_ipv6_subnets_added(self):
        router = l3_test_common.prepare_router_data()
        ri = self._process_router_ipv6_subnet_added(router, ipv6_subnet_modes=[
            {'ra_mode': l3_constants.IPV6_SLAAC,
             'address_mode': l3_constants.IPV6_SLAAC},
            {'ra_mode': l3_constants.DHCPV6_STATELESS,
             'address_mode': l3_constants.DHCPV6_STATELESS},
            {'ra_mode': l3_constants.DHCPV6_STATEFUL,
             'address_mode': l3_constants.DHCPV6_STATEFUL}])
        self._assert_ri_process_enabled(ri, 'radvd')
        radvd_config = self.utils_replace_file.call_args[0][1].split()
        # Assert we have a prefix from IPV6_SLAAC and a prefix from
        # DHCPV6_STATELESS on one interface
        self.assertEqual(2, radvd_config.count("prefix"))
        self.assertEqual(1, radvd_config.count("interface"))

    def test_process_router_ipv6_subnets_added_to_existing_port(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        agent.external_gateway_added = mock.Mock()
        self._process_router_instance_for_agent(agent, ri, router)
        # Add the first subnet on a new interface
        l3_test_common.router_append_subnet(
            router, count=1,
            ip_version=6, ipv6_subnet_modes=[
                {'ra_mode': l3_constants.IPV6_SLAAC,
                 'address_mode': l3_constants.IPV6_SLAAC}])
        self._process_router_instance_for_agent(agent, ri, router)
        self._assert_ri_process_enabled(ri, 'radvd')
        radvd_config = self.utils_replace_file.call_args[0][1].split()
        self.assertEqual(1, len(ri.internal_ports[1]['subnets']))
        self.assertEqual(1, len(ri.internal_ports[1]['fixed_ips']))
        self.assertEqual(1, radvd_config.count("prefix"))
        self.assertEqual(1, radvd_config.count("interface"))
        # Reset mocks to verify radvd enabled and configured correctly
        # after second subnet added to interface
        self.external_process.reset_mock()
        self.utils_replace_file.reset_mock()
        # Add the second subnet on the same interface
        interface_id = router[l3_constants.INTERFACE_KEY][1]['id']
        l3_test_common.router_append_subnet(
            router, count=1,
            ip_version=6,
            ipv6_subnet_modes=[
                {'ra_mode': l3_constants.IPV6_SLAAC,
                 'address_mode': l3_constants.IPV6_SLAAC}],
            interface_id=interface_id)
        self._process_router_instance_for_agent(agent, ri, router)
        # radvd should have been enabled again and the interface
        # should have two prefixes
        self._assert_ri_process_enabled(ri, 'radvd')
        radvd_config = self.utils_replace_file.call_args[0][1].split()
        self.assertEqual(2, len(ri.internal_ports[1]['subnets']))
        self.assertEqual(2, len(ri.internal_ports[1]['fixed_ips']))
        self.assertEqual(2, radvd_config.count("prefix"))
        self.assertEqual(1, radvd_config.count("interface"))

    def test_process_router_ipv6v4_interface_added(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        # Process with NAT
        ri.process(agent)
        # Add an IPv4 and IPv6 interface and reprocess
        l3_test_common.router_append_interface(router, count=1, ip_version=4)
        l3_test_common.router_append_interface(router, count=1, ip_version=6)
        # Reassign the router object to RouterInfo
        self._process_router_instance_for_agent(agent, ri, router)
        self._assert_ri_process_enabled(ri, 'radvd')

    def test_process_router_interface_removed(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        # Process with NAT
        ri.process(agent)
        # Add an interface and reprocess
        del router[l3_constants.INTERFACE_KEY][1]
        # Reassign the router object to RouterInfo
        ri.router = router
        ri.process(agent)
        # send_ip_addr_adv_notif is called both times process is called
        self.assertEqual(self.send_adv_notif.call_count, 2)

    def test_process_router_ipv6_interface_removed(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        self._process_router_instance_for_agent(agent, ri, router)
        # Add an IPv6 interface and reprocess
        l3_test_common.router_append_interface(router, count=1, ip_version=6)
        self._process_router_instance_for_agent(agent, ri, router)
        self._assert_ri_process_enabled(ri, 'radvd')
        # Reset the calls so we can check for disable radvd
        self.external_process.reset_mock()
        self.process_monitor.reset_mock()
        # Remove the IPv6 interface and reprocess
        del router[l3_constants.INTERFACE_KEY][1]
        self._process_router_instance_for_agent(agent, ri, router)
        self._assert_ri_process_disabled(ri, 'radvd')

    def test_process_router_ipv6_subnet_removed(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        agent.external_gateway_added = mock.Mock()
        self._process_router_instance_for_agent(agent, ri, router)
        # Add an IPv6 interface with two subnets and reprocess
        l3_test_common.router_append_subnet(
            router, count=2, ip_version=6,
            ipv6_subnet_modes=([{'ra_mode': l3_constants.IPV6_SLAAC,
                                 'address_mode': l3_constants.IPV6_SLAAC}]
                               * 2))
        self._process_router_instance_for_agent(agent, ri, router)
        self._assert_ri_process_enabled(ri, 'radvd')
        # Reset mocks to check for modified radvd config
        self.utils_replace_file.reset_mock()
        self.external_process.reset_mock()
        # Remove one subnet from the interface and reprocess
        interfaces = copy.deepcopy(router[l3_constants.INTERFACE_KEY])
        del interfaces[1]['subnets'][0]
        del interfaces[1]['fixed_ips'][0]
        router[l3_constants.INTERFACE_KEY] = interfaces
        self._process_router_instance_for_agent(agent, ri, router)
        # Assert radvd was enabled again and that we only have one
        # prefix on the interface
        self._assert_ri_process_enabled(ri, 'radvd')
        radvd_config = self.utils_replace_file.call_args[0][1].split()
        self.assertEqual(1, len(ri.internal_ports[1]['subnets']))
        self.assertEqual(1, len(ri.internal_ports[1]['fixed_ips']))
        self.assertEqual(1, radvd_config.count("interface"))
        self.assertEqual(1, radvd_config.count("prefix"))

    def test_process_router_internal_network_added_unexpected_error(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        with mock.patch.object(
                ri,
                'internal_network_added') as internal_network_added:
            # raise RuntimeError to simulate that an unexpected exception
            # occurs
            internal_network_added.side_effect = RuntimeError
            self.assertRaises(RuntimeError, ri.process, agent)
            self.assertNotIn(
                router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

            # The unexpected exception has been fixed manually
            internal_network_added.side_effect = None

            # periodic_sync_routers_task finds out that _rpc_loop failed to
            # process the router last time, it will retry in the next run.
            ri.process(agent)
            # We were able to add the port to ri.internal_ports
            self.assertIn(
                router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

    def test_process_router_internal_network_removed_unexpected_error(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
        ri.external_gateway_added = mock.Mock()
        # add an internal port
        ri.process(agent)

        with mock.patch.object(
                ri,
                'internal_network_removed') as internal_net_removed:
            # raise RuntimeError to simulate that an unexpected exception
            # occurs
            internal_net_removed.side_effect = RuntimeError
            ri.internal_ports[0]['admin_state_up'] = False
            # The above port is set to down state, remove it.
            self.assertRaises(RuntimeError, ri.process, agent)
            self.assertIn(
                router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

            # The unexpected exception has been fixed manually
            internal_net_removed.side_effect = None

            # periodic_sync_routers_task finds out that _rpc_loop failed to
            # process the router last time, it will retry in the next run.
            ri.process(agent)
            # We were able to remove the port from ri.internal_ports
            self.assertNotIn(
                router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

    def test_process_router_floatingip_nochange(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        with mock.patch.object(
            agent.plugin_rpc, 'update_floatingip_statuses'
        ) as mock_update_fip_status:
            router = l3_test_common.prepare_router_data(num_internal_ports=1)
            fip1 = {'id': _uuid(), 'floating_ip_address': '8.8.8.8',
                    'fixed_ip_address': '7.7.7.7', 'status': 'ACTIVE',
                    'port_id': router[l3_constants.INTERFACE_KEY][0]['id']}
            fip2 = copy.copy(fip1)
            fip2.update({'id': _uuid(), 'status': 'DOWN'})
            router[l3_constants.FLOATINGIP_KEY] = [fip1, fip2]

            ri = legacy_router.LegacyRouter(router['id'], router,
                                            **self.ri_kwargs)
            ri.external_gateway_added = mock.Mock()
            ri.process(agent)
            # make sure only the one that went from DOWN->ACTIVE was sent
            mock_update_fip_status.assert_called_once_with(
                mock.ANY, ri.router_id, {fip2['id']: 'ACTIVE'})

    def test_process_router_floatingip_disabled(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        with mock.patch.object(
            agent.plugin_rpc,
            'update_floatingip_statuses') as mock_update_fip_status:
            fip_id = _uuid()
            router = l3_test_common.prepare_router_data(num_internal_ports=1)
            router[l3_constants.FLOATINGIP_KEY] = [
                {'id': fip_id,
                 'floating_ip_address': '8.8.8.8',
                 'fixed_ip_address': '7.7.7.7',
                 'status': 'DOWN',
                 'port_id': router[l3_constants.INTERFACE_KEY][0]['id']}]

            ri = legacy_router.LegacyRouter(router['id'],
                                            router,
                                            **self.ri_kwargs)
            ri.external_gateway_added = mock.Mock()
            ri.process(agent)
            # Assess the call for putting the floating IP up was performed
            mock_update_fip_status.assert_called_once_with(
                mock.ANY, ri.router_id,
                {fip_id: l3_constants.FLOATINGIP_STATUS_ACTIVE})
            mock_update_fip_status.reset_mock()
            # Process the router again, this time without floating IPs
            router[l3_constants.FLOATINGIP_KEY] = []
            ri.router = router
            ri.process(agent)
            # Assess the call for putting the floating IP up was performed
            mock_update_fip_status.assert_called_once_with(
                mock.ANY, ri.router_id,
                {fip_id: l3_constants.FLOATINGIP_STATUS_DOWN})

    def test_process_router_floatingip_exception(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        with mock.patch.object(
            agent.plugin_rpc,
            'update_floatingip_statuses') as mock_update_fip_status:
            fip_id = _uuid()
            router = l3_test_common.prepare_router_data(num_internal_ports=1)
            router[l3_constants.FLOATINGIP_KEY] = [
                {'id': fip_id,
                 'floating_ip_address': '8.8.8.8',
                 'fixed_ip_address': '7.7.7.7',
                 'port_id': router[l3_constants.INTERFACE_KEY][0]['id']}]

            ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
            ri.process_floating_ip_addresses = mock.Mock(
                side_effect=RuntimeError)
            ri.external_gateway_added = mock.Mock()
            ri.process(agent)
            # Assess the call for putting the floating IP into Error
            # was performed
            mock_update_fip_status.assert_called_once_with(
                mock.ANY, ri.router_id,
                {fip_id: l3_constants.FLOATINGIP_STATUS_ERROR})

    def test_process_external_iptables_exception(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        with mock.patch.object(
            agent.plugin_rpc,
            'update_floatingip_statuses') as mock_update_fip_status:
            fip_id = _uuid()
            router = l3_test_common.prepare_router_data(num_internal_ports=1)
            router[l3_constants.FLOATINGIP_KEY] = [
                {'id': fip_id,
                 'floating_ip_address': '8.8.8.8',
                 'fixed_ip_address': '7.7.7.7',
                 'port_id': router[l3_constants.INTERFACE_KEY][0]['id']}]

            ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)
            ri.iptables_manager._apply = mock.Mock(side_effect=Exception)
            ri.process_external(agent)
            # Assess the call for putting the floating IP into Error
            # was performed
            mock_update_fip_status.assert_called_once_with(
                mock.ANY, ri.router_id,
                {fip_id: l3_constants.FLOATINGIP_STATUS_ERROR})

            self.assertEqual(ri.iptables_manager._apply.call_count, 1)

    def test_handle_router_snat_rules_distributed_without_snat_manager(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = dvr_router.DvrEdgeRouter(
            agent,
            HOSTNAME,
            'foo_router_id',
            {},
            **self.ri_kwargs)
        ri.iptables_manager = mock.Mock()
        ri._is_this_snat_host = mock.Mock(return_value=True)
        ri.get_ex_gw_port = mock.Mock(return_value=mock.ANY)

        with mock.patch.object(dvr_router.LOG, 'debug') as log_debug:
            ri._handle_router_snat_rules(mock.ANY, mock.ANY)
        self.assertIsNone(ri.snat_iptables_manager)
        self.assertFalse(ri.iptables_manager.called)
        self.assertTrue(log_debug.called)

    def test_handle_router_snat_rules_add_back_jump(self):
        ri = l3router.RouterInfo(_uuid(), {}, **self.ri_kwargs)
        ri.iptables_manager = mock.MagicMock()
        port = {'fixed_ips': [{'ip_address': '192.168.1.4'}]}

        ri._handle_router_snat_rules(port, "iface")

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
        ri = l3router.RouterInfo(_uuid(), {}, **self.ri_kwargs)
        ex_gw_port = {'fixed_ips': [{'ip_address': '192.168.1.4'}]}
        ri.router = {'distributed': False}
        ri._handle_router_snat_rules(ex_gw_port, "iface")

        nat_rules = list(map(str, ri.iptables_manager.ipv4['nat'].rules))
        wrap_name = ri.iptables_manager.wrap_name

        jump_float_rule = "-A %s-snat -j %s-float-snat" % (wrap_name,
                                                           wrap_name)
        snat_rule1 = ("-A %s-snat -o iface -j SNAT --to-source %s") % (
            wrap_name, ex_gw_port['fixed_ips'][0]['ip_address'])
        snat_rule2 = ("-A %s-snat -m mark ! --mark 0x2/%s "
                      "-m conntrack --ctstate DNAT "
                      "-j SNAT --to-source %s") % (
            wrap_name, l3_constants.ROUTER_MARK_MASK,
            ex_gw_port['fixed_ips'][0]['ip_address'])

        self.assertIn(jump_float_rule, nat_rules)

        self.assertIn(snat_rule1, nat_rules)
        self.assertIn(snat_rule2, nat_rules)
        self.assertThat(nat_rules.index(jump_float_rule),
                        matchers.LessThan(nat_rules.index(snat_rule1)))

        mangle_rules = list(map(str, ri.iptables_manager.ipv4['mangle'].rules))
        mangle_rule = ("-A %s-mark -i iface "
                       "-j MARK --set-xmark 0x2/%s" %
                       (wrap_name, l3_constants.ROUTER_MARK_MASK))
        self.assertIn(mangle_rule, mangle_rules)

    def test_process_router_delete_stale_internal_devices(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        stale_devlist = [l3_test_common.FakeDev('qr-a1b2c3d4-e5'),
                         l3_test_common.FakeDev('qr-b2c3d4e5-f6')]
        stale_devnames = [dev.name for dev in stale_devlist]

        get_devices_return = []
        get_devices_return.extend(stale_devlist)
        self.mock_ip.get_devices.return_value = get_devices_return

        router = l3_test_common.prepare_router_data(enable_snat=True,
                                                    num_internal_ports=1)
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)

        internal_ports = ri.router.get(l3_constants.INTERFACE_KEY, [])
        self.assertEqual(len(internal_ports), 1)
        internal_port = internal_ports[0]

        with mock.patch.object(ri, 'internal_network_removed'
                               ) as internal_network_removed,\
                mock.patch.object(ri, 'internal_network_added'
                                  ) as internal_network_added,\
                mock.patch.object(ri, 'external_gateway_removed'
                                  ) as external_gateway_removed,\
                mock.patch.object(ri, 'external_gateway_added'
                                  ) as external_gateway_added:

            ri.process(agent)

            self.assertEqual(external_gateway_added.call_count, 1)
            self.assertFalse(external_gateway_removed.called)
            self.assertFalse(internal_network_removed.called)
            internal_network_added.assert_called_once_with(internal_port)
            self.assertEqual(self.mock_driver.unplug.call_count,
                             len(stale_devnames))
            calls = [mock.call(stale_devname,
                               namespace=ri.ns_name,
                               prefix=l3_agent.INTERNAL_DEV_PREFIX)
                     for stale_devname in stale_devnames]
            self.mock_driver.unplug.assert_has_calls(calls, any_order=True)

    def test_process_router_delete_stale_external_devices(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        stale_devlist = [l3_test_common.FakeDev('qg-a1b2c3d4-e5')]
        stale_devnames = [dev.name for dev in stale_devlist]

        router = l3_test_common.prepare_router_data(enable_snat=True,
                                                    num_internal_ports=1)
        del router['gw_port']
        ri = l3router.RouterInfo(router['id'], router, **self.ri_kwargs)

        self.mock_ip.get_devices.return_value = stale_devlist

        ri.process(agent)

        self.mock_driver.unplug.assert_called_with(
            stale_devnames[0],
            bridge="br-ex",
            namespace=ri.ns_name,
            prefix=l3_agent.EXTERNAL_DEV_PREFIX)

    def test_router_deleted(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._queue = mock.Mock()
        agent.router_deleted(None, FAKE_ID)
        self.assertEqual(1, agent._queue.add.call_count)

    def test_routers_updated(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._queue = mock.Mock()
        agent.routers_updated(None, [FAKE_ID])
        self.assertEqual(1, agent._queue.add.call_count)

    def test_removed_from_agent(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._queue = mock.Mock()
        agent.router_removed_from_agent(None, {'router_id': FAKE_ID})
        self.assertEqual(1, agent._queue.add.call_count)

    def test_added_to_agent(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._queue = mock.Mock()
        agent.router_added_to_agent(None, [FAKE_ID])
        self.assertEqual(1, agent._queue.add.call_count)

    def test_destroy_namespace(self):
        namespace = 'qrouter-bar'

        self.mock_ip.get_namespaces.return_value = [namespace]
        self.mock_ip.get_devices.return_value = [
            l3_test_common.FakeDev('qr-aaaa'),
            l3_test_common.FakeDev('rfp-aaaa')]

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        ns = namespaces.RouterNamespace(
            'bar', self.conf, agent.driver, agent.use_ipv6)
        ns.create()

        ns.delete()
        self.mock_driver.unplug.assert_called_once_with('qr-aaaa',
                                                        prefix='qr-',
                                                        namespace='qrouter'
                                                        '-bar')
        self.mock_ip.del_veth.assert_called_once_with('rfp-aaaa')

    def test_destroy_router_namespace_skips_ns_removal(self):
        self.conf.set_override('router_delete_namespaces', False)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ns = namespaces.Namespace(
            'qrouter-bar', self.conf, agent.driver, agent.use_ipv6)
        ns.create()
        ns.delete()
        self.assertEqual(self.mock_ip.netns.delete.call_count, 0)

    def test_destroy_router_namespace_removes_ns(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ns = namespaces.Namespace(
            'qrouter-bar', self.conf, agent.driver, agent.use_ipv6)
        ns.create()
        ns.delete()
        self.mock_ip.netns.delete.assert_called_once_with("qrouter-bar")

    def _configure_metadata_proxy(self, enableflag=True):
        if not enableflag:
            self.conf.set_override('enable_metadata_proxy', False)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router_id = _uuid()
        router = {'id': router_id,
                  'external_gateway_info': {},
                  'routes': [],
                  'distributed': False}
        driver = metadata_driver.MetadataDriver
        with mock.patch.object(
            driver, 'destroy_monitored_metadata_proxy') as destroy_proxy:
            with mock.patch.object(
                driver, 'spawn_monitored_metadata_proxy') as spawn_proxy:
                agent._process_added_router(router)
                if enableflag:
                    spawn_proxy.assert_called_with(
                        mock.ANY,
                        mock.ANY,
                        self.conf.metadata_port,
                        mock.ANY,
                        router_id=router_id
                    )
                else:
                    self.assertFalse(spawn_proxy.call_count)
                agent._router_removed(router_id)
                if enableflag:
                    destroy_proxy.assert_called_with(mock.ANY,
                                                     router_id,
                                                     mock.ANY)
                else:
                    self.assertFalse(destroy_proxy.call_count)

    def test_enable_metadata_proxy(self):
        self._configure_metadata_proxy()

    def test_disable_metadata_proxy_spawn(self):
        self._configure_metadata_proxy(enableflag=False)

    def test_router_id_specified_in_conf(self):
        self.conf.set_override('use_namespaces', False)
        self.conf.set_override('router_id', '')
        self.assertRaises(SystemExit, l3_agent.L3NATAgent,
                          HOSTNAME, self.conf)

        self.conf.set_override('router_id', '1234')
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.assertEqual('1234', agent.conf.router_id)
        self.assertFalse(agent.namespaces_manager._clean_stale)

    def test_process_routers_update_rpc_timeout_on_get_routers(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.fullsync = False
        agent._process_router_if_compatible = mock.Mock()
        self.plugin_api.get_routers.side_effect = (
            oslo_messaging.MessagingTimeout)
        agent._queue = mock.Mock()
        update = mock.Mock()
        update.router = None
        agent._queue.each_update_to_next_router.side_effect = [
            [(None, update)]]

        agent._process_router_update()
        self.assertTrue(agent.fullsync)
        self.assertFalse(agent._process_router_if_compatible.called)

    def test_process_routers_update_rpc_timeout_on_get_ext_net(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.fullsync = False
        agent._process_router_if_compatible = mock.Mock()
        agent._process_router_if_compatible.side_effect = (
            oslo_messaging.MessagingTimeout)
        agent._queue = mock.Mock()
        agent._queue.each_update_to_next_router.side_effect = [
            [(None, mock.Mock())]]

        agent._process_router_update()
        self.assertTrue(agent.fullsync)

    def test_process_routers_update_router_deleted(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent._queue = mock.Mock()
        update = mock.Mock()
        update.router = None
        update.action = 1  # ROUTER_DELETED
        router_info = mock.MagicMock()
        agent.router_info[update.id] = router_info
        router_processor = mock.Mock()
        agent._queue.each_update_to_next_router.side_effect = [
            [(router_processor, update)]]
        agent._process_router_update()
        router_info.delete.assert_called_once_with(agent)
        self.assertFalse(agent.router_info)
        router_processor.fetched_and_processed.assert_called_once_with(
            update.timestamp)

    def test_process_router_if_compatible_with_no_ext_net_in_conf(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.plugin_api.get_external_network_id.return_value = 'aaa'

        router = {'id': _uuid(),
                  'routes': [],
                  'admin_state_up': True,
                  'external_gateway_info': {'network_id': 'aaa'}}

        agent._process_router_if_compatible(router)
        self.assertIn(router['id'], agent.router_info)
        self.plugin_api.get_external_network_id.assert_called_with(
            agent.context)

    def test_process_router_if_compatible_with_cached_ext_net(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.plugin_api.get_external_network_id.return_value = 'aaa'
        agent.target_ex_net_id = 'aaa'

        router = {'id': _uuid(),
                  'routes': [],
                  'admin_state_up': True,
                  'external_gateway_info': {'network_id': 'aaa'}}

        agent._process_router_if_compatible(router)
        self.assertIn(router['id'], agent.router_info)
        self.assertFalse(self.plugin_api.get_external_network_id.called)

    def test_process_router_if_compatible_with_stale_cached_ext_net(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.plugin_api.get_external_network_id.return_value = 'aaa'
        agent.target_ex_net_id = 'bbb'

        router = {'id': _uuid(),
                  'routes': [],
                  'admin_state_up': True,
                  'external_gateway_info': {'network_id': 'aaa'}}

        agent._process_router_if_compatible(router)
        self.assertIn(router['id'], agent.router_info)
        self.plugin_api.get_external_network_id.assert_called_with(
            agent.context)

    def test_process_router_if_compatible_w_no_ext_net_and_2_net_plugin(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        router = {'id': _uuid(),
                  'routes': [],
                  'admin_state_up': True,
                  'external_gateway_info': {'network_id': 'aaa'}}

        agent.router_info = {}
        self.plugin_api.get_external_network_id.side_effect = (
            n_exc.TooManyExternalNetworks())
        self.assertRaises(n_exc.TooManyExternalNetworks,
                          agent._process_router_if_compatible,
                          router)
        self.assertNotIn(router['id'], agent.router_info)

    def test_process_router_if_compatible_with_ext_net_in_conf(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.plugin_api.get_external_network_id.return_value = 'aaa'

        router = {'id': _uuid(),
                  'routes': [],
                  'admin_state_up': True,
                  'external_gateway_info': {'network_id': 'bbb'}}

        agent.router_info = {}
        self.conf.set_override('gateway_external_network_id', 'aaa')
        self.assertRaises(n_exc.RouterNotCompatibleWithAgent,
                          agent._process_router_if_compatible,
                          router)
        self.assertNotIn(router['id'], agent.router_info)

    def test_process_router_if_compatible_with_no_bridge_no_ext_net(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.plugin_api.get_external_network_id.return_value = 'aaa'

        router = {'id': _uuid(),
                  'routes': [],
                  'admin_state_up': True,
                  'external_gateway_info': {'network_id': 'aaa'}}

        agent.router_info = {}
        self.conf.set_override('external_network_bridge', '')
        agent._process_router_if_compatible(router)
        self.assertIn(router['id'], agent.router_info)

    def test_nonexistent_interface_driver(self):
        self.conf.set_override('interface_driver', None)
        self.assertRaises(SystemExit, l3_agent.L3NATAgent,
                          HOSTNAME, self.conf)

        self.conf.set_override('interface_driver', 'wrong.driver')
        self.assertRaises(SystemExit, l3_agent.L3NATAgent,
                          HOSTNAME, self.conf)

    @mock.patch.object(namespaces.RouterNamespace, 'delete')
    @mock.patch.object(dvr_snat_ns.SnatNamespace, 'delete')
    def _cleanup_namespace_test(self,
                                stale_namespace_list,
                                router_list,
                                other_namespaces,
                                mock_snat_ns,
                                mock_router_ns):

        good_namespace_list = [namespaces.NS_PREFIX + r['id']
                               for r in router_list]
        good_namespace_list += [dvr_snat_ns.SNAT_NS_PREFIX + r['id']
                                for r in router_list]
        self.mock_ip.get_namespaces.return_value = (stale_namespace_list +
                                                    good_namespace_list +
                                                    other_namespaces)

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        self.assertTrue(agent.namespaces_manager._clean_stale)

        pm = self.external_process.return_value
        pm.reset_mock()

        with agent.namespaces_manager as ns_manager:
            for r in router_list:
                ns_manager.keep_router(r['id'])
        qrouters = [n for n in stale_namespace_list
                    if n.startswith(namespaces.NS_PREFIX)]
        self.assertEqual(mock_router_ns.call_count, len(qrouters))
        self.assertEqual(mock_snat_ns.call_count,
            len(stale_namespace_list) - len(qrouters))

        self.assertFalse(agent.namespaces_manager._clean_stale)

    def test_cleanup_namespace(self):
        self.conf.set_override('router_id', None)
        stale_namespaces = [namespaces.NS_PREFIX + 'foo',
                            namespaces.NS_PREFIX + 'bar',
                            dvr_snat_ns.SNAT_NS_PREFIX + 'foo']
        other_namespaces = ['unknown']

        self._cleanup_namespace_test(stale_namespaces,
                                     [],
                                     other_namespaces)

    def test_cleanup_namespace_with_registered_router_ids(self):
        self.conf.set_override('router_id', None)
        stale_namespaces = [namespaces.NS_PREFIX + 'cccc',
                            namespaces.NS_PREFIX + 'eeeee',
                            dvr_snat_ns.SNAT_NS_PREFIX + 'fffff']
        router_list = [{'id': 'foo', 'distributed': False},
                       {'id': 'aaaa', 'distributed': False}]
        other_namespaces = ['qdhcp-aabbcc', 'unknown']

        self._cleanup_namespace_test(stale_namespaces,
                                     router_list,
                                     other_namespaces)

    def test_cleanup_namespace_with_conf_router_id(self):
        self.conf.set_override('router_id', 'bbbbb')
        stale_namespaces = [namespaces.NS_PREFIX + 'cccc',
                            namespaces.NS_PREFIX + 'eeeee',
                            namespaces.NS_PREFIX + self.conf.router_id]
        router_list = [{'id': 'foo', 'distributed': False},
                       {'id': 'aaaa', 'distributed': False}]
        other_namespaces = ['qdhcp-aabbcc', 'unknown']

        self._cleanup_namespace_test(stale_namespaces,
                                     router_list,
                                     other_namespaces)

    def test_create_dvr_gateway(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data()
        ri = dvr_router.DvrEdgeRouter(agent,
                                      HOSTNAME,
                                      router['id'],
                                      router,
                                      **self.ri_kwargs)

        port_id = _uuid()
        subnet_id = _uuid()
        dvr_gw_port = {'fixed_ips': [{'ip_address': '20.0.0.30',
                                      'prefixlen': 24,
                                      'subnet_id': subnet_id}],
                       'subnets': [{'id': subnet_id,
                                    'cidr': '20.0.0.0/24',
                                    'gateway_ip': '20.0.0.1'}],
                       'id': port_id,
                       'network_id': _uuid(),
                       'mac_address': 'ca:fe:de:ad:be:ef'}

        interface_name = ri.get_snat_int_device_name(port_id)
        self.device_exists.return_value = False

        with mock.patch.object(ri, 'get_snat_interfaces') as get_interfaces:
            get_interfaces.return_value = self.snat_ports
            ri._create_dvr_gateway(dvr_gw_port, interface_name)

        # check 2 internal ports are plugged
        # check 1 ext-gw-port is plugged
        self.assertEqual(self.mock_driver.plug.call_count, 3)
        self.assertEqual(self.mock_driver.init_router_port.call_count, 3)

    def test_get_service_plugin_list(self):
        service_plugins = [p_const.L3_ROUTER_NAT]
        self.plugin_api.get_service_plugin_list.return_value = service_plugins
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.assertEqual(service_plugins, agent.neutron_service_plugins)
        self.assertTrue(self.plugin_api.get_service_plugin_list.called)

    def test_get_service_plugin_list_failed(self):
        raise_rpc = oslo_messaging.RemoteError()
        self.plugin_api.get_service_plugin_list.side_effect = raise_rpc
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.assertIsNone(agent.neutron_service_plugins)
        self.assertTrue(self.plugin_api.get_service_plugin_list.called)

    def test_get_service_plugin_list_retried(self):
        raise_timeout = oslo_messaging.MessagingTimeout()
        # Raise a timeout the first 2 times it calls
        # get_service_plugin_list then return a empty tuple
        self.plugin_api.get_service_plugin_list.side_effect = (
            raise_timeout, raise_timeout, tuple()
        )
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        self.assertEqual(agent.neutron_service_plugins, tuple())

    def test_get_service_plugin_list_retried_max(self):
        raise_timeout = oslo_messaging.MessagingTimeout()
        # Raise a timeout 5 times
        self.plugin_api.get_service_plugin_list.side_effect = (
            (raise_timeout, ) * 5
        )
        self.assertRaises(oslo_messaging.MessagingTimeout, l3_agent.L3NATAgent,
                          HOSTNAME, self.conf)

    def test_external_gateway_removed_ext_gw_port_no_fip_ns(self):
        self.conf.set_override('state_path', '/tmp')

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.conf.agent_mode = 'dvr_snat'
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['gw_port_host'] = HOSTNAME
        self.mock_driver.unplug.reset_mock()

        external_net_id = router['gw_port']['network_id']
        ri = dvr_router.DvrEdgeRouter(
            agent, HOSTNAME, router['id'], router, **self.ri_kwargs)
        ri.remove_floating_ip = mock.Mock()
        agent._fetch_external_net_id = mock.Mock(return_value=external_net_id)
        ri.ex_gw_port = ri.router['gw_port']
        del ri.router['gw_port']
        ri.fip_ns = None
        nat = ri.iptables_manager.ipv4['nat']
        nat.clear_rules_by_tag = mock.Mock()
        nat.add_rule = mock.Mock()

        ri.snat_namespace = mock.Mock()
        ri.external_gateway_removed(
            ri.ex_gw_port,
            ri.get_external_device_name(ri.ex_gw_port['id']))

        self.assertFalse(ri.remove_floating_ip.called)

    def test_spawn_radvd(self):
        router = l3_test_common.prepare_router_data(ip_version=6)

        conffile = '/fake/radvd.conf'
        pidfile = '/fake/radvd.pid'
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)

        # we don't want the whole process manager to be mocked to be
        # able to catch execute() calls
        self.external_process_p.stop()
        self.ip_cls_p.stop()

        get_conf_file_name = 'neutron.agent.linux.utils.get_conf_file_name'
        get_pid_file_name = ('neutron.agent.linux.external_process.'
                             'ProcessManager.get_pid_file_name')
        utils_execute = 'neutron.agent.common.utils.execute'

        mock.patch(get_conf_file_name).start().return_value = conffile
        mock.patch(get_pid_file_name).start().return_value = pidfile
        execute = mock.patch(utils_execute).start()

        radvd = ra.DaemonMonitor(
            router['id'],
            namespaces.RouterNamespace._get_ns_name(router['id']),
            agent.process_monitor,
            l3_test_common.FakeDev)
        radvd.enable(router['_interfaces'])

        cmd = execute.call_args[0][0]

        self.assertIn('radvd', cmd)

        _join = lambda *args: ' '.join(args)

        cmd = _join(*cmd)
        self.assertIn(_join('-C', conffile), cmd)
        self.assertIn(_join('-p', pidfile), cmd)
        self.assertIn(_join('-m', 'syslog'), cmd)

    def test_generate_radvd_conf_other_and_managed_flag(self):
        # expected = {ra_mode: (AdvOtherConfigFlag, AdvManagedFlag), ...}
        expected = {l3_constants.IPV6_SLAAC: (False, False),
                    l3_constants.DHCPV6_STATELESS: (True, False),
                    l3_constants.DHCPV6_STATEFUL: (False, True)}

        modes = [l3_constants.IPV6_SLAAC, l3_constants.DHCPV6_STATELESS,
                 l3_constants.DHCPV6_STATEFUL]
        mode_combos = list(iter_chain(*[[list(combo) for combo in
            iter_combinations(modes, i)] for i in range(1, len(modes) + 1)]))

        for mode_list in mode_combos:
            ipv6_subnet_modes = [{'ra_mode': mode, 'address_mode': mode}
                                 for mode in mode_list]
            router = l3_test_common.prepare_router_data()
            ri = self._process_router_ipv6_subnet_added(router,
                                                        ipv6_subnet_modes)

            ri.radvd._generate_radvd_conf(router[l3_constants.INTERFACE_KEY])

            def assertFlag(flag):
                return (self.assertIn if flag else self.assertNotIn)

            other_flag, managed_flag = (
                    any(expected[mode][0] for mode in mode_list),
                    any(expected[mode][1] for mode in mode_list))

            assertFlag(other_flag)('AdvOtherConfigFlag on;',
                self.utils_replace_file.call_args[0][1])
            assertFlag(managed_flag)('AdvManagedFlag on;',
                self.utils_replace_file.call_args[0][1])
