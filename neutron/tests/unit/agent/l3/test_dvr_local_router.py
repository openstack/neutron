# Copyright (c) 2015 Openstack Foundation
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

import mock
import netaddr

from oslo_log import log
from oslo_utils import uuidutils

from neutron.agent.common import config as agent_config
from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import config as l3_config
from neutron.agent.l3 import dvr_local_router as dvr_router
from neutron.agent.l3 import ha
from neutron.agent.l3 import link_local_allocator as lla
from neutron.agent.l3 import router_info
from neutron.agent.linux import external_process
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.common import config as base_config
from neutron.common import constants as l3_constants
from neutron.common import utils as common_utils
from neutron.tests import base
from neutron.tests.common import l3_test_common

_uuid = uuidutils.generate_uuid
FIP_PRI = 32768
HOSTNAME = 'myhost'


class TestDvrRouterOperations(base.BaseTestCase):

    def setUp(self):
        super(TestDvrRouterOperations, self).setUp()
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

    def _create_router(self, router=None, **kwargs):
        agent_conf = mock.Mock()
        self.router_id = _uuid()
        if not router:
            router = mock.MagicMock()
        return dvr_router.DvrLocalRouter(mock.sentinel.agent,
                                    mock.sentinel.myhost,
                                    self.router_id,
                                    router,
                                    agent_conf,
                                    mock.sentinel.interface_driver,
                                    **kwargs)

    def test_get_floating_ips_dvr(self):
        router = mock.MagicMock()
        router.get.return_value = [{'host': mock.sentinel.myhost},
                                   {'host': mock.sentinel.otherhost}]
        ri = self._create_router(router)

        fips = ri.get_floating_ips()

        self.assertEqual([{'host': mock.sentinel.myhost}], fips)

    @mock.patch.object(ip_lib, 'send_ip_addr_adv_notif')
    @mock.patch.object(ip_lib, 'IPDevice')
    @mock.patch.object(ip_lib, 'IPRule')
    def test_floating_ip_added_dist(self, mIPRule, mIPDevice, mock_adv_notif):
        router = mock.MagicMock()
        ri = self._create_router(router)
        ext_net_id = _uuid()
        subnet_id = _uuid()
        agent_gw_port = {'fixed_ips': [{'ip_address': '20.0.0.30',
                                        'prefixlen': 24,
                                        'subnet_id': subnet_id}],
                         'subnets': [{'id': subnet_id,
                                      'cidr': '20.0.0.0/24',
                                      'gateway_ip': '20.0.0.1'}],
                         'id': _uuid(),
                         'network_id': ext_net_id,
                         'mac_address': 'ca:fe:de:ad:be:ef'}

        fip = {'id': _uuid(),
               'host': HOSTNAME,
               'floating_ip_address': '15.1.2.3',
               'fixed_ip_address': '192.168.0.1',
               'floating_network_id': ext_net_id,
               'port_id': _uuid()}
        ri.fip_ns = mock.Mock()
        ri.fip_ns.agent_gateway_port = agent_gw_port
        ri.fip_ns.allocate_rule_priority.return_value = FIP_PRI
        ri.rtr_fip_subnet = lla.LinkLocalAddressPair('169.254.30.42/31')
        ri.dist_fip_count = 0
        ip_cidr = common_utils.ip_to_cidr(fip['floating_ip_address'])
        ri.floating_ip_added_dist(fip, ip_cidr)
        mIPRule().rule.add.assert_called_with(ip='192.168.0.1',
                                              table=16,
                                              priority=FIP_PRI)
        self.assertEqual(1, ri.dist_fip_count)
        # TODO(mrsmith): add more asserts

    @mock.patch.object(ip_lib, 'IPWrapper')
    @mock.patch.object(ip_lib, 'IPDevice')
    @mock.patch.object(ip_lib, 'IPRule')
    def test_floating_ip_removed_dist(self, mIPRule, mIPDevice, mIPWrapper):
        router = mock.MagicMock()
        ri = self._create_router(router)

        subnet_id = _uuid()
        agent_gw_port = {'fixed_ips': [{'ip_address': '20.0.0.30',
                                        'prefixlen': 24,
                                        'subnet_id': subnet_id}],
                         'subnets': [{'id': subnet_id,
                                      'cidr': '20.0.0.0/24',
                                      'gateway_ip': '20.0.0.1'}],
                         'id': _uuid(),
                         'network_id': _uuid(),
                         'mac_address': 'ca:fe:de:ad:be:ef'}
        fip_cidr = '11.22.33.44/24'

        ri.dist_fip_count = 2
        ri.fip_ns = mock.Mock()
        ri.fip_ns.get_name.return_value = 'fip_ns_name'
        ri.floating_ips_dict['11.22.33.44'] = FIP_PRI
        ri.fip_2_rtr = '11.22.33.42'
        ri.rtr_2_fip = '11.22.33.40'
        ri.fip_ns.agent_gateway_port = agent_gw_port
        s = lla.LinkLocalAddressPair('169.254.30.42/31')
        ri.rtr_fip_subnet = s
        ri.floating_ip_removed_dist(fip_cidr)
        mIPRule().rule.delete.assert_called_with(
            ip=str(netaddr.IPNetwork(fip_cidr).ip), table=16, priority=FIP_PRI)
        mIPDevice().route.delete_route.assert_called_with(fip_cidr, str(s.ip))
        self.assertFalse(ri.fip_ns.unsubscribe.called)

        ri.dist_fip_count = 1
        ri.rtr_fip_subnet = lla.LinkLocalAddressPair('15.1.2.3/32')
        _, fip_to_rtr = ri.rtr_fip_subnet.get_pair()
        fip_ns = ri.fip_ns

        ri.floating_ip_removed_dist(fip_cidr)

        self.assertTrue(fip_ns.destroyed)
        mIPWrapper().del_veth.assert_called_once_with(
            fip_ns.get_int_device_name(router['id']))
        mIPDevice().route.delete_gateway.assert_called_once_with(
            str(fip_to_rtr.ip), table=16)
        fip_ns.unsubscribe.assert_called_once_with(ri.router_id)

    def _test_add_floating_ip(self, ri, fip, is_failure):
        ri._add_fip_addr_to_device = mock.Mock(return_value=is_failure)
        ri.floating_ip_added_dist = mock.Mock()

        result = ri.add_floating_ip(fip,
                                    mock.sentinel.interface_name,
                                    mock.sentinel.device)
        ri._add_fip_addr_to_device.assert_called_once_with(
            fip, mock.sentinel.device)
        return result

    def test_add_floating_ip(self):
        ri = self._create_router(mock.MagicMock())
        ip = '15.1.2.3'
        fip = {'floating_ip_address': ip}
        result = self._test_add_floating_ip(ri, fip, True)
        ri.floating_ip_added_dist.assert_called_once_with(fip, ip + '/32')
        self.assertEqual(l3_constants.FLOATINGIP_STATUS_ACTIVE, result)

    def test_add_floating_ip_error(self):
        ri = self._create_router(mock.MagicMock())
        result = self._test_add_floating_ip(
            ri, {'floating_ip_address': '15.1.2.3'}, False)
        self.assertFalse(ri.floating_ip_added_dist.called)
        self.assertEqual(l3_constants.FLOATINGIP_STATUS_ERROR, result)

    @mock.patch.object(router_info.RouterInfo, 'remove_floating_ip')
    def test_remove_floating_ip(self, super_remove_floating_ip):
        ri = self._create_router(mock.MagicMock())
        ri.floating_ip_removed_dist = mock.Mock()

        ri.remove_floating_ip(mock.sentinel.device, mock.sentinel.ip_cidr)

        super_remove_floating_ip.assert_called_once_with(
            mock.sentinel.device, mock.sentinel.ip_cidr)
        ri.floating_ip_removed_dist.assert_called_once_with(
            mock.sentinel.ip_cidr)

    def test__get_internal_port(self):
        ri = self._create_router()
        port = {'fixed_ips': [{'subnet_id': mock.sentinel.subnet_id}]}
        router_ports = [port]
        ri.router.get.return_value = router_ports
        self.assertEqual(port, ri._get_internal_port(mock.sentinel.subnet_id))

    def test__get_internal_port_not_found(self):
        ri = self._create_router()
        port = {'fixed_ips': [{'subnet_id': mock.sentinel.subnet_id}]}
        router_ports = [port]
        ri.router.get.return_value = router_ports
        self.assertEqual(None, ri._get_internal_port(mock.sentinel.subnet_id2))

    def test__get_snat_idx_ipv4(self):
        ip_cidr = '101.12.13.00/24'
        ri = self._create_router(mock.MagicMock())
        snat_idx = ri._get_snat_idx(ip_cidr)
        # 0x650C0D00 is numerical value of 101.12.13.00
        self.assertEqual(0x650C0D00, snat_idx)

    def test__get_snat_idx_ipv6(self):
        ip_cidr = '2620:0:a03:e100::/64'
        ri = self._create_router(mock.MagicMock())
        snat_idx = ri._get_snat_idx(ip_cidr)
        # 0x3D345705 is 30 bit xor folded crc32 of the ip_cidr
        self.assertEqual(0x3D345705, snat_idx)

    def test__get_snat_idx_ipv6_below_32768(self):
        ip_cidr = 'd488::/30'
        # crc32 of this ip_cidr is 0x1BD7
        ri = self._create_router(mock.MagicMock())
        snat_idx = ri._get_snat_idx(ip_cidr)
        # 0x1BD7 + 0x3FFFFFFF = 0x40001BD6
        self.assertEqual(0x40001BD6, snat_idx)

    def test__set_subnet_arp_info(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        ri = dvr_router.DvrLocalRouter(
            agent, HOSTNAME, router['id'], router, **self.ri_kwargs)
        ports = ri.router.get(l3_constants.INTERFACE_KEY, [])
        subnet_id = l3_test_common.get_subnet_id(ports[0])
        test_ports = [{'mac_address': '00:11:22:33:44:55',
                      'device_owner': 'network:dhcp',
                      'fixed_ips': [{'ip_address': '1.2.3.4',
                                     'prefixlen': 24,
                                     'subnet_id': subnet_id}]}]

        self.plugin_api.get_ports_by_subnet.return_value = test_ports

        # Test basic case
        ports[0]['subnets'] = [{'id': subnet_id,
                                'cidr': '1.2.3.0/24'}]
        ri._set_subnet_arp_info(subnet_id)
        self.mock_ip_dev.neigh.add.assert_called_once_with(
            '1.2.3.4', '00:11:22:33:44:55')

        # Test negative case
        router['distributed'] = False
        ri._set_subnet_arp_info(subnet_id)
        self.mock_ip_dev.neigh.add.never_called()

    def test_add_arp_entry(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        subnet_id = l3_test_common.get_subnet_id(
            router[l3_constants.INTERFACE_KEY][0])
        arp_table = {'ip_address': '1.7.23.11',
                     'mac_address': '00:11:22:33:44:55',
                     'subnet_id': subnet_id}

        payload = {'arp_table': arp_table, 'router_id': router['id']}
        agent._router_added(router['id'], router)
        agent.add_arp_entry(None, payload)
        agent.router_deleted(None, router['id'])
        self.mock_ip_dev.neigh.add.assert_called_once_with(
            '1.7.23.11', '00:11:22:33:44:55')

    def test_add_arp_entry_no_routerinfo(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        subnet_id = l3_test_common.get_subnet_id(
            router[l3_constants.INTERFACE_KEY][0])
        arp_table = {'ip_address': '1.7.23.11',
                     'mac_address': '00:11:22:33:44:55',
                     'subnet_id': subnet_id}

        payload = {'arp_table': arp_table, 'router_id': router['id']}
        agent.add_arp_entry(None, payload)

    def test__update_arp_entry_with_no_subnet(self):
        ri = dvr_router.DvrLocalRouter(
            mock.sentinel.agent,
            HOSTNAME,
            'foo_router_id',
            {'distributed': True, 'gw_port_host': HOSTNAME},
            **self.ri_kwargs)
        with mock.patch.object(l3_agent.ip_lib, 'IPDevice') as f:
            ri._update_arp_entry(mock.ANY, mock.ANY, 'foo_subnet_id', 'add')
        self.assertFalse(f.call_count)

    def test_del_arp_entry(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        subnet_id = l3_test_common.get_subnet_id(
            router[l3_constants.INTERFACE_KEY][0])
        arp_table = {'ip_address': '1.5.25.15',
                     'mac_address': '00:44:33:22:11:55',
                     'subnet_id': subnet_id}

        payload = {'arp_table': arp_table, 'router_id': router['id']}
        agent._router_added(router['id'], router)
        # first add the entry
        agent.add_arp_entry(None, payload)
        # now delete it
        agent.del_arp_entry(None, payload)
        self.mock_ip_dev.neigh.delete.assert_called_once_with(
            '1.5.25.15', '00:44:33:22:11:55')
        agent.router_deleted(None, router['id'])

    def test_get_floating_agent_gw_interfaces(self):
        fake_network_id = _uuid()
        subnet_id = _uuid()
        agent_gateway_port = (
            [{'fixed_ips': [{'ip_address': '20.0.0.30',
                             'prefixlen': 24,
                             'subnet_id': subnet_id}],
              'subnets': [{'id': subnet_id,
                           'cidr': '20.0.0.0/24',
                           'gateway_ip': '20.0.0.1'}],
              'id': _uuid(),
              'binding:host_id': 'myhost',
              'device_owner': 'network:floatingip_agent_gateway',
              'network_id': fake_network_id,
              'mac_address': 'ca:fe:de:ad:be:ef'}]
        )

        router = l3_test_common.prepare_router_data(enable_snat=True)
        router[l3_constants.FLOATINGIP_AGENT_INTF_KEY] = agent_gateway_port
        router['distributed'] = True
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = dvr_router.DvrLocalRouter(
            agent, HOSTNAME, router['id'], router, **self.ri_kwargs)
        self.assertEqual(
            agent_gateway_port[0],
            ri.get_floating_agent_gw_interface(fake_network_id))

    def test_process_router_dist_floating_ip_add(self):
        fake_floatingips = {'floatingips': [
            {'id': _uuid(),
             'host': HOSTNAME,
             'floating_ip_address': '15.1.2.3',
             'fixed_ip_address': '192.168.0.1',
             'floating_network_id': mock.sentinel.ext_net_id,
             'port_id': _uuid()},
            {'id': _uuid(),
             'host': 'some-other-host',
             'floating_ip_address': '15.1.2.4',
             'fixed_ip_address': '192.168.0.10',
             'floating_network_id': mock.sentinel.ext_net_id,
             'port_id': _uuid()}]}

        router = l3_test_common.prepare_router_data(enable_snat=True)
        router[l3_constants.FLOATINGIP_KEY] = fake_floatingips['floatingips']
        router['distributed'] = True
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = dvr_router.DvrLocalRouter(agent,
                                  HOSTNAME,
                                  router['id'],
                                  router,
                                  **self.ri_kwargs)
        ri.iptables_manager.ipv4['nat'] = mock.MagicMock()
        ri.dist_fip_count = 0
        fip_ns = agent.get_fip_ns(mock.sentinel.ext_net_id)
        subnet_id = _uuid()
        fip_ns.agent_gateway_port = (
            {'fixed_ips': [{'ip_address': '20.0.0.30',
                            'subnet_id': subnet_id}],
             'subnets': [{'id': subnet_id,
                          'cidr': '20.0.0.0/24',
                          'gateway_ip': '20.0.0.1'}],
             'id': _uuid(),
             'network_id': _uuid(),
             'mac_address': 'ca:fe:de:ad:be:ef'}
        )

    def _test_ext_gw_updated_dvr_agent_mode(self, host,
                                            agent_mode, expected_call_count):
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        ri = dvr_router.DvrLocalRouter(agent,
                                       HOSTNAME,
                                       router['id'],
                                       router,
                                       **self.ri_kwargs)

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

    def test_ext_gw_updated_dvr_agent_mode_host(self):
        # no gateway should be added on dvr node
        self._test_ext_gw_updated_dvr_agent_mode(HOSTNAME,
                                                 'dvr', 0)

    def test_external_gateway_removed_ext_gw_port_and_fip(self):
        self.conf.set_override('state_path', '/tmp')

        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.conf.agent_mode = 'dvr'
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['gw_port_host'] = HOSTNAME
        self.mock_driver.unplug.reset_mock()

        external_net_id = router['gw_port']['network_id']
        ri = dvr_router.DvrLocalRouter(
            agent, HOSTNAME, router['id'], router, **self.ri_kwargs)
        ri.remove_floating_ip = mock.Mock()
        agent._fetch_external_net_id = mock.Mock(return_value=external_net_id)
        ri.ex_gw_port = ri.router['gw_port']
        del ri.router['gw_port']
        ri.fip_ns = None
        nat = ri.iptables_manager.ipv4['nat']
        nat.clear_rules_by_tag = mock.Mock()
        nat.add_rule = mock.Mock()

        ri.fip_ns = agent.get_fip_ns(external_net_id)
        subnet_id = _uuid()
        ri.fip_ns.agent_gateway_port = {
            'fixed_ips': [{
                            'ip_address': '20.0.0.30',
                            'prefixlen': 24,
                            'subnet_id': subnet_id
                         }],
            'subnets': [{'id': subnet_id,
                         'cidr': '20.0.0.0/24',
                         'gateway_ip': '20.0.0.1'}],
            'id': _uuid(),
            'network_id': external_net_id,
            'mac_address': 'ca:fe:de:ad:be:ef'}

        vm_floating_ip = '19.4.4.2'
        ri.floating_ips_dict[vm_floating_ip] = FIP_PRI
        ri.dist_fip_count = 1
        ri.rtr_fip_subnet = ri.fip_ns.local_subnets.allocate(ri.router_id)
        _, fip_to_rtr = ri.rtr_fip_subnet.get_pair()
        self.mock_ip.get_devices.return_value = [
            l3_test_common.FakeDev(ri.fip_ns.get_ext_device_name(_uuid()))]
        self.mock_ip_dev.addr.list.return_value = [
            {'cidr': vm_floating_ip + '/32'},
            {'cidr': '19.4.4.1/24'}]
        self.device_exists.return_value = True

        ri.external_gateway_removed(
            ri.ex_gw_port,
            ri.get_external_device_name(ri.ex_gw_port['id']))

        ri.remove_floating_ip.assert_called_once_with(self.mock_ip_dev,
                                                      '19.4.4.2/32')
