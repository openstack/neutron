# Copyright (c) 2015 OpenStack Foundation
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
from unittest import mock

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as lib_constants
from oslo_config import cfg
from oslo_log import log
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import dvr_edge_ha_router as dvr_edge_ha_rtr
from neutron.agent.l3 import dvr_edge_router as dvr_edge_rtr
from neutron.agent.l3 import dvr_fip_ns
from neutron.agent.l3 import dvr_local_router as dvr_router
from neutron.agent.l3 import ha as l3_ha
from neutron.agent.l3 import link_local_allocator as lla
from neutron.agent.l3 import router_info
from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib
from neutron.common import utils as common_utils
from neutron.conf.agent import common as agent_config
from neutron.conf.agent.l3 import config as l3_config
from neutron.conf.agent.l3 import ha as ha_conf
from neutron.conf import common as base_config
from neutron.tests import base
from neutron.tests.common import l3_test_common

_uuid = uuidutils.generate_uuid
FIP_PRI = 32768
HOSTNAME = 'myhost'
FIP_RULE_PRIO_LIST = [['fip_1', 'fixed_ip_1', 'prio_1'],
                      ['fip_2', 'fixed_ip_2', 'prio_2'],
                      ['fip_3', 'fixed_ip_3', 'prio_3']]


class TestDvrRouterOperations(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.conf = agent_config.setup_conf()
        self.conf.register_opts(base_config.core_opts)
        log.register_options(self.conf)
        self.conf.register_opts(agent_config.AGENT_STATE_OPTS, 'AGENT')
        l3_config.register_l3_agent_config_opts(l3_config.OPTS, self.conf)
        ha_conf.register_l3_agent_ha_opts(self.conf)
        agent_config.register_interface_driver_opts_helper(self.conf)
        agent_config.register_process_monitor_opts(self.conf)
        agent_config.register_interface_opts(self.conf)
        agent_config.register_external_process_opts(self.conf)
        self.conf.set_override('interface_driver',
                               'neutron.agent.linux.interface.NullDriver')
        self.conf.set_override('state_path', cfg.CONF.state_path)

        self.device_exists_p = mock.patch(
            'neutron.agent.linux.ip_lib.device_exists')
        self.device_exists = self.device_exists_p.start()

        self.ensure_dir = mock.patch(
            'oslo_utils.fileutils.ensure_tree').start()

        mock.patch('neutron.agent.linux.keepalived.KeepalivedManager'
                   '.get_full_config_file_path').start()

        self.utils_exec_p = mock.patch(
            'neutron.agent.linux.utils.execute')
        self.utils_exec = self.utils_exec_p.start()

        self.utils_replace_file_p = mock.patch(
            'neutron_lib.utils.file.replace_file')
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

        self.mock_delete_ip_rule = mock.patch.object(ip_lib,
                                                     'delete_ip_rule').start()

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

        self.mock_load_fip_p = mock.patch.object(dvr_router.DvrLocalRouter,
                                                 '_load_used_fip_information')
        self.mock_load_fip = self.mock_load_fip_p.start()

        subnet_id_1 = _uuid()
        subnet_id_2 = _uuid()
        self.snat_ports = [{'subnets': [{'cidr': '152.2.0.0/16',
                                         'gateway_ip': '152.2.0.1',
                                         'id': subnet_id_1}],
                            'network_id': _uuid(),
                            'device_owner':
                            lib_constants.DEVICE_OWNER_ROUTER_SNAT,
                            'mac_address': 'fa:16:3e:80:8d:80',
                            'fixed_ips': [{'subnet_id': subnet_id_1,
                                           'ip_address': '152.2.0.13',
                                           'prefixlen': 16}],
                            'id': _uuid(), 'device_id': _uuid()},
                           {'subnets': [{'cidr': '152.10.0.0/16',
                                         'gateway_ip': '152.10.0.1',
                                         'id': subnet_id_2}],
                            'network_id': _uuid(),
                            'device_owner':
                            lib_constants.DEVICE_OWNER_ROUTER_SNAT,
                            'mac_address': 'fa:16:3e:80:8d:80',
                            'fixed_ips': [{'subnet_id': subnet_id_2,
                                           'ip_address': '152.10.0.13',
                                           'prefixlen': 16}],
                            'id': _uuid(), 'device_id': _uuid()}]

        self.ri_kwargs = {'agent_conf': self.conf,
                          'interface_driver': self.mock_driver}

        self.mock_list_all = mock.patch(
            'neutron.agent.l3.namespace_manager.NamespaceManager'
            '.list_all', return_value={}).start()
        self.mock_ka_notifications = mock.patch.object(
            l3_ha.AgentMixin, '_start_keepalived_notifications_server')
        self.mock_ka_notifications.start()

    def _create_router(self, router=None, **kwargs):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.init_host()
        self.router_id = _uuid()
        if not router:
            router = mock.MagicMock()
        kwargs['agent'] = agent
        kwargs['router_id'] = self.router_id
        kwargs['router'] = router
        kwargs['agent_conf'] = self.conf
        kwargs['interface_driver'] = mock.Mock()
        return dvr_router.DvrLocalRouter(HOSTNAME, **kwargs)

    def _set_ri_kwargs(self, agent, router_id, router):
        self.ri_kwargs['agent'] = agent
        self.ri_kwargs['router_id'] = router_id
        self.ri_kwargs['router'] = router

    def test_gw_ns_name(self):
        ri = self._create_router()
        self.assertEqual(ri.ns_name, ri.get_gw_ns_name())

    def test_create_dvr_fip_interfaces_update(self):
        ri = self._create_router()
        fip_agent_port = {'subnets': []}
        ri.get_floating_agent_gw_interface = mock.Mock(
            return_value=fip_agent_port)
        ri.get_floating_ips = mock.Mock(return_value=True)
        ri.fip_ns = mock.Mock()
        ri.fip_ns.subscribe.return_value = False
        ri.rtr_fip_connect = True
        ex_gw_port = {'network_id': 'fake_net_id'}
        ri.create_dvr_external_gateway_on_agent(ex_gw_port)
        ri.fip_ns.create_or_update_gateway_port.assert_called_once_with(
            fip_agent_port)

    def test_create_dvr_fip_interfaces_with_matching_address_scope(self):
        self._setup_create_dvr_fip_interfaces_for_setting_routing_rules(
            address_scopes_match=True)

    def test_create_dvr_fip_interfaces_with_address_scope_mismatch(self):
        self._setup_create_dvr_fip_interfaces_for_setting_routing_rules()

    def test__get_address_scope_mark(self):
        ri = self._create_router()
        fake_fip_ns = mock.Mock(return_value=True)
        fake_fip_ns.get_name = mock.Mock(return_value="fip-fakenamespace")
        fake_fip_ns.get_int_device_name = mock.Mock(
            return_value="fake-int-device-name")
        ri.fip_ns = fake_fip_ns
        ri.get_external_device_interface_name = mock.Mock(
            return_value="fake-ext-device-name")
        ri.get_ex_gw_port = mock.Mock(
            return_value={"id": "fake-ext-port-id",
                          "fixed_ips": [{"ip_address": "1.1.1.1"},
                                        {"ip_address": "1111::1111"}]})

        scope_mark = ri._get_address_scope_mark()
        self.assertNotEqual({}, scope_mark[6])

    def _setup_create_dvr_fip_interfaces_for_setting_routing_rules(
            self, address_scopes_match=False):
        ri = self._create_router()
        ri.get_floating_agent_gw_interface = mock.Mock()
        ri.fip_ns = mock.Mock()
        ri._add_interface_routing_rule_to_router_ns = mock.Mock()
        ri._add_interface_route_to_fip_ns = mock.Mock()
        ri.fip_ns._create_rtr_2_fip_link = mock.Mock()
        ri.internal_ports = ['moke_port_1', 'moke_port_2']
        if address_scopes_match:
            ri._check_if_address_scopes_match = mock.Mock(
                return_value=True)
        else:
            ri._check_if_address_scopes_match = mock.Mock(
                return_value=False)
        ri.rtr_fip_connect = False
        ex_gw_port = {'network_id': 'fake_net_id'}
        ri.create_dvr_external_gateway_on_agent(ex_gw_port)
        ri._check_rtr_2_fip_connect = mock.Mock()
        ri.connect_rtr_2_fip()
        self.assertTrue(ri._check_if_address_scopes_match.called)
        if address_scopes_match:
            self.assertTrue(
                ri.fip_ns.create_rtr_2_fip_link.called)
            self.assertTrue(
                ri._add_interface_routing_rule_to_router_ns.called)
            self.assertTrue(
                ri._add_interface_route_to_fip_ns.called)
        else:
            self.assertFalse(
                ri._add_interface_routing_rule_to_router_ns.called)
            self.assertFalse(
                ri._add_interface_route_to_fip_ns.called)
            self.assertTrue(
                ri.fip_ns.create_rtr_2_fip_link.called)

    @mock.patch.object(ip_lib, 'add_ip_rule')
    def test__load_used_fip_information(self, mock_add_ip_rule):
        # This test will simulate how "DvrLocalRouter" reloads the FIP
        # information from both the FipNamespace._rule_priorities state file
        # and the namespace "ip rule" list.
        router = self._create_router()
        self.mock_load_fip_p.stop()
        fip_ns = router.agent.get_fip_ns('net_id')

        # To simulate a partially populated FipNamespace._rule_priorities
        # state file, we load all FIPs but last.
        fip_rule_prio_list = copy.deepcopy(FIP_RULE_PRIO_LIST)
        for idx, (fip, _, _) in enumerate(FIP_RULE_PRIO_LIST[:-1]):
            prio = fip_ns.allocate_rule_priority(fip)
            fip_rule_prio_list[idx][2] = prio

        fips = [{'floating_ip_address': fip, 'fixed_ip_address': fixed_ip} for
                fip, fixed_ip, _ in fip_rule_prio_list]
        with mock.patch.object(dvr_fip_ns.FipNamespace,
                               'allocate_rule_priority',
                               return_value=fip_rule_prio_list[-1][2]), \
                mock.patch.object(router, '_cleanup_unused_fip_ip_rules'), \
                mock.patch.object(router, 'get_floating_ips',
                                  return_value=fips):
            router._load_used_fip_information()

        mock_add_ip_rule.assert_called_once_with(
            router.ns_name, fip_rule_prio_list[2][1],
            table=dvr_fip_ns.FIP_RT_TBL, priority=fip_rule_prio_list[-1][2])
        self.assertEqual(3, len(router.floating_ips_dict))
        ret = [[fip, fixed_ip, prio] for fip, (fixed_ip, prio) in
               router.floating_ips_dict.items()]
        self.assertEqual(sorted(ret, key=lambda ret: ret[0]),
                         fip_rule_prio_list)

    @mock.patch.object(router_info.RouterInfo, 'initialize')
    def test_initialize_dvr_local_router(self, super_initialize):
        ri = self._create_router()
        self.mock_load_fip.assert_not_called()

        ri.initialize(self.process_monitor)
        super_initialize.assert_called_once_with(self.process_monitor)
        self.mock_load_fip.assert_called_once()

    def test_get_floating_ips_dvr(self):
        router = mock.MagicMock()
        router.get.return_value = [{'host': HOSTNAME},
                                   {'host': mock.sentinel.otherhost}]
        ri = self._create_router(router)

        fips = ri.get_floating_ips()

        self.assertEqual(
            [{'host': HOSTNAME}, {'host': mock.sentinel.otherhost}], fips)

    def test_floating_forward_rules_no_fip_ns(self):
        router = mock.MagicMock()
        router.get.return_value = [{'host': HOSTNAME},
                                   {'host': mock.sentinel.otherhost}]
        fip = {'id': _uuid()}
        ri = self._create_router(router)
        self.assertFalse(ri.floating_forward_rules(fip))

    def test_floating_forward_rules(self):
        self.utils_exec.return_value = "iptables v1.6.2 (legacy)"
        router = mock.MagicMock()
        router.get.return_value = [{'host': HOSTNAME},
                                   {'host': mock.sentinel.otherhost}]
        ri = self._create_router(router)
        floating_ip = '15.1.2.3'
        rtr_2_fip_name = 'fake_router'
        fixed_ip = '192.168.0.1'
        fip = {'id': _uuid(),
               'fixed_ip_address': '192.168.0.1',
               'floating_ip_address': '15.1.2.3'}
        instance = mock.Mock()
        instance.get_rtr_ext_device_name = mock.Mock(
                                               return_value=rtr_2_fip_name)
        ri.fip_ns = instance
        dnat_from_floatingip_to_fixedip = (
            'PREROUTING', '-d {}/32 -i {} -j DNAT --to-destination {}'.format(
                floating_ip, rtr_2_fip_name, fixed_ip))
        to_source = '-s {}/32 -j SNAT --to-source {}'.format(
            fixed_ip, floating_ip)

        if ri.iptables_manager.random_fully:
            to_source += ' --random-fully'
        snat_from_fixedip_to_floatingip = ('float-snat', to_source)
        actual = ri.floating_forward_rules(fip)
        expected = [dnat_from_floatingip_to_fixedip,
                    snat_from_fixedip_to_floatingip]
        self.assertEqual(expected, actual)

    def test_floating_mangle_rules_no_fip_ns(self):
        router = mock.MagicMock()
        router.get.return_value = [{'host': HOSTNAME},
                                   {'host': mock.sentinel.otherhost}]
        ri = self._create_router(router)
        floating_ip = mock.Mock()
        fixed_ip = mock.Mock()
        internal_mark = mock.Mock()
        self.assertFalse(ri.floating_mangle_rules(floating_ip, fixed_ip,
                                                  internal_mark))

    def test_floating_mangle_rules(self):
        router = mock.MagicMock()
        router.get.return_value = [{'host': HOSTNAME},
                                   {'host': mock.sentinel.otherhost}]
        ri = self._create_router(router)
        floating_ip = '15.1.2.3'
        fixed_ip = '192.168.0.1'
        internal_mark = 'fake_mark'
        rtr_2_fip_name = 'fake_router'
        instance = mock.Mock()
        instance.get_rtr_ext_device_name = mock.Mock(
                                               return_value=rtr_2_fip_name)
        ri.fip_ns = instance
        mark_traffic_to_floating_ip = (
            'floatingip', '-d {}/32 -i {} -j MARK --set-xmark {}'.format(
                floating_ip, rtr_2_fip_name, internal_mark))
        mark_traffic_from_fixed_ip = (
            'FORWARD', '-s %s/32 -j $float-snat' % fixed_ip)
        actual = ri.floating_mangle_rules(floating_ip, fixed_ip, internal_mark)
        expected = [mark_traffic_to_floating_ip, mark_traffic_from_fixed_ip]
        self.assertEqual(expected, actual)

    @mock.patch.object(ip_lib, 'send_ip_addr_adv_notif')
    @mock.patch.object(ip_lib, 'IPDevice')
    @mock.patch.object(ip_lib, 'add_ip_rule')
    def test_floating_ip_added_dist(self, mock_add_ip_rule, mIPDevice,
                                    mock_adv_notif):
        router = mock.MagicMock()
        ri = self._create_router(router)
        ri.ex_gw_port = ri.router['gw_port']
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
        ri.create_dvr_external_gateway_on_agent(ri.ex_gw_port)
        ri._check_rtr_2_fip_connect = mock.Mock()
        ri.connect_rtr_2_fip()
        self.assertTrue(ri.rtr_fip_connect)
        ri.fip_ns.allocate_rule_priority.return_value = FIP_PRI
        subnet = lla.LinkLocalAddressPair('169.254.30.42/31')
        ri.rtr_fip_subnet = subnet
        ri.fip_ns.local_subnets = mock.Mock()
        ri.fip_ns.local_subnets.allocate.return_value = subnet
        ip_cidr = common_utils.ip_to_cidr(fip['floating_ip_address'])
        ri.floating_ip_added_dist(fip, ip_cidr)
        mock_add_ip_rule.assert_called_with(
            namespace=ri.router_namespace.name, ip='192.168.0.1',
            table=16, priority=FIP_PRI)
        ri.fip_ns.local_subnets.allocate.assert_not_called()

        # Validate that fip_ns.local_subnets is called when
        # ri.rtr_fip_subnet is None
        ri.rtr_fip_subnet = None
        ri.floating_ip_added_dist(fip, ip_cidr)
        mock_add_ip_rule.assert_called_with(
            namespace=ri.router_namespace.name, ip='192.168.0.1',
            table=16, priority=FIP_PRI)
        ri.fip_ns.local_subnets.allocate.assert_called_once_with(ri.router_id)
        # TODO(mrsmith): add more asserts

    @mock.patch.object(ip_lib, 'IPWrapper')
    @mock.patch.object(ip_lib, 'IPDevice')
    def test_floating_ip_removed_dist(self, mIPDevice, mIPWrapper):
        router = mock.MagicMock()
        ri = self._create_router(router)
        ri.ex_gw_port = ri.router['gw_port']
        subnet_id = _uuid()
        fixed_ip = '20.0.0.30'
        agent_gw_port = {'fixed_ips': [{'ip_address': fixed_ip,
                                        'prefixlen': 24,
                                        'subnet_id': subnet_id}],
                         'subnets': [{'id': subnet_id,
                                      'cidr': '20.0.0.0/24',
                                      'gateway_ip': '20.0.0.1'}],
                         'id': _uuid(),
                         'network_id': _uuid(),
                         'mac_address': 'ca:fe:de:ad:be:ef'}
        fip_cidr = '11.22.33.44/24'
        ri.fip_ns = mock.Mock()
        ri.fip_ns.get_name.return_value = 'fip_ns_name'
        ri.floating_ips_dict['11.22.33.44'] = (fixed_ip, FIP_PRI)
        ri.fip_2_rtr = '11.22.33.42'
        ri.rtr_2_fip = '11.22.33.40'
        ri.fip_ns.agent_gateway_port = agent_gw_port
        s = lla.LinkLocalAddressPair('169.254.30.42/31')
        ri.rtr_fip_subnet = s
        ri.fip_ns.local_subnets = mock.Mock()
        ri.floating_ip_removed_dist(fip_cidr)
        self.mock_delete_ip_rule.assert_called_with(
            ri.router_namespace.name, ip=fixed_ip, table=16, priority=FIP_PRI)
        mIPDevice().route.delete_route.assert_called_with(fip_cidr,
                                                          via=str(s.ip))
        ri.fip_ns.local_subnets.allocate.assert_not_called()

    @mock.patch.object(ip_lib, 'add_ip_rule')
    def test_floating_ip_moved_dist(self, mock_add_ip_rule):
        router = mock.MagicMock()
        ri = self._create_router(router)
        floating_ip_address = '15.1.2.3'
        fixed_ip = '192.168.0.1'
        fip = {'floating_ip_address': floating_ip_address,
               'fixed_ip_address': fixed_ip}
        ri.floating_ips_dict['15.1.2.3'] = (fixed_ip, FIP_PRI)
        ri.fip_ns = mock.Mock()
        ri.fip_ns.allocate_rule_priority.return_value = FIP_PRI
        ri.floating_ip_moved_dist(fip)

        self.mock_delete_ip_rule.assert_called_once_with(
            ri.router_namespace.name, ip=fixed_ip, table=16, priority=FIP_PRI)
        ri.fip_ns.deallocate_rule_priority.assert_called_once_with(
            floating_ip_address)
        ri.fip_ns.allocate_rule_priority.assert_called_once_with(
            floating_ip_address)
        mock_add_ip_rule.assert_called_with(
            namespace=ri.router_namespace.name, ip=fixed_ip,
            table=16, priority=FIP_PRI)

    def _test_add_floating_ip(self, ri, fip, is_failure=False):
        if not is_failure:
            ri.floating_ip_added_dist = mock.Mock(
                return_value=lib_constants.FLOATINGIP_STATUS_ACTIVE)
        else:
            ri.floating_ip_added_dist = mock.Mock(
                return_value=lib_constants.FLOATINGIP_STATUS_ERROR)
        result = ri.add_floating_ip(fip,
                                    mock.sentinel.interface_name,
                                    mock.sentinel.device)
        ri.floating_ip_added_dist.assert_called_once_with(
            fip, mock.ANY)
        return result

    def test_add_floating_ip(self):
        ri = self._create_router(mock.MagicMock())
        ip = '15.1.2.3'
        fip = {'floating_ip_address': ip}
        result = self._test_add_floating_ip(ri, fip)
        ri.floating_ip_added_dist.assert_called_once_with(fip, ip + '/32')
        self.assertEqual(lib_constants.FLOATINGIP_STATUS_ACTIVE, result)

    def test_add_floating_ip_failure(self):
        ri = self._create_router(mock.MagicMock())
        ip = '15.1.2.3'
        fip = {'floating_ip_address': ip}
        result = self._test_add_floating_ip(ri, fip, True)
        ri.floating_ip_added_dist.assert_called_once_with(fip, ip + '/32')
        self.assertEqual(lib_constants.FLOATINGIP_STATUS_ERROR, result)

    @mock.patch.object(router_info.RouterInfo, 'remove_floating_ip')
    def test_remove_floating_ip(self, super_remove_floating_ip):
        ri = self._create_router(mock.MagicMock())
        ri.floating_ip_removed_dist = mock.Mock()

        ri.remove_floating_ip(mock.sentinel.device, mock.sentinel.ip_cidr)

        self.assertFalse(super_remove_floating_ip.called)
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
        self.assertIsNone(ri._get_internal_port(mock.sentinel.subnet_id2))

    def test__get_snat_idx_ipv4(self):
        ip_cidr = '101.12.13.0/24'
        ri = self._create_router(mock.MagicMock())
        snat_idx = ri._get_snat_idx(ip_cidr)
        # 0x650C0D00 is numerical value of 101.12.13.0
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
        agent.init_host()
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrLocalRouter(HOSTNAME, **self.ri_kwargs)
        ports = ri.router.get(lib_constants.INTERFACE_KEY, [])
        subnet_id = l3_test_common.get_subnet_id(ports[0])
        subnet = {
            'id': subnet_id,
            'cidr': '1.2.3.0/24'
        }
        ri.router['_snat_router_interfaces'] = [{
            'mac_address': 'fa:16:3e:80:8d:80',
            'fixed_ips': [
                {'subnet_id': subnet_id,
                 'ip_address': '1.2.3.10'},
                {'subnet_id': _uuid(),
                 'ip_address': '2001:db8::1'}
            ]
        }]

        test_ports = [{'mac_address': '00:11:22:33:44:55',
                       'device_owner': lib_constants.DEVICE_OWNER_DHCP,
                       'fixed_ips': [{'ip_address': '1.2.3.4',
                                      'prefixlen': 24,
                                      'subnet_id': subnet_id}],
                       'allowed_address_pairs': [
                           {'ip_address': '10.20.30.40',
                            'mac_address': '00:11:22:33:44:55'}]}]

        self.plugin_api.get_ports_by_subnet.return_value = test_ports

        # Test basic case
        ports[0]['subnets'] = [{'id': subnet_id,
                                'cidr': '1.2.3.0/24'}]
        with mock.patch.object(ri,
                               '_process_arp_cache_for_internal_port') as parp:
            ri._set_subnet_arp_info(subnet)
        self.assertEqual(1, parp.call_count)
        self.mock_ip_dev.neigh.add.assert_has_calls([
            mock.call('1.2.3.4', '00:11:22:33:44:55'),
            mock.call('10.20.30.40', '00:11:22:33:44:55'),
            mock.call('1.2.3.10', 'fa:16:3e:80:8d:80')])

        # Test negative case
        router['distributed'] = False
        ri._set_subnet_arp_info(subnet)
        self.mock_ip_dev.neigh.add.never_called()

    def test_add_arp_entry(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.init_host()
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        subnet_id = l3_test_common.get_subnet_id(
            router[lib_constants.INTERFACE_KEY][0])
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
        agent.init_host()
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        subnet_id = l3_test_common.get_subnet_id(
            router[lib_constants.INTERFACE_KEY][0])
        arp_table = {'ip_address': '1.7.23.11',
                     'mac_address': '00:11:22:33:44:55',
                     'subnet_id': subnet_id}

        payload = {'arp_table': arp_table, 'router_id': router['id']}
        agent.add_arp_entry(None, payload)

    def test_get_arp_related_dev_no_subnet(self):
        self._set_ri_kwargs(mock.sentinel.agent,
                            'foo_router_id',
                            {'distributed': True, 'gw_port_host': HOSTNAME})
        ri = dvr_router.DvrLocalRouter(HOSTNAME, **self.ri_kwargs)
        with mock.patch('neutron.agent.linux.ip_lib.IPDevice') as f:
            ri.get_arp_related_dev('foo_subnet_id')
        self.assertFalse(f.call_count)

    def _setup_test_for_arp_entry_cache(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.init_host()
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrLocalRouter(HOSTNAME, **self.ri_kwargs)
        subnet_id = l3_test_common.get_subnet_id(
            ri.router[lib_constants.INTERFACE_KEY][0])
        return ri, subnet_id

    def test__update_arp_entry_calls_arp_cache_with_no_device(self):
        ri, subnet_id = self._setup_test_for_arp_entry_cache()
        state = True
        with mock.patch('neutron.agent.linux.ip_lib.IPDevice') as rtrdev,\
                mock.patch.object(ri, '_cache_arp_entry') as arp_cache:
            state = ri._update_arp_entry(
                mock.ANY, mock.ANY, subnet_id, 'add',
                mock.ANY, device_exists=False)
        self.assertFalse(state)
        self.assertTrue(arp_cache.called)
        arp_cache.assert_called_once_with(mock.ANY, mock.ANY,
                                          subnet_id, 'add')
        self.assertFalse(rtrdev.neigh.add.called)

    def test__process_arp_cache_for_internal_port(self):
        ri, subnet_id = self._setup_test_for_arp_entry_cache()
        ri._cache_arp_entry('1.7.23.11', '00:11:22:33:44:55',
                            subnet_id, 'add')
        self.assertEqual(1, len(ri._pending_arp_set))
        with mock.patch.object(ri, '_update_arp_entry') as update_arp:
            update_arp.return_value = True
        ri._process_arp_cache_for_internal_port(subnet_id)
        self.assertEqual(0, len(ri._pending_arp_set))

    def test__delete_arp_cache_for_internal_port(self):
        ri, subnet_id = self._setup_test_for_arp_entry_cache()
        ri._cache_arp_entry('1.7.23.11', '00:11:22:33:44:55',
                            subnet_id, 'add')
        self.assertEqual(1, len(ri._pending_arp_set))
        ri._delete_arp_cache_for_internal_port(subnet_id)
        self.assertEqual(0, len(ri._pending_arp_set))

    def test_del_arp_entry(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.init_host()
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['distributed'] = True
        subnet_id = l3_test_common.get_subnet_id(
            router[lib_constants.INTERFACE_KEY][0])
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
              portbindings.HOST_ID: 'myhost',
              'device_owner': lib_constants.DEVICE_OWNER_AGENT_GW,
              'network_id': fake_network_id,
              'mac_address': 'ca:fe:de:ad:be:ef'}]
        )

        router = l3_test_common.prepare_router_data(enable_snat=True)
        router[lib_constants.FLOATINGIP_AGENT_INTF_KEY] = agent_gateway_port
        router['distributed'] = True
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.init_host()
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrLocalRouter(HOSTNAME, **self.ri_kwargs)
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
        router[lib_constants.FLOATINGIP_KEY] = fake_floatingips['floatingips']
        router['distributed'] = True
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.init_host()
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrLocalRouter(HOSTNAME, **self.ri_kwargs)
        ri.iptables_manager.ipv4['nat'] = mock.MagicMock()
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
        agent.init_host()
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_router.DvrLocalRouter(HOSTNAME, **self.ri_kwargs)

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
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.init_host()
        agent.conf.agent_mode = lib_constants.L3_AGENT_MODE_DVR_SNAT
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['gw_port_host'] = HOSTNAME
        self.mock_driver.unplug.reset_mock()

        external_net_id = router['gw_port']['network_id']
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_edge_rtr.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        ri.remove_floating_ip = mock.Mock()
        agent._fetch_external_net_id = mock.Mock(return_value=external_net_id)
        ri.ex_gw_port = ri.router['gw_port']
        del ri.router['gw_port']
        ri.external_gateway_added(
            ri.ex_gw_port,
            ri.get_external_device_name(ri.ex_gw_port['id']))
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
        ri.rtr_fip_subnet = ri.fip_ns.local_subnets.allocate(ri.router_id)
        _, fip_to_rtr = ri.rtr_fip_subnet.get_pair()
        self.mock_ip.get_devices.return_value = [
            l3_test_common.FakeDev(ri.fip_ns.get_ext_device_name(_uuid()))]
        ri.get_router_cidrs = mock.Mock(
            return_value={vm_floating_ip + '/32', '19.4.4.1/24'})
        self.device_exists.return_value = True
        ri.external_gateway_removed(
            ri.ex_gw_port,
            ri.get_external_device_name(ri.ex_gw_port['id']))
        ri.remove_floating_ip.assert_called_once_with(self.mock_ip_dev,
                                                      '19.4.4.2/32')

    def test_get_router_cidrs_no_fip_ns(self):
        router = mock.MagicMock()
        router.get.return_value = [{'host': HOSTNAME},
                                   {'host': mock.sentinel.otherhost}]
        ri = self._create_router(router)
        device = mock.Mock()
        self.assertFalse(ri.get_router_cidrs(device))

    def test_get_router_cidrs_no_device_exists(self):
        router = mock.MagicMock()
        router.get.return_value = [{'host': HOSTNAME},
                                   {'host': mock.sentinel.otherhost}]
        ri = self._create_router(router)
        fake_fip_ns = mock.Mock(return_value=True)
        fake_fip_ns.get_name = mock.Mock(return_value=None)
        fake_fip_ns.get_int_device_name = mock.Mock(return_value=None)
        ri.fip_ns = fake_fip_ns
        device = mock.Mock()
        device.exists = mock.Mock(return_value=False)
        with mock.patch.object(ip_lib, 'IPDevice', return_value=device):
            self.assertFalse(ri.get_router_cidrs(device))

    @mock.patch.object(router_info.RouterInfo, '_add_snat_rules')
    @mock.patch.object(dvr_router.DvrLocalRouter, '_handle_router_snat_rules')
    def test_handle_snat_rule_for_centralized_fip(
            self, _add_snat_rules, _handle_router_snat_rules):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.init_host()
        agent.conf.agent_mode = lib_constants.L3_AGENT_MODE_DVR_SNAT
        self.mock_driver.unplug.reset_mock()

        router = l3_test_common.prepare_router_data(enable_floating_ip=True)
        router['gw_port_host'] = HOSTNAME
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_edge_rtr.DvrEdgeRouter(HOSTNAME, **self.ri_kwargs)
        ri.snat_iptables_manager = mock.MagicMock()
        ipv4_nat = ri.snat_iptables_manager.ipv4['nat']
        interface_name, ex_gw_port = l3_test_common.prepare_ext_gw_test(self,
                                                                        ri)
        ri._handle_router_snat_rules(ex_gw_port, interface_name)
        ipv4_nat.add_rule.assert_called_once_with('snat', '-j $float-snat')

    @mock.patch.object(dvr_edge_rtr.DvrEdgeRouter,
                       'add_centralized_floatingip')
    def test_add_centralized_floatingip_dvr_ha(
            self,
            super_add_centralized_floatingip):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.init_host()
        agent.conf.agent_mode = lib_constants.L3_AGENT_MODE_DVR_SNAT
        router = l3_test_common.prepare_router_data(
            num_internal_ports=2, enable_ha=True)
        router['gw_port_host'] = HOSTNAME
        self.mock_driver.unplug.reset_mock()
        self._set_ri_kwargs(agent, router['id'], router)
        fip = {'id': _uuid()}
        fip_cidr = '11.22.33.44/24'

        ri = dvr_edge_ha_rtr.DvrEdgeHaRouter(HOSTNAME, **self.ri_kwargs)
        ri.is_router_primary = mock.Mock(return_value=False)
        ri._add_vip = mock.Mock()
        interface_name = ri.get_snat_external_device_interface_name(
            ri.get_ex_gw_port())
        ri.add_centralized_floatingip(fip, fip_cidr)
        ri._add_vip.assert_called_once_with(fip_cidr, interface_name)
        super_add_centralized_floatingip.assert_not_called()

        router[lib_constants.HA_INTERFACE_KEY]['status'] = 'DOWN'
        self._set_ri_kwargs(agent, router['id'], router)
        ri_1 = dvr_edge_ha_rtr.DvrEdgeHaRouter(HOSTNAME, **self.ri_kwargs)
        ri_1.is_router_primary = mock.Mock(return_value=True)
        ri_1._add_vip = mock.Mock()
        interface_name = ri_1.get_snat_external_device_interface_name(
            ri_1.get_ex_gw_port())
        ri_1.add_centralized_floatingip(fip, fip_cidr)
        ri_1._add_vip.assert_called_once_with(fip_cidr, interface_name)
        super_add_centralized_floatingip.assert_not_called()

        router[lib_constants.HA_INTERFACE_KEY]['status'] = 'ACTIVE'
        self._set_ri_kwargs(agent, router['id'], router)
        ri_2 = dvr_edge_ha_rtr.DvrEdgeHaRouter(HOSTNAME, **self.ri_kwargs)
        ri_2.is_router_primary = mock.Mock(return_value=True)
        ri_2._add_vip = mock.Mock()
        interface_name = ri_2.get_snat_external_device_interface_name(
            ri_2.get_ex_gw_port())
        ri_2.add_centralized_floatingip(fip, fip_cidr)
        ri_2._add_vip.assert_called_once_with(fip_cidr, interface_name)
        super_add_centralized_floatingip.assert_called_once_with(fip,
                                                                 fip_cidr)

    @mock.patch.object(dvr_edge_rtr.DvrEdgeRouter,
                       'remove_centralized_floatingip')
    def test_remove_centralized_floatingip(
            self, super_remove_centralized_floatingip):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.conf.agent_mode = lib_constants.L3_AGENT_MODE_DVR_SNAT
        router = l3_test_common.prepare_router_data(num_internal_ports=2)
        router['gw_port_host'] = HOSTNAME
        self.mock_driver.unplug.reset_mock()
        self._set_ri_kwargs(agent, router['id'], router)
        fip_cidr = '11.22.33.44/24'

        ri = dvr_edge_ha_rtr.DvrEdgeHaRouter(HOSTNAME, **self.ri_kwargs)
        ri.is_router_primary = mock.Mock(return_value=False)
        ri._remove_vip = mock.Mock()
        ri.remove_centralized_floatingip(fip_cidr)
        ri._remove_vip.assert_called_once_with(fip_cidr)
        super_remove_centralized_floatingip.assert_not_called()

        ri1 = dvr_edge_ha_rtr.DvrEdgeHaRouter(HOSTNAME, **self.ri_kwargs)
        ri1.is_router_primary = mock.Mock(return_value=True)
        ri1._remove_vip = mock.Mock()
        ri1.remove_centralized_floatingip(fip_cidr)
        ri1._remove_vip.assert_called_once_with(fip_cidr)
        super_remove_centralized_floatingip.assert_called_once_with(fip_cidr)

    def test_initialize_dvr_ha_router_snat_ns_once(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.conf.agent_mode = lib_constants.L3_AGENT_MODE_DVR_SNAT
        router = l3_test_common.prepare_router_data(
            num_internal_ports=2, enable_ha=True)
        router['gw_port_host'] = HOSTNAME
        router[lib_constants.HA_INTERFACE_KEY]['status'] = 'ACTIVE'
        self.mock_driver.unplug.reset_mock()
        self._set_ri_kwargs(agent, router['id'], router)
        ri = dvr_edge_ha_rtr.DvrEdgeHaRouter(HOSTNAME, **self.ri_kwargs)
        ri._create_snat_namespace = mock.Mock()
        ri._plug_external_gateway = mock.Mock()
        ri.initialize(mock.Mock())
        ri._create_dvr_gateway(mock.Mock(), mock.Mock())
        ri._create_snat_namespace.assert_called_once_with()

    def test_initialize_dvr_ha_router_reset_state(self):
        agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        agent.conf.agent_mode = lib_constants.L3_AGENT_MODE_DVR_SNAT
        router = l3_test_common.prepare_router_data(
            num_internal_ports=2, enable_ha=True)
        router['gw_port_host'] = HOSTNAME
        router[lib_constants.HA_INTERFACE_KEY]['status'] = 'ACTIVE'
        self.mock_driver.unplug.reset_mock()
        self._set_ri_kwargs(agent, router['id'], router)

        ri = dvr_edge_ha_rtr.DvrEdgeHaRouter(HOSTNAME, **self.ri_kwargs)
        ri._ha_state_path = self.get_temp_file_path('router_ha_state')

        with open(ri._ha_state_path, "w") as f:
            f.write("primary")

        ri._create_snat_namespace = mock.Mock()
        ri._plug_external_gateway = mock.Mock()
        with mock.patch("neutron.agent.linux.keepalived."
                        "KeepalivedManager.check_processes",
                        return_value=False):
            ri.initialize(mock.Mock())
            with open(ri._ha_state_path) as f:
                state = f.readline()
                self.assertEqual("backup", state)
