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

from neutron_lib.exceptions import l3 as l3_exc
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.agent.common import utils
from neutron.agent.l3 import dvr_fip_ns
from neutron.agent.l3 import link_local_allocator as lla
from neutron.agent.l3 import router_info
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.common import utils as n_utils
from neutron.tests import base

_uuid = uuidutils.generate_uuid


class TestDvrFipNs(base.BaseTestCase):
    def setUp(self):
        super(TestDvrFipNs, self).setUp()
        self.conf = mock.Mock()
        self.conf.state_path = cfg.CONF.state_path
        self.driver = mock.Mock()
        self.driver.DEV_NAME_LEN = 14
        self.net_id = _uuid()
        self.fip_ns = dvr_fip_ns.FipNamespace(self.net_id,
                                              self.conf,
                                              self.driver,
                                              use_ipv6=True)

    def test_subscribe(self):
        is_first = self.fip_ns.subscribe(mock.sentinel.external_net_id)
        self.assertTrue(is_first)

    def test_subscribe_not_first(self):
        self.fip_ns.subscribe(mock.sentinel.external_net_id)
        is_first = self.fip_ns.subscribe(mock.sentinel.external_net_id2)
        self.assertFalse(is_first)

    def test_unsubscribe(self):
        self.fip_ns.subscribe(mock.sentinel.external_net_id)
        is_last = self.fip_ns.unsubscribe(mock.sentinel.external_net_id)
        self.assertTrue(is_last)

    def test_unsubscribe_not_last(self):
        self.fip_ns.subscribe(mock.sentinel.external_net_id)
        self.fip_ns.subscribe(mock.sentinel.external_net_id2)
        is_last = self.fip_ns.unsubscribe(mock.sentinel.external_net_id2)
        self.assertFalse(is_last)

    def test_allocate_rule_priority(self):
        pr = self.fip_ns.allocate_rule_priority('20.0.0.30')
        self.assertIn('20.0.0.30', self.fip_ns._rule_priorities.allocations)
        self.assertNotIn(pr, self.fip_ns._rule_priorities.pool)

    def test_deallocate_rule_priority(self):
        pr = self.fip_ns.allocate_rule_priority('20.0.0.30')
        self.fip_ns.deallocate_rule_priority('20.0.0.30')
        self.assertNotIn('20.0.0.30', self.fip_ns._rule_priorities.allocations)
        self.assertIn(pr, self.fip_ns._rule_priorities.pool)

    def _get_agent_gw_port(self):
        v4_subnet_id = _uuid()
        v6_subnet_id = _uuid()
        agent_gw_port = {'fixed_ips': [{'ip_address': '20.0.0.30',
                                        'prefixlen': 24,
                                        'subnet_id': v4_subnet_id},
                                       {'ip_address': 'cafe:dead:beef::3',
                                        'prefixlen': 64,
                                        'subnet_id': v6_subnet_id}],
                         'subnets': [{'id': v4_subnet_id,
                                      'cidr': '20.0.0.0/24',
                                      'gateway_ip': '20.0.0.1'},
                                     {'id': v6_subnet_id,
                                      'cidr': 'cafe:dead:beef::/64',
                                      'gateway_ip': 'cafe:dead:beef::1'}],
                         'id': _uuid(),
                         'network_id': self.net_id,
                         'mac_address': 'ca:fe:de:ad:be:ef'}
        return agent_gw_port

    @mock.patch.object(ip_lib, 'IPWrapper')
    @mock.patch.object(ip_lib, 'device_exists')
    @mock.patch.object(dvr_fip_ns.FipNamespace, 'create')
    def test_create_gateway_port(self, fip_create, device_exists, ip_wrapper):
        agent_gw_port = self._get_agent_gw_port()

        device_exists.return_value = False
        with mock.patch.object(self.fip_ns.driver, 'set_onlink_routes') as \
                mock_set_onlink_routes:
            self.fip_ns.create_or_update_gateway_port(agent_gw_port)
        self.assertTrue(fip_create.called)
        self.assertEqual(1, self.driver.plug.call_count)
        self.assertEqual(1, self.driver.init_l3.call_count)
        interface_name = self.fip_ns.get_ext_device_name(agent_gw_port['id'])
        gw_cidrs = [sn['cidr'] for sn in agent_gw_port['subnets']
                    if sn.get('cidr')]
        mock_set_onlink_routes.assert_called_once_with(
            interface_name, self.fip_ns.name, [], preserve_ips=gw_cidrs,
            is_ipv6=False)

    @mock.patch.object(ip_lib, 'IPDevice')
    @mock.patch.object(ip_lib, 'send_ip_addr_adv_notif')
    @mock.patch.object(dvr_fip_ns.FipNamespace, 'subscribe')
    @mock.patch.object(dvr_fip_ns.FipNamespace, '_add_default_gateway_for_fip')
    def test_update_gateway_port(self, def_gw, fip_sub, send_adv_notif,
                                 IPDevice):
        fip_sub.return_value = False
        self.fip_ns._check_for_gateway_ip_change = mock.Mock(return_value=True)
        agent_gw_port = self._get_agent_gw_port()
        interface_name = self.fip_ns.get_ext_device_name(agent_gw_port['id'])
        self.fip_ns.agent_gateway_port = agent_gw_port
        with mock.patch.object(self.fip_ns.driver, 'set_onlink_routes'):
            self.fip_ns.create_or_update_gateway_port(agent_gw_port)
        expected = [
            mock.call(self.fip_ns.get_name(),
                      interface_name,
                      agent_gw_port['fixed_ips'][0]['ip_address']),
            mock.call(self.fip_ns.get_name(),
                      interface_name,
                      agent_gw_port['fixed_ips'][1]['ip_address'])]
        send_adv_notif.assert_has_calls(expected)
        self.assertTrue(def_gw.called)

    @mock.patch.object(ip_lib.IPDevice, 'exists')
    @mock.patch.object(dvr_fip_ns.FipNamespace, 'subscribe')
    @mock.patch.object(dvr_fip_ns.FipNamespace, 'delete')
    @mock.patch.object(dvr_fip_ns.FipNamespace, 'unsubscribe')
    def test_update_gateway_port_raises_exception(self, fip_unsub, fip_delete,
                                                  fip_sub, exists):
        agent_gw_port = self._get_agent_gw_port()
        self.fip_ns._create_gateway_port = mock.Mock()
        self.fip_ns.create_or_update_gateway_port(agent_gw_port)
        exists.return_value = False
        fip_sub.return_value = False
        self.fip_ns._check_for_gateway_ip_change = mock.Mock(return_value=True)
        self.fip_ns.agent_gateway_port = agent_gw_port

        self.assertRaises(l3_exc.FloatingIpSetupException,
                          self.fip_ns.create_or_update_gateway_port,
                          agent_gw_port)
        self.assertTrue(fip_unsub.called)
        self.assertTrue(fip_delete.called)

    @mock.patch.object(ip_lib, 'IPDevice')
    @mock.patch.object(ip_lib, 'send_ip_addr_adv_notif')
    @mock.patch.object(dvr_fip_ns.FipNamespace, 'subscribe')
    @mock.patch.object(dvr_fip_ns.FipNamespace, '_add_default_gateway_for_fip')
    def test_update_gateway_port_gateway_outside_subnet_added(
            self, def_gw, fip_sub, send_adv_notif, IPDevice):
        fip_sub.return_value = False
        self.fip_ns.agent_gateway_port = None
        agent_gw_port = self._get_agent_gw_port()
        agent_gw_port['subnets'][0]['gateway_ip'] = '20.0.1.1'
        self.fip_ns._check_for_gateway_ip_change = mock.Mock(return_value=True)
        self.fip_ns.agent_gateway_port = agent_gw_port
        with mock.patch.object(self.fip_ns.driver, 'set_onlink_routes'):
            self.fip_ns.create_or_update_gateway_port(agent_gw_port)

        IPDevice().route.add_route.assert_called_once_with('20.0.1.1',
                                                           scope='link')
        self.assertTrue(def_gw.called)

    def test_check_gateway_ip_changed_no_change(self):
        agent_gw_port = self._get_agent_gw_port()
        self.fip_ns.agent_gateway_port = copy.deepcopy(agent_gw_port)
        agent_gw_port['mac_address'] = 'aa:bb:cc:dd:ee:ff'
        self.assertFalse(self.fip_ns._check_for_gateway_ip_change(
            agent_gw_port))

    def test_check_gateway_ip_changed_v4(self):
        agent_gw_port = self._get_agent_gw_port()
        self.fip_ns.agent_gateway_port = copy.deepcopy(agent_gw_port)
        agent_gw_port['subnets'][0]['gateway_ip'] = '20.0.0.2'
        self.assertTrue(self.fip_ns._check_for_gateway_ip_change(
            agent_gw_port))

    def test_check_gateway_ip_changed_v6(self):
        agent_gw_port = self._get_agent_gw_port()
        self.fip_ns.agent_gateway_port = copy.deepcopy(agent_gw_port)
        agent_gw_port['subnets'][1]['gateway_ip'] = 'cafe:dead:beef::2'
        self.assertTrue(self.fip_ns._check_for_gateway_ip_change(
            agent_gw_port))

    @mock.patch.object(iptables_manager, 'IptablesManager')
    @mock.patch.object(utils, 'execute')
    @mock.patch.object(ip_lib.IpNetnsCommand, 'exists')
    def _test_create(self, old_kernel, exists, execute, IPTables):
        exists.return_value = True
        # There are up to six sysctl calls - two to enable forwarding,
        # two for arp_ignore and arp_announce, and two for ip_nonlocal_bind
        execute.side_effect = [None, None, None, None,
                               RuntimeError if old_kernel else None, None]

        self.fip_ns._iptables_manager = IPTables()
        self.fip_ns.create()

        ns_name = self.fip_ns.get_name()

        netns_cmd = ['ip', 'netns', 'exec', ns_name]
        bind_cmd = ['sysctl', '-w', 'net.ipv4.ip_nonlocal_bind=1']
        expected = [mock.call(netns_cmd + bind_cmd, check_exit_code=True,
                              extra_ok_codes=None, log_fail_as_error=False,
                              run_as_root=True)]

        if old_kernel:
            expected.append(mock.call(bind_cmd, check_exit_code=True,
                                      extra_ok_codes=None,
                                      log_fail_as_error=True,
                                      run_as_root=True))

        execute.assert_has_calls(expected)

    def test_create_old_kernel(self):
        self._test_create(True)

    def test_create_new_kernel(self):
        self._test_create(False)

    @mock.patch.object(ip_lib, 'IPWrapper')
    def test_destroy(self, IPWrapper):
        ip_wrapper = IPWrapper()
        dev1 = mock.Mock()
        dev1.name = 'fpr-aaaa'
        dev2 = mock.Mock()
        dev2.name = 'fg-aaaa'
        ip_wrapper.get_devices.return_value = [dev1, dev2]

        with mock.patch.object(self.fip_ns.ip_wrapper_root.netns,
                               'delete') as delete,\
                mock.patch.object(self.fip_ns.ip_wrapper_root.netns,
                                  'exists', return_value=True) as exists:
            self.fip_ns.delete()
            exists.assert_called_once_with(self.fip_ns.name)
            delete.assert_called_once_with(self.fip_ns.name)

        ns_name = self.fip_ns.get_name()
        self.driver.unplug.assert_called_once_with('fg-aaaa',
                                                   prefix='fg-',
                                                   namespace=ns_name)
        ip_wrapper.del_veth.assert_called_once_with('fpr-aaaa')

    def test_destroy_no_namespace(self):
        with mock.patch.object(self.fip_ns.ip_wrapper_root.netns,
                               'delete') as delete,\
                mock.patch.object(self.fip_ns.ip_wrapper_root.netns,
                                  'exists', return_value=False) as exists:
            self.fip_ns.delete()
            exists.assert_called_once_with(self.fip_ns.name)
            self.assertFalse(delete.called)

    @mock.patch.object(ip_lib, 'IPWrapper')
    @mock.patch.object(ip_lib, 'IPDevice')
    def _test_create_rtr_2_fip_link(self, dev_exists, addr_exists,
                                    IPDevice, IPWrapper):
        ri = mock.Mock()
        ri.router_id = _uuid()
        ri.rtr_fip_subnet = None
        ri.ns_name = mock.sentinel.router_ns
        ri.get_ex_gw_port.return_value = {'mtu': 2000}

        rtr_2_fip_name = self.fip_ns.get_rtr_ext_device_name(ri.router_id)
        fip_2_rtr_name = self.fip_ns.get_int_device_name(ri.router_id)
        fip_ns_name = self.fip_ns.get_name()

        self.fip_ns.local_subnets = allocator = mock.Mock()
        pair = lla.LinkLocalAddressPair('169.254.31.28/31')
        allocator.allocate.return_value = pair
        addr_pair = pair.get_pair()
        ip_wrapper = IPWrapper()
        ip_wrapper.add_veth.return_value = (IPDevice(), IPDevice())
        device = IPDevice()
        device.exists.return_value = dev_exists
        device.addr.list.return_value = addr_exists
        ri._get_snat_idx = mock.Mock()
        self.fip_ns._add_rtr_ext_route_rule_to_route_table = mock.Mock()
        self.fip_ns.create_rtr_2_fip_link(ri)

        if not dev_exists:
            ip_wrapper.add_veth.assert_called_with(rtr_2_fip_name,
                                                   fip_2_rtr_name,
                                                   fip_ns_name)

            self.assertEqual(2, device.link.set_up.call_count)

        device.link.set_mtu.assert_called_with(2000)
        self.assertEqual(2, device.link.set_mtu.call_count)

        if not addr_exists:
            expected = [mock.call(str(addr_pair[0]), add_broadcast=False),
                        mock.call(str(addr_pair[1]), add_broadcast=False)]
            device.addr.add.assert_has_calls(expected)
            self.assertEqual(2, device.addr.add.call_count)

        expected = [mock.call(n_utils.cidr_to_ip(addr_pair[1]), mock.ANY),
                    mock.call(n_utils.cidr_to_ip(addr_pair[0]), mock.ANY)]
        device.neigh.add.assert_has_calls(expected)
        self.assertEqual(2, device.neigh.add.call_count)

        device.route.add_gateway.assert_called_once_with(
            '169.254.31.29', table=16)
        self.assertTrue(
            self.fip_ns._add_rtr_ext_route_rule_to_route_table.called)

    def test_create_rtr_2_fip_link(self):
        self._test_create_rtr_2_fip_link(False, False)

    def test_create_rtr_2_fip_link_already_exists(self):
        self._test_create_rtr_2_fip_link(True, False)

    def test_create_rtr_2_fip_link_and_addr_already_exist(self):
        self._test_create_rtr_2_fip_link(True, True)

    @mock.patch.object(router_info.RouterInfo, 'get_router_cidrs')
    @mock.patch.object(ip_lib, 'IPDevice')
    def _test_scan_fip_ports(self, ri, ip_list, stale_list, IPDevice,
                             get_router_cidrs):
        IPDevice.return_value = device = mock.Mock()
        device.exists.return_value = True
        ri.get_router_cidrs.return_value = ip_list
        get_router_cidrs.return_value = stale_list
        self.fip_ns.get_rtr_ext_device_name = mock.Mock(
            return_value=mock.sentinel.rtr_ext_device_name)
        self.fip_ns.scan_fip_ports(ri)
        if stale_list:
            device.delete_addr_and_conntrack_state.assert_called_once_with(
                stale_list[0])

    def test_scan_fip_ports_restart_fips(self):
        ri = mock.Mock()
        ri.floating_ips_dict = {}
        ip_list = [{'cidr': '111.2.3.4'}, {'cidr': '111.2.3.5'}]
        stale_list = ['111.2.3.7/32']
        self._test_scan_fip_ports(ri, ip_list, stale_list)
        self.assertTrue(ri.rtr_fip_connect)

    def test_scan_fip_ports_restart_none(self):
        ri = mock.Mock()
        ri.floating_ips_dict = {}
        ri.rtr_fip_connect = False
        self._test_scan_fip_ports(ri, [], [])
        self.assertFalse(ri.rtr_fip_connect)
