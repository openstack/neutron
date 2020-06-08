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

from unittest import mock

from neutron_lib import constants as lib_constants
from neutron_lib.exceptions import l3 as l3_exc
from oslo_utils import uuidutils

from neutron.agent.l3 import router_info
from neutron.agent.linux import ip_lib
from neutron.conf.agent import common as config
from neutron.conf.agent.l3 import config as l3_config
from neutron.tests import base


_uuid = uuidutils.generate_uuid


class TestRouterInfo(base.BaseTestCase):
    def setUp(self):
        super(TestRouterInfo, self).setUp()

        conf = config.setup_conf()
        l3_config.register_l3_agent_config_opts(l3_config.OPTS, conf)

        self.ip_cls_p = mock.patch('neutron.agent.linux.ip_lib.IPWrapper')
        ip_cls = self.ip_cls_p.start()
        self.mock_ip = mock.MagicMock()
        ip_cls.return_value = self.mock_ip
        self.mock_add_ip_route = mock.patch.object(
            ip_lib, 'add_ip_route').start()
        self.mock_delete_ip_route = mock.patch.object(
            ip_lib, 'delete_ip_route').start()
        self.ri_kwargs = {'agent_conf': conf,
                          'interface_driver': mock.sentinel.interface_driver}

    def _check_agent_method_called(self, router, action_calls):
        for action, calls in action_calls.items():
            mock_calls = [mock.call(router.ns_name, c[0], via=c[1])
                          for c in calls]
            mock_method = (self.mock_add_ip_route if action == 'replace' else
                           self.mock_delete_ip_route)
            mock_method.assert_has_calls(mock_calls, any_order=True)

    def test_routing_table_update(self):
        ri = router_info.RouterInfo(mock.Mock(), _uuid(), {}, **self.ri_kwargs)
        ri.router = {}

        fake_route1 = {'destination': '135.207.0.0/16',
                       'nexthop': '1.2.3.4'}
        fake_route2 = {'destination': '135.207.111.111/32',
                       'nexthop': '1.2.3.4'}

        ri.update_routing_table('replace', fake_route1)
        expected = {'replace': [('135.207.0.0/16', '1.2.3.4')]}
        self._check_agent_method_called(ri, expected)

        ri.update_routing_table('delete', fake_route1)
        expected = {'delete': [('135.207.0.0/16', '1.2.3.4')]}
        self._check_agent_method_called(ri, expected)

        ri.update_routing_table('replace', fake_route2)
        expected = {'replace': [('135.207.111.111/32', '1.2.3.4')]}
        self._check_agent_method_called(ri, expected)

        ri.update_routing_table('delete', fake_route2)
        expected = {'delete': [('135.207.111.111/32', '1.2.3.4')]}
        self._check_agent_method_called(ri, expected)

    def test_update_routing_table(self):
        # Just verify the correct namespace was used in the call
        uuid = _uuid()
        netns = 'qrouter-' + uuid
        fake_route1 = {'destination': '135.207.0.0/16',
                       'nexthop': '1.2.3.4'}

        ri = router_info.RouterInfo(mock.Mock(), uuid,
                                    {'id': uuid}, **self.ri_kwargs)
        ri._update_routing_table = mock.Mock()

        ri.update_routing_table('replace', fake_route1)
        ri._update_routing_table.assert_called_once_with('replace',
                                                         fake_route1,
                                                         netns)

    def test_routes_updated(self):
        ri = router_info.RouterInfo(mock.Mock(), _uuid(), {}, **self.ri_kwargs)
        ri.router = {}

        fake_old_routes = []
        fake_new_routes = [{'destination': "110.100.31.0/24",
                            'nexthop': "10.100.10.30"},
                           {'destination': "110.100.30.0/24",
                            'nexthop': "10.100.10.30"}]
        ri.routes = fake_old_routes
        ri.router['routes'] = fake_new_routes
        ri.routes_updated(fake_old_routes, fake_new_routes)

        expected = {'replace': [('110.100.30.0/24', '10.100.10.30'),
                                ('110.100.31.0/24', '10.100.10.30')]}
        self._check_agent_method_called(ri, expected)
        ri.routes = fake_new_routes
        fake_new_routes = [{'destination': "110.100.30.0/24",
                            'nexthop': "10.100.10.30"}]
        ri.router['routes'] = fake_new_routes
        ri.routes_updated(ri.routes, fake_new_routes)
        expected = {'delete': [('110.100.31.0/24', '10.100.10.30')]}
        self._check_agent_method_called(ri, expected)
        fake_new_routes = []
        ri.router['routes'] = fake_new_routes
        ri.routes_updated(ri.routes, fake_new_routes)

        expected = {'delete': [('110.100.30.0/24', '10.100.10.30')]}
        self._check_agent_method_called(ri, expected)

    def test__process_pd_iptables_rules(self):
        subnet_id = _uuid()
        ex_gw_port = {'id': _uuid()}
        prefix = '2001:db8:cafe::/64'

        ri = router_info.RouterInfo(mock.Mock(), _uuid(), {}, **self.ri_kwargs)

        ipv6_mangle = ri.iptables_manager.ipv6['mangle'] = mock.MagicMock()
        ri.get_ex_gw_port = mock.Mock(return_value=ex_gw_port)
        ri.get_external_device_name = mock.Mock(return_value='fake_device')
        ri.get_address_scope_mark_mask = mock.Mock(return_value='fake_mark')

        ri._process_pd_iptables_rules(prefix, subnet_id)

        mangle_rule = '-d %s ' % prefix
        mangle_rule += ri.address_scope_mangle_rule('fake_device', 'fake_mark')

        ipv6_mangle.add_rule.assert_called_once_with(
            'scope',
            mangle_rule,
            tag='prefix_delegation_%s' % subnet_id)

    def test_add_ports_address_scope_iptables(self):
        ri = router_info.RouterInfo(mock.Mock(), _uuid(), {}, **self.ri_kwargs)
        port = {
            'id': _uuid(),
            'fixed_ips': [{'ip_address': '172.9.9.9'}],
            'address_scopes': {lib_constants.IP_VERSION_4: '1234'}
        }
        ipv4_mangle = ri.iptables_manager.ipv4['mangle'] = mock.MagicMock()
        ri.get_address_scope_mark_mask = mock.Mock(return_value='fake_mark')
        ri.get_internal_device_name = mock.Mock(return_value='fake_device')
        ri.rt_tables_manager = mock.MagicMock()
        ri.process_external_port_address_scope_routing = mock.Mock()
        ri.process_floating_ip_address_scope_rules = mock.Mock()
        ri.iptables_manager._apply = mock.Mock()

        ri.router[lib_constants.INTERFACE_KEY] = [port]
        ri.process_address_scope()

        ipv4_mangle.add_rule.assert_called_once_with(
            'scope', ri.address_scope_mangle_rule('fake_device', 'fake_mark'))

    def test_address_scope_mark_ids_handling(self):
        mark_ids = set(range(router_info.ADDRESS_SCOPE_MARK_ID_MIN,
                             router_info.ADDRESS_SCOPE_MARK_ID_MAX))
        ri = router_info.RouterInfo(mock.Mock(), _uuid(), {}, **self.ri_kwargs)
        # first mark id is used for the default address scope
        scope_to_mark_id = {router_info.DEFAULT_ADDRESS_SCOPE: mark_ids.pop()}
        self.assertEqual(scope_to_mark_id, ri._address_scope_to_mark_id)
        self.assertEqual(mark_ids, ri.available_mark_ids)

        # new id should be used for new address scope
        ri.get_address_scope_mark_mask('new_scope')
        scope_to_mark_id['new_scope'] = mark_ids.pop()
        self.assertEqual(scope_to_mark_id, ri._address_scope_to_mark_id)
        self.assertEqual(mark_ids, ri.available_mark_ids)

        # new router should have it's own mark ids set
        new_mark_ids = set(range(router_info.ADDRESS_SCOPE_MARK_ID_MIN,
                                 router_info.ADDRESS_SCOPE_MARK_ID_MAX))
        new_ri = router_info.RouterInfo(mock.Mock(), _uuid(),
                                        {}, **self.ri_kwargs)
        new_mark_ids.pop()
        self.assertEqual(new_mark_ids, new_ri.available_mark_ids)
        self.assertNotEqual(ri.available_mark_ids, new_ri.available_mark_ids)

    def test_process_delete(self):
        ri = router_info.RouterInfo(mock.Mock(), _uuid(), {}, **self.ri_kwargs)
        ri.router = {'id': _uuid()}
        with mock.patch.object(ri, '_process_internal_ports') as p_i_p,\
                mock.patch.object(ri,
                                  '_process_external_on_delete') as p_e_o_d:
            self.mock_ip.netns.exists.return_value = False
            ri.process_delete()
            self.assertFalse(p_i_p.called)
            self.assertFalse(p_e_o_d.called)

            p_i_p.reset_mock()
            p_e_o_d.reset_mock()
            self.mock_ip.netns.exists.return_value = True
            ri.process_delete()
            p_i_p.assert_called_once_with()
            p_e_o_d.assert_called_once_with()

    def test__update_internal_ports_cache(self):
        ri = router_info.RouterInfo(mock.Mock(), _uuid(), {}, **self.ri_kwargs)
        ri.internal_ports = [
            {'id': 'port-id-1', 'mtu': 1500},
            {'id': 'port-id-2', 'mtu': 2000}]
        initial_internal_ports = ri.internal_ports[:]

        # Test add new element to the cache
        new_port = {'id': 'new-port-id', 'mtu': 1500}
        ri._update_internal_ports_cache(new_port)
        self.assertEqual(
            initial_internal_ports + [new_port],
            ri.internal_ports)

        # Test update existing port in cache
        updated_port = new_port.copy()
        updated_port['mtu'] = 2500
        ri._update_internal_ports_cache(updated_port)
        self.assertEqual(
            initial_internal_ports + [updated_port],
            ri.internal_ports)


class BasicRouterTestCaseFramework(base.BaseTestCase):
    def _create_router(self, router=None, **kwargs):
        if not router:
            router = mock.MagicMock()
        self.agent_conf = mock.Mock()
        self.router_id = _uuid()
        return router_info.RouterInfo(mock.Mock(),
                                      self.router_id,
                                      router,
                                      self.agent_conf,
                                      mock.sentinel.interface_driver,
                                      **kwargs)


class TestBasicRouterOperations(BasicRouterTestCaseFramework):

    def test_get_floating_ips(self):
        router = mock.MagicMock()
        router.get.return_value = [mock.sentinel.floating_ip]
        ri = self._create_router(router)

        fips = ri.get_floating_ips()

        self.assertEqual([mock.sentinel.floating_ip], fips)

    def test_process_floating_ip_nat_rules(self):
        ri = self._create_router()
        fips = [{'fixed_ip_address': mock.sentinel.ip,
                 'floating_ip_address': mock.sentinel.fip}]
        ri.get_floating_ips = mock.Mock(return_value=fips)
        ri.iptables_manager = mock.MagicMock()
        ipv4_nat = ri.iptables_manager.ipv4['nat']
        ri.floating_forward_rules = mock.Mock(
            return_value=[(mock.sentinel.chain, mock.sentinel.rule)])

        ri.process_floating_ip_nat_rules()

        # Be sure that the rules are cleared first and apply is called last
        self.assertEqual(mock.call.clear_rules_by_tag('floating_ip'),
                         ipv4_nat.mock_calls[0])
        self.assertEqual(mock.call.apply(), ri.iptables_manager.mock_calls[-1])

        # Be sure that add_rule is called somewhere in the middle
        ipv4_nat.add_rule.assert_called_once_with(mock.sentinel.chain,
                                                  mock.sentinel.rule,
                                                  tag='floating_ip')

    def test_process_floating_ip_nat_rules_removed(self):
        ri = self._create_router()
        ri.get_floating_ips = mock.Mock(return_value=[])
        ri.iptables_manager = mock.MagicMock()
        ipv4_nat = ri.iptables_manager.ipv4['nat']

        ri.process_floating_ip_nat_rules()

        # Be sure that the rules are cleared first and apply is called last
        self.assertEqual(mock.call.clear_rules_by_tag('floating_ip'),
                         ipv4_nat.mock_calls[0])
        self.assertEqual(mock.call.apply(), ri.iptables_manager.mock_calls[-1])

        # Be sure that add_rule is called somewhere in the middle
        self.assertFalse(ipv4_nat.add_rule.called)

    def test_process_floating_ip_address_scope_rules_diff_scopes(self):
        ri = self._create_router()
        fips = [{'fixed_ip_address': mock.sentinel.ip,
                 'floating_ip_address': mock.sentinel.fip,
                 'fixed_ip_address_scope': 'scope1'}]
        ri.get_floating_ips = mock.Mock(return_value=fips)
        ri._get_external_address_scope = mock.Mock(return_value='scope2')
        ipv4_mangle = ri.iptables_manager.ipv4['mangle'] = mock.MagicMock()
        ri.floating_mangle_rules = mock.Mock(
            return_value=[(mock.sentinel.chain1, mock.sentinel.rule1)])
        ri.get_external_device_name = mock.Mock()

        ri.process_floating_ip_address_scope_rules()

        # Be sure that the rules are cleared first
        self.assertEqual(mock.call.clear_rules_by_tag('floating_ip'),
                         ipv4_mangle.mock_calls[0])
        # Be sure that add_rule is called somewhere in the middle
        self.assertEqual(1, ipv4_mangle.add_rule.call_count)
        self.assertEqual(mock.call.add_rule(mock.sentinel.chain1,
                                            mock.sentinel.rule1,
                                            tag='floating_ip'),
                         ipv4_mangle.mock_calls[1])

    def test_process_floating_ip_address_scope_rules_same_scopes(self):
        ri = self._create_router()
        fips = [{'fixed_ip_address': mock.sentinel.ip,
                 'floating_ip_address': mock.sentinel.fip,
                 'fixed_ip_address_scope': 'scope1'}]
        ri.get_floating_ips = mock.Mock(return_value=fips)
        ri._get_external_address_scope = mock.Mock(return_value='scope1')
        ipv4_mangle = ri.iptables_manager.ipv4['mangle'] = mock.MagicMock()

        ri.process_floating_ip_address_scope_rules()

        # Be sure that the rules are cleared first
        self.assertEqual(mock.call.clear_rules_by_tag('floating_ip'),
                         ipv4_mangle.mock_calls[0])
        # Be sure that add_rule is not called somewhere in the middle
        self.assertFalse(ipv4_mangle.add_rule.called)

    def test_process_floating_ip_mangle_rules_removed(self):
        ri = self._create_router()
        ri.get_floating_ips = mock.Mock(return_value=[])
        ipv4_mangle = ri.iptables_manager.ipv4['mangle'] = mock.MagicMock()

        ri.process_floating_ip_address_scope_rules()

        # Be sure that the rules are cleared first
        self.assertEqual(mock.call.clear_rules_by_tag('floating_ip'),
                         ipv4_mangle.mock_calls[0])

        # Be sure that add_rule is not called somewhere in the middle
        self.assertFalse(ipv4_mangle.add_rule.called)

    def _test_add_fip_addr_to_device_error(self, device):
        ri = self._create_router()
        ip = '15.1.2.3'

        result = ri._add_fip_addr_to_device(
            {'id': mock.sentinel.id, 'floating_ip_address': ip}, device)

        device.addr.add.assert_called_with(ip + '/32')
        return result

    def test__add_fip_addr_to_device(self):
        result = self._test_add_fip_addr_to_device_error(mock.Mock())
        self.assertTrue(result)

    def test__add_fip_addr_to_device_error(self):
        device = mock.Mock()
        device.addr.add.side_effect = RuntimeError
        result = self._test_add_fip_addr_to_device_error(device)
        self.assertFalse(result)

    def test_process_snat_dnat_for_fip(self):
        ri = self._create_router()
        ri.process_floating_ip_nat_rules = mock.Mock(side_effect=Exception)

        self.assertRaises(l3_exc.FloatingIpSetupException,
                          ri.process_snat_dnat_for_fip)

        ri.process_floating_ip_nat_rules.assert_called_once_with()

    def test_put_fips_in_error_state(self):
        ri = self._create_router()
        ri.router = mock.Mock()
        ri.router.get.return_value = [{'id': mock.sentinel.id1},
                                      {'id': mock.sentinel.id2}]

        statuses = ri.put_fips_in_error_state()

        expected = [{mock.sentinel.id1: lib_constants.FLOATINGIP_STATUS_ERROR,
                     mock.sentinel.id2: lib_constants.FLOATINGIP_STATUS_ERROR}]
        self.assertNotEqual(expected, statuses)

    def test_configure_fip_addresses(self):
        ri = self._create_router()
        ri.process_floating_ip_addresses = mock.Mock(
            side_effect=Exception)

        self.assertRaises(l3_exc.FloatingIpSetupException,
                          ri.configure_fip_addresses,
                          mock.sentinel.interface_name)

        ri.process_floating_ip_addresses.assert_called_once_with(
            mock.sentinel.interface_name)

    def test_get_router_cidrs_returns_cidrs(self):
        ri = self._create_router()
        addresses = ['15.1.2.2/24', '15.1.2.3/32']
        device = mock.MagicMock()
        device.addr.list.return_value = [{'cidr': addresses[0]},
                                         {'cidr': addresses[1]}]
        self.assertEqual(set(addresses), ri.get_router_cidrs(device))


@mock.patch.object(ip_lib, 'IPDevice')
class TestFloatingIpWithMockDevice(BasicRouterTestCaseFramework):

    def test_process_floating_ip_addresses_remap(self, IPDevice):
        fip_id = _uuid()
        fip = {
            'id': fip_id, 'port_id': _uuid(),
            'floating_ip_address': '15.1.2.3',
            'fixed_ip_address': '192.168.0.2',
            'status': lib_constants.FLOATINGIP_STATUS_DOWN
        }

        IPDevice.return_value = device = mock.Mock()
        device.addr.list.return_value = [{'cidr': '15.1.2.3/32'}]
        ri = self._create_router()
        ri.get_floating_ips = mock.Mock(return_value=[fip])

        fip_statuses = ri.process_floating_ip_addresses(
            mock.sentinel.interface_name)
        self.assertEqual({fip_id: lib_constants.FLOATINGIP_STATUS_ACTIVE},
                         fip_statuses)

        self.assertFalse(device.addr.add.called)
        self.assertFalse(device.addr.delete.called)

    def test_process_router_with_disabled_floating_ip(self, IPDevice):
        fip_id = _uuid()
        fip = {
            'id': fip_id, 'port_id': _uuid(),
            'floating_ip_address': '15.1.2.3',
            'fixed_ip_address': '192.168.0.2'
        }

        ri = self._create_router()
        ri.floating_ips = [fip]
        ri.get_floating_ips = mock.Mock(return_value=[])

        fip_statuses = ri.process_floating_ip_addresses(
            mock.sentinel.interface_name)

        self.assertIsNone(fip_statuses.get(fip_id))

    def test_process_router_floating_ip_with_device_add_error(self, IPDevice):
        IPDevice.return_value = device = mock.Mock(side_effect=RuntimeError)
        device.addr.list.return_value = []
        fip_id = _uuid()
        fip = {
            'id': fip_id, 'port_id': _uuid(),
            'floating_ip_address': '15.1.2.3',
            'fixed_ip_address': '192.168.0.2',
            'status': 'DOWN'
        }
        ri = self._create_router()
        ri.add_floating_ip = mock.Mock(
            return_value=lib_constants.FLOATINGIP_STATUS_ERROR)
        ri.get_floating_ips = mock.Mock(return_value=[fip])

        fip_statuses = ri.process_floating_ip_addresses(
            mock.sentinel.interface_name)

        self.assertEqual({fip_id: lib_constants.FLOATINGIP_STATUS_ERROR},
                         fip_statuses)

    # TODO(mrsmith): refactor for DVR cases
    def test_process_floating_ip_addresses_remove(self, IPDevice):
        IPDevice.return_value = device = mock.Mock()
        device.addr.list.return_value = [{'cidr': '15.1.2.3/32'}]

        ri = self._create_router()
        ri.remove_floating_ip = mock.Mock()
        ri.router.get = mock.Mock(return_value=[])

        fip_statuses = ri.process_floating_ip_addresses(
            mock.sentinel.interface_name)
        self.assertEqual({}, fip_statuses)
        ri.remove_floating_ip.assert_called_once_with(device, '15.1.2.3/32')

    def test_process_floating_ip_reassignment(self, IPDevice):
        IPDevice.return_value = device = mock.Mock()
        device.addr.list.return_value = [{'cidr': '15.1.2.3/32'}]

        fip_id = _uuid()
        fip = {
            'id': fip_id, 'port_id': _uuid(),
            'floating_ip_address': '15.1.2.3',
            'fixed_ip_address': '192.168.0.3',
            'status': 'DOWN'
        }
        ri = self._create_router()
        ri.get_floating_ips = mock.Mock(return_value=[fip])
        ri.move_floating_ip = mock.Mock()
        ri.fip_map = {'15.1.2.3': '192.168.0.2'}

        ri.process_floating_ip_addresses(mock.sentinel.interface_name)
        ri.move_floating_ip.assert_called_once_with(fip)

    def test_process_floating_ip_addresses_gw_secondary_ip_not_removed(
            self, IPDevice):
        IPDevice.return_value = device = mock.Mock()
        device.addr.list.return_value = [{'cidr': '1.1.1.1/16'},
                                         {'cidr': '2.2.2.2/32'},
                                         {'cidr': '3.3.3.3/32'},
                                         {'cidr': '4.4.4.4/32'}]
        ri = self._create_router()

        ri.get_floating_ips = mock.Mock(return_value=[
            {'id': _uuid(),
             'floating_ip_address': '3.3.3.3',
             'status': 'DOWN'}])
        ri.add_floating_ip = mock.Mock()
        ri.get_ex_gw_port = mock.Mock(return_value={
            "fixed_ips": [{"ip_address": "1.1.1.1"},
                          {"ip_address": "2.2.2.2"}]})
        ri.remove_floating_ip = mock.Mock()

        ri.process_floating_ip_addresses("qg-fake-device")
        ri.remove_floating_ip.assert_called_once_with(device, '4.4.4.4/32')
