# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
from oslo_db import exception as db_exc

from neutron.api.rpc.handlers import dhcp_rpc
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.tests import base


class TestDhcpRpcCallback(base.BaseTestCase):

    def setUp(self):
        super(TestDhcpRpcCallback, self).setUp()
        self.plugin_p = mock.patch('neutron.manager.NeutronManager.get_plugin')
        get_plugin = self.plugin_p.start()
        self.plugin = mock.MagicMock()
        get_plugin.return_value = self.plugin
        self.callbacks = dhcp_rpc.DhcpRpcCallback()
        self.log_p = mock.patch('neutron.api.rpc.handlers.dhcp_rpc.LOG')
        self.log = self.log_p.start()

    def test_get_active_networks(self):
        plugin_retval = [dict(id='a'), dict(id='b')]
        self.plugin.get_networks.return_value = plugin_retval

        networks = self.callbacks.get_active_networks(mock.Mock(), host='host')

        self.assertEqual(networks, ['a', 'b'])
        self.plugin.assert_has_calls(
            [mock.call.get_networks(mock.ANY,
                                    filters=dict(admin_state_up=[True]))])

        self.assertEqual(len(self.log.mock_calls), 1)

    def test_group_by_network_id(self):
        port1 = {'network_id': 'a'}
        port2 = {'network_id': 'b'}
        port3 = {'network_id': 'a'}
        grouped_ports = self.callbacks._group_by_network_id(
                                                        [port1, port2, port3])
        expected = {'a': [port1, port3], 'b': [port2]}
        self.assertEqual(expected, grouped_ports)

    def test_get_active_networks_info(self):
        plugin_retval = [{'id': 'a'}, {'id': 'b'}]
        self.plugin.get_networks.return_value = plugin_retval
        port = {'network_id': 'a'}
        subnet = {'network_id': 'b'}
        self.plugin.get_ports.return_value = [port]
        self.plugin.get_subnets.return_value = [subnet]
        networks = self.callbacks.get_active_networks_info(mock.Mock(),
                                                           host='host')
        expected = [{'id': 'a', 'subnets': [], 'ports': [port]},
                    {'id': 'b', 'subnets': [subnet], 'ports': []}]
        self.assertEqual(expected, networks)

    def _test__port_action_with_failures(self, exc=None, action=None):
        port = {
            'network_id': 'foo_network_id',
            'device_owner': constants.DEVICE_OWNER_DHCP,
            'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]
        }
        self.plugin.create_port.side_effect = exc
        self.assertIsNone(self.callbacks._port_action(self.plugin,
                                                      mock.Mock(),
                                                      {'port': port},
                                                      action))

    def _test__port_action_good_action(self, action, port, expected_call):
        self.callbacks._port_action(self.plugin, mock.Mock(),
                                    port, action)
        self.plugin.assert_has_calls([expected_call])

    def test_port_action_create_port(self):
        self._test__port_action_good_action(
            'create_port', mock.Mock(),
            mock.call.create_port(mock.ANY, mock.ANY))

    def test_port_action_update_port(self):
        fake_port = {'id': 'foo_port_id', 'port': mock.Mock()}
        self._test__port_action_good_action(
            'update_port', fake_port,
            mock.call.update_port(mock.ANY, 'foo_port_id', mock.ANY))

    def test__port_action_bad_action(self):
        self.assertRaises(
            n_exc.Invalid,
            self._test__port_action_with_failures,
            exc=None,
            action='foo_action')

    def test_create_port_catch_network_not_found(self):
        self._test__port_action_with_failures(
            exc=n_exc.NetworkNotFound(net_id='foo_network_id'),
            action='create_port')

    def test_create_port_catch_subnet_not_found(self):
        self._test__port_action_with_failures(
            exc=n_exc.SubnetNotFound(subnet_id='foo_subnet_id'),
            action='create_port')

    def test_create_port_catch_db_error(self):
        self._test__port_action_with_failures(exc=db_exc.DBError(),
                                              action='create_port')

    def test_create_port_catch_ip_generation_failure_reraise(self):
        self.assertRaises(
            n_exc.IpAddressGenerationFailure,
            self._test__port_action_with_failures,
            exc=n_exc.IpAddressGenerationFailure(net_id='foo_network_id'),
            action='create_port')

    def test_create_port_catch_and_handle_ip_generation_failure(self):
        self.plugin.get_subnet.side_effect = (
            n_exc.SubnetNotFound(subnet_id='foo_subnet_id'))
        self._test__port_action_with_failures(
            exc=n_exc.IpAddressGenerationFailure(net_id='foo_network_id'),
            action='create_port')

    def test_get_network_info_return_none_on_not_found(self):
        self.plugin.get_network.side_effect = n_exc.NetworkNotFound(net_id='a')
        retval = self.callbacks.get_network_info(mock.Mock(), network_id='a')
        self.assertIsNone(retval)

    def test_get_network_info(self):
        network_retval = dict(id='a')

        subnet_retval = mock.Mock()
        port_retval = mock.Mock()

        self.plugin.get_network.return_value = network_retval
        self.plugin.get_subnets.return_value = subnet_retval
        self.plugin.get_ports.return_value = port_retval

        retval = self.callbacks.get_network_info(mock.Mock(), network_id='a')
        self.assertEqual(retval, network_retval)
        self.assertEqual(retval['subnets'], subnet_retval)
        self.assertEqual(retval['ports'], port_retval)

    def _test_get_dhcp_port_helper(self, port_retval, other_expectations=[],
                                   update_port=None, create_port=None):
        subnets_retval = [dict(id='a', enable_dhcp=True),
                          dict(id='b', enable_dhcp=False)]

        self.plugin.get_subnets.return_value = subnets_retval
        if port_retval:
            self.plugin.get_ports.return_value = [port_retval]
        else:
            self.plugin.get_ports.return_value = []
        if isinstance(update_port, n_exc.NotFound):
            self.plugin.update_port.side_effect = update_port
        else:
            self.plugin.update_port.return_value = update_port
        self.plugin.create_port.return_value = create_port

        retval = self.callbacks.get_dhcp_port(mock.Mock(),
                                              network_id='netid',
                                              device_id='devid',
                                              host='host')

        expected = [mock.call.get_subnets(mock.ANY,
                                          filters=dict(network_id=['netid'])),
                    mock.call.get_ports(mock.ANY,
                                        filters=dict(network_id=['netid'],
                                                     device_id=['devid']))]

        expected.extend(other_expectations)
        self.plugin.assert_has_calls(expected)
        return retval

    def test_update_dhcp_port_verify_port_action_port_dict(self):
        port = {'port': {'network_id': 'foo_network_id',
                         'device_owner': constants.DEVICE_OWNER_DHCP,
                         'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]}
                }
        expected_port = {'port': {'network_id': 'foo_network_id',
                                  'device_owner': constants.DEVICE_OWNER_DHCP,
                                  'binding:host_id': 'foo_host',
                                  'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]
                                  },
                         'id': 'foo_port_id'
                         }

        def _fake_port_action(plugin, context, port, action):
            self.assertEqual(expected_port, port)

        self.callbacks._port_action = _fake_port_action
        self.callbacks.update_dhcp_port(mock.Mock(),
                                        host='foo_host',
                                        port_id='foo_port_id',
                                        port=port)

    def test_update_dhcp_port(self):
        port = {'port': {'network_id': 'foo_network_id',
                         'device_owner': constants.DEVICE_OWNER_DHCP,
                         'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]}
                }
        expected_port = {'port': {'network_id': 'foo_network_id',
                                  'device_owner': constants.DEVICE_OWNER_DHCP,
                                  'binding:host_id': 'foo_host',
                                  'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]
                                  },
                         'id': 'foo_port_id'
                         }
        self.callbacks.update_dhcp_port(mock.Mock(),
                                        host='foo_host',
                                        port_id='foo_port_id',
                                        port=port)
        self.plugin.assert_has_calls([
            mock.call.update_port(mock.ANY, 'foo_port_id', expected_port)])

    def test_get_dhcp_port_existing(self):
        port_retval = dict(id='port_id', fixed_ips=[dict(subnet_id='a')])
        expectations = [
            mock.call.update_port(mock.ANY, 'port_id', dict(port=port_retval))]

        self._test_get_dhcp_port_helper(port_retval, expectations,
                                        update_port=port_retval)
        self.assertEqual(len(self.log.mock_calls), 1)

    def _test_get_dhcp_port_create_new(self, update_port=None):
        self.plugin.get_network.return_value = dict(tenant_id='tenantid')
        create_spec = dict(tenant_id='tenantid', device_id='devid',
                           network_id='netid', name='',
                           admin_state_up=True,
                           device_owner=constants.DEVICE_OWNER_DHCP,
                           mac_address=mock.ANY)
        create_retval = create_spec.copy()
        create_retval['id'] = 'port_id'
        create_retval['fixed_ips'] = [dict(subnet_id='a', enable_dhcp=True)]

        create_spec['fixed_ips'] = [dict(subnet_id='a')]

        expectations = [
            mock.call.get_network(mock.ANY, 'netid'),
            mock.call.create_port(mock.ANY, dict(port=create_spec))]

        retval = self._test_get_dhcp_port_helper(None, expectations,
                                                 update_port=update_port,
                                                 create_port=create_retval)
        self.assertEqual(create_retval, retval)
        self.assertEqual(len(self.log.mock_calls), 2)

    def test_get_dhcp_port_create_new(self):
        self._test_get_dhcp_port_create_new()

    def test_get_dhcp_port_create_new_with_failure_on_port_update(self):
        self._test_get_dhcp_port_create_new(
            update_port=n_exc.PortNotFound(port_id='foo'))

    def test_release_dhcp_port(self):
        port_retval = dict(id='port_id', fixed_ips=[dict(subnet_id='a')])
        self.plugin.get_ports.return_value = [port_retval]

        self.callbacks.release_dhcp_port(mock.ANY, network_id='netid',
                                         device_id='devid')

        self.plugin.assert_has_calls([
            mock.call.delete_ports_by_device_id(mock.ANY, 'devid', 'netid')])

    def test_release_port_fixed_ip(self):
        port_retval = dict(id='port_id', fixed_ips=[dict(subnet_id='a')])
        port_update = dict(id='port_id', fixed_ips=[])
        self.plugin.get_ports.return_value = [port_retval]

        self.callbacks.release_port_fixed_ip(mock.ANY, network_id='netid',
                                             device_id='devid', subnet_id='a')

        self.plugin.assert_has_calls([
            mock.call.get_ports(mock.ANY, filters=dict(network_id=['netid'],
                                                       device_id=['devid'])),
            mock.call.update_port(mock.ANY, 'port_id',
                                  dict(port=port_update))])
