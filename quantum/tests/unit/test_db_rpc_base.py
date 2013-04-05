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

from quantum.db import dhcp_rpc_base
from quantum.tests import base


class TestDhcpRpcCallackMixin(base.BaseTestCase):

    def setUp(self):
        super(TestDhcpRpcCallackMixin, self).setUp()
        self.plugin_p = mock.patch('quantum.manager.QuantumManager.get_plugin')
        get_plugin = self.plugin_p.start()
        self.plugin = mock.MagicMock()
        get_plugin.return_value = self.plugin
        self.callbacks = dhcp_rpc_base.DhcpRpcCallbackMixin()
        self.log_p = mock.patch('quantum.db.dhcp_rpc_base.LOG')
        self.log = self.log_p.start()

    def tearDown(self):
        self.log_p.stop()
        self.plugin_p.stop()
        super(TestDhcpRpcCallackMixin, self).tearDown()

    def test_get_active_networks(self):
        plugin_retval = [dict(id='a'), dict(id='b')]
        self.plugin.get_networks.return_value = plugin_retval

        networks = self.callbacks.get_active_networks(mock.Mock(), host='host')

        self.assertEqual(networks, ['a', 'b'])
        self.plugin.assert_has_calls(
            [mock.call.get_networks(mock.ANY,
                                    filters=dict(admin_state_up=[True]))])

        self.assertEqual(len(self.log.mock_calls), 1)

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

    def test_get_dhcp_port_existing(self):
        port_retval = dict(id='port_id', fixed_ips=[dict(subnet_id='a')])
        expectations = [
            mock.call.update_port(mock.ANY, 'port_id', dict(port=port_retval))]

        self._test_get_dhcp_port_helper(port_retval, expectations,
                                        update_port=port_retval)
        self.assertEqual(len(self.log.mock_calls), 1)

    def test_get_dhcp_port_create_new(self):
        self.plugin.get_network.return_value = dict(tenant_id='tenantid')
        create_spec = dict(tenant_id='tenantid', device_id='devid',
                           network_id='netid', name='',
                           admin_state_up=True,
                           device_owner='network:dhcp',
                           mac_address=mock.ANY)
        create_retval = create_spec.copy()
        create_retval['id'] = 'port_id'
        create_retval['fixed_ips'] = [dict(subnet_id='a', enable_dhcp=True)]

        create_spec['fixed_ips'] = [dict(subnet_id='a')]

        expectations = [
            mock.call.get_network(mock.ANY, 'netid'),
            mock.call.create_port(mock.ANY, dict(port=create_spec))]

        retval = self._test_get_dhcp_port_helper(None, expectations,
                                                 create_port=create_retval)
        self.assertEqual(create_retval, retval)
        self.assertEqual(len(self.log.mock_calls), 2)

    def test_release_dhcp_port(self):
        port_retval = dict(id='port_id', fixed_ips=[dict(subnet_id='a')])
        self.plugin.get_ports.return_value = [port_retval]

        self.callbacks.release_dhcp_port(mock.ANY, network_id='netid',
                                         device_id='devid')

        self.plugin.assert_has_calls([
            mock.call.get_ports(mock.ANY, filters=dict(network_id=['netid'],
                                                       device_id=['devid'])),
            mock.call.delete_port(mock.ANY, 'port_id')])

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
