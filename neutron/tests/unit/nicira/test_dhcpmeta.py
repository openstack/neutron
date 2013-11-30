# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 VMware, Inc.
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

from oslo.config import cfg

from neutron.common import exceptions as n_exc
from neutron.plugins.nicira.common import exceptions as p_exc
from neutron.plugins.nicira.dhcp_meta import nvp
from neutron.plugins.nicira.NvpApiClient import NvpApiException
from neutron.tests import base


class LsnManagerTestCase(base.BaseTestCase):

    def setUp(self):
        super(LsnManagerTestCase, self).setUp()
        self.net_id = 'foo_network_id'
        self.sub_id = 'foo_subnet_id'
        self.port_id = 'foo_port_id'
        self.lsn_id = 'foo_lsn_id'
        self.mac = 'aa:bb:cc:dd:ee:ff'
        self.lsn_port_id = 'foo_lsn_port_id'
        self.manager = nvp.LsnManager(mock.Mock())
        self.mock_lsn_api_p = mock.patch.object(nvp, 'lsn_api')
        self.mock_lsn_api = self.mock_lsn_api_p.start()
        nvp.register_dhcp_opts(cfg)
        self.addCleanup(cfg.CONF.reset)
        self.addCleanup(self.mock_lsn_api_p.stop)

    def test_lsn_get(self):
        self.mock_lsn_api.lsn_for_network_get.return_value = self.lsn_id
        expected = self.manager.lsn_get(mock.ANY, self.net_id)
        self.mock_lsn_api.lsn_for_network_get.assert_called_once_with(
            mock.ANY, self.net_id)
        self.assertEqual(expected, self.lsn_id)

    def _test_lsn_get_raise_not_found_with_exc(self, exc):
        self.mock_lsn_api.lsn_for_network_get.side_effect = exc
        self.assertRaises(p_exc.LsnNotFound,
                          self.manager.lsn_get,
                          mock.ANY, self.net_id)
        self.mock_lsn_api.lsn_for_network_get.assert_called_once_with(
            mock.ANY, self.net_id)

    def test_lsn_get_raise_not_found_with_not_found(self):
        self._test_lsn_get_raise_not_found_with_exc(n_exc.NotFound)

    def test_lsn_get_raise_not_found_with_api_error(self):
        self._test_lsn_get_raise_not_found_with_exc(NvpApiException)

    def _test_lsn_get_silent_raise_with_exc(self, exc):
        self.mock_lsn_api.lsn_for_network_get.side_effect = exc
        expected = self.manager.lsn_get(
            mock.ANY, self.net_id, raise_on_err=False)
        self.mock_lsn_api.lsn_for_network_get.assert_called_once_with(
            mock.ANY, self.net_id)
        self.assertIsNone(expected)

    def test_lsn_get_silent_raise_with_not_found(self):
        self._test_lsn_get_silent_raise_with_exc(n_exc.NotFound)

    def test_lsn_get_silent_raise_with_api_error(self):
        self._test_lsn_get_silent_raise_with_exc(NvpApiException)

    def test_lsn_create(self):
        self.mock_lsn_api.lsn_for_network_create.return_value = self.lsn_id
        self.manager.lsn_create(mock.ANY, self.net_id)
        self.mock_lsn_api.lsn_for_network_create.assert_called_once_with(
            mock.ANY, self.net_id)

    def test_lsn_create_raise_api_error(self):
        self.mock_lsn_api.lsn_for_network_create.side_effect = NvpApiException
        self.assertRaises(p_exc.NvpPluginException,
                          self.manager.lsn_create,
                          mock.ANY, self.net_id)
        self.mock_lsn_api.lsn_for_network_create.assert_called_once_with(
            mock.ANY, self.net_id)

    def test_lsn_delete(self):
        self.manager.lsn_delete(mock.ANY, self.lsn_id)
        self.mock_lsn_api.lsn_delete.assert_called_once_with(
            mock.ANY, self.lsn_id)

    def _test_lsn_delete_with_exc(self, exc):
        self.mock_lsn_api.lsn_delete.side_effect = exc
        self.manager.lsn_delete(mock.ANY, self.lsn_id)
        self.mock_lsn_api.lsn_delete.assert_called_once_with(
            mock.ANY, self.lsn_id)

    def test_lsn_delete_with_not_found(self):
        self._test_lsn_delete_with_exc(n_exc.NotFound)

    def test_lsn_delete_api_exception(self):
        self._test_lsn_delete_with_exc(NvpApiException)

    def test_lsn_delete_by_network(self):
        self.mock_lsn_api.lsn_for_network_get.return_value = self.lsn_id
        with mock.patch.object(self.manager, 'lsn_delete') as f:
            self.manager.lsn_delete_by_network(mock.ANY, self.net_id)
            self.mock_lsn_api.lsn_for_network_get.assert_called_once_with(
                mock.ANY, self.net_id)
            f.assert_called_once_with(mock.ANY, self.lsn_id)

    def _test_lsn_delete_by_network_with_exc(self, exc):
        self.mock_lsn_api.lsn_for_network_get.side_effect = exc
        with mock.patch.object(nvp.LOG, 'warn') as l:
            self.manager.lsn_delete_by_network(mock.ANY, self.net_id)
            self.assertEqual(1, l.call_count)

    def test_lsn_delete_by_network_with_not_found(self):
        self._test_lsn_delete_by_network_with_exc(n_exc.NotFound)

    def test_lsn_delete_by_network_with_not_api_error(self):
        self._test_lsn_delete_by_network_with_exc(NvpApiException)

    def test_lsn_port_get(self):
        self.mock_lsn_api.lsn_port_by_subnet_get.return_value = (
            self.lsn_port_id)
        with mock.patch.object(
            self.manager, 'lsn_get', return_value=self.lsn_id):
            expected = self.manager.lsn_port_get(
                mock.ANY, self.net_id, self.sub_id)
            self.assertEqual(expected, (self.lsn_id, self.lsn_port_id))

    def test_lsn_port_get_lsn_not_found_on_raise(self):
        with mock.patch.object(
            self.manager, 'lsn_get',
            side_effect=p_exc.LsnNotFound(entity='network',
                                          entity_id=self.net_id)):
            self.assertRaises(p_exc.LsnNotFound,
                              self.manager.lsn_port_get,
                              mock.ANY, self.net_id, self.sub_id)

    def test_lsn_port_get_lsn_not_found_silent_raise(self):
        with mock.patch.object(self.manager, 'lsn_get', return_value=None):
            expected = self.manager.lsn_port_get(
                mock.ANY, self.net_id, self.sub_id, raise_on_err=False)
            self.assertEqual(expected, (None, None))

    def test_lsn_port_get_port_not_found_on_raise(self):
        self.mock_lsn_api.lsn_port_by_subnet_get.side_effect = n_exc.NotFound
        with mock.patch.object(
            self.manager, 'lsn_get', return_value=self.lsn_id):
            self.assertRaises(p_exc.LsnPortNotFound,
                              self.manager.lsn_port_get,
                              mock.ANY, self.net_id, self.sub_id)

    def test_lsn_port_get_port_not_found_silent_raise(self):
        self.mock_lsn_api.lsn_port_by_subnet_get.side_effect = n_exc.NotFound
        with mock.patch.object(
            self.manager, 'lsn_get', return_value=self.lsn_id):
            expected = self.manager.lsn_port_get(
                mock.ANY, self.net_id, self.sub_id, raise_on_err=False)
            self.assertEqual(expected, (self.lsn_id, None))

    def test_lsn_port_create(self):
        self.mock_lsn_api.lsn_port_create.return_value = self.lsn_port_id
        expected = self.manager.lsn_port_create(mock.ANY, mock.ANY, mock.ANY)
        self.assertEqual(expected, self.lsn_port_id)

    def _test_lsn_port_create_with_exc(self, exc, expected):
        self.mock_lsn_api.lsn_port_create.side_effect = exc
        self.assertRaises(expected,
                          self.manager.lsn_port_create,
                          mock.ANY, mock.ANY, mock.ANY)

    def test_lsn_port_create_with_not_found(self):
        self._test_lsn_port_create_with_exc(n_exc.NotFound, p_exc.LsnNotFound)

    def test_lsn_port_create_api_exception(self):
        self._test_lsn_port_create_with_exc(NvpApiException,
                                            p_exc.NvpPluginException)

    def test_lsn_port_delete(self):
        self.manager.lsn_port_delete(mock.ANY, mock.ANY, mock.ANY)
        self.assertEqual(1, self.mock_lsn_api.lsn_port_delete.call_count)

    def _test_lsn_port_delete_with_exc(self, exc):
        self.mock_lsn_api.lsn_port_delete.side_effect = exc
        with mock.patch.object(nvp.LOG, 'warn') as l:
            self.manager.lsn_port_delete(mock.ANY, mock.ANY, mock.ANY)
            self.assertEqual(1, self.mock_lsn_api.lsn_port_delete.call_count)
            self.assertEqual(1, l.call_count)

    def test_lsn_port_delete_with_not_found(self):
        self._test_lsn_port_delete_with_exc(n_exc.NotFound)

    def test_lsn_port_delete_api_exception(self):
        self._test_lsn_port_delete_with_exc(NvpApiException)

    def _test_lsn_port_dhcp_setup(self, ret_val, sub):
        self.mock_lsn_api.lsn_port_create.return_value = self.lsn_port_id
        with mock.patch.object(
            self.manager, 'lsn_get', return_value=self.lsn_id):
            with mock.patch.object(nvp.nvplib, 'get_port_by_neutron_tag'):
                expected = self.manager.lsn_port_dhcp_setup(
                    mock.ANY, mock.ANY, mock.ANY, mock.ANY, subnet_config=sub)
                self.assertEqual(
                    1, self.mock_lsn_api.lsn_port_create.call_count)
                self.assertEqual(
                    1, self.mock_lsn_api.lsn_port_plug_network.call_count)
                self.assertEqual(expected, ret_val)

    def test_lsn_port_dhcp_setup(self):
        self._test_lsn_port_dhcp_setup((self.lsn_id, self.lsn_port_id), None)

    def test_lsn_port_dhcp_setup_with_config(self):
        with mock.patch.object(self.manager, 'lsn_port_dhcp_configure') as f:
            self._test_lsn_port_dhcp_setup(None, mock.ANY)
            self.assertEqual(1, f.call_count)

    def test_lsn_port_dhcp_setup_with_not_found(self):
        with mock.patch.object(nvp.nvplib, 'get_port_by_neutron_tag') as f:
            f.side_effect = n_exc.NotFound
            self.assertRaises(p_exc.PortConfigurationError,
                              self.manager.lsn_port_dhcp_setup,
                              mock.ANY, mock.ANY, mock.ANY, mock.ANY)

    def test_lsn_port_dhcp_setup_with_conflict(self):
        self.mock_lsn_api.lsn_port_plug_network.side_effect = (
            p_exc.LsnConfigurationConflict(lsn_id=self.lsn_id))
        with mock.patch.object(nvp.nvplib, 'get_port_by_neutron_tag'):
            with mock.patch.object(self.manager, 'lsn_port_delete') as g:
                self.assertRaises(p_exc.PortConfigurationError,
                                  self.manager.lsn_port_dhcp_setup,
                                  mock.ANY, mock.ANY, mock.ANY, mock.ANY)
                self.assertEqual(1, g.call_count)

    def _test_lsn_port_dhcp_configure_with_subnet(
        self, expected, dns=None, gw=None, routes=None):
        subnet = {
            'enable_dhcp': True,
            'dns_nameservers': dns or [],
            'gateway_ip': gw,
            'host_routes': routes
        }
        self.manager.lsn_port_dhcp_configure(mock.ANY, self.lsn_id,
                                             self.lsn_port_id, subnet)
        self.mock_lsn_api.lsn_port_dhcp_configure.assert_called_once_with(
            mock.ANY, self.lsn_id, self.lsn_port_id, subnet['enable_dhcp'],
            expected)

    def test_lsn_port_dhcp_configure(self):
        expected = {
            'routers': '127.0.0.1',
            'default_lease_time': cfg.CONF.NVP_DHCP.default_lease_time,
            'domain_name': cfg.CONF.NVP_DHCP.domain_name
        }
        self._test_lsn_port_dhcp_configure_with_subnet(
            expected, dns=[], gw='127.0.0.1', routes=[])

    def test_lsn_port_dhcp_configure_gatewayless(self):
        expected = {
            'default_lease_time': cfg.CONF.NVP_DHCP.default_lease_time,
            'domain_name': cfg.CONF.NVP_DHCP.domain_name
        }
        self._test_lsn_port_dhcp_configure_with_subnet(expected, gw=None)

    def test_lsn_port_dhcp_configure_with_extra_dns_servers(self):
        expected = {
            'default_lease_time': cfg.CONF.NVP_DHCP.default_lease_time,
            'domain_name_servers': '8.8.8.8,9.9.9.9',
            'domain_name': cfg.CONF.NVP_DHCP.domain_name
        }
        self._test_lsn_port_dhcp_configure_with_subnet(
            expected, dns=['8.8.8.8', '9.9.9.9'])

    def test_lsn_port_dhcp_configure_with_host_routes(self):
        expected = {
            'default_lease_time': cfg.CONF.NVP_DHCP.default_lease_time,
            'domain_name': cfg.CONF.NVP_DHCP.domain_name,
            'classless_static_routes': '8.8.8.8,9.9.9.9'
        }
        self._test_lsn_port_dhcp_configure_with_subnet(
            expected, routes=['8.8.8.8', '9.9.9.9'])

    def _test_lsn_port_dispose_with_values(self, lsn_id, lsn_port_id, count):
        with mock.patch.object(self.manager,
                               'lsn_port_get_by_mac',
                               return_value=(lsn_id, lsn_port_id)):
            self.manager.lsn_port_dispose(mock.ANY, self.net_id, self.mac)
            self.assertEqual(count,
                             self.mock_lsn_api.lsn_port_delete.call_count)

    def test_lsn_port_dispose(self):
        self._test_lsn_port_dispose_with_values(
            self.lsn_id, self.lsn_port_id, 1)

    def test_lsn_port_dispose_lsn_not_found(self):
        self._test_lsn_port_dispose_with_values(None, None, 0)

    def test_lsn_port_dispose_lsn_port_not_found(self):
        self._test_lsn_port_dispose_with_values(self.lsn_id, None, 0)

    def test_lsn_port_dispose_api_error(self):
        self.mock_lsn_api.lsn_port_delete.side_effect = NvpApiException
        with mock.patch.object(nvp.LOG, 'warn') as l:
            self.manager.lsn_port_dispose(mock.ANY, self.net_id, self.mac)
            self.assertEqual(1, l.call_count)

    def test_lsn_port_host_conf(self):
        with mock.patch.object(self.manager,
                               'lsn_port_get',
                               return_value=(self.lsn_id, self.lsn_port_id)):
            f = mock.Mock()
            self.manager._lsn_port_host_conf(mock.ANY, self.net_id,
                                             self.sub_id, mock.ANY, f)
            self.assertEqual(1, f.call_count)

    def test_lsn_port_host_conf_lsn_port_not_found(self):
        with mock.patch.object(
            self.manager,
            'lsn_port_get',
            side_effect=p_exc.LsnPortNotFound(lsn_id=self.lsn_id,
                                              entity='subnet',
                                              entity_id=self.sub_id)):
            self.assertRaises(p_exc.PortConfigurationError,
                              self.manager._lsn_port_host_conf, mock.ANY,
                              self.net_id, self.sub_id, mock.ANY, mock.Mock())


class DhcpAgentNotifyAPITestCase(base.BaseTestCase):

    def setUp(self):
        super(DhcpAgentNotifyAPITestCase, self).setUp()
        self.notifier = nvp.DhcpAgentNotifyAPI(mock.Mock(), mock.Mock())
        self.plugin = self.notifier.plugin
        self.lsn_manager = self.notifier.lsn_manager

    def _test_notify_subnet_action(self, action):
        with mock.patch.object(self.notifier, '_subnet_%s' % action) as f:
            self.notifier._handle_subnet_dhcp_access[action] = f
            subnet = {'subnet': mock.ANY}
            self.notifier.notify(
                mock.ANY, subnet, 'subnet.%s.end' % action)
            f.assert_called_once_with(mock.ANY, subnet)

    def test_notify_subnet_create(self):
        self._test_notify_subnet_action('create')

    def test_notify_subnet_update(self):
        self._test_notify_subnet_action('update')

    def test_notify_subnet_delete(self):
        self._test_notify_subnet_action('delete')

    def _test_subnet_create(self, enable_dhcp, exc=None,
                            exc_obj=None, call_notify=True):
        subnet = {
            'id': 'foo_subnet_id',
            'enable_dhcp': enable_dhcp,
            'network_id': 'foo_network_id',
            'tenant_id': 'foo_tenant_id',
            'cidr': '0.0.0.0/0'
        }
        if exc:
            self.plugin.create_port.side_effect = exc_obj or exc
            self.assertRaises(exc,
                              self.notifier.notify,
                              mock.ANY,
                              {'subnet': subnet},
                              'subnet.create.end')
            self.plugin.delete_subnet.assert_called_with(
                mock.ANY, subnet['id'])
        else:
            if call_notify:
                self.notifier.notify(
                    mock.ANY, {'subnet': subnet}, 'subnet.create.end')
            if enable_dhcp:
                dhcp_port = {
                    'name': '',
                    'admin_state_up': True,
                    'network_id': 'foo_network_id',
                    'tenant_id': 'foo_tenant_id',
                    'device_owner': 'network:dhcp',
                    'mac_address': mock.ANY,
                    'fixed_ips': [{'subnet_id': 'foo_subnet_id'}],
                    'device_id': ''
                }
                self.plugin.create_port.assert_called_once_with(
                    mock.ANY, {'port': dhcp_port})
            else:
                self.assertEqual(0, self.plugin.create_port.call_count)

    def test_subnet_create_enabled_dhcp(self):
        self._test_subnet_create(True)

    def test_subnet_create_disabled_dhcp(self):
        self._test_subnet_create(False)

    def test_subnet_create_raise_port_config_error(self):
        with mock.patch.object(nvp.db_base_plugin_v2.NeutronDbPluginV2,
                               'delete_port') as d:
            self._test_subnet_create(
                True,
                exc=n_exc.Conflict,
                exc_obj=p_exc.PortConfigurationError(lsn_id='foo_lsn_id',
                                                     net_id='foo_net_id',
                                                     port_id='foo_port_id'))
            d.assert_called_once_with(self.plugin, mock.ANY, 'foo_port_id')

    def test_subnet_update(self):
        subnet = {
            'id': 'foo_subnet_id',
            'network_id': 'foo_network_id',
        }
        self.lsn_manager.lsn_port_get.return_value = ('foo_lsn_id',
                                                      'foo_lsn_port_id')
        self.notifier.notify(
            mock.ANY, {'subnet': subnet}, 'subnet.update.end')
        self.lsn_manager.lsn_port_dhcp_configure.assert_called_once_with(
            mock.ANY, 'foo_lsn_id', 'foo_lsn_port_id', subnet)

    def test_subnet_update_raise_lsn_not_found(self):
        subnet = {
            'id': 'foo_subnet_id',
            'network_id': 'foo_network_id',
        }
        self.lsn_manager.lsn_port_get.side_effect = (
            p_exc.LsnNotFound(entity='network',
                              entity_id=subnet['network_id']))
        self.assertRaises(p_exc.LsnNotFound,
                          self.notifier.notify,
                          mock.ANY, {'subnet': subnet}, 'subnet.update.end')

    def _test_subnet_update_lsn_port_not_found(self, dhcp_port):
        subnet = {
            'id': 'foo_subnet_id',
            'enable_dhcp': True,
            'network_id': 'foo_network_id',
            'tenant_id': 'foo_tenant_id'
        }
        self.lsn_manager.lsn_port_get.side_effect = (
            p_exc.LsnPortNotFound(lsn_id='foo_lsn_id',
                                  entity='subnet',
                                  entity_id=subnet['id']))
        self.notifier.plugin.get_ports.return_value = dhcp_port
        count = 0 if dhcp_port is None else 1
        with mock.patch.object(nvp, 'handle_port_dhcp_access') as h:
            self.notifier.notify(
                mock.ANY, {'subnet': subnet}, 'subnet.update.end')
            self.assertEqual(count, h.call_count)
            if not dhcp_port:
                self._test_subnet_create(enable_dhcp=True,
                                         exc=None, call_notify=False)

    def test_subnet_update_lsn_port_not_found_without_dhcp_port(self):
        self._test_subnet_update_lsn_port_not_found(None)

    def test_subnet_update_lsn_port_not_found_with_dhcp_port(self):
        self._test_subnet_update_lsn_port_not_found([mock.ANY])

    def _test_subnet_delete(self, ports=None):
        subnet = {
            'id': 'foo_subnet_id',
            'network_id': 'foo_network_id',
            'cidr': '0.0.0.0/0'
        }
        self.plugin.get_ports.return_value = ports
        self.notifier.notify(mock.ANY, {'subnet': subnet}, 'subnet.delete.end')
        filters = {
            'network_id': [subnet['network_id']],
            'device_owner': ['network:dhcp']
        }
        self.plugin.get_ports.assert_called_once_with(
            mock.ANY, filters=filters)
        if ports:
            self.plugin.delete_port.assert_called_once_with(
                mock.ANY, ports[0]['id'])
        else:
            self.assertEqual(0, self.plugin.delete_port.call_count)

    def test_subnet_delete_enabled_dhcp_no_ports(self):
        self._test_subnet_delete()

    def test_subnet_delete_enabled_dhcp_with_dhcp_port(self):
        self._test_subnet_delete([{'id': 'foo_port_id'}])


class DhcpTestCase(base.BaseTestCase):

    def setUp(self):
        super(DhcpTestCase, self).setUp()
        self.plugin = mock.Mock()
        self.plugin.lsn_manager = mock.Mock()

    def test_handle_create_network(self):
        network = {'id': 'foo_network_id'}
        nvp.handle_network_dhcp_access(
            self.plugin, mock.ANY, network, 'create_network')
        self.plugin.lsn_manager.lsn_create.assert_called_once_with(
            mock.ANY, network['id'])

    def test_handle_delete_network(self):
        network_id = 'foo_network_id'
        self.plugin.lsn_manager.lsn_delete_by_network.return_value = (
            'foo_lsn_id')
        nvp.handle_network_dhcp_access(
            self.plugin, mock.ANY, network_id, 'delete_network')
        self.plugin.lsn_manager.lsn_delete_by_network.assert_called_once_with(
            mock.ANY, 'foo_network_id')

    def _test_handle_create_dhcp_owner_port(self, exc=None):
        subnet = {
            'cidr': '0.0.0.0/0',
            'id': 'foo_subnet_id'
        }
        port = {
            'id': 'foo_port_id',
            'device_owner': 'network:dhcp',
            'mac_address': 'aa:bb:cc:dd:ee:ff',
            'network_id': 'foo_network_id',
            'fixed_ips': [{'subnet_id': subnet['id']}]
        }
        expected_data = {
            'subnet_id': subnet['id'],
            'ip_address': subnet['cidr'],
            'mac_address': port['mac_address']
        }
        self.plugin.get_subnet.return_value = subnet
        if exc is None:
            nvp.handle_port_dhcp_access(
                self.plugin, mock.ANY, port, 'create_port')
            (self.plugin.lsn_manager.lsn_port_dhcp_setup.
             assert_called_once_with(mock.ANY, port['network_id'],
                                     port['id'], expected_data, subnet))
        else:
            self.plugin.lsn_manager.lsn_port_dhcp_setup.side_effect = exc
            self.assertRaises(n_exc.NeutronException,
                              nvp.handle_port_dhcp_access,
                              self.plugin, mock.ANY, port, 'create_port')

    def test_handle_create_dhcp_owner_port(self):
        self._test_handle_create_dhcp_owner_port()

    def test_handle_create_dhcp_owner_port_raise_port_config_error(self):
        config_error = p_exc.PortConfigurationError(lsn_id='foo_lsn_id',
                                                    net_id='foo_net_id',
                                                    port_id='foo_port_id')
        self._test_handle_create_dhcp_owner_port(exc=config_error)

    def test_handle_delete_dhcp_owner_port(self):
        port = {
            'id': 'foo_port_id',
            'device_owner': 'network:dhcp',
            'network_id': 'foo_network_id',
            'fixed_ips': [],
            'mac_address': 'aa:bb:cc:dd:ee:ff'
        }
        nvp.handle_port_dhcp_access(self.plugin, mock.ANY, port, 'delete_port')
        self.plugin.lsn_manager.lsn_port_dispose.assert_called_once_with(
            mock.ANY, port['network_id'], port['mac_address'])

    def _test_handle_user_port(self, action, handler):
        port = {
            'id': 'foo_port_id',
            'device_owner': 'foo_device_owner',
            'network_id': 'foo_network_id',
            'mac_address': 'aa:bb:cc:dd:ee:ff',
            'fixed_ips': [{'subnet_id': 'foo_subnet_id',
                           'ip_address': '1.2.3.4'}]
        }
        expected_data = {
            'ip_address': '1.2.3.4',
            'mac_address': 'aa:bb:cc:dd:ee:ff'
        }
        self.plugin.get_subnet.return_value = {'enable_dhcp': True}
        nvp.handle_port_dhcp_access(self.plugin, mock.ANY, port, action)
        handler.assert_called_once_with(
            mock.ANY, port['network_id'], 'foo_subnet_id', expected_data)

    def test_handle_create_user_port(self):
        self._test_handle_user_port(
            'create_port', self.plugin.lsn_manager.lsn_port_dhcp_host_add)

    def test_handle_delete_user_port(self):
        self._test_handle_user_port(
            'delete_port', self.plugin.lsn_manager.lsn_port_dhcp_host_remove)

    def _test_handle_user_port_disabled_dhcp(self, action, handler):
        port = {
            'id': 'foo_port_id',
            'device_owner': 'foo_device_owner',
            'network_id': 'foo_network_id',
            'mac_address': 'aa:bb:cc:dd:ee:ff',
            'fixed_ips': [{'subnet_id': 'foo_subnet_id',
                           'ip_address': '1.2.3.4'}]
        }
        self.plugin.get_subnet.return_value = {'enable_dhcp': False}
        nvp.handle_port_dhcp_access(self.plugin, mock.ANY, port, action)
        self.assertEqual(0, handler.call_count)

    def test_handle_create_user_port_disabled_dhcp(self):
        self._test_handle_user_port_disabled_dhcp(
            'create_port', self.plugin.lsn_manager.lsn_port_dhcp_host_add)

    def test_handle_delete_user_port_disabled_dhcp(self):
        self._test_handle_user_port_disabled_dhcp(
            'delete_port', self.plugin.lsn_manager.lsn_port_dhcp_host_remove)

    def _test_handle_user_port_no_fixed_ips(self, action, handler):
        port = {
            'id': 'foo_port_id',
            'device_owner': 'foo_device_owner',
            'network_id': 'foo_network_id',
            'fixed_ips': []
        }
        nvp.handle_port_dhcp_access(self.plugin, mock.ANY, port, action)
        self.assertEqual(0, handler.call_count)

    def test_handle_create_user_port_no_fixed_ips(self):
        self._test_handle_user_port_no_fixed_ips(
            'create_port', self.plugin.lsn_manager.lsn_port_dhcp_host_add)

    def test_handle_delete_user_port_no_fixed_ips(self):
        self._test_handle_user_port_no_fixed_ips(
            'delete_port', self.plugin.lsn_manager.lsn_port_dhcp_host_remove)
