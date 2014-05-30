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

from neutron.common import constants as n_consts
from neutron.common import exceptions as n_exc
from neutron import context
from neutron.db import api as db
from neutron.plugins.vmware.api_client.exception import NsxApiException
from neutron.plugins.vmware.common import exceptions as p_exc
from neutron.plugins.vmware.dbexts import lsn_db
from neutron.plugins.vmware.dhcp_meta import constants
from neutron.plugins.vmware.dhcp_meta import lsnmanager as lsn_man
from neutron.plugins.vmware.dhcp_meta import migration as mig_man
from neutron.plugins.vmware.dhcp_meta import nsx
from neutron.plugins.vmware.dhcp_meta import rpc
from neutron.tests import base


class DhcpMetadataBuilderTestCase(base.BaseTestCase):

    def setUp(self):
        super(DhcpMetadataBuilderTestCase, self).setUp()
        self.builder = mig_man.DhcpMetadataBuilder(mock.Mock(), mock.Mock())
        self.network_id = 'foo_network_id'
        self.subnet_id = 'foo_subnet_id'
        self.router_id = 'foo_router_id'

    def test_dhcp_agent_get_all(self):
        expected = []
        self.builder.plugin.list_dhcp_agents_hosting_network.return_value = (
            {'agents': expected})
        agents = self.builder.dhcp_agent_get_all(mock.ANY, self.network_id)
        self.assertEqual(expected, agents)

    def test_dhcp_port_get_all(self):
        expected = []
        self.builder.plugin.get_ports.return_value = expected
        ports = self.builder.dhcp_port_get_all(mock.ANY, self.network_id)
        self.assertEqual(expected, ports)

    def test_router_id_get(self):
        port = {
            'device_id': self.router_id,
            'network_id': self.network_id,
            'fixed_ips': [{'subnet_id': self.subnet_id}]
        }
        subnet = {
            'id': self.subnet_id,
            'network_id': self.network_id
        }
        self.builder.plugin.get_ports.return_value = [port]
        result = self.builder.router_id_get(context, subnet)
        self.assertEqual(self.router_id, result)

    def test_router_id_get_none_subnet(self):
        self.assertIsNone(self.builder.router_id_get(mock.ANY, None))

    def test_router_id_get_none_no_router(self):
        self.builder.plugin.get_ports.return_value = []
        subnet = {'network_id': self.network_id}
        self.assertIsNone(self.builder.router_id_get(mock.ANY, subnet))

    def test_metadata_deallocate(self):
        self.builder.metadata_deallocate(
            mock.ANY, self.router_id, self.subnet_id)
        self.assertTrue(self.builder.plugin.remove_router_interface.call_count)

    def test_metadata_allocate(self):
        self.builder.metadata_allocate(
            mock.ANY, self.router_id, self.subnet_id)
        self.assertTrue(self.builder.plugin.add_router_interface.call_count)

    def test_dhcp_deallocate(self):
        agents = [{'id': 'foo_agent_id'}]
        ports = [{'id': 'foo_port_id'}]
        self.builder.dhcp_deallocate(mock.ANY, self.network_id, agents, ports)
        self.assertTrue(
            self.builder.plugin.remove_network_from_dhcp_agent.call_count)
        self.assertTrue(self.builder.plugin.delete_port.call_count)

    def _test_dhcp_allocate(self, subnet, expected_notify_count):
        with mock.patch.object(mig_man.nsx, 'handle_network_dhcp_access') as f:
            self.builder.dhcp_allocate(mock.ANY, self.network_id, subnet)
            self.assertTrue(f.call_count)
            self.assertEqual(expected_notify_count,
                             self.builder.notifier.notify.call_count)

    def test_dhcp_allocate(self):
        subnet = {'network_id': self.network_id, 'id': self.subnet_id}
        self._test_dhcp_allocate(subnet, 2)

    def test_dhcp_allocate_none_subnet(self):
        self._test_dhcp_allocate(None, 0)


class MigrationManagerTestCase(base.BaseTestCase):

    def setUp(self):
        super(MigrationManagerTestCase, self).setUp()
        self.manager = mig_man.MigrationManager(mock.Mock(),
                                                mock.Mock(),
                                                mock.Mock())
        self.network_id = 'foo_network_id'
        self.router_id = 'foo_router_id'
        self.subnet_id = 'foo_subnet_id'
        self.mock_builder_p = mock.patch.object(self.manager, 'builder')
        self.mock_builder = self.mock_builder_p.start()
        self.addCleanup(self.mock_builder_p.stop)

    def _test_validate(self, lsn_exists=False, ext_net=False, subnets=None):
        network = {'router:external': ext_net}
        self.manager.manager.lsn_exists.return_value = lsn_exists
        self.manager.plugin.get_network.return_value = network
        self.manager.plugin.get_subnets.return_value = subnets
        result = self.manager.validate(mock.ANY, self.network_id)
        if len(subnets):
            self.assertEqual(subnets[0], result)
        else:
            self.assertIsNone(result)

    def test_validate_no_subnets(self):
        self._test_validate(subnets=[])

    def test_validate_with_one_subnet(self):
        self._test_validate(subnets=[{'cidr': '0.0.0.0/0'}])

    def test_validate_raise_conflict_many_subnets(self):
        self.assertRaises(p_exc.LsnMigrationConflict,
                          self._test_validate,
                          subnets=[{'id': 'sub1'}, {'id': 'sub2'}])

    def test_validate_raise_conflict_lsn_exists(self):
        self.assertRaises(p_exc.LsnMigrationConflict,
                          self._test_validate,
                          lsn_exists=True)

    def test_validate_raise_badrequest_external_net(self):
        self.assertRaises(n_exc.BadRequest,
                          self._test_validate,
                          ext_net=True)

    def test_validate_raise_badrequest_metadata_net(self):
        self.assertRaises(n_exc.BadRequest,
                          self._test_validate,
                          ext_net=False,
                          subnets=[{'cidr': rpc.METADATA_SUBNET_CIDR}])

    def _test_migrate(self, router, subnet, expected_calls):
        self.mock_builder.router_id_get.return_value = router
        self.manager.migrate(mock.ANY, self.network_id, subnet)
        # testing the exact the order of calls is important
        self.assertEqual(expected_calls, self.mock_builder.mock_calls)

    def test_migrate(self):
        subnet = {
            'id': self.subnet_id,
            'network_id': self.network_id
        }
        call_sequence = [
            mock.call.router_id_get(mock.ANY, subnet),
            mock.call.metadata_deallocate(
                mock.ANY, self.router_id, self.subnet_id),
            mock.call.dhcp_agent_get_all(mock.ANY, self.network_id),
            mock.call.dhcp_port_get_all(mock.ANY, self.network_id),
            mock.call.dhcp_deallocate(
                mock.ANY, self.network_id, mock.ANY, mock.ANY),
            mock.call.dhcp_allocate(mock.ANY, self.network_id, subnet),
            mock.call.metadata_allocate(
                mock.ANY, self.router_id, self.subnet_id)
        ]
        self._test_migrate(self.router_id, subnet, call_sequence)

    def test_migrate_no_router_uplink(self):
        subnet = {
            'id': self.subnet_id,
            'network_id': self.network_id
        }
        call_sequence = [
            mock.call.router_id_get(mock.ANY, subnet),
            mock.call.dhcp_agent_get_all(mock.ANY, self.network_id),
            mock.call.dhcp_port_get_all(mock.ANY, self.network_id),
            mock.call.dhcp_deallocate(
                mock.ANY, self.network_id, mock.ANY, mock.ANY),
            mock.call.dhcp_allocate(mock.ANY, self.network_id, subnet),
        ]
        self._test_migrate(None, subnet, call_sequence)

    def test_migrate_no_subnet(self):
        call_sequence = [
            mock.call.router_id_get(mock.ANY, None),
            mock.call.dhcp_allocate(mock.ANY, self.network_id, None),
        ]
        self._test_migrate(None, None, call_sequence)

    def _test_report(self, lsn_attrs, expected):
        self.manager.manager.lsn_port_get.return_value = lsn_attrs
        report = self.manager.report(mock.ANY, self.network_id, self.subnet_id)
        self.assertEqual(expected, report)

    def test_report_for_lsn(self):
        self._test_report(('foo_lsn_id', 'foo_lsn_port_id'),
                          {'ports': ['foo_lsn_port_id'],
                           'services': ['foo_lsn_id'], 'type': 'lsn'})

    def test_report_for_lsn_without_lsn_port(self):
        self._test_report(('foo_lsn_id', None),
                          {'ports': [],
                           'services': ['foo_lsn_id'], 'type': 'lsn'})

    def _test_report_for_lsn_without_subnet(self, validated_subnet):
        with mock.patch.object(self.manager.plugin, 'get_subnets',
                               return_value=validated_subnet):
            self.manager.manager.lsn_port_get.return_value = (
                ('foo_lsn_id', 'foo_lsn_port_id'))
            report = self.manager.report(context, self.network_id)
            expected = {
                'ports': ['foo_lsn_port_id'] if validated_subnet else [],
                'services': ['foo_lsn_id'], 'type': 'lsn'
            }
            self.assertEqual(expected, report)

    def test_report_for_lsn_without_subnet_subnet_found(self):
        self._test_report_for_lsn_without_subnet([{'id': self.subnet_id}])

    def test_report_for_lsn_without_subnet_subnet_not_found(self):
        self.manager.manager.lsn_get.return_value = 'foo_lsn_id'
        self._test_report_for_lsn_without_subnet(None)

    def test_report_for_dhcp_agent(self):
        self.manager.manager.lsn_port_get.return_value = (None, None)
        self.mock_builder.dhcp_agent_get_all.return_value = (
            [{'id': 'foo_agent_id'}])
        self.mock_builder.dhcp_port_get_all.return_value = (
            [{'id': 'foo_dhcp_port_id'}])
        result = self.manager.report(mock.ANY, self.network_id, self.subnet_id)
        expected = {
            'ports': ['foo_dhcp_port_id'],
            'services': ['foo_agent_id'],
            'type': 'agent'
        }
        self.assertEqual(expected, result)


class LsnManagerTestCase(base.BaseTestCase):

    def setUp(self):
        super(LsnManagerTestCase, self).setUp()
        self.net_id = 'foo_network_id'
        self.sub_id = 'foo_subnet_id'
        self.port_id = 'foo_port_id'
        self.lsn_id = 'foo_lsn_id'
        self.mac = 'aa:bb:cc:dd:ee:ff'
        self.switch_id = 'foo_switch_id'
        self.lsn_port_id = 'foo_lsn_port_id'
        self.tenant_id = 'foo_tenant_id'
        self.manager = lsn_man.LsnManager(mock.Mock())
        self.context = context.get_admin_context()
        self.mock_lsn_api_p = mock.patch.object(lsn_man, 'lsn_api')
        self.mock_lsn_api = self.mock_lsn_api_p.start()
        self.mock_nsx_utils_p = mock.patch.object(lsn_man, 'nsx_utils')
        self.mock_nsx_utils = self.mock_nsx_utils_p.start()
        nsx.register_dhcp_opts(cfg)
        nsx.register_metadata_opts(cfg)
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
        self._test_lsn_get_raise_not_found_with_exc(NsxApiException)

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
        self._test_lsn_get_silent_raise_with_exc(NsxApiException)

    def test_lsn_create(self):
        self.mock_lsn_api.lsn_for_network_create.return_value = self.lsn_id
        self.manager.lsn_create(mock.ANY, self.net_id)
        self.mock_lsn_api.lsn_for_network_create.assert_called_once_with(
            mock.ANY, self.net_id)

    def test_lsn_create_raise_api_error(self):
        self.mock_lsn_api.lsn_for_network_create.side_effect = NsxApiException
        self.assertRaises(p_exc.NsxPluginException,
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
        self._test_lsn_delete_with_exc(NsxApiException)

    def test_lsn_delete_by_network(self):
        self.mock_lsn_api.lsn_for_network_get.return_value = self.lsn_id
        with mock.patch.object(self.manager, 'lsn_delete') as f:
            self.manager.lsn_delete_by_network(mock.ANY, self.net_id)
            self.mock_lsn_api.lsn_for_network_get.assert_called_once_with(
                mock.ANY, self.net_id)
            f.assert_called_once_with(mock.ANY, self.lsn_id)

    def _test_lsn_delete_by_network_with_exc(self, exc):
        self.mock_lsn_api.lsn_for_network_get.side_effect = exc
        with mock.patch.object(lsn_man.LOG, 'warn') as l:
            self.manager.lsn_delete_by_network(mock.ANY, self.net_id)
            self.assertEqual(1, l.call_count)

    def test_lsn_delete_by_network_with_not_found(self):
        self._test_lsn_delete_by_network_with_exc(n_exc.NotFound)

    def test_lsn_delete_by_network_with_not_api_error(self):
        self._test_lsn_delete_by_network_with_exc(NsxApiException)

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
        self._test_lsn_port_create_with_exc(NsxApiException,
                                            p_exc.NsxPluginException)

    def test_lsn_port_delete(self):
        self.manager.lsn_port_delete(mock.ANY, mock.ANY, mock.ANY)
        self.assertEqual(1, self.mock_lsn_api.lsn_port_delete.call_count)

    def _test_lsn_port_delete_with_exc(self, exc):
        self.mock_lsn_api.lsn_port_delete.side_effect = exc
        with mock.patch.object(lsn_man.LOG, 'warn') as l:
            self.manager.lsn_port_delete(mock.ANY, mock.ANY, mock.ANY)
            self.assertEqual(1, self.mock_lsn_api.lsn_port_delete.call_count)
            self.assertEqual(1, l.call_count)

    def test_lsn_port_delete_with_not_found(self):
        self._test_lsn_port_delete_with_exc(n_exc.NotFound)

    def test_lsn_port_delete_api_exception(self):
        self._test_lsn_port_delete_with_exc(NsxApiException)

    def _test_lsn_port_dhcp_setup(self, ret_val, sub):
        self.mock_nsx_utils.get_nsx_switch_ids.return_value = [self.switch_id]
        self.mock_lsn_api.lsn_port_create.return_value = self.lsn_port_id
        with mock.patch.object(
            self.manager, 'lsn_get', return_value=self.lsn_id):
            with mock.patch.object(lsn_man.switch_api,
                                   'get_port_by_neutron_tag'):
                expected = self.manager.lsn_port_dhcp_setup(
                    mock.Mock(), mock.ANY, mock.ANY,
                    mock.ANY, subnet_config=sub)
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
        self.mock_nsx_utils.get_nsx_switch_ids.return_value = [self.switch_id]
        with mock.patch.object(lsn_man.switch_api,
                               'get_port_by_neutron_tag') as f:
            f.side_effect = n_exc.NotFound
            self.assertRaises(p_exc.PortConfigurationError,
                              self.manager.lsn_port_dhcp_setup,
                              mock.Mock(), mock.ANY, mock.ANY, mock.ANY)

    def test_lsn_port_dhcp_setup_with_conflict(self):
        self.mock_lsn_api.lsn_port_plug_network.side_effect = (
            p_exc.LsnConfigurationConflict(lsn_id=self.lsn_id))
        self.mock_nsx_utils.get_nsx_switch_ids.return_value = [self.switch_id]
        with mock.patch.object(lsn_man.switch_api, 'get_port_by_neutron_tag'):
            with mock.patch.object(self.manager, 'lsn_port_delete') as g:
                self.assertRaises(p_exc.PortConfigurationError,
                                  self.manager.lsn_port_dhcp_setup,
                                  mock.Mock(), mock.ANY, mock.ANY, mock.ANY)
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
            'default_lease_time': cfg.CONF.NSX_DHCP.default_lease_time,
            'domain_name': cfg.CONF.NSX_DHCP.domain_name
        }
        self._test_lsn_port_dhcp_configure_with_subnet(
            expected, dns=[], gw='127.0.0.1', routes=[])

    def test_lsn_port_dhcp_configure_gatewayless(self):
        expected = {
            'default_lease_time': cfg.CONF.NSX_DHCP.default_lease_time,
            'domain_name': cfg.CONF.NSX_DHCP.domain_name
        }
        self._test_lsn_port_dhcp_configure_with_subnet(expected, gw=None)

    def test_lsn_port_dhcp_configure_with_extra_dns_servers(self):
        expected = {
            'default_lease_time': cfg.CONF.NSX_DHCP.default_lease_time,
            'domain_name_servers': '8.8.8.8,9.9.9.9',
            'domain_name': cfg.CONF.NSX_DHCP.domain_name
        }
        self._test_lsn_port_dhcp_configure_with_subnet(
            expected, dns=['8.8.8.8', '9.9.9.9'])

    def test_lsn_port_dhcp_configure_with_host_routes(self):
        expected = {
            'default_lease_time': cfg.CONF.NSX_DHCP.default_lease_time,
            'domain_name': cfg.CONF.NSX_DHCP.domain_name,
            'classless_static_routes': '8.8.8.8,9.9.9.9'
        }
        self._test_lsn_port_dhcp_configure_with_subnet(
            expected, routes=['8.8.8.8', '9.9.9.9'])

    def _test_lsn_metadata_configure(self, is_enabled):
        with mock.patch.object(self.manager, 'lsn_port_dispose') as f:
            self.manager.plugin.get_subnet.return_value = (
                {'network_id': self.net_id})
            self.manager.lsn_metadata_configure(mock.ANY,
                                                self.sub_id, is_enabled)
            expected = {
                'metadata_server_port': 8775,
                'metadata_server_ip': '127.0.0.1',
                'metadata_proxy_shared_secret': ''
            }
            self.mock_lsn_api.lsn_metadata_configure.assert_called_once_with(
                mock.ANY, mock.ANY, is_enabled, expected)
            if is_enabled:
                self.assertEqual(
                    1, self.mock_lsn_api.lsn_port_by_subnet_get.call_count)
            else:
                self.assertEqual(1, f.call_count)

    def test_lsn_metadata_configure_enabled(self):
        self._test_lsn_metadata_configure(True)

    def test_lsn_metadata_configure_disabled(self):
        self._test_lsn_metadata_configure(False)

    def test_lsn_metadata_configure_not_found(self):
        self.mock_lsn_api.lsn_metadata_configure.side_effect = (
            p_exc.LsnNotFound(entity='lsn', entity_id=self.lsn_id))
        self.manager.plugin.get_subnet.return_value = (
            {'network_id': self.net_id})
        self.assertRaises(p_exc.NsxPluginException,
                          self.manager.lsn_metadata_configure,
                          mock.ANY, self.sub_id, True)

    def test_lsn_port_metadata_setup(self):
        subnet = {
            'cidr': '0.0.0.0/0',
            'id': self.sub_id,
            'network_id': self.net_id,
            'tenant_id': self.tenant_id
        }
        expected_data = {
            'subnet_id': subnet['id'],
            'ip_address': subnet['cidr'],
            'mac_address': constants.METADATA_MAC
        }
        self.mock_nsx_utils.get_nsx_switch_ids.return_value = [self.switch_id]
        with mock.patch.object(lsn_man.switch_api, 'create_lport') as f:
            with mock.patch.object(self.manager, 'lsn_port_create') as g:
                f.return_value = {'uuid': self.port_id}
                self.manager.lsn_port_metadata_setup(
                    self.context, self.lsn_id, subnet)
                (self.mock_lsn_api.lsn_port_plug_network.
                 assert_called_once_with(mock.ANY, self.lsn_id,
                                         mock.ANY, self.port_id))
                g.assert_called_once_with(
                    self.context, self.lsn_id, expected_data)

    def test_lsn_port_metadata_setup_raise_not_found(self):
        subnet = {
            'cidr': '0.0.0.0/0',
            'id': self.sub_id,
            'network_id': self.net_id,
            'tenant_id': self.tenant_id
        }
        self.mock_nsx_utils.get_nsx_switch_ids.return_value = [self.switch_id]
        with mock.patch.object(lsn_man.switch_api, 'create_lport') as f:
            f.side_effect = n_exc.NotFound
            self.assertRaises(p_exc.PortConfigurationError,
                              self.manager.lsn_port_metadata_setup,
                              mock.Mock(), self.lsn_id, subnet)

    def test_lsn_port_metadata_setup_raise_conflict(self):
        subnet = {
            'cidr': '0.0.0.0/0',
            'id': self.sub_id,
            'network_id': self.net_id,
            'tenant_id': self.tenant_id
        }
        self.mock_nsx_utils.get_nsx_switch_ids.return_value = [self.switch_id]
        with mock.patch.object(lsn_man.switch_api, 'create_lport') as f:
            with mock.patch.object(lsn_man.switch_api, 'delete_port') as g:
                f.return_value = {'uuid': self.port_id}
                self.mock_lsn_api.lsn_port_plug_network.side_effect = (
                    p_exc.LsnConfigurationConflict(lsn_id=self.lsn_id))
                self.assertRaises(p_exc.PortConfigurationError,
                                  self.manager.lsn_port_metadata_setup,
                                  mock.Mock(), self.lsn_id, subnet)
                self.assertEqual(1,
                                 self.mock_lsn_api.lsn_port_delete.call_count)
                self.assertEqual(1, g.call_count)

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

    def test_lsn_port_dispose_meta_mac(self):
        self.mac = constants.METADATA_MAC
        with mock.patch.object(lsn_man.switch_api,
                               'get_port_by_neutron_tag') as f:
            with mock.patch.object(lsn_man.switch_api, 'delete_port') as g:
                f.return_value = {'uuid': self.port_id}
                self._test_lsn_port_dispose_with_values(
                    self.lsn_id, self.lsn_port_id, 1)
                f.assert_called_once_with(
                    mock.ANY, self.net_id, constants.METADATA_PORT_ID)
                g.assert_called_once_with(mock.ANY, self.net_id, self.port_id)

    def test_lsn_port_dispose_lsn_not_found(self):
        self._test_lsn_port_dispose_with_values(None, None, 0)

    def test_lsn_port_dispose_lsn_port_not_found(self):
        self._test_lsn_port_dispose_with_values(self.lsn_id, None, 0)

    def test_lsn_port_dispose_api_error(self):
        self.mock_lsn_api.lsn_port_delete.side_effect = NsxApiException
        with mock.patch.object(lsn_man.LOG, 'warn') as l:
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
            self.manager, 'lsn_port_get', return_value=(None, None)) as f:
            self.manager._lsn_port_host_conf(
                mock.ANY, self.net_id, self.sub_id, mock.ANY, mock.Mock())
            self.assertEqual(1, f.call_count)

    def _test_lsn_port_update(self, dhcp=None, meta=None):
        self.manager.lsn_port_update(
            mock.ANY, self.net_id, self.sub_id, dhcp, meta)
        count = 1 if dhcp else 0
        count = count + 1 if meta else count
        self.assertEqual(count, (self.mock_lsn_api.
                                 lsn_port_host_entries_update.call_count))

    def test_lsn_port_update(self):
        self._test_lsn_port_update()

    def test_lsn_port_update_dhcp_meta(self):
        self._test_lsn_port_update(mock.ANY, mock.ANY)

    def test_lsn_port_update_dhcp_and_nometa(self):
        self._test_lsn_port_update(mock.ANY, None)

    def test_lsn_port_update_nodhcp_and_nmeta(self):
        self._test_lsn_port_update(None, mock.ANY)

    def test_lsn_port_update_raise_error(self):
        self.mock_lsn_api.lsn_port_host_entries_update.side_effect = (
            NsxApiException)
        self.assertRaises(p_exc.PortConfigurationError,
                          self.manager.lsn_port_update,
                          mock.ANY, mock.ANY, mock.ANY, mock.ANY)


class PersistentLsnManagerTestCase(base.BaseTestCase):

    def setUp(self):
        super(PersistentLsnManagerTestCase, self).setUp()
        self.net_id = 'foo_network_id'
        self.sub_id = 'foo_subnet_id'
        self.port_id = 'foo_port_id'
        self.lsn_id = 'foo_lsn_id'
        self.mac = 'aa:bb:cc:dd:ee:ff'
        self.lsn_port_id = 'foo_lsn_port_id'
        self.tenant_id = 'foo_tenant_id'
        db.configure_db()
        nsx.register_dhcp_opts(cfg)
        nsx.register_metadata_opts(cfg)
        lsn_man.register_lsn_opts(cfg)
        self.manager = lsn_man.PersistentLsnManager(mock.Mock())
        self.context = context.get_admin_context()
        self.mock_lsn_api_p = mock.patch.object(lsn_man, 'lsn_api')
        self.mock_lsn_api = self.mock_lsn_api_p.start()
        self.addCleanup(self.mock_lsn_api_p.stop)
        self.addCleanup(db.clear_db)

    def test_lsn_get(self):
        lsn_db.lsn_add(self.context, self.net_id, self.lsn_id)
        result = self.manager.lsn_get(self.context, self.net_id)
        self.assertEqual(self.lsn_id, result)

    def test_lsn_get_raise_not_found(self):
        self.assertRaises(p_exc.LsnNotFound,
                          self.manager.lsn_get, self.context, self.net_id)

    def test_lsn_get_silent_not_found(self):
        result = self.manager.lsn_get(
            self.context, self.net_id, raise_on_err=False)
        self.assertIsNone(result)

    def test_lsn_get_sync_on_missing(self):
        cfg.CONF.set_override('sync_on_missing_data', True, 'NSX_LSN')
        self.manager = lsn_man.PersistentLsnManager(mock.Mock())
        with mock.patch.object(self.manager, 'lsn_save') as f:
            self.manager.lsn_get(self.context, self.net_id, raise_on_err=True)
            self.assertTrue(self.mock_lsn_api.lsn_for_network_get.call_count)
            self.assertTrue(f.call_count)

    def test_lsn_save(self):
        self.manager.lsn_save(self.context, self.net_id, self.lsn_id)
        result = self.manager.lsn_get(self.context, self.net_id)
        self.assertEqual(self.lsn_id, result)

    def test_lsn_create(self):
        self.mock_lsn_api.lsn_for_network_create.return_value = self.lsn_id
        with mock.patch.object(self.manager, 'lsn_save') as f:
            result = self.manager.lsn_create(self.context, self.net_id)
            self.assertTrue(
                self.mock_lsn_api.lsn_for_network_create.call_count)
            self.assertTrue(f.call_count)
            self.assertEqual(self.lsn_id, result)

    def test_lsn_create_failure(self):
        with mock.patch.object(
            self.manager, 'lsn_save',
            side_effect=p_exc.NsxPluginException(err_msg='')):
            self.assertRaises(p_exc.NsxPluginException,
                              self.manager.lsn_create,
                              self.context, self.net_id)
            self.assertTrue(self.mock_lsn_api.lsn_delete.call_count)

    def test_lsn_delete(self):
        self.mock_lsn_api.lsn_for_network_create.return_value = self.lsn_id
        self.manager.lsn_create(self.context, self.net_id)
        self.manager.lsn_delete(self.context, self.lsn_id)
        self.assertIsNone(self.manager.lsn_get(
            self.context, self.net_id, raise_on_err=False))

    def test_lsn_delete_not_existent(self):
        self.manager.lsn_delete(self.context, self.lsn_id)
        self.assertTrue(self.mock_lsn_api.lsn_delete.call_count)

    def test_lsn_port_get(self):
        lsn_db.lsn_add(self.context, self.net_id, self.lsn_id)
        lsn_db.lsn_port_add_for_lsn(self.context, self.lsn_port_id,
                                    self.sub_id, self.mac, self.lsn_id)
        res = self.manager.lsn_port_get(self.context, self.net_id, self.sub_id)
        self.assertEqual((self.lsn_id, self.lsn_port_id), res)

    def test_lsn_port_get_raise_not_found(self):
        self.assertRaises(p_exc.LsnPortNotFound,
                          self.manager.lsn_port_get,
                          self.context, self.net_id, self.sub_id)

    def test_lsn_port_get_silent_not_found(self):
        result = self.manager.lsn_port_get(
            self.context, self.net_id, self.sub_id, raise_on_err=False)
        self.assertEqual((None, None), result)

    def test_lsn_port_get_sync_on_missing(self):
        return
        cfg.CONF.set_override('sync_on_missing_data', True, 'NSX_LSN')
        self.manager = lsn_man.PersistentLsnManager(mock.Mock())
        self.mock_lsn_api.lsn_for_network_get.return_value = self.lsn_id
        self.mock_lsn_api.lsn_port_by_subnet_get.return_value = (
            self.lsn_id, self.lsn_port_id)
        with mock.patch.object(self.manager, 'lsn_save') as f:
            with mock.patch.object(self.manager, 'lsn_port_save') as g:
                self.manager.lsn_port_get(
                    self.context, self.net_id, self.sub_id)
                self.assertTrue(
                    self.mock_lsn_api.lsn_port_by_subnet_get.call_count)
                self.assertTrue(
                    self.mock_lsn_api.lsn_port_info_get.call_count)
                self.assertTrue(f.call_count)
                self.assertTrue(g.call_count)

    def test_lsn_port_get_by_mac(self):
        lsn_db.lsn_add(self.context, self.net_id, self.lsn_id)
        lsn_db.lsn_port_add_for_lsn(self.context, self.lsn_port_id,
                                    self.sub_id, self.mac, self.lsn_id)
        res = self.manager.lsn_port_get_by_mac(
            self.context, self.net_id, self.mac)
        self.assertEqual((self.lsn_id, self.lsn_port_id), res)

    def test_lsn_port_get_by_mac_raise_not_found(self):
        self.assertRaises(p_exc.LsnPortNotFound,
                          self.manager.lsn_port_get_by_mac,
                          self.context, self.net_id, self.sub_id)

    def test_lsn_port_get_by_mac_silent_not_found(self):
        result = self.manager.lsn_port_get_by_mac(
            self.context, self.net_id, self.sub_id, raise_on_err=False)
        self.assertEqual((None, None), result)

    def test_lsn_port_create(self):
        lsn_db.lsn_add(self.context, self.net_id, self.lsn_id)
        self.mock_lsn_api.lsn_port_create.return_value = self.lsn_port_id
        subnet = {'subnet_id': self.sub_id, 'mac_address': self.mac}
        with mock.patch.object(self.manager, 'lsn_port_save') as f:
            result = self.manager.lsn_port_create(
                self.context, self.net_id, subnet)
            self.assertTrue(
                self.mock_lsn_api.lsn_port_create.call_count)
            self.assertTrue(f.call_count)
            self.assertEqual(self.lsn_port_id, result)

    def test_lsn_port_create_failure(self):
        subnet = {'subnet_id': self.sub_id, 'mac_address': self.mac}
        with mock.patch.object(
            self.manager, 'lsn_port_save',
            side_effect=p_exc.NsxPluginException(err_msg='')):
            self.assertRaises(p_exc.NsxPluginException,
                              self.manager.lsn_port_create,
                              self.context, self.net_id, subnet)
            self.assertTrue(self.mock_lsn_api.lsn_port_delete.call_count)

    def test_lsn_port_delete(self):
        lsn_db.lsn_add(self.context, self.net_id, self.lsn_id)
        lsn_db.lsn_port_add_for_lsn(self.context, self.lsn_port_id,
                                    self.sub_id, self.mac, self.lsn_id)
        self.manager.lsn_port_delete(
            self.context, self.lsn_id, self.lsn_port_id)
        self.assertEqual((None, None), self.manager.lsn_port_get(
            self.context, self.lsn_id, self.sub_id, raise_on_err=False))

    def test_lsn_port_delete_not_existent(self):
        self.manager.lsn_port_delete(
            self.context, self.lsn_id, self.lsn_port_id)
        self.assertTrue(self.mock_lsn_api.lsn_port_delete.call_count)

    def test_lsn_port_save(self):
        self.manager.lsn_save(self.context, self.net_id, self.lsn_id)
        self.manager.lsn_port_save(self.context, self.lsn_port_id,
                                   self.sub_id, self.mac, self.lsn_id)
        result = self.manager.lsn_port_get(
            self.context, self.net_id, self.sub_id, raise_on_err=False)
        self.assertEqual((self.lsn_id, self.lsn_port_id), result)


class DhcpAgentNotifyAPITestCase(base.BaseTestCase):

    def setUp(self):
        super(DhcpAgentNotifyAPITestCase, self).setUp()
        self.notifier = nsx.DhcpAgentNotifyAPI(mock.Mock(), mock.Mock())
        self.plugin = self.notifier.plugin
        self.lsn_manager = self.notifier.lsn_manager

    def _test_notify_port_update(
        self, ports, expected_count, expected_args=None):
        port = {
            'id': 'foo_port_id',
            'network_id': 'foo_network_id',
            'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]
        }
        self.notifier.plugin.get_ports.return_value = ports
        self.notifier.notify(mock.ANY, {'port': port}, 'port.update.end')
        self.lsn_manager.lsn_port_update.assert_has_calls(expected_args)

    def test_notify_ports_update_no_ports(self):
        self._test_notify_port_update(None, 0, [])
        self._test_notify_port_update([], 0, [])

    def test_notify_ports_update_one_port(self):
        ports = [{
            'fixed_ips': [{'subnet_id': 'foo_subnet_id',
                           'ip_address': '1.2.3.4'}],
            'device_id': 'foo_device_id',
            'device_owner': 'foo_device_owner',
            'mac_address': 'fa:16:3e:da:1d:46'
        }]
        call_args = mock.call(
            mock.ANY, 'foo_network_id', 'foo_subnet_id',
            dhcp=[{'ip_address': '1.2.3.4',
                   'mac_address': 'fa:16:3e:da:1d:46'}],
            meta=[{'instance_id': 'foo_device_id',
                   'ip_address': '1.2.3.4'}])
        self._test_notify_port_update(ports, 1, call_args)

    def test_notify_ports_update_ports_with_empty_device_id(self):
        ports = [{
            'fixed_ips': [{'subnet_id': 'foo_subnet_id',
                           'ip_address': '1.2.3.4'}],
            'device_id': '',
            'device_owner': 'foo_device_owner',
            'mac_address': 'fa:16:3e:da:1d:46'
        }]
        call_args = mock.call(
            mock.ANY, 'foo_network_id', 'foo_subnet_id',
            dhcp=[{'ip_address': '1.2.3.4',
                   'mac_address': 'fa:16:3e:da:1d:46'}],
            meta=[]
        )
        self._test_notify_port_update(ports, 1, call_args)

    def test_notify_ports_update_ports_with_no_fixed_ips(self):
        ports = [{
            'fixed_ips': [],
            'device_id': 'foo_device_id',
            'device_owner': 'foo_device_owner',
            'mac_address': 'fa:16:3e:da:1d:46'
        }]
        call_args = mock.call(
            mock.ANY, 'foo_network_id', 'foo_subnet_id', dhcp=[], meta=[])
        self._test_notify_port_update(ports, 1, call_args)

    def test_notify_ports_update_ports_with_no_fixed_ips_and_no_device(self):
        ports = [{
            'fixed_ips': [],
            'device_id': '',
            'device_owner': 'foo_device_owner',
            'mac_address': 'fa:16:3e:da:1d:46'
        }]
        call_args = mock.call(
            mock.ANY, 'foo_network_id', 'foo_subnet_id', dhcp=[], meta=[])
        self._test_notify_port_update(ports, 0, call_args)

    def test_notify_ports_update_with_special_ports(self):
        ports = [{'fixed_ips': [],
                  'device_id': '',
                  'device_owner': n_consts.DEVICE_OWNER_DHCP,
                  'mac_address': 'fa:16:3e:da:1d:46'},
                 {'fixed_ips': [{'subnet_id': 'foo_subnet_id',
                                 'ip_address': '1.2.3.4'}],
                  'device_id': 'foo_device_id',
                  'device_owner': n_consts.DEVICE_OWNER_ROUTER_GW,
                  'mac_address': 'fa:16:3e:da:1d:46'}]
        call_args = mock.call(
            mock.ANY, 'foo_network_id', 'foo_subnet_id', dhcp=[], meta=[])
        self._test_notify_port_update(ports, 0, call_args)

    def test_notify_ports_update_many_ports(self):
        ports = [{'fixed_ips': [],
                  'device_id': '',
                  'device_owner': 'foo_device_owner',
                  'mac_address': 'fa:16:3e:da:1d:46'},
                 {'fixed_ips': [{'subnet_id': 'foo_subnet_id',
                                 'ip_address': '1.2.3.4'}],
                  'device_id': 'foo_device_id',
                  'device_owner': 'foo_device_owner',
                  'mac_address': 'fa:16:3e:da:1d:46'}]
        call_args = mock.call(
            mock.ANY, 'foo_network_id', 'foo_subnet_id',
            dhcp=[{'ip_address': '1.2.3.4',
                   'mac_address': 'fa:16:3e:da:1d:46'}],
            meta=[{'instance_id': 'foo_device_id',
                   'ip_address': '1.2.3.4'}])
        self._test_notify_port_update(ports, 1, call_args)

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
                    'device_owner': n_consts.DEVICE_OWNER_DHCP,
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
        with mock.patch.object(nsx.db_base_plugin_v2.NeutronDbPluginV2,
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
        with mock.patch.object(nsx, 'handle_port_dhcp_access') as h:
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
            'device_owner': [n_consts.DEVICE_OWNER_DHCP]
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
        nsx.handle_network_dhcp_access(
            self.plugin, mock.ANY, network, 'create_network')
        self.plugin.lsn_manager.lsn_create.assert_called_once_with(
            mock.ANY, network['id'])

    def test_handle_create_network_router_external(self):
        network = {'id': 'foo_network_id', 'router:external': True}
        nsx.handle_network_dhcp_access(
            self.plugin, mock.ANY, network, 'create_network')
        self.assertFalse(self.plugin.lsn_manager.lsn_create.call_count)

    def test_handle_delete_network(self):
        network_id = 'foo_network_id'
        self.plugin.lsn_manager.lsn_delete_by_network.return_value = (
            'foo_lsn_id')
        nsx.handle_network_dhcp_access(
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
            'device_owner': n_consts.DEVICE_OWNER_DHCP,
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
            nsx.handle_port_dhcp_access(
                self.plugin, mock.ANY, port, 'create_port')
            (self.plugin.lsn_manager.lsn_port_dhcp_setup.
             assert_called_once_with(mock.ANY, port['network_id'],
                                     port['id'], expected_data, subnet))
        else:
            self.plugin.lsn_manager.lsn_port_dhcp_setup.side_effect = exc
            self.assertRaises(n_exc.NeutronException,
                              nsx.handle_port_dhcp_access,
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
            'device_owner': n_consts.DEVICE_OWNER_DHCP,
            'network_id': 'foo_network_id',
            'fixed_ips': [],
            'mac_address': 'aa:bb:cc:dd:ee:ff'
        }
        nsx.handle_port_dhcp_access(self.plugin, mock.ANY, port, 'delete_port')
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
        nsx.handle_port_dhcp_access(self.plugin, mock.ANY, port, action)
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
        nsx.handle_port_dhcp_access(self.plugin, mock.ANY, port, action)
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
        nsx.handle_port_dhcp_access(self.plugin, mock.ANY, port, action)
        self.assertEqual(0, handler.call_count)

    def test_handle_create_user_port_no_fixed_ips(self):
        self._test_handle_user_port_no_fixed_ips(
            'create_port', self.plugin.lsn_manager.lsn_port_dhcp_host_add)

    def test_handle_delete_user_port_no_fixed_ips(self):
        self._test_handle_user_port_no_fixed_ips(
            'delete_port', self.plugin.lsn_manager.lsn_port_dhcp_host_remove)


class MetadataTestCase(base.BaseTestCase):

    def setUp(self):
        super(MetadataTestCase, self).setUp()
        self.plugin = mock.Mock()
        self.plugin.lsn_manager = mock.Mock()

    def _test_handle_port_metadata_access_special_owners(
        self, owner, dev_id='foo_device_id', ips=None):
        port = {
            'id': 'foo_port_id',
            'device_owner': owner,
            'device_id': dev_id,
            'fixed_ips': ips or []
        }
        nsx.handle_port_metadata_access(self.plugin, mock.ANY, port, mock.ANY)
        self.assertFalse(
            self.plugin.lsn_manager.lsn_port_meta_host_add.call_count)
        self.assertFalse(
            self.plugin.lsn_manager.lsn_port_meta_host_remove.call_count)

    def test_handle_port_metadata_access_external_network(self):
        port = {
            'id': 'foo_port_id',
            'device_owner': 'foo_device_owner',
            'device_id': 'foo_device_id',
            'network_id': 'foo_network_id',
            'fixed_ips': [{'subnet_id': 'foo_subnet'}]
        }
        self.plugin.get_network.return_value = {'router:external': True}
        nsx.handle_port_metadata_access(self.plugin, mock.ANY, port, mock.ANY)
        self.assertFalse(
            self.plugin.lsn_manager.lsn_port_meta_host_add.call_count)
        self.assertFalse(
            self.plugin.lsn_manager.lsn_port_meta_host_remove.call_count)

    def test_handle_port_metadata_access_dhcp_port(self):
        self._test_handle_port_metadata_access_special_owners(
            n_consts.DEVICE_OWNER_DHCP, [{'subnet_id': 'foo_subnet'}])

    def test_handle_port_metadata_access_router_port(self):
        self._test_handle_port_metadata_access_special_owners(
            n_consts.DEVICE_OWNER_ROUTER_INTF, [{'subnet_id': 'foo_subnet'}])

    def test_handle_port_metadata_access_no_device_id(self):
        self._test_handle_port_metadata_access_special_owners(
            n_consts.DEVICE_OWNER_DHCP, '')

    def test_handle_port_metadata_access_no_fixed_ips(self):
        self._test_handle_port_metadata_access_special_owners(
            'foo', 'foo', None)

    def _test_handle_port_metadata_access(self, is_delete, raise_exc=False):
        port = {
            'id': 'foo_port_id',
            'device_owner': 'foo_device_id',
            'network_id': 'foo_network_id',
            'device_id': 'foo_device_id',
            'tenant_id': 'foo_tenant_id',
            'fixed_ips': [
                {'subnet_id': 'foo_subnet_id', 'ip_address': '1.2.3.4'}
            ]
        }
        meta = {
            'instance_id': port['device_id'],
            'tenant_id': port['tenant_id'],
            'ip_address': port['fixed_ips'][0]['ip_address']
        }
        self.plugin.get_network.return_value = {'router:external': False}
        if is_delete:
            mock_func = self.plugin.lsn_manager.lsn_port_meta_host_remove
        else:
            mock_func = self.plugin.lsn_manager.lsn_port_meta_host_add
        if raise_exc:
            mock_func.side_effect = p_exc.PortConfigurationError(
                lsn_id='foo_lsn_id', net_id='foo_net_id', port_id=None)
            with mock.patch.object(nsx.db_base_plugin_v2.NeutronDbPluginV2,
                                   'delete_port') as d:
                self.assertRaises(p_exc.PortConfigurationError,
                                  nsx.handle_port_metadata_access,
                                  self.plugin, mock.ANY, port,
                                  is_delete=is_delete)
                if not is_delete:
                    d.assert_called_once_with(mock.ANY, mock.ANY, port['id'])
                else:
                    self.assertFalse(d.call_count)
        else:
            nsx.handle_port_metadata_access(
                self.plugin, mock.ANY, port, is_delete=is_delete)
        mock_func.assert_called_once_with(mock.ANY, mock.ANY, mock.ANY, meta)

    def test_handle_port_metadata_access_on_delete_true(self):
        self._test_handle_port_metadata_access(True)

    def test_handle_port_metadata_access_on_delete_false(self):
        self._test_handle_port_metadata_access(False)

    def test_handle_port_metadata_access_on_delete_true_raise(self):
        self._test_handle_port_metadata_access(True, raise_exc=True)

    def test_handle_port_metadata_access_on_delete_false_raise(self):
        self._test_handle_port_metadata_access(False, raise_exc=True)

    def _test_handle_router_metadata_access(
        self, is_port_found, raise_exc=False):
        subnet = {
            'id': 'foo_subnet_id',
            'network_id': 'foo_network_id'
        }
        interface = {
            'subnet_id': subnet['id'],
            'port_id': 'foo_port_id'
        }
        mock_func = self.plugin.lsn_manager.lsn_metadata_configure
        if not is_port_found:
            self.plugin.get_port.side_effect = n_exc.NotFound
        if raise_exc:
            with mock.patch.object(nsx.l3_db.L3_NAT_db_mixin,
                                   'remove_router_interface') as d:
                mock_func.side_effect = p_exc.NsxPluginException(err_msg='')
                self.assertRaises(p_exc.NsxPluginException,
                                  nsx.handle_router_metadata_access,
                                  self.plugin, mock.ANY, 'foo_router_id',
                                  interface)
                d.assert_called_once_with(mock.ANY, mock.ANY, 'foo_router_id',
                                          interface)
        else:
            nsx.handle_router_metadata_access(
                self.plugin, mock.ANY, 'foo_router_id', interface)
            mock_func.assert_called_once_with(
                mock.ANY, subnet['id'], is_port_found)

    def test_handle_router_metadata_access_add_interface(self):
        self._test_handle_router_metadata_access(True)

    def test_handle_router_metadata_access_delete_interface(self):
        self._test_handle_router_metadata_access(False)

    def test_handle_router_metadata_access_raise_error_on_add(self):
        self._test_handle_router_metadata_access(True, raise_exc=True)

    def test_handle_router_metadata_access_raise_error_on_delete(self):
        self._test_handle_router_metadata_access(True, raise_exc=False)
