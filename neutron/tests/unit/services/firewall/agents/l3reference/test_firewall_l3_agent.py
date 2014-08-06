# Copyright (c) 2013 OpenStack Foundation
# All Rights Reserved.
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
import uuid

import mock
from oslo.config import cfg

from neutron.agent.common import config as agent_config
from neutron.agent import l3_agent
from neutron.agent import l3_ha_agent
from neutron.agent.linux import ip_lib
from neutron.common import config as base_config
from neutron import context
from neutron.plugins.common import constants
from neutron.services.firewall.agents import firewall_agent_api
from neutron.services.firewall.agents.l3reference import firewall_l3_agent
from neutron.tests import base
from neutron.tests.unit.services.firewall.agents import test_firewall_agent_api


class FWaasHelper(object):
    def __init__(self, host):
        pass


class FWaasAgent(firewall_l3_agent.FWaaSL3AgentRpcCallback, FWaasHelper):
    neutron_service_plugins = []


def _setup_test_agent_class(service_plugins):
    class FWaasTestAgent(firewall_l3_agent.FWaaSL3AgentRpcCallback,
                         FWaasHelper):
        neutron_service_plugins = service_plugins

    return FWaasTestAgent


class TestFwaasL3AgentRpcCallback(base.BaseTestCase):
    def setUp(self):
        super(TestFwaasL3AgentRpcCallback, self).setUp()

        self.conf = cfg.ConfigOpts()
        self.conf.register_opts(base_config.core_opts)
        self.conf.register_opts(l3_agent.L3NATAgent.OPTS)
        self.conf.register_opts(l3_ha_agent.OPTS)
        agent_config.register_use_namespaces_opts_helper(self.conf)
        agent_config.register_root_helper(self.conf)
        self.conf.root_helper = 'sudo'
        self.conf.register_opts(firewall_agent_api.FWaaSOpts, 'fwaas')
        self.api = FWaasAgent(self.conf)
        self.api.fwaas_driver = test_firewall_agent_api.NoopFwaasDriver()

    def test_fw_config_match(self):
        test_agent_class = _setup_test_agent_class([constants.FIREWALL])
        cfg.CONF.set_override('enabled', True, 'fwaas')
        with mock.patch('neutron.openstack.common.importutils.import_object'):
            test_agent_class(cfg.CONF)

    def test_fw_config_mismatch_plugin_enabled_agent_disabled(self):
        test_agent_class = _setup_test_agent_class([constants.FIREWALL])
        cfg.CONF.set_override('enabled', False, 'fwaas')
        self.assertRaises(SystemExit, test_agent_class, cfg.CONF)

    def test_fw_plugin_list_unavailable(self):
        test_agent_class = _setup_test_agent_class(None)
        cfg.CONF.set_override('enabled', False, 'fwaas')
        with mock.patch('neutron.openstack.common.importutils.import_object'):
            test_agent_class(cfg.CONF)

    def test_create_firewall(self):
        fake_firewall = {'id': 0}
        with mock.patch.object(
            self.api,
            '_invoke_driver_for_plugin_api'
        ) as mock_driver:
            self.assertEqual(
                self.api.create_firewall(
                    mock.sentinel.context,
                    fake_firewall,
                    'host'),
                mock_driver.return_value)

    def test_update_firewall(self):
        fake_firewall = {'id': 0}
        with mock.patch.object(
            self.api,
            '_invoke_driver_for_plugin_api'
        ) as mock_driver:
            self.assertEqual(
                self.api.update_firewall(
                    mock.sentinel.context,
                    fake_firewall,
                    'host'),
                mock_driver.return_value)

    def test_delete_firewall(self):
        fake_firewall = {'id': 0}
        with mock.patch.object(
            self.api,
            '_invoke_driver_for_plugin_api'
        ) as mock_driver:
            self.assertEqual(
                self.api.delete_firewall(
                    mock.sentinel.context,
                    fake_firewall,
                    'host'),
                mock_driver.return_value)

    def test_invoke_driver_for_plugin_api(self):
        fake_firewall = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': True}
        self.api.plugin_rpc = mock.Mock()
        with contextlib.nested(
            mock.patch.object(self.api.plugin_rpc, 'get_routers'),
            mock.patch.object(self.api, '_get_router_info_list_for_tenant'),
            mock.patch.object(self.api.fwaas_driver, 'create_firewall'),
            mock.patch.object(self.api.fwplugin_rpc, 'set_firewall_status')
        ) as (
            mock_get_routers,
            mock_get_router_info_list_for_tenant,
            mock_driver_create_firewall,
            mock_set_firewall_status):

            mock_driver_create_firewall.return_value = True
            self.api.create_firewall(
                context=mock.sentinel.context,
                firewall=fake_firewall, host='host')

            mock_get_routers.assert_called_once_with(
                mock.sentinel.context)

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                mock_get_routers.return_value, fake_firewall['tenant_id'])

            mock_set_firewall_status.assert_called_once_with(
                mock.sentinel.context,
                fake_firewall['id'],
                'ACTIVE')

    def test_invoke_driver_for_plugin_api_admin_state_down(self):
        fake_firewall = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': False}
        self.api.plugin_rpc = mock.Mock()
        with contextlib.nested(
            mock.patch.object(self.api.plugin_rpc, 'get_routers'),
            mock.patch.object(self.api, '_get_router_info_list_for_tenant'),
            mock.patch.object(self.api.fwaas_driver, 'update_firewall'),
            mock.patch.object(self.api.fwplugin_rpc,
                              'get_firewalls_for_tenant'),
            mock.patch.object(self.api.fwplugin_rpc, 'set_firewall_status')
        ) as (
            mock_get_routers,
            mock_get_router_info_list_for_tenant,
            mock_driver_update_firewall,
            mock_get_firewalls_for_tenant,
            mock_set_firewall_status):

            mock_driver_update_firewall.return_value = True
            self.api.update_firewall(
                context=mock.sentinel.context,
                firewall=fake_firewall, host='host')

            mock_get_routers.assert_called_once_with(
                mock.sentinel.context)

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                mock_get_routers.return_value, fake_firewall['tenant_id'])

            mock_set_firewall_status.assert_called_once_with(
                mock.sentinel.context,
                fake_firewall['id'],
                'DOWN')

    def test_invoke_driver_for_plugin_api_delete(self):
        fake_firewall = {'id': 0, 'tenant_id': 1,
                         'admin_state_up': True}
        self.api.plugin_rpc = mock.Mock()
        with contextlib.nested(
            mock.patch.object(self.api.plugin_rpc, 'get_routers'),
            mock.patch.object(self.api, '_get_router_info_list_for_tenant'),
            mock.patch.object(self.api.fwaas_driver, 'delete_firewall'),
            mock.patch.object(self.api.fwplugin_rpc, 'firewall_deleted')
        ) as (
            mock_get_routers,
            mock_get_router_info_list_for_tenant,
            mock_driver_delete_firewall,
            mock_firewall_deleted):

            mock_driver_delete_firewall.return_value = True
            self.api.delete_firewall(
                context=mock.sentinel.context,
                firewall=fake_firewall, host='host')

            mock_get_routers.assert_called_once_with(
                mock.sentinel.context)

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                mock_get_routers.return_value, fake_firewall['tenant_id'])

            mock_firewall_deleted.assert_called_once_with(
                mock.sentinel.context,
                fake_firewall['id'])

    def test_delete_firewall_no_router(self):
        fake_firewall = {'id': 0, 'tenant_id': 1}
        self.api.plugin_rpc = mock.Mock()
        with contextlib.nested(
            mock.patch.object(self.api.plugin_rpc, 'get_routers'),
            mock.patch.object(self.api, '_get_router_info_list_for_tenant'),
            mock.patch.object(self.api.fwplugin_rpc, 'firewall_deleted')
        ) as (
            mock_get_routers,
            mock_get_router_info_list_for_tenant,
            mock_firewall_deleted):

            mock_get_router_info_list_for_tenant.return_value = []
            self.api.delete_firewall(
                context=mock.sentinel.context,
                firewall=fake_firewall, host='host')

            mock_get_routers.assert_called_once_with(
                mock.sentinel.context)

            mock_get_router_info_list_for_tenant.assert_called_once_with(
                mock_get_routers.return_value, fake_firewall['tenant_id'])

            mock_firewall_deleted.assert_called_once_with(
                mock.sentinel.context,
                fake_firewall['id'])

    def test_process_router_add_fw_update(self):
        fake_firewall_list = [{'id': 0, 'tenant_id': 1,
                               'status': constants.PENDING_UPDATE,
                               'admin_state_up': True}]
        fake_router = {'id': 1111, 'tenant_id': 2}
        self.api.plugin_rpc = mock.Mock()
        agent_mode = 'legacy'
        ri = mock.Mock()
        ri.router = fake_router
        routers = [ri.router]
        with contextlib.nested(
            mock.patch.object(self.api.plugin_rpc, 'get_routers'),
            mock.patch.object(self.api, '_get_router_info_list_for_tenant'),
            mock.patch.object(self.api.fwaas_driver, 'update_firewall'),
            mock.patch.object(self.api.fwplugin_rpc, 'set_firewall_status'),
            mock.patch.object(self.api.fwplugin_rpc,
                              'get_firewalls_for_tenant'),
            mock.patch.object(context, 'Context')
        ) as (
            mock_get_routers,
            mock_get_router_info_list_for_tenant,
            mock_driver_update_firewall,
            mock_set_firewall_status,
            mock_get_firewalls_for_tenant,
            mock_Context):

            mock_driver_update_firewall.return_value = True
            ctx = mock.sentinel.context
            mock_Context.return_value = ctx
            mock_get_router_info_list_for_tenant.return_value = routers
            mock_get_firewalls_for_tenant.return_value = fake_firewall_list

            self.api._process_router_add(ri)
            mock_get_router_info_list_for_tenant.assert_called_with(
                routers,
                ri.router['tenant_id'])
            mock_get_firewalls_for_tenant.assert_called_once_with(ctx)
            mock_driver_update_firewall.assert_called_once_with(
                agent_mode,
                routers,
                fake_firewall_list[0])

            mock_set_firewall_status.assert_called_once_with(
                ctx,
                fake_firewall_list[0]['id'],
                constants.ACTIVE)

    def test_process_router_add_fw_delete(self):
        fake_firewall_list = [{'id': 0, 'tenant_id': 1,
                               'status': constants.PENDING_DELETE}]
        fake_router = {'id': 1111, 'tenant_id': 2}
        agent_mode = 'legacy'
        self.api.plugin_rpc = mock.Mock()
        ri = mock.Mock()
        ri.router = fake_router
        routers = [ri.router]
        with contextlib.nested(
            mock.patch.object(self.api.plugin_rpc, 'get_routers'),
            mock.patch.object(self.api, '_get_router_info_list_for_tenant'),
            mock.patch.object(self.api.fwaas_driver, 'delete_firewall'),
            mock.patch.object(self.api.fwplugin_rpc, 'firewall_deleted'),
            mock.patch.object(self.api.fwplugin_rpc,
                              'get_firewalls_for_tenant'),
            mock.patch.object(context, 'Context')
        ) as (
            mock_get_routers,
            mock_get_router_info_list_for_tenant,
            mock_driver_delete_firewall,
            mock_firewall_deleted,
            mock_get_firewalls_for_tenant,
            mock_Context):

            mock_driver_delete_firewall.return_value = True
            ctx = mock.sentinel.context
            mock_Context.return_value = ctx
            mock_get_router_info_list_for_tenant.return_value = routers
            mock_get_firewalls_for_tenant.return_value = fake_firewall_list

            self.api._process_router_add(ri)
            mock_get_router_info_list_for_tenant.assert_called_with(
                routers,
                ri.router['tenant_id'])
            mock_get_firewalls_for_tenant.assert_called_once_with(ctx)
            mock_driver_delete_firewall.assert_called_once_with(
                agent_mode,
                routers,
                fake_firewall_list[0])

            mock_firewall_deleted.assert_called_once_with(
                ctx,
                fake_firewall_list[0]['id'])

    def _prepare_router_data(self, use_namespaces):
        router = {'id': str(uuid.uuid4()), 'tenant_id': str(uuid.uuid4())}
        return l3_agent.RouterInfo(router['id'], self.conf.root_helper,
                                   use_namespaces, router=router)

    def _get_router_info_list_with_namespace_helper(self,
                                                    router_use_namespaces):
        self.conf.set_override('use_namespaces', True)
        ri = self._prepare_router_data(
            use_namespaces=router_use_namespaces)
        routers = [ri.router]
        self.api.router_info = {ri.router_id: ri}
        with mock.patch.object(ip_lib.IPWrapper,
                               'get_namespaces') as mock_get_namespaces:
            mock_get_namespaces.return_value = ri.ns_name
            router_info_list = self.api._get_router_info_list_for_tenant(
                routers,
                ri.router['tenant_id'])
            self.assertEqual([ri], router_info_list)
            mock_get_namespaces.assert_called_once_with(
                self.conf.root_helper)

    def _get_router_info_list_without_namespace_helper(self,
                                                       router_use_namespaces):
        self.conf.set_override('use_namespaces', False)
        ri = self._prepare_router_data(
            use_namespaces=router_use_namespaces)
        routers = [ri.router]
        self.api.router_info = {ri.router_id: ri}
        router_info_list = self.api._get_router_info_list_for_tenant(
            routers,
            ri.router['tenant_id'])
        if router_use_namespaces:
            self.assertFalse(router_info_list)
        else:
            self.assertEqual([ri], router_info_list)

    def test_get_router_info_list_for_tenant_for_namespaces_enabled(self):
        self._get_router_info_list_with_namespace_helper(
            router_use_namespaces=True)

    def test_get_router_info_list_for_tenant_for_namespaces_disabled(self):
        self._get_router_info_list_without_namespace_helper(
            router_use_namespaces=False)

    def test_get_router_info_list_tenant_with_namespace_router_without(self):
        self._get_router_info_list_with_namespace_helper(
            router_use_namespaces=False)

    def test_get_router_info_list_tenant_without_namespace_router_with(self):
        self._get_router_info_list_without_namespace_helper(
            router_use_namespaces=True)

    def _get_router_info_list_router_without_router_info_helper(self,
                                                                rtr_with_ri):
        self.conf.set_override('use_namespaces', True)
        # ri.router with associated router_info (ri)
        # rtr2 has no router_info
        ri = self._prepare_router_data(use_namespaces=True)
        rtr2 = {'id': str(uuid.uuid4()), 'tenant_id': ri.router['tenant_id']}
        routers = [rtr2]
        self.api.router_info = {}
        ri_expected = []
        if rtr_with_ri:
            self.api.router_info[ri.router_id] = ri
            routers.append(ri.router)
            ri_expected.append(ri)
        with mock.patch.object(ip_lib.IPWrapper,
                               'get_namespaces') as mock_get_namespaces:
            mock_get_namespaces.return_value = ri.ns_name
            router_info_list = self.api._get_router_info_list_for_tenant(
                routers,
                ri.router['tenant_id'])
            self.assertEqual(ri_expected, router_info_list)

    def test_get_router_info_list_router_without_router_info(self):
        self._get_router_info_list_router_without_router_info_helper(
            rtr_with_ri=False)

    def test_get_router_info_list_two_routers_one_without_router_info(self):
        self._get_router_info_list_router_without_router_info_helper(
            rtr_with_ri=True)
