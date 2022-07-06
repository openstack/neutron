# Copyright 2021 Troila
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

from unittest import mock

from neutron_lib import constants as lib_const
from neutron_lib import context
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import dvr_edge_router
from neutron.agent.l3 import dvr_local_router as dvr_router
from neutron.agent.l3.extensions import ndp_proxy as np
from neutron.agent.l3 import l3_agent_extension_api as l3_ext_api
from neutron.agent.l3 import router_info
from neutron.agent.linux import iptables_manager
from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.objects import agent as agent_obj
from neutron.objects import ndp_proxy as np_obj
from neutron.objects import ports as ports_obj
from neutron.tests import base
from neutron.tests.unit.agent.l3 import test_agent
from neutron.tests.unit.agent.l3 import test_dvr_local_router

_uuid = uuidutils.generate_uuid

HOSTNAME = 'testhost'


class NDPProxyExtensionTestCaseBase(base.BaseTestCase):

    def setUp(self):
        super(NDPProxyExtensionTestCaseBase, self).setUp()
        self.context = context.get_admin_context()
        self.connection = mock.Mock()
        self.ext_port_id = _uuid()
        self.ex_net_id = _uuid()
        self.ex_gw_port = {'id': self.ext_port_id,
                           'network_id': self.ex_net_id,
                           'gw_port_host': HOSTNAME}
        self.fake_router_id = _uuid()
        self.port_id = _uuid()
        self.agent_api = l3_ext_api.L3AgentExtensionAPI(None, None)
        self.np_ext = np.NDPProxyAgentExtension()
        self.np_ext.consume_api(self.agent_api)
        self.np_ext.initialize(
            self.connection, lib_const.L3_AGENT_MODE)
        self.ndpproxy = np_obj.NDPProxy(
            context=None, id=_uuid(),
            router_id=self.fake_router_id,
            port_id=self.port_id, ip_address='2002::1:3')
        port_binding = ports_obj.PortBinding(port_id=self.port_id,
                                             host=HOSTNAME)
        port_obj = ports_obj.Port(id=self.port_id, bindings=[port_binding])
        self.ndp_proxies = [self.ndpproxy]
        self.ports = [port_obj]
        agent_configurations = {
            'agent_mode': lib_const.L3_AGENT_MODE_DVR_NO_EXTERNAL}
        self.agent_obj = agent_obj.Agent(
            id=_uuid(), host=HOSTNAME,
            agent_type=lib_const.AGENT_TYPE_L3,
            configurations=agent_configurations)
        self.ip_wrapper = mock.patch('neutron.agent.linux.'
                                     'ip_lib.IPWrapper').start()
        self._set_pull_mock()

    def _set_pull_mock(self):

        def _bulk_pull_mock(context, resource_type, filter_kwargs=None):
            if resource_type == resources.PORT:
                return [port for port in self.ports if
                        port.id == filter_kwargs['id']]
            if resource_type == resources.AGENT:
                return [self.agent_obj]
            if resource_type == resources.NDPPROXY:
                result = []
                if 'router_id' in filter_kwargs:
                    for ndp_proxy in self.ndp_proxies:
                        if ndp_proxy.router_id in filter_kwargs['router_id']:
                            result.append(ndp_proxy)
                    return result
                return self.ndp_proxie

        self.pull = mock.patch('neutron.api.rpc.handlers.resources_rpc.'
                               'ResourcesPullRpcApi.pull').start()
        self.bulk_pull = mock.patch('neutron.api.rpc.handlers.resources_rpc.'
                                    'ResourcesPullRpcApi.bulk_pull').start()
        self.bulk_pull.side_effect = _bulk_pull_mock


class NDPProxyExtensionDVRTestCase(
        NDPProxyExtensionTestCaseBase,
        test_dvr_local_router.TestDvrRouterOperations):

    def setUp(self):
        super(NDPProxyExtensionDVRTestCase, self).setUp()
        self.conf.host = HOSTNAME
        self.conf.agent_mode = lib_const.L3_AGENT_MODE_DVR
        self.agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.add_route = mock.MagicMock()
        self.delete_route = mock.MagicMock()
        mock_route_cmd = mock.MagicMock()
        mock_route_cmd.add_route = self.add_route
        mock_route_cmd.delete_route = self.delete_route
        self.mock_ip_dev.route = mock_route_cmd
        self.lladdr = "fe80::f816:3eff:fe5f:9d67"
        get_ipv6_lladdr = mock.patch("neutron.agent.linux.ip_lib."
                                     "get_ipv6_lladdr").start()
        get_ipv6_lladdr.return_value = "%s/64" % self.lladdr
        self.router = {'id': self.fake_router_id,
                       'gw_port': self.ex_gw_port,
                       'ha': False,
                       'distributed': True,
                       'enable_ndp_proxy': True}
        kwargs = {
            'agent': self.agent,
            'router_id': self.fake_router_id,
            'router': self.router,
            'agent_conf': self.conf,
            'interface_driver': mock.Mock()}
        self.router_info = dvr_router.DvrLocalRouter(HOSTNAME, **kwargs)
        self.get_router_info = mock.patch(
            'neutron.agent.l3.l3_agent_extension_api.'
            'L3AgentExtensionAPI.get_router_info').start()
        self.get_router_info.return_value = self.router_info
        self.router_info.fip_ns = self.agent.get_fip_ns(self.ex_net_id)
        agent_ext_port_id = _uuid()
        self.router_info.fip_ns.agent_gateway_port = {'id': agent_ext_port_id}
        self.namespace = "fip-%s" % self.ex_net_id
        self.agent_ext_dvice = "fg-%s" % agent_ext_port_id[:11]
        self.ip_wrapper.reset_mock()

    def test_create_router(self):
        self.np_ext.add_router(self.context, self.router)
        expected_calls = [
            mock.call('2002::1:3', via=self.lladdr)]
        self.assertEqual(expected_calls, self.add_route.mock_calls)
        sysctl_cmd = ['sysctl', '-w',
                      'net.ipv6.conf.%s.proxy_ndp=1' % self.agent_ext_dvice]
        proxy_cmd = ['ip', '-6', 'neigh', 'add',
                     'proxy', '2002::1:3', 'dev', self.agent_ext_dvice]
        ndsend_cmd = ['ndsend', '2002::1:3', self.agent_ext_dvice]
        expected_calls = [
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(sysctl_cmd, privsep_exec=True),
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(proxy_cmd, privsep_exec=True),
            mock.call().netns.execute(
                ndsend_cmd, check_exit_code=False,
                log_fail_as_error=True, privsep_exec=True),
            mock.call(namespace=self.namespace)]
        self.assertEqual(expected_calls, self.ip_wrapper.mock_calls)

    def test_update_router(self):
        self.np_ext.add_router(self.context, self.router)
        self.add_route.reset_mock()
        self.ip_wrapper.reset_mock()
        self.np_ext.update_router(self.context, self.router)
        self.add_route.assert_not_called()
        sysctl_cmd = ['sysctl', '-w',
                      'net.ipv6.conf.%s.proxy_ndp=1' % self.agent_ext_dvice]
        expected_calls = [
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(sysctl_cmd, privsep_exec=True),
            mock.call(namespace=self.namespace)]
        self.assertEqual(expected_calls, self.ip_wrapper.mock_calls)

    def test_add_ndp_proxy_update_router(self):
        self.np_ext.add_router(self.context, self.router)
        self.add_route.reset_mock()
        self.ip_wrapper.reset_mock()
        ndpproxy = np_obj.NDPProxy(
            context=None, id=_uuid(),
            router_id=self.fake_router_id,
            port_id=self.port_id, ip_address='2002::1:6')
        self.ndp_proxies.append(ndpproxy)
        self.np_ext.update_router(self.context, self.router)
        expected_calls = [
            mock.call('2002::1:6', via=self.lladdr)]
        self.assertEqual(expected_calls, self.add_route.mock_calls)
        sysctl_cmd = ['sysctl', '-w',
                      'net.ipv6.conf.%s.proxy_ndp=1' % self.agent_ext_dvice]
        proxy_cmd = ['ip', '-6', 'neigh', 'add',
                     'proxy', '2002::1:6', 'dev', self.agent_ext_dvice]
        ndsend_cmd = ['ndsend', '2002::1:6', self.agent_ext_dvice]
        expected_calls = [
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(sysctl_cmd, privsep_exec=True),
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(proxy_cmd, privsep_exec=True),
            mock.call().netns.execute(
                ndsend_cmd, check_exit_code=False,
                log_fail_as_error=True, privsep_exec=True),
            mock.call(namespace=self.namespace)]
        self.assertEqual(expected_calls, self.ip_wrapper.mock_calls)

    def test_del_ndp_proxy_update_router(self):
        self.np_ext.add_router(self.context, self.router)
        self.add_route.reset_mock()
        self.ip_wrapper.reset_mock()
        self.ndp_proxies = []
        self.np_ext.update_router(self.context, self.router)
        self.add_route.assert_not_called()
        expected_calls = [
            mock.call('2002::1:3', via=self.lladdr)]
        self.assertEqual(expected_calls, self.delete_route.mock_calls)
        sysctl_cmd = ['sysctl', '-w',
                      'net.ipv6.conf.%s.proxy_ndp=1' % self.agent_ext_dvice]
        proxy_cmd = ['ip', '-6', 'neigh', 'del',
                     'proxy', '2002::1:3', 'dev', self.agent_ext_dvice]
        expected_calls = [
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(sysctl_cmd, privsep_exec=True),
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(proxy_cmd, privsep_exec=True)]
        self.assertEqual(expected_calls, self.ip_wrapper.mock_calls)

    def test__handle_notification(self):
        self.np_ext.add_router(self.context, self.router)
        self.add_route.reset_mock()
        self.ip_wrapper.reset_mock()
        ndpproxy = np_obj.NDPProxy(
            context=None, id=_uuid(),
            router_id=self.fake_router_id,
            port_id=self.port_id, ip_address='2002::1:5')
        self.np_ext._handle_notification(mock.MagicMock(), mock.MagicMock(),
                                         [ndpproxy], events.CREATED)
        expected_calls = [
            mock.call('2002::1:5', via=self.lladdr)]
        self.assertEqual(expected_calls, self.add_route.mock_calls)
        proxy_cmd = ['ip', '-6', 'neigh', 'add',
                     'proxy', '2002::1:5', 'dev', self.agent_ext_dvice]
        ndsend_cmd = ['ndsend', '2002::1:5', self.agent_ext_dvice]
        expected_calls = [
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(proxy_cmd, privsep_exec=True),
            mock.call().netns.execute(
                ndsend_cmd, check_exit_code=False,
                log_fail_as_error=True, privsep_exec=True)]
        self.assertEqual(expected_calls, self.ip_wrapper.mock_calls)
        self.add_route.reset_mock()
        self.ip_wrapper.reset_mock()
        self.np_ext._handle_notification(mock.MagicMock(), mock.MagicMock(),
                                         [ndpproxy], events.DELETED)
        self.add_route.assert_not_called()
        expected_calls = [
            mock.call('2002::1:5', via=self.lladdr)]
        self.assertEqual(expected_calls, self.delete_route.mock_calls)
        proxy_cmd = ['ip', '-6', 'neigh', 'del',
                     'proxy', '2002::1:5', 'dev', self.agent_ext_dvice]
        expected_calls = [
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(proxy_cmd, privsep_exec=True)]
        self.assertEqual(expected_calls, self.ip_wrapper.mock_calls)


class NDPProxyExtensionLegacyDVRNoExternalTestCaseBase(
        NDPProxyExtensionTestCaseBase,
        test_agent.BasicRouterOperationsFramework):

    def _mock_iptables_actions(self):
        self.get_router_info = mock.patch(
            'neutron.agent.l3.l3_agent_extension_api.'
            'L3AgentExtensionAPI.get_router_info').start()
        self.add_chain = mock.patch('neutron.agent.linux.iptables_manager.'
                                    'IptablesTable.add_chain').start()
        self.remove_chain = mock.patch('neutron.agent.linux.iptables_manager.'
                                       'IptablesTable.remove_chain').start()
        self.add_rule = mock.patch('neutron.agent.linux.iptables_manager.'
                                   'IptablesTable.add_rule').start()
        self.remove_rule = mock.patch('neutron.agent.linux.iptables_manager.'
                                      'IptablesTable.remove_rule').start()

        def _add_chain_mock(chain):
            self.iptables_manager.ipv6[
                'filter'].chains.append(chain)

        def _remove_chain_mock(chain):
            self.iptables_manager.ipv6[
                'filter'].chains.remove(chain)

        def _add_rule_mock(chain, rule, top=False):
            rule_obj = mock.MagicMock()
            rule_obj.rule = rule
            self.iptables_manager.ipv6[
                'filter'].rules.append(rule_obj)

        def _remove_rule_mock(chain, rule, top=False):
            for rule_obj in self.iptables_manager.ipv6[
                    'filter'].rules:
                if rule == rule_obj.rule:
                    self.iptables_manager.ipv6[
                        'filter'].rules.remove(rule_obj)
                    break

        self.get_router_info.return_value = self.router_info
        self.add_chain.side_effect = _add_chain_mock
        self.remove_chain.side_effect = _remove_chain_mock
        self.add_rule.side_effect = _add_rule_mock
        self.remove_rule.side_effect = _remove_rule_mock

    def _test_create_router(self):
        self.np_ext.add_router(self.context, self.router)
        expected_calls = [mock.call(np.DEFAULT_NDP_PROXY_CHAIN)]
        self.assertEqual(expected_calls, self.add_chain.mock_calls)
        default_rule = '-i %s -j DROP' % self.ext_device_name
        subnet_rule = ('-i %s --destination %s -j %s-%s') % (
            self.ext_device_name, '2001::1:0/112', self.wrap_name,
            np.DEFAULT_NDP_PROXY_CHAIN)
        accept_rule = '-i %s --destination %s -j ACCEPT' % (
            self.ext_device_name, '2002::1:3')
        expected_calls = [
            mock.call(np.DEFAULT_NDP_PROXY_CHAIN, default_rule),
            mock.call('FORWARD', subnet_rule),
            mock.call(np.DEFAULT_NDP_PROXY_CHAIN, accept_rule, top=True)]
        self.assertEqual(expected_calls, self.add_rule.mock_calls)
        sysctl_cmd = ['sysctl', '-w',
                      'net.ipv6.conf.%s.proxy_ndp=1' % self.ext_device_name]
        proxy_cmd = ['ip', '-6', 'neigh', 'add', 'proxy',
                     '2002::1:3', 'dev', self.ext_device_name]
        ndsend_cmd = ['ndsend', '2002::1:3', self.ext_device_name]
        expected_calls = [
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(sysctl_cmd, privsep_exec=True),
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(proxy_cmd, privsep_exec=True),
            mock.call().netns.execute(ndsend_cmd, check_exit_code=False,
                                      log_fail_as_error=True,
                                      privsep_exec=True),
            mock.call(namespace=self.namespace)]
        self.assertEqual(expected_calls, self.ip_wrapper.mock_calls)

    def _test_update_router(self):
        self.np_ext.add_router(self.context, self.router)
        self.add_chain.reset_mock()
        self.add_rule.reset_mock()
        self.ip_wrapper.reset_mock()
        self.np_ext.update_router(self.context, self.router)
        self.add_chain.assert_not_called()
        self.add_rule.assert_not_called()
        sysctl_cmd = ['sysctl', '-w',
                      'net.ipv6.conf.%s.proxy_ndp=1' % self.ext_device_name]
        expected_calls = [
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(sysctl_cmd, privsep_exec=True),
            mock.call(namespace=self.namespace),
            mock.call(namespace=self.namespace)]
        self.assertEqual(expected_calls, self.ip_wrapper.mock_calls)

    def _test_add_ndp_proxy_update_router(self):
        self.np_ext.add_router(self.context, self.router)
        self.add_chain.reset_mock()
        self.add_rule.reset_mock()
        self.ip_wrapper.reset_mock()
        self.ndp_proxies.append(
            np_obj.NDPProxy(context=None, id=_uuid(),
                            router_id=self.fake_router_id,
                            port_id=self.port_id,
                            ip_address='2002::1:4'))
        self.np_ext.update_router(self.context, self.router)
        self.add_chain.assert_not_called()
        accept_rule = '-i %s --destination %s -j ACCEPT' % (
            self.ext_device_name, '2002::1:4')
        expected_calls = [
            mock.call(np.DEFAULT_NDP_PROXY_CHAIN, accept_rule, top=True)]
        self.assertEqual(expected_calls, self.add_rule.mock_calls)
        sysctl_cmd = ['sysctl', '-w',
                      'net.ipv6.conf.%s.proxy_ndp=1' % self.ext_device_name]
        proxy_cmd = ['ip', '-6', 'neigh', 'add', 'proxy',
                     '2002::1:4', 'dev', self.ext_device_name]
        ndsend_cmd = ['ndsend', '2002::1:4', self.ext_device_name]
        expected_calls = [
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(sysctl_cmd, privsep_exec=True),
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(proxy_cmd, privsep_exec=True),
            mock.call().netns.execute(ndsend_cmd, check_exit_code=False,
                                      log_fail_as_error=True,
                                      privsep_exec=True),
            mock.call(namespace=self.namespace)]
        self.assertEqual(expected_calls, self.ip_wrapper.mock_calls)

    def _test_del_ndp_proxy_update_router(self):
        self.np_ext.add_router(self.context, self.router)
        self.add_chain.reset_mock()
        self.add_rule.reset_mock()
        self.ip_wrapper.reset_mock()
        self.ndp_proxies = []
        self.np_ext.update_router(self.context, self.router)
        self.add_chain.assert_not_called()
        self.remove_chain.assert_not_called()
        self.add_rule.assert_not_called()
        accept_rule = '-i %s --destination %s -j ACCEPT' % (
            self.ext_device_name, '2002::1:3')
        expected_calls = [mock.call(np.DEFAULT_NDP_PROXY_CHAIN,
                                    accept_rule, top=True)]
        self.assertEqual(expected_calls, self.remove_rule.mock_calls)
        sysctl_cmd = ['sysctl', '-w',
                      'net.ipv6.conf.%s.proxy_ndp=1' % self.ext_device_name]
        proxy_cmd = ['ip', '-6', 'neigh', 'del',
                     'proxy', '2002::1:3', 'dev', self.ext_device_name]
        expected_calls = [
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(sysctl_cmd, privsep_exec=True),
            mock.call(namespace=self.namespace),
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(proxy_cmd, privsep_exec=True)]
        self.assertEqual(expected_calls, self.ip_wrapper.mock_calls)

    def _test_add_subnet_update_router(self):
        self.np_ext.add_router(self.context, self.router)
        self.add_chain.reset_mock()
        self.add_rule.reset_mock()
        self.ip_wrapper.reset_mock()
        self.internal_ports.append(
            {'subnets': [{'cidr': '2001::5:0/112'}]})
        self.np_ext.update_router(self.context, self.router)
        self.add_chain.assert_not_called()
        self.remove_chain.assert_not_called()
        subnet_rule = ('-i %s --destination 2001::5:0/112 -j %s-%s') % (
            self.ext_device_name, self.wrap_name,
            np.DEFAULT_NDP_PROXY_CHAIN)
        expected_calls = [mock.call('FORWARD', subnet_rule)]
        self.assertEqual(expected_calls, self.add_rule.mock_calls)
        self.remove_rule.assert_not_called()
        sysctl_cmd = ['sysctl', '-w',
                      'net.ipv6.conf.%s.proxy_ndp=1' % self.ext_device_name]
        expected_calls = [
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(sysctl_cmd, privsep_exec=True),
            mock.call(namespace=self.namespace),
            mock.call(namespace=self.namespace)]
        self.assertEqual(expected_calls, self.ip_wrapper.mock_calls)

    def _test_remove_subnet_update_router(self):
        self.np_ext.add_router(self.context, self.router)
        self.add_chain.reset_mock()
        self.add_rule.reset_mock()
        self.ip_wrapper.reset_mock()
        self.router_info.internal_ports = []
        self.np_ext.update_router(self.context, self.router)
        self.add_chain.assert_not_called()
        self.remove_chain.assert_not_called()
        self.add_rule.assert_not_called()
        subnet_rule = ('-i %s --destination %s -j %s-%s') % (
            self.ext_device_name, '2001::1:0/112', self.wrap_name,
            np.DEFAULT_NDP_PROXY_CHAIN)
        expected_calls = [mock.call('FORWARD', subnet_rule)]
        self.assertEqual(expected_calls, self.remove_rule.mock_calls)
        sysctl_cmd = ['sysctl', '-w',
                      'net.ipv6.conf.%s.proxy_ndp=1' % self.ext_device_name]
        expected_calls = [
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(sysctl_cmd, privsep_exec=True),
            mock.call(namespace=self.namespace),
            mock.call(namespace=self.namespace)]
        self.assertEqual(expected_calls, self.ip_wrapper.mock_calls)

    def _test_disable_ndp_proxy_update_router(self):
        self.np_ext.add_router(self.context, self.router)
        self.add_chain.reset_mock()
        self.add_rule.reset_mock()
        self.ip_wrapper.reset_mock()
        self.router['enable_ndp_proxy'] = False
        self.np_ext.update_router(self.context, self.router)
        self.add_chain.assert_not_called()
        expected_calls = [mock.call(np.DEFAULT_NDP_PROXY_CHAIN)]
        self.assertEqual(expected_calls, self.remove_chain.mock_calls)
        self.add_rule.assert_not_called()
        self.remove_rule.assert_not_called()
        flush_cmd = ['ip', '-6', 'neigh', 'flush', 'proxy']
        sysctl_cmd = ['sysctl', '-w',
                      'net.ipv6.conf.%s.proxy_ndp=0' % self.ext_device_name]
        expected_calls = [
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(flush_cmd, check_exit_code=False,
                                      privsep_exec=True),
            mock.call().netns.execute(sysctl_cmd, privsep_exec=True)]
        self.assertEqual(expected_calls, self.ip_wrapper.mock_calls)

    def _test__handle_notification(self):
        self.np_ext.add_router(self.context, self.router)
        self.add_chain.reset_mock()
        self.add_rule.reset_mock()
        self.ip_wrapper.reset_mock()
        ndpproxy = np_obj.NDPProxy(
            context=None, id=_uuid(),
            router_id=self.fake_router_id,
            port_id=self.port_id, ip_address='2002::1:5')
        self.np_ext._handle_notification(mock.MagicMock(), mock.MagicMock(),
                                         [ndpproxy], events.CREATED)
        self.add_chain.assert_not_called()
        self.remove_chain.assert_not_called()
        accept_rule = '-i %s --destination %s -j ACCEPT' % (
            self.ext_device_name, '2002::1:5')
        expected_calls = [
            mock.call(np.DEFAULT_NDP_PROXY_CHAIN, accept_rule, top=True)]
        self.assertEqual(expected_calls, self.add_rule.mock_calls)
        self.remove_rule.assert_not_called()
        proxy_cmd = ['ip', '-6', 'neigh', 'add', 'proxy',
                     '2002::1:5', 'dev', self.ext_device_name]
        ndsend_cmd = ['ndsend', '2002::1:5', self.ext_device_name]
        expected_calls = [
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(proxy_cmd, privsep_exec=True),
            mock.call().netns.execute(ndsend_cmd, check_exit_code=False,
                                      log_fail_as_error=True,
                                      privsep_exec=True)]
        self.assertEqual(expected_calls, self.ip_wrapper.mock_calls)
        self.add_chain.reset_mock()
        self.remove_chain.reset_mock()
        self.add_rule.reset_mock()
        self.remove_rule.reset_mock()
        self.ip_wrapper.reset_mock()
        self.np_ext._handle_notification(mock.MagicMock(), mock.MagicMock(),
                                         [ndpproxy], events.DELETED)
        self.add_chain.assert_not_called()
        self.remove_chain.assert_not_called()
        self.add_rule.assert_not_called()
        accept_rule = ('-i %s --destination %s -j ACCEPT') % (
            self.ext_device_name, '2002::1:5')
        expected_calls = [
            mock.call(np.DEFAULT_NDP_PROXY_CHAIN, accept_rule, top=True)]
        self.assertEqual(expected_calls, self.remove_rule.mock_calls)
        proxy_cmd = ['ip', '-6', 'neigh', 'del', 'proxy', '2002::1:5',
                     'dev', self.ext_device_name]
        expected_calls = [
            mock.call(namespace=self.namespace),
            mock.call().netns.execute(proxy_cmd, privsep_exec=True)]
        self.assertEqual(expected_calls, self.ip_wrapper.mock_calls)


class NDPProxyExtensionLegacyTestCase(
        NDPProxyExtensionLegacyDVRNoExternalTestCaseBase):
    def setUp(self):
        super(NDPProxyExtensionLegacyTestCase, self).setUp()
        self.conf.host = HOSTNAME
        self.conf.agent_mode = lib_const.L3_AGENT_MODE_LEGACY
        self.agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.ext_device_name = 'qg-%s' % self.ext_port_id[0:11]
        self.internal_ports = [{'subnets': [{'cidr': '2001::1:0/112'}]}]
        self.router = {'id': self.fake_router_id,
                       'gw_port': self.ex_gw_port,
                       'ha': False,
                       'distributed': False,
                       'enable_ndp_proxy': True}
        self.router_info = router_info.RouterInfo(
            self.agent, self.fake_router_id, self.router, **self.ri_kwargs)
        self.iptables_manager = self.router_info.iptables_manager
        self.router_info.internal_ports = self.internal_ports
        self.router_info.ex_gw_port = self.ex_gw_port
        self.iptables_manager.ipv6['filter'].chains = []
        self.iptables_manager.ipv6['filter'].rules = []
        self.agent.router_info[self.router['id']] = self.router_info
        self.wrap_name = self.iptables_manager.wrap_name
        self.namespace = "qrouter-" + self.fake_router_id
        self._mock_iptables_actions()
        self.ip_wrapper.reset_mock()

    def test_create_router(self):
        self._test_create_router()

    def test_update_router(self):
        self._test_update_router()

    def test_add_ndp_proxy_update_router(self):
        self._test_add_ndp_proxy_update_router()

    def test_del_ndp_proxy_update_router(self):
        self._test_del_ndp_proxy_update_router()

    def test_add_subnet_update_router(self):
        self._test_add_subnet_update_router()

    def test_remove_subnet_update_router(self):
        self._test_remove_subnet_update_router()

    def test_disable_ndp_proxy_update_router(self):
        self._test_disable_ndp_proxy_update_router()

    def test__handle_notification(self):
        self._test__handle_notification()


class NDPProxyExtensionDVRNoExternalTestCase(
        NDPProxyExtensionLegacyDVRNoExternalTestCaseBase):
    def setUp(self):
        super(NDPProxyExtensionLegacyDVRNoExternalTestCaseBase, self).setUp()
        self.conf.host = HOSTNAME
        self.conf.agent_mode = lib_const.L3_AGENT_MODE_DVR_SNAT
        self.agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.ext_device_name = 'qg-%s' % self.ext_port_id[0:11]
        self.internal_ports = [{'subnets': [{'cidr': '2001::1:0/112'}]}]
        self.router = {'id': self.fake_router_id,
                       'gw_port': self.ex_gw_port,
                       'gw_port_host': HOSTNAME,
                       'ha': False,
                       'distributed': True,
                       'enable_ndp_proxy': True}
        interface_driver = mock.Mock()
        interface_driver.DEV_NAME_LEN = 14
        kwargs = {
            'agent': self.agent,
            'router_id': self.fake_router_id,
            'router': self.router,
            'agent_conf': self.conf,
            'interface_driver': interface_driver}
        self._mock_load_fip = mock.patch.object(
            dvr_edge_router.DvrEdgeRouter,
            '_load_used_fip_information').start()
        self.router_info = dvr_edge_router.DvrEdgeRouter(HOSTNAME, **kwargs)
        self.iptables_manager = iptables_manager.IptablesManager(
            namespace=self.router_info.snat_namespace.name,
            use_ipv6=self.router_info.use_ipv6)
        self.router_info.snat_iptables_manager = self.iptables_manager
        self.router_info.internal_ports = self.internal_ports
        self.router_info.ex_gw_port = self.ex_gw_port
        self.iptables_manager.ipv6['filter'].chains = []
        self.iptables_manager.ipv6['filter'].rules = []
        self.agent.router_info[self.router['id']] = self.router_info
        self.wrap_name = self.iptables_manager.wrap_name
        self.namespace = "snat-" + self.fake_router_id
        self._mock_iptables_actions()
        self.ip_wrapper.reset_mock()

    def test_create_router(self):
        self._test_create_router()

    def test_update_router(self):
        self._test_update_router()

    def test_add_ndp_proxy_update_router(self):
        self._test_add_ndp_proxy_update_router()

    def test_del_ndp_proxy_update_router(self):
        self._test_del_ndp_proxy_update_router()

    def test_add_subnet_update_router(self):
        self._test_add_subnet_update_router()

    def test_remove_subnet_update_router(self):
        self._test_remove_subnet_update_router()

    def test_disable_ndp_proxy_update_router(self):
        self._test_disable_ndp_proxy_update_router()

    def test__handle_notification(self):
        self._test__handle_notification()


class NDPProxyExtensionInitializeTestCase(NDPProxyExtensionTestCaseBase):

    @mock.patch.object(registry, 'register')
    @mock.patch.object(resources_rpc, 'ResourcesPushRpcCallback')
    def test_initialize_subscribed_to_rpc(self, rpc_mock, subscribe_mock):
        call_to_patch = 'neutron_lib.rpc.Connection'
        with mock.patch(call_to_patch,
                        return_value=self.connection) as create_connection:
            self.np_ext.initialize(
                self.connection, lib_const.L3_AGENT_MODE)
            create_connection.assert_has_calls([mock.call()])
            self.connection.create_consumer.assert_has_calls(
                [mock.call(
                     resources_rpc.resource_type_versioned_topic(
                         resources.NDPPROXY),
                     [rpc_mock()],
                     fanout=True)]
            )
            subscribe_mock.assert_called_with(
                mock.ANY, resources.NDPPROXY)


class RouterNDPProxyMappingTestCase(base.BaseTestCase):
    def setUp(self):
        super(RouterNDPProxyMappingTestCase, self).setUp()
        self.mapping = np.RouterNDPProxyMapping()
        self.router1 = _uuid()
        self.router2 = _uuid()
        self.ndpproxy1 = np_obj.NDPProxy(
            context=None, id=_uuid(),
            router_id=self.router1,
            port_id=_uuid(), ip_address='2002::1:3')
        self.ndpproxy2 = np_obj.NDPProxy(
            context=None, id=_uuid(),
            router_id=self.router2,
            port_id=_uuid(), ip_address='2002::1:4')
        self.ndpproxies = [self.ndpproxy1, self.ndpproxy2]

    def test_set_ndp_proxies(self):
        self.mapping.set_ndp_proxies(self.ndpproxies)
        for ndp_proxy in self.ndpproxies:
            res = self.mapping.get_ndp_proxy(ndp_proxy.id)
            self.assertEqual(ndp_proxy, res)
        router1_ndp_proxies = self.mapping.get_ndp_proxies_by_router_id(
            self.router1)
        self.assertEqual([self.ndpproxy1], router1_ndp_proxies)
        router2_ndp_proxies = self.mapping.get_ndp_proxies_by_router_id(
            self.router2)
        self.assertEqual([self.ndpproxy2], router2_ndp_proxies)

    def test_del_ndp_proxies(self):
        self.mapping.set_ndp_proxies(self.ndpproxies)
        self.mapping.del_ndp_proxies([self.ndpproxy2])
        res = self.mapping.get_ndp_proxy(self.ndpproxy2.id)
        self.assertIsNone(res)
        router1_ndp_proxies = self.mapping.get_ndp_proxies_by_router_id(
            self.router1)
        self.assertEqual([self.ndpproxy1], router1_ndp_proxies)
        router2_ndp_proxies = self.mapping.get_ndp_proxies_by_router_id(
            self.router2)
        self.assertEqual([], router2_ndp_proxies)

    def test_clear_by_router_id(self):
        self.mapping.set_ndp_proxies(self.ndpproxies)
        self.mapping.clear_by_router_id(self.router1)
        np1 = self.mapping.get_ndp_proxy(self.ndpproxy1.id)
        self.assertIsNone(np1)
        np2 = self.mapping.get_ndp_proxy(self.ndpproxy2.id)
        self.assertEqual(self.ndpproxy2, np2)
        router1_ndp_proxies = self.mapping.get_ndp_proxies_by_router_id(
            self.router1)
        self.assertEqual([], router1_ndp_proxies)
        router2_ndp_proxies = self.mapping.get_ndp_proxies_by_router_id(
            self.router2)
        self.assertEqual([self.ndpproxy2], router2_ndp_proxies)
