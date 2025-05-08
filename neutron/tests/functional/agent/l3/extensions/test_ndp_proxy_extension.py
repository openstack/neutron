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

import netaddr
from neutron_lib import constants
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as neutron_l3_agent
from neutron.agent.l3.extensions import ndp_proxy as np
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager as iptable_mng
from neutron.api.rpc.callbacks import resources
from neutron.common import utils as common_utils
from neutron.objects import agent as agent_obj
from neutron.objects import ndp_proxy as np_obj
from neutron.objects import ports as ports_obj
from neutron.tests.functional.agent.l3 import framework
from neutron.tests.functional.agent.l3 import test_dvr_router

HOSTNAME = 'agent1'


class L3AgentNDPProxyTestFramework(framework.L3AgentTestFramework):

    def setUp(self):
        super().setUp()
        # TODO(slaweq): Investigate why those tests are failing with enabled
        # debug_iptables_rules config option, but for now lets just disable it
        cfg.CONF.set_override('debug_iptables_rules', False, group='AGENT')
        self.conf.set_override('extensions', ['ndp_proxy'], 'agent')
        self.agent = neutron_l3_agent.L3NATAgentWithStateReport(HOSTNAME,
                                                                self.conf)
        self.agent.init_host()
        self.np_ext = np.NDPProxyAgentExtension()

        port_id1 = uuidutils.generate_uuid()
        port1_binding = ports_obj.PortBinding(port_id=port_id1,
                                              host=self.agent.host)
        port1_obj = ports_obj.Port(id=port_id1, bindings=[port1_binding])
        port_id2 = uuidutils.generate_uuid()
        port2_binding = ports_obj.PortBinding(port_id=port_id1,
                                              host='fake_host')
        port2_obj = ports_obj.Port(id=port_id2, bindings=[port2_binding])
        self.ports = [port1_obj, port2_obj]
        self.port_binding_map = {port_id1: port1_binding,
                                 port_id2: port2_binding}
        self.ndpproxy1 = np_obj.NDPProxy(
            context=None, id=uuidutils.generate_uuid(),
            router_id=uuidutils.generate_uuid(),
            port_id=port_id1, ip_address='2002::1:3')
        self.ndpproxy2 = np_obj.NDPProxy(
            context=None, id=uuidutils.generate_uuid(),
            router_id=uuidutils.generate_uuid(),
            port_id=port_id2, ip_address='2002::1:4')
        self.ndp_proxies = [self.ndpproxy1, self.ndpproxy2]
        agent_configurations = {
            'agent_mode': constants.L3_AGENT_MODE_DVR_NO_EXTERNAL}
        self.agent_obj = agent_obj.Agent(
            id=uuidutils.generate_uuid(), host=self.agent.host,
            agent_type=constants.AGENT_TYPE_L3,
            configurations=agent_configurations)
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

    def _get_existing_ndp_proxies(self, interface_name, namespace):
        ip_wrapper = ip_lib.IPWrapper(namespace=namespace)
        cmd = ['ip', '-6', 'neigh', 'list', 'proxy']
        res = ip_wrapper.netns.execute(cmd)
        proxies = []
        for proxy in res.split('\n'):
            # Exclude null line
            if proxy:
                proxy_list = proxy.split(' ')
                if interface_name in proxy_list:
                    try:
                        if netaddr.IPAddress(proxy_list[0]).version == 6:
                            proxies.append(proxy_list[0])
                    except Exception:
                        pass
        return proxies

    def _assert_ndp_proxy_kernel_parameter(self, ip_wrapper, interface_name):
        sysctl_cmd = ['sysctl', '-b',
                      'net.ipv6.conf.%s.proxy_ndp' % interface_name]

        def check_kernel_parameter():
            res = ip_wrapper.netns.execute(sysctl_cmd, privsep_exec=True)
            if res == "1":
                return True

        common_utils.wait_until_true(check_kernel_parameter)

    def _assert_ndp_iptable_chain_is_set(self, iptables_manager,
                                         interface_name):
        rule = '-i %s -j DROP' % interface_name
        rule_obj = iptable_mng.IptablesRule('NDP', rule, True, False,
                                            iptables_manager.wrap_name)

        def check_chain_is_set():
            existing_chains = iptables_manager.ipv6['filter'].chains
            if 'NDP' not in existing_chains:
                return False

            existing_rules = iptables_manager.ipv6['filter'].rules
            if rule_obj in existing_rules:
                return True

        common_utils.wait_until_true(check_chain_is_set)

    def _assert_ndp_proxy_state_iptable_rules_is_set(
            self, ri, iptables_manager, interface_name):
        wrap_name = iptables_manager.wrap_name
        expected_rules = []
        for port in ri.internal_ports:
            for subnet in port['subnets']:
                if netaddr.IPNetwork(subnet['cidr']).version == \
                        constants.IP_VERSION_4:
                    continue
                rule = (
                    '-i %s --destination %s -j '
                    '%s-NDP') % (interface_name,
                                 subnet['cidr'],
                                 wrap_name)

                rule_obj = iptable_mng.IptablesRule(
                    'FORWARD', rule, True, False, iptables_manager.wrap_name)
                expected_rules.append(rule_obj)

        def check_rules_is_set():
            existing_rules = iptables_manager.ipv6['filter'].rules
            for rule in expected_rules:
                if rule not in existing_rules:
                    return False
            return True

        common_utils.wait_until_true(check_rules_is_set)

    def _assect_ndp_proxy_rules_is_set(self, ip_wrapper, iptables_manager,
                                       interface_name, namespace):
        expected_iptable_rules = []
        expected_proxy_address = []
        for ndp_proxy in self.ndp_proxies:
            rule = '-i {} --destination {} -j ACCEPT'.format(
                interface_name, ndp_proxy.ip_address)
            rule_obj = iptable_mng.IptablesRule('NDP', rule, True, True,
                                                iptables_manager.wrap_name)
            expected_iptable_rules.append(rule_obj)
            expected_proxy_address.append(str(ndp_proxy.ip_address))

        def check_rules_is_set():
            existing_iptable_rules = iptables_manager.ipv6['filter'].rules
            for iptable_rule in expected_iptable_rules:
                if iptable_rule not in existing_iptable_rules:
                    return False

            existing_proxy_addresses = self._get_existing_ndp_proxies(
                interface_name, namespace)
            for address in expected_proxy_address:
                if address not in existing_proxy_addresses:
                    return False

            return True

        common_utils.wait_until_true(check_rules_is_set)


class TestL3AgentNDPProxyExtension(L3AgentNDPProxyTestFramework):

    def _test_router_ndp_proxy(self, enable_ha):
        router_info = self.generate_router_info(enable_ha=enable_ha)
        router_info['enable_ndp_proxy'] = True
        ri = self.manage_router(self.agent, router_info)
        for ndp_proxy in self.ndp_proxies:
            ndp_proxy.router_id = ri.router_id
        (interface_name, namespace,
            iptables_manager) = self.np_ext._get_resource_by_router(ri)
        ip_wrapper = ip_lib.IPWrapper(namespace=namespace)
        self._assert_ndp_proxy_kernel_parameter(ip_wrapper, interface_name)
        self._assert_ndp_iptable_chain_is_set(iptables_manager, interface_name)
        slaac = constants.IPV6_SLAAC
        slaac_mode = {'ra_mode': slaac, 'address_mode': slaac}
        self._add_internal_interface_by_subnet(
            ri.router, count=1, ip_version=constants.IP_VERSION_6,
            ipv6_subnet_modes=[slaac_mode])
        self.agent._process_updated_router(ri.router)
        self._assert_ndp_proxy_state_iptable_rules_is_set(
            ri, iptables_manager, interface_name)
        self._assect_ndp_proxy_rules_is_set(
            ip_wrapper, iptables_manager,
            interface_name, namespace)
        ri.router['enable_ndp_proxy'] = False
        self.agent._process_updated_router(ri.router)

    def test_legacy_router_ndp_proxy(self):
        self._test_router_ndp_proxy(enable_ha=False)

    def test_ha_router_ndp_proxy(self):
        self._test_router_ndp_proxy(enable_ha=True)


class TestL3AgentNDPProxyExtensionDVR(test_dvr_router.TestDvrRouter,
                                      L3AgentNDPProxyTestFramework):

    def test_local_dvr_router(self):
        self.agent.conf.agent_mode = constants.L3_AGENT_MODE_DVR
        router_info = self.generate_dvr_router_info(enable_ha=False)
        for ndp_proxy in self.ndp_proxies:
            ndp_proxy.router_id = router_info['id']
        router_info['enable_ndp_proxy'] = True
        ri = self.manage_router(self.agent, router_info)
        (interface_name, namespace,
            iptables_manager) = self.np_ext._get_resource_by_router(ri)
        ip_wrapper = ip_lib.IPWrapper(namespace=namespace)
        self._assert_ndp_proxy_kernel_parameter(ip_wrapper, interface_name)
        self._assect_ndp_proxy_rules_is_set(ri, interface_name, namespace)

    def test_edge_dvr_router(self):
        self.agent.conf.agent_mode = constants.L3_AGENT_MODE_DVR_SNAT
        router_info = self.generate_dvr_router_info(enable_ha=False)
        for ndp_proxy in self.ndp_proxies:
            ndp_proxy.router_id = router_info['id']
        router_info['enable_ndp_proxy'] = True
        ri = self.manage_router(self.agent, router_info)
        (interface_name, namespace,
            iptables_manager) = self.np_ext._get_resource_by_router(ri)
        ip_wrapper = ip_lib.IPWrapper(namespace=namespace)
        self._assert_ndp_proxy_kernel_parameter(ip_wrapper, interface_name)
        self._assert_ndp_iptable_chain_is_set(iptables_manager, interface_name)
        slaac = constants.IPV6_SLAAC
        slaac_mode = {'ra_mode': slaac, 'address_mode': slaac}
        self._add_internal_interface_by_subnet(
            ri.router, count=1, ip_version=constants.IP_VERSION_6,
            ipv6_subnet_modes=[slaac_mode])
        self.agent._process_updated_router(ri.router)
        self._assert_ndp_proxy_state_iptable_rules_is_set(
            ri, iptables_manager, interface_name)
        super()._assect_ndp_proxy_rules_is_set(
                ip_wrapper, iptables_manager,
                interface_name, namespace)
        ri.router['enable_ndp_proxy'] = False
        self.agent._process_updated_router(ri.router)

    def _assect_ndp_proxy_rules_is_set(self, ri, interface_name, namespace):
        rtr_2_fip_dev = ri.fip_ns.get_rtr_2_fip_device(ri)
        fip_2_rtr_dev = ri.fip_ns.get_fip_2_rtr_device(ri)
        rtr_2_fip_v6_address = self.np_ext._get_device_ipv6_lladdr(
            rtr_2_fip_dev)
        expected_proxy_address = []
        expected_routes = []
        for ndp_proxy in self.ndp_proxies:
            port_binding_obj = self.port_binding_map.get(ndp_proxy.port_id)
            if port_binding_obj and port_binding_obj.host == self.agent.host:
                expected_proxy_address.append(str(ndp_proxy.ip_address))
                expected_routes.append(
                    {'table': 'main', 'source_prefix': None,
                     'cidr': '%s/128' % ndp_proxy.ip_address,
                     'scope': 'global', 'metric': 1024,
                     'proto': 'static', 'device': fip_2_rtr_dev.name,
                     'via': rtr_2_fip_v6_address})

        def check_rules_is_set():
            existing_proxy_addresses = self._get_existing_ndp_proxies(
                interface_name, namespace)
            for address in expected_proxy_address:
                if address not in existing_proxy_addresses:
                    return False

            existing_routes = fip_2_rtr_dev.route.list_routes(
                ip_version=constants.IP_VERSION_6)
            for route in expected_routes:
                if route not in existing_routes:
                    return False

            return True

        common_utils.wait_until_true(check_rules_is_set)
