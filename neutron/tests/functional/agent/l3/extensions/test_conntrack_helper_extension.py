# Copyright (c) 2019 Red Hat Inc.
# All rights reserved.
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


import collections

import mock

from neutron_lib import constants
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as neutron_l3_agent
from neutron.agent.l3.extensions import conntrack_helper
from neutron.agent.linux import iptables_manager as iptable_mng
from neutron.common import utils as common_utils
from neutron.objects import conntrack_helper as cth_obj
from neutron.tests.functional.agent.l3 import framework
from neutron.tests.functional.agent.l3 import test_dvr_router


class L3AgentConntrackHelperExtensionTestFramework(
        framework.L3AgentTestFramework):

    def setUp(self):
        super(L3AgentConntrackHelperExtensionTestFramework, self).setUp()
        self.conf.set_override('extensions', ['conntrack_helper'], 'agent')
        self.agent = neutron_l3_agent.L3NATAgentWithStateReport('agent1',
                                                                self.conf)

        self.cth_ext = conntrack_helper.ConntrackHelperAgentExtension()

        self.router_id1 = uuidutils.generate_uuid()
        self.router_id2 = uuidutils.generate_uuid()
        self.conntrackhelper1 = cth_obj.ConntrackHelper(
            context=None, id=uuidutils.generate_uuid(), protocol='udp',
            port=69, helper='tftp', router_id=self.router_id1)
        self.conntrackhelper2 = cth_obj.ConntrackHelper(
            context=None, id=uuidutils.generate_uuid(), protocol='tcp',
            port=21, helper='ftp', router_id=self.router_id2)

        self.conntrack_helpers = [self.conntrackhelper1, self.conntrackhelper2]

        self.managed_cths = {}
        self.managed_cths[self.conntrackhelper1.id] = self.conntrackhelper1
        self.managed_cths[self.conntrackhelper2.id] = self.conntrackhelper2

        self.router_cth_map = collections.defaultdict(set)
        self.router_cth_map[self.router_id1].add(self.conntrackhelper1.id)
        self.router_cth_map[self.router_id2].add(self.conntrackhelper2.id)

        self._set_bulk_poll_mock()

    def _set_bulk_poll_mock(self):

        def _bulk_pull_mock(context, resource_type, filter_kwargs=None):
            if 'router_id' in filter_kwargs:
                result = []
                for cthobj in self.conntrack_helpers:
                    if cthobj.router_id in filter_kwargs['router_id']:
                        result.append(cthobj)
                return result
            return self.conntrack_helpers

        self.bulk_pull = mock.patch('neutron.api.rpc.handlers.resources_rpc.'
                                    'ResourcesPullRpcApi.bulk_pull').start()
        self.bulk_pull.side_effect = _bulk_pull_mock

    def _assert_conntrack_helper_iptables_is_set(self, router_info, cth):
        iptables_manager = self.cth_ext._get_iptables_manager(router_info)
        tag = conntrack_helper.CONNTRACK_HELPER_PREFIX + cth.id
        chain_name = (conntrack_helper.CONNTRACK_HELPER_CHAIN_PREFIX +
                      cth.id)[:constants.MAX_IPTABLES_CHAIN_LEN_WRAP]
        rule = ('-p %s --dport %s -j CT --helper %s' %
                (cth.protocol, cth.port, cth.helper))

        rule_obj = iptable_mng.IptablesRule(chain_name, rule, True, False,
                                            iptables_manager.wrap_name, tag,
                                            None)

        def check_chain_rules_set():
            existing_ipv4_chains = iptables_manager.ipv4['raw'].chains
            existing_ipv6_chains = iptables_manager.ipv6['raw'].chains
            if (chain_name not in existing_ipv4_chains or
                    chain_name not in existing_ipv6_chains):
                return False
            existing_ipv4_rules = iptables_manager.ipv4['raw'].rules
            existing_ipv6_rules = iptables_manager.ipv6['raw'].rules
            return (rule_obj in existing_ipv4_rules and
                    rule_obj in existing_ipv6_rules)

        common_utils.wait_until_true(check_chain_rules_set)

    def _test_centralized_routers(self, router_info):
        router_id = router_info['id']
        for cthobj in self.conntrack_helpers:
            cthobj.router_id = router_id
        router_info['managed_conntrack_helpers'] = self.managed_cths
        router_info['router_conntrack_helper_mapping'] = self.router_cth_map
        ri = self.manage_router(self.agent, router_info)
        for cthobj in self.conntrack_helpers:
            self._assert_conntrack_helper_iptables_is_set(ri, cthobj)


class TestL3AgentConntrackHelperExtension(
        test_dvr_router.DvrRouterTestFramework,
        L3AgentConntrackHelperExtensionTestFramework):

    def test_legacy_router_conntrack_helper(self):
        router_info = self.generate_router_info(enable_ha=False)
        self._test_centralized_routers(router_info)

    def test_ha_router_conntrack_helper(self):
        router_info = self.generate_router_info(enable_ha=True)
        self._test_centralized_routers(router_info)

    def test_dvr_edge_router(self):
        self.agent.conf.agent_mode = constants.L3_AGENT_MODE_DVR_SNAT
        router_info = self.generate_dvr_router_info(enable_ha=False)
        self._test_centralized_routers(router_info)

    def test_dvr_ha_router(self):
        self.agent.conf.agent_mode = constants.L3_AGENT_MODE_DVR_SNAT
        router_info = self.generate_dvr_router_info(enable_ha=True)
        self._test_centralized_routers(router_info)
