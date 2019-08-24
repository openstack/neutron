# Copyright 2018 OpenStack Foundation
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

import os
import re
from unittest import mock

from neutron_lib import constants
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as neutron_l3_agent
from neutron.agent.l3.extensions import port_forwarding as pf
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager as iptable_mng
from neutron.agent.linux import utils
from neutron.common import utils as common_utils
from neutron.objects import port_forwarding as pf_obj
from neutron.tests.functional.agent.l3 import framework
from neutron.tests.functional.agent.l3 import test_dvr_router

_uuid = uuidutils.generate_uuid


class L3AgentFipPortForwardingExtensionTestFramework(
     framework.L3AgentTestFramework):

    def setUp(self):
        super(L3AgentFipPortForwardingExtensionTestFramework, self).setUp()
        self.conf.set_override('extensions', ['port_forwarding'], 'agent')
        self.agent = neutron_l3_agent.L3NATAgentWithStateReport('agent1',
                                                                self.conf)
        self.fip_pf_ext = pf.PortForwardingAgentExtension()
        self.fip_id1 = _uuid()
        self.fip_id2 = _uuid()
        self.fip_id3 = _uuid()
        self.portforwarding1 = pf_obj.PortForwarding(
            context=None, id=_uuid(), floatingip_id=self.fip_id1,
            external_port=1111, protocol='tcp', internal_port_id=_uuid(),
            external_port_range='1111:1111',
            internal_port_range='11111:11111',
            internal_ip_address='1.1.1.1', internal_port=11111,
            floating_ip_address='111.111.111.111', router_id=_uuid())
        self.portforwarding2 = pf_obj.PortForwarding(
            context=None, id=_uuid(), floatingip_id=self.fip_id1,
            external_port=1112, protocol='tcp', internal_port_id=_uuid(),
            external_port_range='1112:1112',
            internal_port_range='11112:11112',
            internal_ip_address='1.1.1.2', internal_port=11112,
            floating_ip_address='111.111.111.111', router_id=_uuid())
        self.portforwarding3 = pf_obj.PortForwarding(
            context=None, id=_uuid(), floatingip_id=self.fip_id2,
            external_port=1113, protocol='tcp', internal_port_id=_uuid(),
            internal_ip_address='1.1.1.3', internal_port=11113,
            external_port_range='1113:1113',
            internal_port_range='11113:11113',
            floating_ip_address='111.222.111.222', router_id=_uuid())
        self.portforwarding4 = pf_obj.PortForwarding(
            context=None, id=_uuid(), floatingip_id=self.fip_id3,
            external_port=2222, protocol='tcp', internal_port_id=_uuid(),
            external_port_range='2222:2222',
            internal_port_range='22222:22222',
            internal_ip_address='2.2.2.2', internal_port=22222,
            floating_ip_address='222.222.222.222', router_id=_uuid())
        self.port_forwardings = [self.portforwarding1, self.portforwarding2,
                                 self.portforwarding3, self.portforwarding4]
        self._set_bulk_pull_mock()
        self.managed_fips = [self.fip_id1, self.fip_id2, self.fip_id3]
        self.fip_list_for_pf = ['111.111.111.111/32', '111.222.111.222/32',
                                '222.222.222.222/32']

    def _set_bulk_pull_mock(self):

        def _bulk_pull_mock(context, resource_type, filter_kwargs=None):
            if 'floatingip_id' in filter_kwargs:
                result = []
                for pfobj in self.port_forwardings:
                    if pfobj.floatingip_id in filter_kwargs['floatingip_id']:
                        result.append(pfobj)
                return result
            return self.port_forwardings
        self.bulk_pull = mock.patch(
            'neutron.api.rpc.handlers.resources_rpc.'
            'ResourcesPullRpcApi.bulk_pull').start()
        self.bulk_pull.side_effect = _bulk_pull_mock

    def _assert_port_forwarding_fip_is_set(self, router_info, pf_fip):
        (interface_name, namespace,
         iptables_manager) = self.fip_pf_ext._get_resource_by_router(
            router_info)
        device = ip_lib.IPDevice(interface_name, namespace=namespace)
        pf_fip_cidr = str(pf_fip) + '/32'

        def check_existing_cidrs():
            existing_cidrs = router_info.get_router_cidrs(device)
            return pf_fip_cidr in existing_cidrs

        common_utils.wait_until_true(check_existing_cidrs)

    def _assert_port_forwarding_iptables_is_set(self, router_info, pf):
        (interface_name, namespace,
         iptables_manager) = self.fip_pf_ext._get_resource_by_router(
            router_info)
        chain_rule = self.fip_pf_ext._get_fip_rules(
            pf, iptables_manager.wrap_name)[1]
        chain_name = chain_rule[0]
        rule = chain_rule[1]
        rule_tag = 'fip_portforwarding-' + pf.id
        rule_obj = iptable_mng.IptablesRule(
            chain_name, rule, True, False, iptables_manager.wrap_name,
            rule_tag, None)

        def check_chain_rules_set():
            existing_chains = iptables_manager.ipv4['nat'].chains
            if chain_name not in existing_chains:
                return False
            existing_rules = iptables_manager.ipv4['nat'].rules
            return rule_obj in existing_rules

        common_utils.wait_until_true(check_chain_rules_set)

    def _assert_harouter_fip_is_set(self, router_info, fip_pf):
        (interface_name, namespace,
         iptables_manager) = self.fip_pf_ext._get_resource_by_router(
            router_info)
        keepalived_pm = router_info.keepalived_manager.get_process()
        utils.get_conf_file_name(keepalived_pm.pids_path,
                                 keepalived_pm.uuid,
                                 keepalived_pm.service_pid_fname)

        conf_path = os.path.join(keepalived_pm.pids_path, keepalived_pm.uuid,
                                 'keepalived.conf')

        regex = "%s dev %s" % (fip_pf, interface_name)
        pattern = re.compile(regex)

        def check_harouter_fip_is_set():
            if re.findall(pattern, utils.get_value_from_file(conf_path)):
                return True
            return False

        common_utils.wait_until_true(check_harouter_fip_is_set)

    def _test_centralized_routers(self, router_info, enable_ha=False):
        router_id = router_info['id']
        for pfobj in self.port_forwardings:
            pfobj.router_id = router_id
        router_info['fip_managed_by_port_forwardings'] = self.managed_fips
        router_info['port_forwardings_fip_set'] = set(self.fip_list_for_pf)
        ri = self.manage_router(self.agent, router_info)
        for pfobj in self.port_forwardings:
            self._assert_port_forwarding_fip_is_set(ri,
                                                    pfobj.floating_ip_address)
            self._assert_port_forwarding_iptables_is_set(ri, pfobj)
        if enable_ha:
            for fip_pf in self.fip_list_for_pf:
                self._assert_harouter_fip_is_set(ri, fip_pf)


class TestL3AgentFipPortForwardingExtension(
     L3AgentFipPortForwardingExtensionTestFramework):

    def test_legacy_router_fip_portforwarding(self):
        router_info = self.generate_router_info(enable_ha=False)
        self._test_centralized_routers(router_info, enable_ha=False)

    def test_ha_router_fip_portforwarding(self):
        router_info = self.generate_router_info(enable_ha=True)
        self._test_centralized_routers(router_info, enable_ha=True)


class TestL3AgentFipPortForwardingExtensionDVR(
        test_dvr_router.TestDvrRouter,
        L3AgentFipPortForwardingExtensionTestFramework):

    def test_dvr_edge_router(self):
        self.agent.conf.agent_mode = constants.L3_AGENT_MODE_DVR_SNAT
        router_info = self.generate_dvr_router_info(enable_ha=False)
        self._test_centralized_routers(router_info, enable_ha=False)

    def test_dvr_ha_router(self):
        self.agent.conf.agent_mode = constants.L3_AGENT_MODE_DVR_SNAT
        router_info = self.generate_dvr_router_info(enable_ha=True)
        self._test_centralized_routers(router_info, enable_ha=True)
