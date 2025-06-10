# Copyright 2017 OpenStack Foundation
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

from neutron_lib import constants
from neutron_lib import exceptions
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as neutron_l3_agent
from neutron.agent.l3.extensions.qos import fip as fip_qos
from neutron.agent.linux import ip_lib
from neutron.common import utils as common_utils
from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.tests.functional.agent.l3 import framework
from neutron.tests.functional.agent.l3 import test_dvr_router

_uuid = uuidutils.generate_uuid
TEST_POLICY_ID1 = _uuid()
TEST_POLICY_ID2 = _uuid()
TEST_POLICY_ID3 = _uuid()


class L3AgentFipQoSExtensionTestFramework(framework.L3AgentTestFramework):

    test_bw_limit_rule_1 = rule.QosBandwidthLimitRule(
            context=None,
            qos_policy_id=TEST_POLICY_ID1,
            id=_uuid(),
            max_kbps=111,
            max_burst_kbps=222,
            direction=constants.INGRESS_DIRECTION)
    test_bw_limit_rule_2 = rule.QosBandwidthLimitRule(
            context=None,
            qos_policy_id=TEST_POLICY_ID1,
            id=_uuid(),
            max_kbps=333,
            max_burst_kbps=444,
            direction=constants.EGRESS_DIRECTION)
    test_bw_limit_rule_3 = rule.QosBandwidthLimitRule(
            context=None,
            qos_policy_id=TEST_POLICY_ID2,
            id=_uuid(),
            max_kbps=555,
            max_burst_kbps=666,
            direction=constants.INGRESS_DIRECTION)
    test_bw_limit_rule_4 = rule.QosBandwidthLimitRule(
            context=None,
            qos_policy_id=TEST_POLICY_ID3,
            id=_uuid(),
            max_kbps=777,
            max_burst_kbps=888,
            direction=constants.EGRESS_DIRECTION)

    def setUp(self):
        # TODO(ralonsoh): refactor this test to make it compatible after the
        # eventlet removal.
        self.skipTest('This test is skipped after the eventlet removal and '
                      'needs to be refactored')
        super().setUp()
        self.conf.set_override('extensions', ['fip_qos'], 'agent')
        self.agent = neutron_l3_agent.L3NATAgentWithStateReport('agent1',
                                                                self.conf)
        self.agent.init_host()
        self._set_pull_mock()
        self.set_test_qos_rules(TEST_POLICY_ID1,
                                [self.test_bw_limit_rule_1,
                                 self.test_bw_limit_rule_2])
        self.set_test_qos_rules(TEST_POLICY_ID2,
                                [self.test_bw_limit_rule_3])
        self.set_test_qos_rules(TEST_POLICY_ID3,
                                [self.test_bw_limit_rule_4])
        self.fip_qos_ext = fip_qos.FipQosAgentExtension()

    def _set_pull_mock(self):

        self.qos_policies = {}

        def _pull_mock(context, resource_type, resource_id):
            return self.qos_policies[resource_id]

        self.pull = mock.patch(
            'neutron.api.rpc.handlers.resources_rpc.'
            'ResourcesPullRpcApi.pull').start()
        self.pull.side_effect = _pull_mock

    def set_test_qos_rules(self, policy_id, policy_rules):
        """This function sets the policy test rules to be exposed."""

        qos_policy = policy.QosPolicy(
            context=None,
            project_id=_uuid(),
            id=policy_id,
            name="Test Policy Name",
            description="This is a policy for testing purposes",
            shared=False,
            rules=policy_rules)

        qos_policy.obj_reset_changes()
        self.qos_policies[policy_id] = qos_policy

    def _assert_bandwidth_limit_rule_is_set(self, router, ip, rule):
        device = self.fip_qos_ext._get_rate_limit_ip_device(router)
        tc_wrapper = self.fip_qos_ext._get_tc_wrapper(device)

        def get_filter_id():
            try:
                return tc_wrapper.get_filter_id_for_ip(rule.direction, ip)
            except exceptions.FilterIDForIPNotFound:
                pass

        common_utils.wait_until_true(get_filter_id)

    def _assert_bandwidth_limit_rule_not_set(self, router, ip, rule,
                                             dvr_no_external=False):
        device = self.fip_qos_ext._get_rate_limit_ip_device(router)
        if dvr_no_external:
            self.assertIsNone(device)
        else:
            tc_wrapper = self.fip_qos_ext._get_tc_wrapper(device)
            filter_id = tc_wrapper.get_filter_id_for_ip(rule.direction, ip)
            self.assertIsNone(filter_id)


class TestL3AgentFipQosExtension(L3AgentFipQoSExtensionTestFramework):

    def _test_centralized_routers(self, enable_ha=False,
                                  ingress=True, egress=True):
        qos_policy_id = TEST_POLICY_ID1
        if ingress and not egress:
            qos_policy_id = TEST_POLICY_ID2
        elif egress and not ingress:
            qos_policy_id = TEST_POLICY_ID3
        router_info = self.generate_router_info(
            enable_ha=enable_ha,
            qos_policy_id=qos_policy_id)
        ri = self.manage_router(self.agent, router_info)
        if qos_policy_id == TEST_POLICY_ID1:
            self._assert_bandwidth_limit_rule_is_set(
                ri, '19.4.4.2', self.test_bw_limit_rule_1)
            self._assert_bandwidth_limit_rule_is_set(
                ri, '19.4.4.2', self.test_bw_limit_rule_2)
        elif qos_policy_id == TEST_POLICY_ID2:
            self._assert_bandwidth_limit_rule_is_set(
                ri, '19.4.4.2', self.test_bw_limit_rule_3)
        elif qos_policy_id == TEST_POLICY_ID3:
            self._assert_bandwidth_limit_rule_is_set(
                ri, '19.4.4.2', self.test_bw_limit_rule_4)

    def test_legacy_router_fip_qos(self):
        self._test_centralized_routers()

    def test_legacy_router_fip_qos_ingress(self):
        self._test_centralized_routers(ingress=True, egress=False)

    def test_legacy_router_fip_qos_egress(self):
        self._test_centralized_routers(ingress=False, egress=True)

    def test_ha_router_fip_qos(self):
        self._test_centralized_routers(enable_ha=True)

    def test_ha_router_fip_qos_ingress(self):
        self._test_centralized_routers(enable_ha=True,
                                       ingress=True, egress=False)

    def test_ha_router_fip_qos_egress(self):
        self._test_centralized_routers(enable_ha=True,
                                       ingress=False, egress=True)

    def _test_router_with_pf_fips_qos(self, enable_ha):
        router_info = self.generate_router_info(
            enable_ha=enable_ha,
            enable_pf_floating_ip=True,
            qos_policy_id=TEST_POLICY_ID1)
        ri = self.manage_router(self.agent, router_info)
        self._assert_bandwidth_limit_rule_is_set(
            ri, '19.4.4.4', self.test_bw_limit_rule_1)
        self._assert_bandwidth_limit_rule_is_set(
            ri, '19.4.4.4', self.test_bw_limit_rule_2)

    def test_ha_router_with_pf_fips_qos(self):
        self._test_router_with_pf_fips_qos(enable_ha=True)

    def test_legacy_router_with_pf_fips_qos(self):
        self._test_router_with_pf_fips_qos(enable_ha=False)


class TestL3AgentFipQosExtensionDVR(
        test_dvr_router.TestDvrRouter,
        L3AgentFipQoSExtensionTestFramework):

    def test_dvr_local_router_no_fip(self):
        self.agent.conf.agent_mode = constants.L3_AGENT_MODE_DVR
        router_info = self.generate_dvr_router_info(
            enable_floating_ip=False)
        ri = self.manage_router(self.agent, router_info)
        self._assert_bandwidth_limit_rule_not_set(
            ri, '19.4.4.2', self.test_bw_limit_rule_1)
        self._assert_bandwidth_limit_rule_not_set(
            ri, '19.4.4.2', self.test_bw_limit_rule_2)

    def _test_dvr_fip_qos(self, enable_ha=False):
        self.agent.conf.agent_mode = constants.L3_AGENT_MODE_DVR
        router_info = self.generate_dvr_router_info(
            enable_ha=enable_ha,
            enable_gw=True, qos_policy_id=TEST_POLICY_ID1)
        ri = self.manage_router(self.agent, router_info)
        self._assert_bandwidth_limit_rule_is_set(
            ri, '19.4.4.2', self.test_bw_limit_rule_1)
        self._assert_bandwidth_limit_rule_is_set(
            ri, '19.4.4.2', self.test_bw_limit_rule_2)

    def test_dvr_local_router_fip_qos(self):
        self._test_dvr_fip_qos()

    def test_ha_dvr_local_router_fip_qos(self):
        self._test_dvr_fip_qos(enable_ha=True)

    def _test_agent_mode_dvr_no_external(self, enable_ha=False):
        self.agent.conf.agent_mode = constants.L3_AGENT_MODE_DVR_NO_EXTERNAL
        router_info = self.generate_dvr_router_info(
            enable_ha=enable_ha,
            enable_floating_ip=True, enable_centralized_fip=True,
            enable_snat=True, snat_bound_fip=True,
            qos_policy_id=TEST_POLICY_ID1)
        ri = self.manage_router(self.agent, router_info)
        self._assert_bandwidth_limit_rule_not_set(
            ri, '19.4.4.2', self.test_bw_limit_rule_1,
            dvr_no_external=True)
        self._assert_bandwidth_limit_rule_not_set(
            ri, '19.4.4.2', self.test_bw_limit_rule_2,
            dvr_no_external=True)

    def test_dvr_no_external_no_qos(self):
        self._test_agent_mode_dvr_no_external()

    def test_ha_dvr_no_external_no_qos(self):
        self._test_agent_mode_dvr_no_external(enable_ha=True)

    def _test_dvr_fip_snat_bound_agent_mode_dvr_snat(self, enable_ha=False):
        self.agent.conf.agent_mode = constants.L3_AGENT_MODE_DVR_SNAT
        router_info = self.generate_dvr_router_info(
            enable_ha=enable_ha,
            snat_bound_fip=True,
            enable_gw=True,
            qos_policy_id=TEST_POLICY_ID1)
        ri = self.manage_router(self.agent, router_info)
        self._assert_bandwidth_limit_rule_is_set(
            ri, '19.4.4.2', self.test_bw_limit_rule_1)
        self._assert_bandwidth_limit_rule_is_set(
            ri, '19.4.4.2', self.test_bw_limit_rule_2)

    def test_dvr_dvr_fip_snat_qos(self):
        self._test_dvr_fip_snat_bound_agent_mode_dvr_snat()

    def test_ha_dvr_dvr_fip_snat_qos(self):
        self._test_dvr_fip_snat_bound_agent_mode_dvr_snat(enable_ha=True)

    def _assert_dvr_snat_qrouter_ns_rule_is_set(self, device, ip, rule):
        tc_wrapper = self.fip_qos_ext._get_tc_wrapper(device)

        def get_filter_id():
            try:
                return tc_wrapper.get_filter_id_for_ip(rule.direction, ip)
            except exceptions.FilterIDForIPNotFound:
                pass

        common_utils.wait_until_true(get_filter_id)

    def test_dvr_snat_qos_rules_set_in_qrouter(self):
        self.agent.conf.agent_mode = constants.L3_AGENT_MODE_DVR_SNAT
        router_info = self.generate_dvr_router_info(
            enable_snat=True,
            enable_gw=True,
            enable_floating_ip=True,
            qos_policy_id=TEST_POLICY_ID1)
        ri = self.manage_router(self.agent, router_info)

        gw_port = ri.get_ex_gw_port()
        rfp_dev_name = ri.get_external_device_interface_name(gw_port)
        if ri.router_namespace.exists():
            dvr_fip_device = ip_lib.IPDevice(
                    rfp_dev_name, namespace=ri.ns_name)
            self._assert_dvr_snat_qrouter_ns_rule_is_set(
                dvr_fip_device, '19.4.4.2', self.test_bw_limit_rule_1)
            self._assert_dvr_snat_qrouter_ns_rule_is_set(
                dvr_fip_device, '19.4.4.2', self.test_bw_limit_rule_2)
