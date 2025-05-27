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

from unittest import mock

from neutron_lib import constants
from neutron_lib import exceptions
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as neutron_l3_agent
from neutron.agent.l3.extensions.qos import gateway_ip as gateway_ip_qos
from neutron.common import utils as common_utils
from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.tests.functional.agent.l3 import framework
from neutron.tests.functional.agent.l3 import test_dvr_router

_uuid = uuidutils.generate_uuid
INGRESS_EGRESS_POLICY_ID = _uuid()
INGRESS_POLICY_ID = _uuid()
EGRESS_POLICY_ID = _uuid()


class RouterGatewayIPQosAgentExtensionTestFramework(
        framework.L3AgentTestFramework):

    test_bw_limit_rule_1 = rule.QosBandwidthLimitRule(
            context=None,
            qos_policy_id=INGRESS_EGRESS_POLICY_ID,
            id=_uuid(),
            max_kbps=111,
            max_burst_kbps=222,
            direction=constants.INGRESS_DIRECTION)
    test_bw_limit_rule_2 = rule.QosBandwidthLimitRule(
            context=None,
            qos_policy_id=INGRESS_EGRESS_POLICY_ID,
            id=_uuid(),
            max_kbps=333,
            max_burst_kbps=444,
            direction=constants.EGRESS_DIRECTION)
    test_bw_limit_rule_3 = rule.QosBandwidthLimitRule(
            context=None,
            qos_policy_id=INGRESS_POLICY_ID,
            id=_uuid(),
            max_kbps=555,
            max_burst_kbps=666,
            direction=constants.INGRESS_DIRECTION)
    test_bw_limit_rule_4 = rule.QosBandwidthLimitRule(
            context=None,
            qos_policy_id=EGRESS_POLICY_ID,
            id=_uuid(),
            max_kbps=777,
            max_burst_kbps=888,
            direction=constants.EGRESS_DIRECTION)

    def setUp(self):
        super().setUp()
        self.conf.set_override('extensions', ['gateway_ip_qos'], 'agent')
        self.agent = neutron_l3_agent.L3NATAgentWithStateReport('agent1',
                                                                self.conf)
        self.agent.init_host()
        self._set_pull_mock()
        self.set_test_qos_rules(INGRESS_EGRESS_POLICY_ID,
                                [self.test_bw_limit_rule_1,
                                 self.test_bw_limit_rule_2])
        self.set_test_qos_rules(INGRESS_POLICY_ID,
                                [self.test_bw_limit_rule_3])
        self.set_test_qos_rules(EGRESS_POLICY_ID,
                                [self.test_bw_limit_rule_4])
        self.gateway_ip_qos_ext = (
            gateway_ip_qos.RouterGatewayIPQosAgentExtension())

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
        ex_gw_port = router.get_ex_gw_port()
        interface_name = router.get_external_device_name(ex_gw_port['id'])
        device = self.gateway_ip_qos_ext._get_gateway_tc_rule_device(
            router, interface_name)
        tc_wrapper = self.gateway_ip_qos_ext._get_tc_wrapper(device)

        def get_filter_id():
            try:
                return tc_wrapper.get_filter_id_for_ip(rule.direction, ip)
            except exceptions.FilterIDForIPNotFound:
                pass

        common_utils.wait_until_true(get_filter_id)


class TestRouterGatewayIPQosAgentExtension(
        RouterGatewayIPQosAgentExtensionTestFramework):

    def _test_centralized_routers(self, enable_ha=False,
                                  ingress=True, egress=True):
        qos_policy_id = INGRESS_EGRESS_POLICY_ID
        if ingress and not egress:
            qos_policy_id = INGRESS_POLICY_ID
        elif egress and not ingress:
            qos_policy_id = EGRESS_POLICY_ID
        router_info = self.generate_router_info(
            enable_ha=enable_ha,
            qos_policy_id=qos_policy_id)
        ri = self.manage_router(self.agent, router_info)
        if qos_policy_id == INGRESS_EGRESS_POLICY_ID:
            self._assert_bandwidth_limit_rule_is_set(
                ri, '19.4.4.4', self.test_bw_limit_rule_1)
            self._assert_bandwidth_limit_rule_is_set(
                ri, '19.4.4.4', self.test_bw_limit_rule_2)
        elif qos_policy_id == INGRESS_POLICY_ID:
            self._assert_bandwidth_limit_rule_is_set(
                ri, '19.4.4.4', self.test_bw_limit_rule_3)
        elif qos_policy_id == EGRESS_POLICY_ID:
            self._assert_bandwidth_limit_rule_is_set(
                ri, '19.4.4.4', self.test_bw_limit_rule_4)

    def test_legacy_router_gateway_ip_qos(self):
        self._test_centralized_routers()

    def test_legacy_router_gateway_ip_qos_ingress(self):
        self._test_centralized_routers(ingress=True, egress=False)

    def test_legacy_router_gateway_ip_qos_egress(self):
        self._test_centralized_routers(ingress=False, egress=True)

    def test_ha_router_gateway_ip_qos(self):
        self._test_centralized_routers(enable_ha=True)

    def test_ha_router_gateway_ip_qos_ingress(self):
        self._test_centralized_routers(enable_ha=True,
                                       ingress=True, egress=False)

    def test_ha_router_gateway_ip_qos_egress(self):
        self._test_centralized_routers(enable_ha=True,
                                       ingress=False, egress=True)


class TestRouterGatewayIPQosAgentExtensionDVR(
        test_dvr_router.TestDvrRouter,
        RouterGatewayIPQosAgentExtensionTestFramework):

    def _test_dvr_gateway_ip_qos(self, enable_ha=False):
        self.agent.conf.agent_mode = constants.L3_AGENT_MODE_DVR_SNAT
        router_info = self.generate_dvr_router_info(
            enable_ha=enable_ha, enable_snat=True,
            enable_gw=True, qos_policy_id=INGRESS_EGRESS_POLICY_ID)
        ri = self.manage_router(self.agent, router_info)
        self._assert_bandwidth_limit_rule_is_set(
            ri, '19.4.4.4', self.test_bw_limit_rule_1)
        self._assert_bandwidth_limit_rule_is_set(
            ri, '19.4.4.4', self.test_bw_limit_rule_2)

    def test_dvr_edge_router_gateway_ip_qos(self):
        self._test_dvr_gateway_ip_qos()

    def test_ha_dvr_edge_router_gateway_ip_qos(self):
        self._test_dvr_gateway_ip_qos(enable_ha=True)
