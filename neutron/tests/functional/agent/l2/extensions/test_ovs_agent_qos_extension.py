# Copyright (c) 2015 Red Hat, Inc.
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

import mock

from oslo_utils import uuidutils

from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.tests.functional.agent.l2 import base


TEST_POLICY_ID1 = "a2d72369-4246-4f19-bd3c-af51ec8d70cd"
TEST_POLICY_ID2 = "46ebaec0-0570-43ac-82f6-60d2b03168c5"
TEST_BW_LIMIT_RULE_1 = rule.QosBandwidthLimitRule(
        context=None,
        id="5f126d84-551a-4dcf-bb01-0e9c0df0c793",
        max_kbps=1000,
        max_burst_kbps=10)
TEST_BW_LIMIT_RULE_2 = rule.QosBandwidthLimitRule(
        context=None,
        id="fa9128d9-44af-49b2-99bb-96548378ad42",
        max_kbps=900,
        max_burst_kbps=9)


class OVSAgentQoSExtensionTestFramework(base.OVSAgentTestFramework):
    def setUp(self):
        super(OVSAgentQoSExtensionTestFramework, self).setUp()
        self.config.set_override('extensions', ['qos'], 'agent')
        self._set_pull_mock()

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
            tenant_id=uuidutils.generate_uuid(),
            id=policy_id,
            name="Test Policy Name",
            description="This is a policy for testing purposes",
            shared=False,
            rules=policy_rules)

        qos_policy.obj_reset_changes()
        self.qos_policies[policy_id] = qos_policy

    def _create_test_port_dict(self, policy_id=None):
        port_dict = super(OVSAgentQoSExtensionTestFramework,
                          self)._create_test_port_dict()
        port_dict['qos_policy_id'] = policy_id
        return port_dict

    def _get_device_details(self, port, network):
        dev = super(OVSAgentQoSExtensionTestFramework,
                    self)._get_device_details(port, network)
        dev['qos_policy_id'] = port['qos_policy_id']
        return dev

    def _assert_bandwidth_limit_rule_is_set(self, port, rule):
        max_rate, burst = (
            self.agent.int_br.get_qos_bw_limit_for_port(port['vif_name']))
        self.assertEqual(max_rate, rule.max_kbps)
        self.assertEqual(burst, rule.max_burst_kbps)

    def _assert_bandwidth_limit_rule_not_set(self, port):
        max_rate, burst = (
            self.agent.int_br.get_qos_bw_limit_for_port(port['vif_name']))
        self.assertIsNone(max_rate)
        self.assertIsNone(burst)


class TestOVSAgentQosExtension(OVSAgentQoSExtensionTestFramework):

    def test_port_creation_with_bandwidth_limit(self):
        """Make sure bandwidth limit rules are set in low level to ports."""

        self.set_test_qos_rules(TEST_POLICY_ID1, [TEST_BW_LIMIT_RULE_1])

        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports(amount=1,
                                              policy_id=TEST_POLICY_ID1))
        self.wait_until_ports_state(self.ports, up=True)

        for port in self.ports:
            self._assert_bandwidth_limit_rule_is_set(
                port, TEST_BW_LIMIT_RULE_1)

    def test_port_creation_with_different_bandwidth_limits(self):
        """Make sure different types of policies end on the right ports."""

        self.set_test_qos_rules(TEST_POLICY_ID1, [TEST_BW_LIMIT_RULE_1])
        self.set_test_qos_rules(TEST_POLICY_ID2, [TEST_BW_LIMIT_RULE_2])

        port_dicts = self.create_test_ports(amount=3)

        port_dicts[0]['qos_policy_id'] = TEST_POLICY_ID1
        port_dicts[1]['qos_policy_id'] = TEST_POLICY_ID2

        self.setup_agent_and_ports(port_dicts)
        self.wait_until_ports_state(self.ports, up=True)

        self._assert_bandwidth_limit_rule_is_set(self.ports[0],
                                                 TEST_BW_LIMIT_RULE_1)

        self._assert_bandwidth_limit_rule_is_set(self.ports[1],
                                                 TEST_BW_LIMIT_RULE_2)

        self._assert_bandwidth_limit_rule_not_set(self.ports[2])
