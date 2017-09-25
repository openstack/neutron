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

import copy

import mock
from neutron_lib import constants
from oslo_utils import uuidutils
import testscenarios

from neutron.api.rpc.callbacks.consumer import registry as consumer_reg
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.tests.common.agents import l2_extensions
from neutron.tests.functional.agent.l2 import base
from neutron.tests.functional.agent.linux import base as linux_base


load_tests = testscenarios.load_tests_apply_scenarios

TEST_POLICY_ID1 = "a2d72369-4246-4f19-bd3c-af51ec8d70cd"
TEST_POLICY_ID2 = "46ebaec0-0570-43ac-82f6-60d2b03168c5"
TEST_DSCP_MARK_1 = 14
TEST_DSCP_MARK_2 = 30


class OVSAgentQoSExtensionTestFramework(base.OVSAgentTestFramework):

    test_dscp_marking_rule_1 = rule.QosDscpMarkingRule(
            context=None,
            qos_policy_id=TEST_POLICY_ID1,
            id="9f126d84-551a-4dcf-bb01-0e9c0df0c793",
            dscp_mark=TEST_DSCP_MARK_1)
    test_dscp_marking_rule_2 = rule.QosDscpMarkingRule(
            context=None,
            qos_policy_id=TEST_POLICY_ID2,
            id="7f126d84-551a-4dcf-bb01-0e9c0df0c793",
            dscp_mark=TEST_DSCP_MARK_2)
    test_bw_limit_rule_1 = rule.QosBandwidthLimitRule(
            context=None,
            qos_policy_id=TEST_POLICY_ID1,
            id="5f126d84-551a-4dcf-bb01-0e9c0df0c793",
            max_kbps=1000,
            max_burst_kbps=10)
    test_bw_limit_rule_2 = rule.QosBandwidthLimitRule(
            context=None,
            qos_policy_id=TEST_POLICY_ID2,
            id="fa9128d9-44af-49b2-99bb-96548378ad42",
            max_kbps=900,
            max_burst_kbps=9)

    def setUp(self):
        super(OVSAgentQoSExtensionTestFramework, self).setUp()
        self.config.set_override('extensions', ['qos'], 'agent')
        self._set_pull_mock()
        self.set_test_qos_rules(TEST_POLICY_ID1,
                                [self.test_bw_limit_rule_1,
                                self.test_dscp_marking_rule_1])
        self.set_test_qos_rules(TEST_POLICY_ID2,
                                [self.test_bw_limit_rule_2,
                                self.test_dscp_marking_rule_2])

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
            project_id=uuidutils.generate_uuid(),
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
        port_dict['network_qos_policy_id'] = None
        return port_dict

    def _get_device_details(self, port, network):
        dev = super(OVSAgentQoSExtensionTestFramework,
                    self)._get_device_details(port, network)
        dev['qos_policy_id'] = port['qos_policy_id']
        return dev

    def _assert_bandwidth_limit_rule_is_set(self, port, rule):
        if rule.direction == constants.INGRESS_DIRECTION:
            max_rate, burst = (
                self.agent.int_br.get_ingress_bw_limit_for_port(
                    port['vif_name']))
        else:
            max_rate, burst = (
                self.agent.int_br.get_egress_bw_limit_for_port(
                    port['vif_name']))
        self.assertEqual(max_rate, rule.max_kbps)
        self.assertEqual(burst, rule.max_burst_kbps)

    def _assert_bandwidth_limit_rule_not_set(self, port, rule_direction):
        if rule_direction == constants.INGRESS_DIRECTION:
            max_rate, burst = (
                self.agent.int_br.get_ingress_bw_limit_for_port(
                    port['vif_name']))
        else:
            max_rate, burst = (
                self.agent.int_br.get_egress_bw_limit_for_port(
                    port['vif_name']))
        self.assertIsNone(max_rate)
        self.assertIsNone(burst)

    def wait_until_bandwidth_limit_rule_applied(self, port, rule):
        if rule and rule.direction == constants.INGRESS_DIRECTION:
            l2_extensions.wait_until_ingress_bandwidth_limit_rule_applied(
                self.agent.int_br, port['vif_name'], rule)
        else:
            l2_extensions.wait_until_egress_bandwidth_limit_rule_applied(
                self.agent.int_br, port['vif_name'], rule)

    def _assert_dscp_marking_rule_is_set(self, port, dscp_rule):
        port_num = self.agent.int_br._get_port_val(port['vif_name'], 'ofport')

        flows = self.agent.int_br.dump_flows_for(table='0',
                                                 in_port=str(port_num))
        tos_mark = l2_extensions.extract_mod_nw_tos_action(flows)
        self.assertEqual(dscp_rule.dscp_mark << 2, tos_mark)

    def _assert_dscp_marking_rule_not_set(self, port):
        port_num = self.agent.int_br._get_port_val(port['vif_name'], 'ofport')

        flows = self.agent.int_br.dump_flows_for(table='0',
                                                 in_port=str(port_num))

        tos_mark = l2_extensions.extract_mod_nw_tos_action(flows)
        self.assertIsNone(tos_mark)

    def wait_until_dscp_marking_rule_applied(self, port, dscp_mark):
        l2_extensions.wait_until_dscp_marking_rule_applied_ovs(
            self.agent.int_br, port['vif_name'], dscp_mark)

    def _create_port_with_qos(self):
        port_dict = self._create_test_port_dict()
        port_dict['qos_policy_id'] = TEST_POLICY_ID1
        self.setup_agent_and_ports([port_dict])
        self.wait_until_ports_state(self.ports, up=True)
        self.wait_until_bandwidth_limit_rule_applied(port_dict,
                                                     self.test_bw_limit_rule_1)
        return port_dict


class TestOVSAgentQosExtension(OVSAgentQoSExtensionTestFramework):

    interface_scenarios = linux_base.BaseOVSLinuxTestCase.scenarios

    direction_scenarios = [
        ('ingress', {'direction': constants.INGRESS_DIRECTION}),
        ('egress', {'direction': constants.EGRESS_DIRECTION})
    ]

    scenarios = testscenarios.multiply_scenarios(
        interface_scenarios, direction_scenarios)

    def setUp(self):
        super(TestOVSAgentQosExtension, self).setUp()
        self.test_bw_limit_rule_1.direction = self.direction
        self.test_bw_limit_rule_2.direction = self.direction

    @property
    def reverse_direction(self):
        if self.direction == constants.INGRESS_DIRECTION:
            return constants.EGRESS_DIRECTION
        elif self.direction == constants.EGRESS_DIRECTION:
            return constants.INGRESS_DIRECTION

    def test_port_creation_with_bandwidth_limit(self):
        """Make sure bandwidth limit rules are set in low level to ports."""

        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports(amount=1,
                                              policy_id=TEST_POLICY_ID1))
        self.wait_until_ports_state(self.ports, up=True)

        for port in self.ports:
            self._assert_bandwidth_limit_rule_is_set(
                port, self.test_bw_limit_rule_1)

    def test_port_creation_with_bandwidth_limits_both_directions(self):
        """Make sure bandwidth limit rules are set in low level to ports.

        This test is checking applying rules for both possible
        directions at once
        """

        reverse_direction_bw_limit_rule = copy.deepcopy(
            self.test_bw_limit_rule_1)
        reverse_direction_bw_limit_rule.direction = self.reverse_direction
        self.qos_policies[TEST_POLICY_ID1].rules.append(
            reverse_direction_bw_limit_rule)

        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports(amount=1,
                                              policy_id=TEST_POLICY_ID1))
        self.wait_until_ports_state(self.ports, up=True)

        for port in self.ports:
            self._assert_bandwidth_limit_rule_is_set(
                port, self.test_bw_limit_rule_1)
            self._assert_bandwidth_limit_rule_is_set(
                port, reverse_direction_bw_limit_rule)

    def test_port_creation_with_different_bandwidth_limits(self):
        """Make sure different types of policies end on the right ports."""

        port_dicts = self.create_test_ports(amount=3)

        port_dicts[0]['qos_policy_id'] = TEST_POLICY_ID1
        port_dicts[1]['qos_policy_id'] = TEST_POLICY_ID2

        self.setup_agent_and_ports(port_dicts)
        self.wait_until_ports_state(self.ports, up=True)

        self._assert_bandwidth_limit_rule_is_set(self.ports[0],
                                                 self.test_bw_limit_rule_1)

        self._assert_bandwidth_limit_rule_is_set(self.ports[1],
                                                 self.test_bw_limit_rule_2)

        self._assert_bandwidth_limit_rule_not_set(self.ports[2],
                                                  self.direction)

    def test_port_creation_with_dscp_marking(self):
        """Make sure dscp marking rules are set in low level to ports."""

        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports(amount=1,
                                              policy_id=TEST_POLICY_ID1))
        self.wait_until_ports_state(self.ports, up=True)

        for port in self.ports:
            self._assert_dscp_marking_rule_is_set(
                port, self.test_dscp_marking_rule_1)

    def test_port_creation_with_different_dscp_markings(self):
        """Make sure different types of policies end on the right ports."""

        port_dicts = self.create_test_ports(amount=3)

        port_dicts[0]['qos_policy_id'] = TEST_POLICY_ID1
        port_dicts[1]['qos_policy_id'] = TEST_POLICY_ID2

        self.setup_agent_and_ports(port_dicts)
        self.wait_until_ports_state(self.ports, up=True)

        self._assert_dscp_marking_rule_is_set(self.ports[0],
                                              self.test_dscp_marking_rule_1)

        self._assert_dscp_marking_rule_is_set(self.ports[1],
                                              self.test_dscp_marking_rule_2)

        self._assert_dscp_marking_rule_not_set(self.ports[2])

    def test_simple_port_policy_update(self):
        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports(amount=1,
                                              policy_id=TEST_POLICY_ID1))
        self.wait_until_ports_state(self.ports, up=True)
        self._assert_dscp_marking_rule_is_set(self.ports[0],
                                              self.test_dscp_marking_rule_1)
        policy_copy = copy.deepcopy(self.qos_policies[TEST_POLICY_ID1])
        policy_copy.rules[0].max_kbps = 500
        policy_copy.rules[0].max_burst_kbps = 5
        policy_copy.rules[1].dscp_mark = TEST_DSCP_MARK_2
        context = mock.Mock()
        consumer_reg.push(context, resources.QOS_POLICY,
                          [policy_copy], events.UPDATED)
        self.wait_until_bandwidth_limit_rule_applied(self.ports[0],
                                                     policy_copy.rules[0])
        self._assert_bandwidth_limit_rule_is_set(self.ports[0],
                                                 policy_copy.rules[0])
        self._assert_dscp_marking_rule_is_set(self.ports[0],
                                              self.test_dscp_marking_rule_2)

    def test_simple_port_policy_update_change_bw_limit_direction(self):
        self.setup_agent_and_ports(
            port_dicts=self.create_test_ports(amount=1,
                                              policy_id=TEST_POLICY_ID1))
        self.wait_until_ports_state(self.ports, up=True)

        self._assert_bandwidth_limit_rule_is_set(self.ports[0],
                                                 self.test_bw_limit_rule_1)
        self._assert_bandwidth_limit_rule_not_set(self.ports[0],
                                                  self.reverse_direction)

        policy_copy = copy.deepcopy(self.qos_policies[TEST_POLICY_ID1])
        policy_copy.rules[0].direction = self.reverse_direction
        context = mock.Mock()
        consumer_reg.push(context, resources.QOS_POLICY,
                          [policy_copy], events.UPDATED)
        self.wait_until_bandwidth_limit_rule_applied(self.ports[0],
                                                     policy_copy.rules[0])

        self._assert_bandwidth_limit_rule_not_set(self.ports[0],
                                                  self.direction)
        self._assert_bandwidth_limit_rule_is_set(self.ports[0],
                                                 policy_copy.rules[0])

    def test_port_qos_disassociation(self):
        """Test that qos_policy_id set to None will remove all qos rules from
           given port.
        """
        port_dict = self._create_port_with_qos()

        port_dict['qos_policy_id'] = None
        self.agent.port_update(None, port=port_dict)

        self.wait_until_bandwidth_limit_rule_applied(port_dict, None)

    def test_port_qos_update_policy_id(self):
        """Test that change of qos policy id on given port refreshes all its
           rules.
        """
        port_dict = self._create_port_with_qos()

        port_dict['qos_policy_id'] = TEST_POLICY_ID2
        self.agent.port_update(None, port=port_dict)

        self.wait_until_bandwidth_limit_rule_applied(port_dict,
                                                     self.test_bw_limit_rule_2)

    def test_policy_rule_delete(self):
        port_dict = self._create_port_with_qos()

        policy_copy = copy.deepcopy(self.qos_policies[TEST_POLICY_ID1])
        policy_copy.rules = list()
        context = mock.Mock()
        consumer_reg.push(context, resources.QOS_POLICY, [policy_copy],
                          events.UPDATED)

        self.wait_until_bandwidth_limit_rule_applied(port_dict, None)
