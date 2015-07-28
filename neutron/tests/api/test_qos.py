# Copyright 2015 Red Hat, Inc.
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

from neutron.services.qos import qos_consts
from neutron.tests.api import base
from neutron.tests.tempest import config
from neutron.tests.tempest import test

CONF = config.CONF


class QosTestJSON(base.BaseAdminNetworkTest):
    @classmethod
    def resource_setup(cls):
        super(QosTestJSON, cls).resource_setup()
        if not test.is_extension_enabled('qos', 'network'):
            msg = "qos extension not enabled."
            raise cls.skipException(msg)

    @test.attr(type='smoke')
    @test.idempotent_id('108fbdf7-3463-4e47-9871-d07f3dcf5bbb')
    def test_create_policy(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy desc',
                                        shared=False)

        # Test 'show policy'
        retrieved_policy = self.admin_client.show_qos_policy(policy['id'])
        retrieved_policy = retrieved_policy['policy']
        self.assertEqual('test-policy', retrieved_policy['name'])
        self.assertEqual('test policy desc', retrieved_policy['description'])
        self.assertEqual(False, retrieved_policy['shared'])

        # Test 'list policies'
        policies = self.admin_client.list_qos_policies()['policies']
        policies_ids = [p['id'] for p in policies]
        self.assertIn(policy['id'], policies_ids)

    @test.attr(type='smoke')
    @test.idempotent_id('8a59b00b-3e9c-4787-92f8-93a5cdf5e378')
    def test_create_rule(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.create_qos_bandwidth_limit_rule(policy_id=policy['id'],
                                                    max_kbps=200,
                                                    max_burst_kbps=1337)

        # Test 'show rule'
        retrieved_policy = self.admin_client.show_bandwidth_limit_rule(
            policy['id'], rule['id'])
        retrieved_policy = retrieved_policy['bandwidth_limit_rule']
        self.assertEqual(rule['id'], retrieved_policy['id'])
        self.assertEqual(200, retrieved_policy['max_kbps'])
        self.assertEqual(1337, retrieved_policy['max_burst_kbps'])

        # Test 'list rules'
        rules = self.admin_client.list_bandwidth_limit_rules(policy['id'])
        rules = rules['bandwidth_limit_rules']
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule['id'], rules_ids)

    @test.attr(type='smoke')
    @test.idempotent_id('cf776f77-8d3d-49f2-8572-12d6a1557224')
    def test_list_rule_types(self):
        # List supported rule types
        expected_rule_types = qos_consts.VALID_RULE_TYPES
        expected_rule_details = ['type']

        rule_types = self.admin_client.list_qos_rule_types()
        actual_list_rule_types = rule_types['rule_types']
        actual_rule_types = [rule['type'] for rule in actual_list_rule_types]

        # Verify that only required fields present in rule details
        for rule in actual_list_rule_types:
            self.assertEqual(tuple(rule.keys()), tuple(expected_rule_details))

        # Verify if expected rules are present in the actual rules list
        for rule in expected_rule_types:
            self.assertIn(rule, actual_rule_types)

    #TODO(QoS): policy update (name)
    #TODO(QoS): create several bandwidth-limit rules (not sure it makes sense,
    #           but to test more than one rule)
    #TODO(QoS): update bandwidth-limit rule
    #TODO(QoS): associate/disassociate policy with network
    #TODO(QoS): associate/disassociate policy with port
