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

from tempest_lib import exceptions

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
                                        description='test policy desc1',
                                        shared=False)

        # Test 'show policy'
        retrieved_policy = self.admin_client.show_qos_policy(policy['id'])
        retrieved_policy = retrieved_policy['policy']
        self.assertEqual('test-policy', retrieved_policy['name'])
        self.assertEqual('test policy desc1', retrieved_policy['description'])
        self.assertFalse(retrieved_policy['shared'])

        # Test 'list policies'
        policies = self.admin_client.list_qos_policies()['policies']
        policies_ids = [p['id'] for p in policies]
        self.assertIn(policy['id'], policies_ids)

    @test.attr(type='smoke')
    @test.idempotent_id('f8d20e92-f06d-4805-b54f-230f77715815')
    def test_list_policy_filter_by_name(self):
        self.create_qos_policy(name='test', description='test policy',
                               shared=False)
        self.create_qos_policy(name='test2', description='test policy',
                               shared=False)

        policies = (self.admin_client.
                    list_qos_policies(name='test')['policies'])
        self.assertEqual(1, len(policies))

        retrieved_policy = policies[0]
        self.assertEqual('test', retrieved_policy['name'])

    @test.attr(type='smoke')
    @test.idempotent_id('8e88a54b-f0b2-4b7d-b061-a15d93c2c7d6')
    def test_policy_update(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='',
                                        shared=False)
        self.admin_client.update_qos_policy(policy['id'],
                                            description='test policy desc2',
                                            shared=True)

        retrieved_policy = self.admin_client.show_qos_policy(policy['id'])
        retrieved_policy = retrieved_policy['policy']
        self.assertEqual('test policy desc2', retrieved_policy['description'])
        self.assertTrue(retrieved_policy['shared'])
        self.assertEqual([], retrieved_policy['rules'])

    @test.attr(type='smoke')
    @test.idempotent_id('1cb42653-54bd-4a9a-b888-c55e18199201')
    def test_delete_policy(self):
        policy = self.admin_client.create_qos_policy(
            'test-policy', 'desc', True)['policy']

        retrieved_policy = self.admin_client.show_qos_policy(policy['id'])
        retrieved_policy = retrieved_policy['policy']
        self.assertEqual('test-policy', retrieved_policy['name'])

        self.admin_client.delete_qos_policy(policy['id'])
        self.assertRaises(exceptions.NotFound,
                          self.admin_client.show_qos_policy, policy['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('cf776f77-8d3d-49f2-8572-12d6a1557224')
    def test_list_rule_types(self):
        # List supported rule types
        # TODO(QoS): since in gate we run both ovs and linuxbridge ml2 drivers,
        # and since Linux Bridge ml2 driver does not have QoS support yet, ml2
        # plugin reports no rule types are supported. Once linuxbridge will
        # receive support for QoS, the list of expected rule types will change.
        #
        # In theory, we could make the test conditional on which ml2 drivers
        # are enabled in gate (or more specifically, on which supported qos
        # rules are claimed by core plugin), but that option doesn't seem to be
        # available thru tempest_lib framework
        expected_rule_types = []
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

    def _disassociate_network(self, client, network_id):
        client.update_network(network_id, qos_policy_id=None)
        updated_network = self.admin_client.show_network(network_id)
        self.assertIsNone(updated_network['network']['qos_policy_id'])

    @test.attr(type='smoke')
    @test.idempotent_id('65b9ef75-1911-406a-bbdb-ca1d68d528b0')
    def test_policy_association_with_admin_network(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        network = self.create_shared_network('test network',
                                             qos_policy_id=policy['id'])

        retrieved_network = self.admin_client.show_network(network['id'])
        self.assertEqual(
            policy['id'], retrieved_network['network']['qos_policy_id'])

        self._disassociate_network(self.admin_client, network['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('1738de5d-0476-4163-9022-5e1b548c208e')
    def test_policy_association_with_tenant_network(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        network = self.create_network('test network',
                                      qos_policy_id=policy['id'])

        retrieved_network = self.admin_client.show_network(network['id'])
        self.assertEqual(
            policy['id'], retrieved_network['network']['qos_policy_id'])

        self._disassociate_network(self.client, network['id'])

#    @test.attr(type='smoke')
#    @test.idempotent_id('1aa55a79-324f-47d9-a076-894a8fc2448b')
#    def test_policy_association_with_network_non_shared_policy(self):
#        policy = self.create_qos_policy(name='test-policy',
#                                        description='test policy',
#                                        shared=False)
#        #TODO(QoS): This currently raises an exception on the server side. See
#        #           core_extensions/qos.py for comments on this subject.
#        network = self.create_network('test network',
#                                      qos_policy_id=policy['id'])
#
#        retrieved_network = self.admin_client.show_network(network['id'])
#        self.assertIsNone(retrieved_network['network']['qos_policy_id'])

    @test.attr(type='smoke')
    @test.idempotent_id('09a9392c-1359-4cbb-989f-fb768e5834a8')
    def test_policy_update_association_with_admin_network(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        network = self.create_shared_network('test network')
        retrieved_network = self.admin_client.show_network(network['id'])
        self.assertIsNone(retrieved_network['network']['qos_policy_id'])

        self.admin_client.update_network(network['id'],
                                         qos_policy_id=policy['id'])
        retrieved_network = self.admin_client.show_network(network['id'])
        self.assertEqual(
            policy['id'], retrieved_network['network']['qos_policy_id'])

        self._disassociate_network(self.admin_client, network['id'])

    def _disassociate_port(self, port_id):
        self.client.update_port(port_id, qos_policy_id=None)
        updated_port = self.admin_client.show_port(port_id)
        self.assertIsNone(updated_port['port']['qos_policy_id'])

    @test.attr(type='smoke')
    @test.idempotent_id('98fcd95e-84cf-4746-860e-44692e674f2e')
    def test_policy_association_with_port_shared_policy(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        network = self.create_shared_network('test network')
        port = self.create_port(network, qos_policy_id=policy['id'])

        retrieved_port = self.admin_client.show_port(port['id'])
        self.assertEqual(
            policy['id'], retrieved_port['port']['qos_policy_id'])

        self._disassociate_port(port['id'])

#    @test.attr(type='smoke')
#    @test.idempotent_id('f53d961c-9fe5-4422-8b66-7add972c6031')
#    def test_policy_association_with_port_non_shared_policy(self):
#        policy = self.create_qos_policy(name='test-policy',
#                                        description='test policy',
#                                        shared=False)
#        network = self.create_shared_network('test network')
#        #TODO(QoS): This currently raises an exception on the server side. See
#        #           core_extensions/qos.py for comments on this subject.
#        port = self.create_port(network, qos_policy_id=policy['id'])
#
#        retrieved_port = self.admin_client.show_port(port['id'])
#        self.assertIsNone(retrieved_port['port']['qos_policy_id'])

    @test.attr(type='smoke')
    @test.idempotent_id('f8163237-fba9-4db5-9526-bad6d2343c76')
    def test_policy_update_association_with_port_shared_policy(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        network = self.create_shared_network('test network')
        port = self.create_port(network)
        retrieved_port = self.admin_client.show_port(port['id'])
        self.assertIsNone(retrieved_port['port']['qos_policy_id'])

        self.client.update_port(port['id'], qos_policy_id=policy['id'])
        retrieved_port = self.admin_client.show_port(port['id'])
        self.assertEqual(
            policy['id'], retrieved_port['port']['qos_policy_id'])

        self._disassociate_port(port['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('18163237-8ba9-4db5-9525-bad6d2343c75')
    def test_delete_not_allowed_if_policy_in_use_by_network(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        network = self.create_shared_network(
            'test network', qos_policy_id=policy['id'])
        self.assertRaises(
            exceptions.Conflict,
            self.admin_client.delete_qos_policy, policy['id'])

        self._disassociate_network(self.admin_client, network['id'])
        self.admin_client.delete_qos_policy(policy['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('24153230-84a9-4dd5-9525-bad6d2343c75')
    def test_delete_not_allowed_if_policy_in_use_by_port(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        network = self.create_shared_network('test network')
        port = self.create_port(network, qos_policy_id=policy['id'])
        self.assertRaises(
            exceptions.Conflict,
            self.admin_client.delete_qos_policy, policy['id'])

        self._disassociate_port(port['id'])
        self.admin_client.delete_qos_policy(policy['id'])


class QosBandwidthLimitRuleTestJSON(base.BaseAdminNetworkTest):
    @classmethod
    def resource_setup(cls):
        super(QosBandwidthLimitRuleTestJSON, cls).resource_setup()
        if not test.is_extension_enabled('qos', 'network'):
            msg = "qos extension not enabled."
            raise cls.skipException(msg)

    @test.attr(type='smoke')
    @test.idempotent_id('8a59b00b-3e9c-4787-92f8-93a5cdf5e378')
    def test_rule_create(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.create_qos_bandwidth_limit_rule(policy_id=policy['id'],
                                                    max_kbps=200,
                                                    max_burst_kbps=1337)

        # Test 'show rule'
        retrieved_rule = self.admin_client.show_bandwidth_limit_rule(
            policy['id'], rule['id'])
        retrieved_rule = retrieved_rule['bandwidth_limit_rule']
        self.assertEqual(rule['id'], retrieved_rule['id'])
        self.assertEqual(200, retrieved_rule['max_kbps'])
        self.assertEqual(1337, retrieved_rule['max_burst_kbps'])

        # Test 'list rules'
        rules = self.admin_client.list_bandwidth_limit_rules(policy['id'])
        rules = rules['bandwidth_limit_rules']
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule['id'], rules_ids)

        # Test 'show policy'
        retrieved_policy = self.admin_client.show_qos_policy(policy['id'])
        policy_rules = retrieved_policy['policy']['rules']
        self.assertEqual(1, len(policy_rules))
        self.assertEqual(rule['id'], policy_rules[0]['id'])
        self.assertEqual(qos_consts.RULE_TYPE_BANDWIDTH_LIMIT,
                         policy_rules[0]['type'])

    @test.attr(type='smoke')
    @test.idempotent_id('8a59b00b-ab01-4787-92f8-93a5cdf5e378')
    def test_rule_create_fail_for_the_same_type(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.create_qos_bandwidth_limit_rule(policy_id=policy['id'],
                                             max_kbps=200,
                                             max_burst_kbps=1337)

        self.assertRaises(exceptions.Conflict,
                          self.create_qos_bandwidth_limit_rule,
                          policy_id=policy['id'],
                          max_kbps=201, max_burst_kbps=1338)

    @test.attr(type='smoke')
    @test.idempotent_id('149a6988-2568-47d2-931e-2dbc858943b3')
    def test_rule_update(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.create_qos_bandwidth_limit_rule(policy_id=policy['id'],
                                                    max_kbps=1,
                                                    max_burst_kbps=1)

        self.admin_client.update_bandwidth_limit_rule(policy['id'],
                                                      rule['id'],
                                                      max_kbps=200,
                                                      max_burst_kbps=1337)

        retrieved_policy = self.admin_client.show_bandwidth_limit_rule(
            policy['id'], rule['id'])
        retrieved_policy = retrieved_policy['bandwidth_limit_rule']
        self.assertEqual(200, retrieved_policy['max_kbps'])
        self.assertEqual(1337, retrieved_policy['max_burst_kbps'])

    @test.attr(type='smoke')
    @test.idempotent_id('67ee6efd-7b33-4a68-927d-275b4f8ba958')
    def test_rule_delete(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.admin_client.create_bandwidth_limit_rule(
            policy['id'], 200, 1337)['bandwidth_limit_rule']

        retrieved_policy = self.admin_client.show_bandwidth_limit_rule(
            policy['id'], rule['id'])
        retrieved_policy = retrieved_policy['bandwidth_limit_rule']
        self.assertEqual(rule['id'], retrieved_policy['id'])

        self.admin_client.delete_bandwidth_limit_rule(policy['id'], rule['id'])
        self.assertRaises(exceptions.NotFound,
                          self.admin_client.show_bandwidth_limit_rule,
                          policy['id'], rule['id'])

    @test.attr(type='smoke')
    @test.idempotent_id('f211222c-5808-46cb-a961-983bbab6b852')
    def test_rule_create_rule_nonexistent_policy(self):
        self.assertRaises(
            exceptions.NotFound,
            self.create_qos_bandwidth_limit_rule,
            'policy', 200, 1337)

    @test.attr(type='smoke')
    @test.idempotent_id('3ba4abf9-7976-4eaf-a5d0-a934a6e09b2d')
    def test_rule_association_nonshared_policy(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False,
                                        tenant_id='tenant-id')
        self.assertRaises(
            exceptions.NotFound,
            self.client.create_bandwidth_limit_rule,
            policy['id'], 200, 1337)
