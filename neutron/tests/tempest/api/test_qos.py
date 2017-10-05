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

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

import testscenarios
import testtools

from neutron.services.qos import qos_consts
from neutron.tests.tempest.api import base


load_tests = testscenarios.load_tests_apply_scenarios


class QosTestJSON(base.BaseAdminNetworkTest):

    required_extensions = ['qos']

    @staticmethod
    def _get_driver_details(rule_type_details, driver_name):
        for driver in rule_type_details['drivers']:
            if driver['name'] == driver_name:
                return driver

    def _create_project(self):
        # Add a project to conduct the test
        test_project = data_utils.rand_name('test_project_')
        test_description = data_utils.rand_name('desc_')
        project = self.identity_admin_client.create_project(
            name=test_project,
            description=test_description)['project']
        self.addCleanup(
            self.identity_admin_client.delete_project, project['id'])
        return project

    @decorators.idempotent_id('108fbdf7-3463-4e47-9871-d07f3dcf5bbb')
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

    @decorators.idempotent_id('606a48e2-5403-4052-b40f-4d54b855af76')
    @utils.requires_ext(extension="project-id", service="network")
    def test_show_policy_has_project_id(self):
        policy = self.create_qos_policy(name='test-policy', shared=False)
        body = self.admin_client.show_qos_policy(policy['id'])
        show_policy = body['policy']
        self.assertIn('project_id', show_policy)
        self.assertIn('tenant_id', show_policy)
        self.assertEqual(self.admin_client.tenant_id,
                         show_policy['project_id'])
        self.assertEqual(self.admin_client.tenant_id,
                         show_policy['tenant_id'])

    @decorators.idempotent_id('f8d20e92-f06d-4805-b54f-230f77715815')
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

    @decorators.idempotent_id('8e88a54b-f0b2-4b7d-b061-a15d93c2c7d6')
    def test_policy_update(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='',
                                        shared=False,
                                        tenant_id=self.admin_client.tenant_id)
        self.admin_client.update_qos_policy(policy['id'],
                                            description='test policy desc2',
                                            shared=True)

        retrieved_policy = self.admin_client.show_qos_policy(policy['id'])
        retrieved_policy = retrieved_policy['policy']
        self.assertEqual('test policy desc2', retrieved_policy['description'])
        self.assertTrue(retrieved_policy['shared'])
        self.assertEqual([], retrieved_policy['rules'])

    @decorators.idempotent_id('6e880e0f-bbfc-4e54-87c6-680f90e1b618')
    def test_policy_update_forbidden_for_regular_tenants_own_policy(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='',
                                        shared=False,
                                        tenant_id=self.client.tenant_id)
        self.assertRaises(
            exceptions.Forbidden,
            self.client.update_qos_policy,
            policy['id'], description='test policy')

    @decorators.idempotent_id('4ecfd7e7-47b6-4702-be38-be9235901a87')
    def test_policy_update_forbidden_for_regular_tenants_foreign_policy(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='',
                                        shared=False,
                                        tenant_id=self.admin_client.tenant_id)
        self.assertRaises(
            exceptions.NotFound,
            self.client.update_qos_policy,
            policy['id'], description='test policy')

    @decorators.idempotent_id('ee263db4-009a-4641-83e5-d0e83506ba4c')
    def test_shared_policy_update(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='',
                                        shared=True,
                                        tenant_id=self.admin_client.tenant_id)

        self.admin_client.update_qos_policy(policy['id'],
                                            description='test policy desc2')
        retrieved_policy = self.admin_client.show_qos_policy(policy['id'])
        retrieved_policy = retrieved_policy['policy']
        self.assertTrue(retrieved_policy['shared'])

        self.admin_client.update_qos_policy(policy['id'],
                                            shared=False)
        retrieved_policy = self.admin_client.show_qos_policy(policy['id'])
        retrieved_policy = retrieved_policy['policy']
        self.assertFalse(retrieved_policy['shared'])

    @decorators.idempotent_id('1cb42653-54bd-4a9a-b888-c55e18199201')
    def test_delete_policy(self):
        policy = self.admin_client.create_qos_policy(
            'test-policy', 'desc', True)['policy']

        retrieved_policy = self.admin_client.show_qos_policy(policy['id'])
        retrieved_policy = retrieved_policy['policy']
        self.assertEqual('test-policy', retrieved_policy['name'])

        self.admin_client.delete_qos_policy(policy['id'])
        self.assertRaises(exceptions.NotFound,
                          self.admin_client.show_qos_policy, policy['id'])

    @decorators.idempotent_id('cf776f77-8d3d-49f2-8572-12d6a1557224')
    def test_list_admin_rule_types(self):
        self._test_list_rule_types(self.admin_client)

    @decorators.idempotent_id('49c8ea35-83a9-453a-bd23-239cf3b13929')
    def test_list_regular_rule_types(self):
        self._test_list_rule_types(self.client)

    def _test_list_rule_types(self, client):
        # List supported rule types
        # Since returned rule types depends on loaded backend drivers this test
        # is checking only if returned keys are same as expected keys
        #
        # In theory, we could make the test conditional on which ml2 drivers
        # are enabled in gate (or more specifically, on which supported qos
        # rules are claimed by core plugin), but that option doesn't seem to be
        # available through tempest.lib framework
        expected_rule_keys = ['type']

        rule_types = client.list_qos_rule_types()
        actual_list_rule_types = rule_types['rule_types']

        # Verify that only required fields present in rule details
        for rule in actual_list_rule_types:
            self.assertEqual(tuple(expected_rule_keys), tuple(rule.keys()))

    @decorators.idempotent_id('8ececa21-ef97-4904-a152-9f04c90f484d')
    def test_show_rule_type_details_as_user(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.show_qos_rule_type,
            qos_consts.RULE_TYPE_BANDWIDTH_LIMIT)

    @decorators.idempotent_id('d0a2460b-7325-481f-a531-050bd96ab25e')
    def test_show_rule_type_details_as_admin(self):
        # Since returned rule types depend on loaded backend drivers this test
        # is checking only if returned keys are same as expected keys

        # In theory, we could make the test conditional on which ml2 drivers
        # are enabled in gate, but that option doesn't seem to be
        # available through tempest.lib framework
        expected_rule_type_details_keys = ['type', 'drivers']

        rule_type_details = self.admin_client.show_qos_rule_type(
            qos_consts.RULE_TYPE_BANDWIDTH_LIMIT).get("rule_type")

        # Verify that only required fields present in rule details
        self.assertEqual(
            sorted(tuple(expected_rule_type_details_keys)),
            sorted(tuple(rule_type_details.keys())))

    @decorators.idempotent_id('65b9ef75-1911-406a-bbdb-ca1d68d528b0')
    def test_policy_association_with_admin_network(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        network = self.create_shared_network('test network',
                                             qos_policy_id=policy['id'])

        retrieved_network = self.admin_client.show_network(network['id'])
        self.assertEqual(
            policy['id'], retrieved_network['network']['qos_policy_id'])

    @decorators.idempotent_id('1738de5d-0476-4163-9022-5e1b548c208e')
    def test_policy_association_with_tenant_network(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        network = self.create_network('test network',
                                      qos_policy_id=policy['id'])

        retrieved_network = self.admin_client.show_network(network['id'])
        self.assertEqual(
            policy['id'], retrieved_network['network']['qos_policy_id'])

    @decorators.idempotent_id('9efe63d0-836f-4cc2-b00c-468e63aa614e')
    def test_policy_association_with_network_nonexistent_policy(self):
        self.assertRaises(
            exceptions.NotFound,
            self.create_network,
            'test network',
            qos_policy_id='9efe63d0-836f-4cc2-b00c-468e63aa614e')

    @decorators.idempotent_id('1aa55a79-324f-47d9-a076-894a8fc2448b')
    def test_policy_association_with_network_non_shared_policy(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.assertRaises(
            exceptions.NotFound,
            self.create_network,
            'test network', qos_policy_id=policy['id'])

    @decorators.idempotent_id('09a9392c-1359-4cbb-989f-fb768e5834a8')
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

    @decorators.idempotent_id('98fcd95e-84cf-4746-860e-44692e674f2e')
    def test_policy_association_with_port_shared_policy(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        network = self.create_shared_network('test network')
        port = self.create_port(network, qos_policy_id=policy['id'])

        retrieved_port = self.admin_client.show_port(port['id'])
        self.assertEqual(
            policy['id'], retrieved_port['port']['qos_policy_id'])

    @decorators.idempotent_id('49e02f5a-e1dd-41d5-9855-cfa37f2d195e')
    def test_policy_association_with_port_nonexistent_policy(self):
        network = self.create_shared_network('test network')
        self.assertRaises(
            exceptions.NotFound,
            self.create_port,
            network,
            qos_policy_id='49e02f5a-e1dd-41d5-9855-cfa37f2d195e')

    @decorators.idempotent_id('f53d961c-9fe5-4422-8b66-7add972c6031')
    def test_policy_association_with_port_non_shared_policy(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        network = self.create_shared_network('test network')
        self.assertRaises(
            exceptions.NotFound,
            self.create_port,
            network, qos_policy_id=policy['id'])

    @decorators.idempotent_id('f8163237-fba9-4db5-9526-bad6d2343c76')
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

    @decorators.idempotent_id('18163237-8ba9-4db5-9525-bad6d2343c75')
    def test_delete_not_allowed_if_policy_in_use_by_network(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        self.create_shared_network('test network', qos_policy_id=policy['id'])
        self.assertRaises(
            exceptions.Conflict,
            self.admin_client.delete_qos_policy, policy['id'])

    @decorators.idempotent_id('24153230-84a9-4dd5-9525-bad6d2343c75')
    def test_delete_not_allowed_if_policy_in_use_by_port(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=True)
        network = self.create_shared_network('test network')
        self.create_port(network, qos_policy_id=policy['id'])
        self.assertRaises(
            exceptions.Conflict,
            self.admin_client.delete_qos_policy, policy['id'])

    @decorators.idempotent_id('a2a5849b-dd06-4b18-9664-0b6828a1fc27')
    def test_qos_policy_delete_with_rules(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.admin_client.create_bandwidth_limit_rule(
            policy['id'], 200, 1337)['bandwidth_limit_rule']

        self.admin_client.delete_qos_policy(policy['id'])

        with testtools.ExpectedException(exceptions.NotFound):
            self.admin_client.show_qos_policy(policy['id'])

    @decorators.idempotent_id('fb384bde-a973-41c3-a542-6f77a092155f')
    def test_get_policy_that_is_shared(self):
        policy = self.create_qos_policy(
            name='test-policy-shared',
            description='shared policy',
            shared=True,
            tenant_id=self.admin_client.tenant_id)
        obtained_policy = self.client.show_qos_policy(policy['id'])['policy']
        self.assertEqual(obtained_policy, policy)

    @decorators.idempotent_id('aed8e2a6-22da-421b-89b9-935a2c1a1b50')
    def test_policy_create_forbidden_for_regular_tenants(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.create_qos_policy,
            'test-policy', 'test policy', False)

    @decorators.idempotent_id('18d94f22-b9d5-4390-af12-d30a0cfc4cd3')
    def test_default_policy_creating_network_without_policy(self):
        project_id = self._create_project()['id']
        policy = self.create_qos_policy(name='test-policy',
                                        tenant_id=project_id,
                                        is_default=True)
        network = self.create_network('test network', client=self.admin_client,
                                      project_id=project_id)
        retrieved_network = self.admin_client.show_network(network['id'])
        self.assertEqual(
            policy['id'], retrieved_network['network']['qos_policy_id'])

    @decorators.idempotent_id('807cce45-38e5-482d-94db-36e1796aba73')
    def test_default_policy_creating_network_with_policy(self):
        project_id = self._create_project()['id']
        self.create_qos_policy(name='test-policy',
                               tenant_id=project_id,
                               is_default=True)
        policy = self.create_qos_policy(name='test-policy',
                                        tenant_id=project_id)
        network = self.create_network('test network', client=self.admin_client,
                                      project_id=project_id,
                                      qos_policy_id=policy['id'])
        retrieved_network = self.admin_client.show_network(network['id'])
        self.assertEqual(
            policy['id'], retrieved_network['network']['qos_policy_id'])


class QosBandwidthLimitRuleTestJSON(base.BaseAdminNetworkTest):

    direction = None
    required_extensions = ['qos']

    @classmethod
    @base.require_qos_rule_type(qos_consts.RULE_TYPE_BANDWIDTH_LIMIT)
    def resource_setup(cls):
        super(QosBandwidthLimitRuleTestJSON, cls).resource_setup()

    @property
    def opposite_direction(self):
        if self.direction == "ingress":
            return "egress"
        elif self.direction == "egress":
            return "ingress"
        else:
            return None

    @decorators.idempotent_id('8a59b00b-3e9c-4787-92f8-93a5cdf5e378')
    def test_rule_create(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'],
            max_kbps=200,
            max_burst_kbps=1337,
            direction=self.direction)

        # Test 'show rule'
        retrieved_rule = self.admin_client.show_bandwidth_limit_rule(
            policy['id'], rule['id'])
        retrieved_rule = retrieved_rule['bandwidth_limit_rule']
        self.assertEqual(rule['id'], retrieved_rule['id'])
        self.assertEqual(200, retrieved_rule['max_kbps'])
        self.assertEqual(1337, retrieved_rule['max_burst_kbps'])
        if self.direction:
            self.assertEqual(self.direction, retrieved_rule['direction'])

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

    @decorators.idempotent_id('8a59b00b-ab01-4787-92f8-93a5cdf5e378')
    def test_rule_create_fail_for_the_same_type(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.create_qos_bandwidth_limit_rule(policy_id=policy['id'],
                                             max_kbps=200,
                                             max_burst_kbps=1337,
                                             direction=self.direction)

        self.assertRaises(exceptions.Conflict,
                          self.create_qos_bandwidth_limit_rule,
                          policy_id=policy['id'],
                          max_kbps=201, max_burst_kbps=1338,
                          direction=self.direction)

    @decorators.idempotent_id('149a6988-2568-47d2-931e-2dbc858943b3')
    def test_rule_update(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.create_qos_bandwidth_limit_rule(policy_id=policy['id'],
                                                    max_kbps=1,
                                                    max_burst_kbps=1,
                                                    direction=self.direction)

        self.admin_client.update_bandwidth_limit_rule(
            policy['id'],
            rule['id'],
            max_kbps=200,
            max_burst_kbps=1337,
            direction=self.opposite_direction)

        retrieved_policy = self.admin_client.show_bandwidth_limit_rule(
            policy['id'], rule['id'])
        retrieved_policy = retrieved_policy['bandwidth_limit_rule']
        self.assertEqual(200, retrieved_policy['max_kbps'])
        self.assertEqual(1337, retrieved_policy['max_burst_kbps'])
        if self.opposite_direction:
            self.assertEqual(self.opposite_direction,
                             retrieved_policy['direction'])

    @decorators.idempotent_id('67ee6efd-7b33-4a68-927d-275b4f8ba958')
    def test_rule_delete(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.admin_client.create_bandwidth_limit_rule(
            policy['id'], 200, 1337, self.direction)['bandwidth_limit_rule']

        retrieved_policy = self.admin_client.show_bandwidth_limit_rule(
            policy['id'], rule['id'])
        retrieved_policy = retrieved_policy['bandwidth_limit_rule']
        self.assertEqual(rule['id'], retrieved_policy['id'])

        self.admin_client.delete_bandwidth_limit_rule(policy['id'], rule['id'])
        self.assertRaises(exceptions.NotFound,
                          self.admin_client.show_bandwidth_limit_rule,
                          policy['id'], rule['id'])

    @decorators.idempotent_id('f211222c-5808-46cb-a961-983bbab6b852')
    def test_rule_create_rule_nonexistent_policy(self):
        self.assertRaises(
            exceptions.NotFound,
            self.create_qos_bandwidth_limit_rule,
            'policy', 200, 1337, self.direction)

    @decorators.idempotent_id('a4a2e7ad-786f-4927-a85a-e545a93bd274')
    def test_rule_create_forbidden_for_regular_tenants(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.create_bandwidth_limit_rule,
            'policy', 1, 2, self.direction)

    @decorators.idempotent_id('1bfc55d9-6fd8-4293-ab3a-b1d69bf7cd2e')
    def test_rule_update_forbidden_for_regular_tenants_own_policy(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False,
                                        tenant_id=self.client.tenant_id)
        rule = self.create_qos_bandwidth_limit_rule(policy_id=policy['id'],
                                                    max_kbps=1,
                                                    max_burst_kbps=1,
                                                    direction=self.direction)
        self.assertRaises(
            exceptions.Forbidden,
            self.client.update_bandwidth_limit_rule,
            policy['id'], rule['id'], max_kbps=2, max_burst_kbps=4)

    @decorators.idempotent_id('9a607936-4b6f-4c2f-ad21-bd5b3d4fc91f')
    def test_rule_update_forbidden_for_regular_tenants_foreign_policy(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False,
                                        tenant_id=self.admin_client.tenant_id)
        rule = self.create_qos_bandwidth_limit_rule(policy_id=policy['id'],
                                                    max_kbps=1,
                                                    max_burst_kbps=1,
                                                    direction=self.direction)
        self.assertRaises(
            exceptions.NotFound,
            self.client.update_bandwidth_limit_rule,
            policy['id'], rule['id'], max_kbps=2, max_burst_kbps=4)

    @decorators.idempotent_id('ce0bd0c2-54d9-4e29-85f1-cfb36ac3ebe2')
    def test_get_rules_by_policy(self):
        policy1 = self.create_qos_policy(name='test-policy1',
                                         description='test policy1',
                                         shared=False)
        rule1 = self.create_qos_bandwidth_limit_rule(policy_id=policy1['id'],
                                                     max_kbps=200,
                                                     max_burst_kbps=1337,
                                                     direction=self.direction)

        policy2 = self.create_qos_policy(name='test-policy2',
                                         description='test policy2',
                                         shared=False)
        rule2 = self.create_qos_bandwidth_limit_rule(policy_id=policy2['id'],
                                                     max_kbps=5000,
                                                     max_burst_kbps=2523,
                                                     direction=self.direction)

        # Test 'list rules'
        rules = self.admin_client.list_bandwidth_limit_rules(policy1['id'])
        rules = rules['bandwidth_limit_rules']
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule1['id'], rules_ids)
        self.assertNotIn(rule2['id'], rules_ids)


class QosBandwidthLimitRuleWithDirectionTestJSON(
    QosBandwidthLimitRuleTestJSON):

    required_extensions = (
        QosBandwidthLimitRuleTestJSON.required_extensions +
        ['qos-bw-limit-direction']
    )
    scenarios = [
        ('ingress', {'direction': 'ingress'}),
        ('egress', {'direction': 'egress'}),
    ]


class RbacSharedQosPoliciesTest(base.BaseAdminNetworkTest):

    force_tenant_isolation = True
    credentials = ['primary', 'alt', 'admin']
    required_extensions = ['qos']

    @classmethod
    def resource_setup(cls):
        super(RbacSharedQosPoliciesTest, cls).resource_setup()
        cls.client2 = cls.os_alt.network_client

    def _create_qos_policy(self, tenant_id=None):
        args = {'name': data_utils.rand_name('test-policy'),
                'description': 'test policy',
                'shared': False,
                'tenant_id': tenant_id}
        qos_policy = self.admin_client.create_qos_policy(**args)['policy']
        self.addCleanup(self.admin_client.delete_qos_policy, qos_policy['id'])

        return qos_policy

    def _make_admin_policy_shared_to_tenant_id(self, tenant_id):
        policy = self._create_qos_policy()
        rbac_policy = self.admin_client.create_rbac_policy(
            object_type='qos_policy',
            object_id=policy['id'],
            action='access_as_shared',
            target_tenant=tenant_id,
        )['rbac_policy']

        return {'policy': policy, 'rbac_policy': rbac_policy}

    def _create_network(self, qos_policy_id, client, should_cleanup=True):
        net = client.create_network(
            name=data_utils.rand_name('test-network'),
            qos_policy_id=qos_policy_id)['network']
        if should_cleanup:
            self.addCleanup(client.delete_network, net['id'])

        return net

    @decorators.idempotent_id('b9dcf582-d3b3-11e5-950a-54ee756c66df')
    def test_policy_sharing_with_wildcard(self):
        qos_pol = self.create_qos_policy(
            name=data_utils.rand_name('test-policy'),
            description='test-shared-policy', shared=False,
            tenant_id=self.admin_client.tenant_id)
        self.assertNotIn(qos_pol, self.client2.list_qos_policies()['policies'])

        # test update shared False -> True
        self.admin_client.update_qos_policy(qos_pol['id'], shared=True)
        qos_pol['shared'] = True
        self.client2.show_qos_policy(qos_pol['id'])
        rbac_pol = {'target_tenant': '*',
                    'tenant_id': self.admin_client.tenant_id,
                    'project_id': self.admin_client.tenant_id,
                    'object_type': 'qos_policy',
                    'object_id': qos_pol['id'],
                    'action': 'access_as_shared'}

        rbac_policies = self.admin_client.list_rbac_policies()['rbac_policies']
        rbac_policies = [r for r in rbac_policies if r.pop('id')]
        self.assertIn(rbac_pol, rbac_policies)

        # update shared True -> False should fail because the policy is bound
        # to a network
        net = self._create_network(qos_pol['id'], self.admin_client, False)
        with testtools.ExpectedException(exceptions.Conflict):
            self.admin_client.update_qos_policy(qos_pol['id'], shared=False)

        # delete the network, and update shared True -> False should pass now
        self.admin_client.delete_network(net['id'])
        self.admin_client.update_qos_policy(qos_pol['id'], shared=False)
        qos_pol['shared'] = False
        self.assertNotIn(qos_pol, self.client2.list_qos_policies()['policies'])

    def _create_net_bound_qos_rbacs(self):
        res = self._make_admin_policy_shared_to_tenant_id(
            self.client.tenant_id)
        qos_policy, rbac_for_client_tenant = res['policy'], res['rbac_policy']

        # add a wildcard rbac rule - now the policy globally shared
        rbac_wildcard = self.admin_client.create_rbac_policy(
            object_type='qos_policy',
            object_id=qos_policy['id'],
            action='access_as_shared',
            target_tenant='*',
        )['rbac_policy']

        # tenant1 now uses qos policy for net
        self._create_network(qos_policy['id'], self.client)

        return rbac_for_client_tenant, rbac_wildcard

    @decorators.idempotent_id('328b1f70-d424-11e5-a57f-54ee756c66df')
    def test_net_bound_shared_policy_wildcard_and_tenant_id_wild_remove(self):
        client_rbac, wildcard_rbac = self._create_net_bound_qos_rbacs()
        # globally unshare the qos-policy, the specific share should remain
        self.admin_client.delete_rbac_policy(wildcard_rbac['id'])
        self.client.list_rbac_policies(id=client_rbac['id'])

    @decorators.idempotent_id('1997b00c-0c75-4e43-8ce2-999f9fa555ee')
    def test_net_bound_shared_policy_wildcard_and_tenant_id_wild_remains(self):
        client_rbac, wildcard_rbac = self._create_net_bound_qos_rbacs()
        # remove client_rbac policy the wildcard share should remain
        self.admin_client.delete_rbac_policy(client_rbac['id'])
        self.client.list_rbac_policies(id=wildcard_rbac['id'])

    @decorators.idempotent_id('2ace9adc-da6e-11e5-aafe-54ee756c66df')
    def test_policy_sharing_with_wildcard_and_tenant_id(self):
        res = self._make_admin_policy_shared_to_tenant_id(
            self.client.tenant_id)
        qos_policy, rbac = res['policy'], res['rbac_policy']
        qos_pol = self.client.show_qos_policy(qos_policy['id'])['policy']
        self.assertTrue(qos_pol['shared'])
        with testtools.ExpectedException(exceptions.NotFound):
            self.client2.show_qos_policy(qos_policy['id'])

        # make the qos-policy globally shared
        self.admin_client.update_qos_policy(qos_policy['id'], shared=True)
        qos_pol = self.client2.show_qos_policy(qos_policy['id'])['policy']
        self.assertTrue(qos_pol['shared'])

        # globally unshare the qos-policy, the specific share should remain
        self.admin_client.update_qos_policy(qos_policy['id'], shared=False)
        self.client.show_qos_policy(qos_policy['id'])
        with testtools.ExpectedException(exceptions.NotFound):
            self.client2.show_qos_policy(qos_policy['id'])
        self.assertIn(rbac,
                      self.admin_client.list_rbac_policies()['rbac_policies'])

    @decorators.idempotent_id('9f85c76a-a350-11e5-8ae5-54ee756c66df')
    def test_policy_target_update(self):
        res = self._make_admin_policy_shared_to_tenant_id(
            self.client.tenant_id)
        # change to client2
        update_res = self.admin_client.update_rbac_policy(
                res['rbac_policy']['id'], target_tenant=self.client2.tenant_id)
        self.assertEqual(self.client2.tenant_id,
                         update_res['rbac_policy']['target_tenant'])
        # make sure everything else stayed the same
        res['rbac_policy'].pop('target_tenant')
        update_res['rbac_policy'].pop('target_tenant')
        self.assertEqual(res['rbac_policy'], update_res['rbac_policy'])

    @decorators.idempotent_id('a9b39f46-a350-11e5-97c7-54ee756c66df')
    def test_network_presence_prevents_policy_rbac_policy_deletion(self):
        res = self._make_admin_policy_shared_to_tenant_id(
            self.client2.tenant_id)
        qos_policy_id = res['policy']['id']
        self._create_network(qos_policy_id, self.client2)
        # a network with shared qos-policy should prevent the deletion of an
        # rbac-policy required for it to be shared
        with testtools.ExpectedException(exceptions.Conflict):
            self.admin_client.delete_rbac_policy(res['rbac_policy']['id'])

        # a wildcard policy should allow the specific policy to be deleted
        # since it allows the remaining port
        wild = self.admin_client.create_rbac_policy(
            object_type='qos_policy', object_id=res['policy']['id'],
            action='access_as_shared', target_tenant='*')['rbac_policy']
        self.admin_client.delete_rbac_policy(res['rbac_policy']['id'])

        # now that wildcard is the only remaining, it should be subjected to
        # the same restriction
        with testtools.ExpectedException(exceptions.Conflict):
            self.admin_client.delete_rbac_policy(wild['id'])

        # we can't update the policy to a different tenant
        with testtools.ExpectedException(exceptions.Conflict):
            self.admin_client.update_rbac_policy(
                wild['id'], target_tenant=self.client2.tenant_id)

    @decorators.idempotent_id('b0fe87e8-a350-11e5-9f08-54ee756c66df')
    def test_regular_client_shares_to_another_regular_client(self):
        # owned by self.admin_client
        policy = self._create_qos_policy()
        with testtools.ExpectedException(exceptions.NotFound):
            self.client.show_qos_policy(policy['id'])
        rbac_policy = self.admin_client.create_rbac_policy(
            object_type='qos_policy', object_id=policy['id'],
            action='access_as_shared',
            target_tenant=self.client.tenant_id)['rbac_policy']
        self.client.show_qos_policy(policy['id'])

        self.assertIn(rbac_policy,
                      self.admin_client.list_rbac_policies()['rbac_policies'])
        # ensure that 'client2' can't see the rbac-policy sharing the
        # qos-policy to it because the rbac-policy belongs to 'client'
        self.assertNotIn(rbac_policy['id'], [p['id'] for p in
                          self.client2.list_rbac_policies()['rbac_policies']])

    @decorators.idempotent_id('ba88d0ca-a350-11e5-a06f-54ee756c66df')
    def test_filter_fields(self):
        policy = self._create_qos_policy()
        self.admin_client.create_rbac_policy(
            object_type='qos_policy', object_id=policy['id'],
            action='access_as_shared', target_tenant=self.client2.tenant_id)
        field_args = (('id',), ('id', 'action'), ('object_type', 'object_id'),
                      ('tenant_id', 'target_tenant'))
        for fields in field_args:
            res = self.admin_client.list_rbac_policies(fields=fields)
            self.assertEqual(set(fields), set(res['rbac_policies'][0].keys()))

    @decorators.idempotent_id('c10d993a-a350-11e5-9c7a-54ee756c66df')
    def test_rbac_policy_show(self):
        res = self._make_admin_policy_shared_to_tenant_id(
            self.client.tenant_id)
        p1 = res['rbac_policy']
        p2 = self.admin_client.create_rbac_policy(
            object_type='qos_policy', object_id=res['policy']['id'],
            action='access_as_shared',
            target_tenant='*')['rbac_policy']

        self.assertEqual(
            p1, self.admin_client.show_rbac_policy(p1['id'])['rbac_policy'])
        self.assertEqual(
            p2, self.admin_client.show_rbac_policy(p2['id'])['rbac_policy'])

    @decorators.idempotent_id('c7496f86-a350-11e5-b380-54ee756c66df')
    def test_filter_rbac_policies(self):
        policy = self._create_qos_policy()
        rbac_pol1 = self.admin_client.create_rbac_policy(
            object_type='qos_policy', object_id=policy['id'],
            action='access_as_shared',
            target_tenant=self.client2.tenant_id)['rbac_policy']
        rbac_pol2 = self.admin_client.create_rbac_policy(
            object_type='qos_policy', object_id=policy['id'],
            action='access_as_shared',
            target_tenant=self.admin_client.tenant_id)['rbac_policy']
        res1 = self.admin_client.list_rbac_policies(id=rbac_pol1['id'])[
            'rbac_policies']
        res2 = self.admin_client.list_rbac_policies(id=rbac_pol2['id'])[
            'rbac_policies']
        self.assertEqual(1, len(res1))
        self.assertEqual(1, len(res2))
        self.assertEqual(rbac_pol1['id'], res1[0]['id'])
        self.assertEqual(rbac_pol2['id'], res2[0]['id'])

    @decorators.idempotent_id('cd7d755a-a350-11e5-a344-54ee756c66df')
    def test_regular_client_blocked_from_sharing_anothers_policy(self):
        qos_policy = self._make_admin_policy_shared_to_tenant_id(
            self.client.tenant_id)['policy']
        with testtools.ExpectedException(exceptions.BadRequest):
            self.client.create_rbac_policy(
                object_type='qos_policy', object_id=qos_policy['id'],
                action='access_as_shared',
                target_tenant=self.client2.tenant_id)

        # make sure the rbac-policy is invisible to the tenant for which it's
        # being shared
        self.assertFalse(self.client.list_rbac_policies()['rbac_policies'])


class QosDscpMarkingRuleTestJSON(base.BaseAdminNetworkTest):
    VALID_DSCP_MARK1 = 56
    VALID_DSCP_MARK2 = 48

    required_extensions = ['qos']

    @classmethod
    @base.require_qos_rule_type(qos_consts.RULE_TYPE_DSCP_MARKING)
    def resource_setup(cls):
        super(QosDscpMarkingRuleTestJSON, cls).resource_setup()

    @decorators.idempotent_id('f5cbaceb-5829-497c-9c60-ad70969e9a08')
    def test_rule_create(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.admin_client.create_dscp_marking_rule(
            policy['id'], self.VALID_DSCP_MARK1)['dscp_marking_rule']

        # Test 'show rule'
        retrieved_rule = self.admin_client.show_dscp_marking_rule(
            policy['id'], rule['id'])
        retrieved_rule = retrieved_rule['dscp_marking_rule']
        self.assertEqual(rule['id'], retrieved_rule['id'])
        self.assertEqual(self.VALID_DSCP_MARK1, retrieved_rule['dscp_mark'])

        # Test 'list rules'
        rules = self.admin_client.list_dscp_marking_rules(policy['id'])
        rules = rules['dscp_marking_rules']
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule['id'], rules_ids)

        # Test 'show policy'
        retrieved_policy = self.admin_client.show_qos_policy(policy['id'])
        policy_rules = retrieved_policy['policy']['rules']
        self.assertEqual(1, len(policy_rules))
        self.assertEqual(rule['id'], policy_rules[0]['id'])
        self.assertEqual(qos_consts.RULE_TYPE_DSCP_MARKING,
                         policy_rules[0]['type'])

    @decorators.idempotent_id('08553ffe-030f-4037-b486-7e0b8fb9385a')
    def test_rule_create_fail_for_the_same_type(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.admin_client.create_dscp_marking_rule(
            policy['id'], self.VALID_DSCP_MARK1)['dscp_marking_rule']

        self.assertRaises(exceptions.Conflict,
                          self.admin_client.create_dscp_marking_rule,
                          policy_id=policy['id'],
                          dscp_mark=self.VALID_DSCP_MARK2)

    @decorators.idempotent_id('76f632e5-3175-4408-9a32-3625e599c8a2')
    def test_rule_update(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.admin_client.create_dscp_marking_rule(
            policy['id'], self.VALID_DSCP_MARK1)['dscp_marking_rule']

        self.admin_client.update_dscp_marking_rule(
            policy['id'], rule['id'], dscp_mark=self.VALID_DSCP_MARK2)

        retrieved_policy = self.admin_client.show_dscp_marking_rule(
            policy['id'], rule['id'])
        retrieved_policy = retrieved_policy['dscp_marking_rule']
        self.assertEqual(self.VALID_DSCP_MARK2, retrieved_policy['dscp_mark'])

    @decorators.idempotent_id('74f81904-c35f-48a3-adae-1f5424cb3c18')
    def test_rule_delete(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.admin_client.create_dscp_marking_rule(
            policy['id'], self.VALID_DSCP_MARK1)['dscp_marking_rule']

        retrieved_policy = self.admin_client.show_dscp_marking_rule(
            policy['id'], rule['id'])
        retrieved_policy = retrieved_policy['dscp_marking_rule']
        self.assertEqual(rule['id'], retrieved_policy['id'])

        self.admin_client.delete_dscp_marking_rule(policy['id'], rule['id'])
        self.assertRaises(exceptions.NotFound,
                          self.admin_client.show_dscp_marking_rule,
                          policy['id'], rule['id'])

    @decorators.idempotent_id('9cb8ef5c-96fc-4978-9ee0-e3b02bab628a')
    def test_rule_create_rule_nonexistent_policy(self):
        self.assertRaises(
            exceptions.NotFound,
            self.admin_client.create_dscp_marking_rule,
            'policy', self.VALID_DSCP_MARK1)

    @decorators.idempotent_id('bf6002ea-29de-486f-b65d-08aea6d4c4e2')
    def test_rule_create_forbidden_for_regular_tenants(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.create_dscp_marking_rule,
            'policy', self.VALID_DSCP_MARK1)

    @decorators.idempotent_id('33646b08-4f05-4493-a48a-bde768a18533')
    def test_invalid_rule_create(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.assertRaises(
            exceptions.BadRequest,
            self.admin_client.create_dscp_marking_rule,
            policy['id'], 58)

    @decorators.idempotent_id('c565131d-4c80-4231-b0f3-9ae2be4de129')
    def test_get_rules_by_policy(self):
        policy1 = self.create_qos_policy(name='test-policy1',
                                         description='test policy1',
                                         shared=False)
        rule1 = self.admin_client.create_dscp_marking_rule(
            policy1['id'], self.VALID_DSCP_MARK1)['dscp_marking_rule']

        policy2 = self.create_qos_policy(name='test-policy2',
                                         description='test policy2',
                                         shared=False)
        rule2 = self.admin_client.create_dscp_marking_rule(
            policy2['id'], self.VALID_DSCP_MARK2)['dscp_marking_rule']

        # Test 'list rules'
        rules = self.admin_client.list_dscp_marking_rules(policy1['id'])
        rules = rules['dscp_marking_rules']
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule1['id'], rules_ids)
        self.assertNotIn(rule2['id'], rules_ids)


class QosMinimumBandwidthRuleTestJSON(base.BaseAdminNetworkTest):
    DIRECTION_EGRESS = "egress"
    DIRECTION_INGRESS = "ingress"
    RULE_NAME = qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH + "_rule"
    RULES_NAME = RULE_NAME + "s"
    required_extensions = ['qos']

    @classmethod
    @base.require_qos_rule_type(qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH)
    def resource_setup(cls):
        super(QosMinimumBandwidthRuleTestJSON, cls).resource_setup()

    @decorators.idempotent_id('aa59b00b-3e9c-4787-92f8-93a5cdf5e378')
    def test_rule_create(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.admin_client.create_minimum_bandwidth_rule(
            policy_id=policy['id'],
            direction=self.DIRECTION_EGRESS,
            min_kbps=1138)[self.RULE_NAME]

        # Test 'show rule'
        retrieved_rule = self.admin_client.show_minimum_bandwidth_rule(
            policy['id'], rule['id'])
        retrieved_rule = retrieved_rule[self.RULE_NAME]
        self.assertEqual(rule['id'], retrieved_rule['id'])
        self.assertEqual(1138, retrieved_rule['min_kbps'])
        self.assertEqual(self.DIRECTION_EGRESS, retrieved_rule['direction'])

        # Test 'list rules'
        rules = self.admin_client.list_minimum_bandwidth_rules(policy['id'])
        rules = rules[self.RULES_NAME]
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule['id'], rules_ids)

        # Test 'show policy'
        retrieved_policy = self.admin_client.show_qos_policy(policy['id'])
        policy_rules = retrieved_policy['policy']['rules']
        self.assertEqual(1, len(policy_rules))
        self.assertEqual(rule['id'], policy_rules[0]['id'])
        self.assertEqual(qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH,
                         policy_rules[0]['type'])

    @decorators.idempotent_id('266d9b87-e51c-48bd-9aa7-8269573621be')
    def test_rule_create_fail_for_missing_min_kbps(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.assertRaises(exceptions.BadRequest,
                          self.admin_client.create_minimum_bandwidth_rule,
                          policy_id=policy['id'],
                          direction=self.DIRECTION_EGRESS)

    @decorators.idempotent_id('aa59b00b-ab01-4787-92f8-93a5cdf5e378')
    def test_rule_create_fail_for_the_same_type(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.admin_client.create_minimum_bandwidth_rule(
            policy_id=policy['id'],
            direction=self.DIRECTION_EGRESS, min_kbps=200)

        self.assertRaises(exceptions.Conflict,
                          self.admin_client.create_minimum_bandwidth_rule,
                          policy_id=policy['id'],
                          direction=self.DIRECTION_EGRESS, min_kbps=201)

    @decorators.idempotent_id('d6fce764-e511-4fa6-9f86-f4b41cf142cf')
    def test_rule_create_fail_for_direction_ingress(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.assertRaises(exceptions.BadRequest,
                          self.admin_client.create_minimum_bandwidth_rule,
                          policy_id=policy['id'],
                          direction=self.DIRECTION_INGRESS,
                          min_kbps=201)

    @decorators.idempotent_id('a49a6988-2568-47d2-931e-2dbc858943b3')
    def test_rule_update(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.admin_client.create_minimum_bandwidth_rule(
            policy_id=policy['id'],
            direction=self.DIRECTION_EGRESS,
            min_kbps=300)[self.RULE_NAME]

        self.admin_client.update_minimum_bandwidth_rule(policy['id'],
            rule['id'], min_kbps=350, direction=self.DIRECTION_EGRESS)

        retrieved_policy = self.admin_client.show_minimum_bandwidth_rule(
            policy['id'], rule['id'])
        retrieved_policy = retrieved_policy[self.RULE_NAME]
        self.assertEqual(350, retrieved_policy['min_kbps'])
        self.assertEqual(self.DIRECTION_EGRESS, retrieved_policy['direction'])

    @decorators.idempotent_id('a7ee6efd-7b33-4a68-927d-275b4f8ba958')
    def test_rule_delete(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        rule = self.admin_client.create_minimum_bandwidth_rule(
            policy['id'], self.DIRECTION_EGRESS, min_kbps=200)[self.RULE_NAME]

        retrieved_policy = self.admin_client.show_minimum_bandwidth_rule(
            policy['id'], rule['id'])
        retrieved_policy = retrieved_policy[self.RULE_NAME]
        self.assertEqual(rule['id'], retrieved_policy['id'])

        self.admin_client.delete_minimum_bandwidth_rule(policy['id'],
                                                        rule['id'])
        self.assertRaises(exceptions.NotFound,
                          self.admin_client.show_minimum_bandwidth_rule,
                          policy['id'], rule['id'])

    @decorators.idempotent_id('a211222c-5808-46cb-a961-983bbab6b852')
    def test_rule_create_rule_nonexistent_policy(self):
        self.assertRaises(
            exceptions.NotFound,
            self.admin_client.create_minimum_bandwidth_rule,
            'policy', self.DIRECTION_EGRESS, min_kbps=200)

    @decorators.idempotent_id('b4a2e7ad-786f-4927-a85a-e545a93bd274')
    def test_rule_create_forbidden_for_regular_tenants(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.create_minimum_bandwidth_rule,
            'policy', self.DIRECTION_EGRESS, min_kbps=300)

    @decorators.idempotent_id('de0bd0c2-54d9-4e29-85f1-cfb36ac3ebe2')
    def test_get_rules_by_policy(self):
        policy1 = self.create_qos_policy(name='test-policy1',
                                         description='test policy1',
                                         shared=False)
        rule1 = self.admin_client.create_minimum_bandwidth_rule(
            policy_id=policy1['id'],
            direction=self.DIRECTION_EGRESS,
            min_kbps=200)[self.RULE_NAME]

        policy2 = self.create_qos_policy(name='test-policy2',
                                         description='test policy2',
                                         shared=False)
        rule2 = self.admin_client.create_minimum_bandwidth_rule(
            policy_id=policy2['id'],
            direction=self.DIRECTION_EGRESS,
            min_kbps=5000)[self.RULE_NAME]

        # Test 'list rules'
        rules = self.admin_client.list_minimum_bandwidth_rules(policy1['id'])
        rules = rules[self.RULES_NAME]
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule1['id'], rules_ids)
        self.assertNotIn(rule2['id'], rules_ids)


class QosSearchCriteriaTest(base.BaseSearchCriteriaTest,
                            base.BaseAdminNetworkTest):

    resource = 'policy'
    plural_name = 'policies'

    # Use unique description to isolate the tests from other QoS tests
    list_kwargs = {'description': 'search-criteria-test'}
    list_as_admin = True

    required_extensions = ['qos']

    @classmethod
    def resource_setup(cls):
        super(QosSearchCriteriaTest, cls).resource_setup()
        for name in cls.resource_names:
            cls.create_qos_policy(
                name=name, description='search-criteria-test')

    @decorators.idempotent_id('55fc0103-fdc1-4d34-ab62-c579bb739a91')
    def test_list_sorts_asc(self):
        self._test_list_sorts_asc()

    @decorators.idempotent_id('13e08ac3-bfed-426b-892a-b3b158560c23')
    def test_list_sorts_desc(self):
        self._test_list_sorts_desc()

    @decorators.idempotent_id('719e61cc-e33c-4918-aa4d-1a791e6e0e86')
    def test_list_pagination(self):
        self._test_list_pagination()

    @decorators.idempotent_id('3bd8fb58-c0f8-4954-87fb-f286e1eb096a')
    def test_list_pagination_with_marker(self):
        self._test_list_pagination_with_marker()

    @decorators.idempotent_id('3bad0747-8082-46e9-be4d-c428a842db41')
    def test_list_pagination_with_href_links(self):
        self._test_list_pagination_with_href_links()

    @decorators.idempotent_id('d6a8bacd-d5e8-4ef3-bc55-23ca6998d208')
    def test_list_pagination_page_reverse_asc(self):
        self._test_list_pagination_page_reverse_asc()

    @decorators.idempotent_id('0b9aecdc-2b27-421b-b104-53d24e905ae8')
    def test_list_pagination_page_reverse_desc(self):
        self._test_list_pagination_page_reverse_desc()

    @decorators.idempotent_id('1a3dc257-dafd-4870-8c71-639ae7ddc6ea')
    def test_list_pagination_page_reverse_with_href_links(self):
        self._test_list_pagination_page_reverse_with_href_links()

    @decorators.idempotent_id('40e09b53-4eb8-4526-9181-d438c8005a20')
    def test_list_no_pagination_limit_0(self):
        self._test_list_no_pagination_limit_0()
