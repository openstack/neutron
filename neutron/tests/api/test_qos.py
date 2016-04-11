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

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest import test

import testtools

from neutron.services.qos import qos_consts
from neutron.tests.api import base


class QosTestJSON(base.BaseAdminNetworkTest):
    @classmethod
    @test.requires_ext(extension="qos", service="network")
    def resource_setup(cls):
        super(QosTestJSON, cls).resource_setup()

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
    def test_list_admin_rule_types(self):
        self._test_list_rule_types(self.admin_client)

    @test.attr(type='smoke')
    @test.idempotent_id('49c8ea35-83a9-453a-bd23-239cf3b13929')
    def test_list_regular_rule_types(self):
        self._test_list_rule_types(self.client)

    def _test_list_rule_types(self, client):
        # List supported rule types
        # TODO(QoS): since in gate we run both ovs and linuxbridge ml2 drivers,
        # and since Linux Bridge ml2 driver does not have QoS support yet, ml2
        # plugin reports no rule types are supported. Once linuxbridge will
        # receive support for QoS, the list of expected rule types will change.
        #
        # In theory, we could make the test conditional on which ml2 drivers
        # are enabled in gate (or more specifically, on which supported qos
        # rules are claimed by core plugin), but that option doesn't seem to be
        # available thru tempest.lib framework
        expected_rule_types = []
        expected_rule_details = ['type']

        rule_types = client.list_qos_rule_types()
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

    @test.attr(type='smoke')
    @test.idempotent_id('9efe63d0-836f-4cc2-b00c-468e63aa614e')
    def test_policy_association_with_network_nonexistent_policy(self):
        self.assertRaises(
            exceptions.NotFound,
            self.create_network,
            'test network',
            qos_policy_id='9efe63d0-836f-4cc2-b00c-468e63aa614e')

    @test.attr(type='smoke')
    @test.idempotent_id('1aa55a79-324f-47d9-a076-894a8fc2448b')
    def test_policy_association_with_network_non_shared_policy(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.assertRaises(
            exceptions.NotFound,
            self.create_network,
            'test network', qos_policy_id=policy['id'])

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

    @test.attr(type='smoke')
    @test.idempotent_id('49e02f5a-e1dd-41d5-9855-cfa37f2d195e')
    def test_policy_association_with_port_nonexistent_policy(self):
        network = self.create_shared_network('test network')
        self.assertRaises(
            exceptions.NotFound,
            self.create_port,
            network,
            qos_policy_id='49e02f5a-e1dd-41d5-9855-cfa37f2d195e')

    @test.attr(type='smoke')
    @test.idempotent_id('f53d961c-9fe5-4422-8b66-7add972c6031')
    def test_policy_association_with_port_non_shared_policy(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        network = self.create_shared_network('test network')
        self.assertRaises(
            exceptions.NotFound,
            self.create_port,
            network, qos_policy_id=policy['id'])

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

    @test.attr(type='smoke')
    @test.idempotent_id('a2a5849b-dd06-4b18-9664-0b6828a1fc27')
    def test_qos_policy_delete_with_rules(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.admin_client.create_bandwidth_limit_rule(
            policy['id'], 200, 1337)['bandwidth_limit_rule']

        self.admin_client.delete_qos_policy(policy['id'])

        with testtools.ExpectedException(exceptions.NotFound):
            self.admin_client.show_qos_policy(policy['id'])


class QosBandwidthLimitRuleTestJSON(base.BaseAdminNetworkTest):
    @classmethod
    @test.requires_ext(extension="qos", service="network")
    def resource_setup(cls):
        super(QosBandwidthLimitRuleTestJSON, cls).resource_setup()

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
    @test.idempotent_id('eed8e2a6-22da-421b-89b9-935a2c1a1b50')
    def test_policy_create_forbidden_for_regular_tenants(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.create_qos_policy,
            'test-policy', 'test policy', False)

    @test.attr(type='smoke')
    @test.idempotent_id('a4a2e7ad-786f-4927-a85a-e545a93bd274')
    def test_rule_create_forbidden_for_regular_tenants(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.create_bandwidth_limit_rule,
            'policy', 1, 2)

    @test.attr(type='smoke')
    @test.idempotent_id('ce0bd0c2-54d9-4e29-85f1-cfb36ac3ebe2')
    def test_get_rules_by_policy(self):
        policy1 = self.create_qos_policy(name='test-policy1',
                                         description='test policy1',
                                         shared=False)
        rule1 = self.create_qos_bandwidth_limit_rule(policy_id=policy1['id'],
                                                     max_kbps=200,
                                                     max_burst_kbps=1337)

        policy2 = self.create_qos_policy(name='test-policy2',
                                         description='test policy2',
                                         shared=False)
        rule2 = self.create_qos_bandwidth_limit_rule(policy_id=policy2['id'],
                                                     max_kbps=5000,
                                                     max_burst_kbps=2523)

        # Test 'list rules'
        rules = self.admin_client.list_bandwidth_limit_rules(policy1['id'])
        rules = rules['bandwidth_limit_rules']
        rules_ids = [r['id'] for r in rules]
        self.assertIn(rule1['id'], rules_ids)
        self.assertNotIn(rule2['id'], rules_ids)


class RbacSharedQosPoliciesTest(base.BaseAdminNetworkTest):

    force_tenant_isolation = True
    credentials = ['primary', 'alt', 'admin']

    @classmethod
    @test.requires_ext(extension="qos", service="network")
    def resource_setup(cls):
        super(RbacSharedQosPoliciesTest, cls).resource_setup()
        cls.client2 = cls.alt_manager.network_client

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

    @test.idempotent_id('b9dcf582-d3b3-11e5-950a-54ee756c66df')
    def test_policy_sharing_with_wildcard(self):
        qos_pol = self.create_qos_policy(
            name=data_utils.rand_name('test-policy'),
            description='test-shared-policy', shared=False)
        self.assertNotIn(qos_pol, self.client2.list_qos_policies()['policies'])

        # test update shared False -> True
        self.admin_client.update_qos_policy(qos_pol['id'], shared=True)
        qos_pol['shared'] = True
        self.client2.show_qos_policy(qos_pol['id'])
        rbac_pol = {'target_tenant': '*',
                    'tenant_id': self.admin_client.tenant_id,
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

    @test.idempotent_id('328b1f70-d424-11e5-a57f-54ee756c66df')
    def test_net_bound_shared_policy_wildcard_and_tenant_id_wild_remove(self):
        client_rbac, wildcard_rbac = self._create_net_bound_qos_rbacs()
        # globally unshare the qos-policy, the specific share should remain
        self.admin_client.delete_rbac_policy(wildcard_rbac['id'])
        self.client.list_rbac_policies(id=client_rbac['id'])

    @test.idempotent_id('328b1f70-d424-11e5-a57f-54ee756c66df')
    def test_net_bound_shared_policy_wildcard_and_tenant_id_wild_remains(self):
        client_rbac, wildcard_rbac = self._create_net_bound_qos_rbacs()
        # remove client_rbac policy the wildcard share should remain
        self.admin_client.delete_rbac_policy(client_rbac['id'])
        self.client.list_rbac_policies(id=wildcard_rbac['id'])

    @test.idempotent_id('2ace9adc-da6e-11e5-aafe-54ee756c66df')
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

    @test.idempotent_id('9f85c76a-a350-11e5-8ae5-54ee756c66df')
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

    @test.idempotent_id('a9b39f46-a350-11e5-97c7-54ee756c66df')
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

    @test.idempotent_id('b0fe87e8-a350-11e5-9f08-54ee756c66df')
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

    @test.idempotent_id('ba88d0ca-a350-11e5-a06f-54ee756c66df')
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

    @test.idempotent_id('c10d993a-a350-11e5-9c7a-54ee756c66df')
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

    @test.idempotent_id('c7496f86-a350-11e5-b380-54ee756c66df')
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

    @test.idempotent_id('cd7d755a-a350-11e5-a344-54ee756c66df')
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

    @classmethod
    @test.requires_ext(extension="qos", service="network")
    def resource_setup(cls):
        super(QosDscpMarkingRuleTestJSON, cls).resource_setup()

    @test.attr(type='smoke')
    @test.idempotent_id('8a59b00b-3e9c-4787-92f8-93a5cdf5e378')
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
        self.assertEqual(qos_consts.RULE_TYPE_DSCP_MARK,
                         policy_rules[0]['type'])

    @test.attr(type='smoke')
    @test.idempotent_id('8a59b00b-ab01-4787-92f8-93a5cdf5e378')
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

    @test.attr(type='smoke')
    @test.idempotent_id('149a6988-2568-47d2-931e-2dbc858943b3')
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

    @test.attr(type='smoke')
    @test.idempotent_id('67ee6efd-7b33-4a68-927d-275b4f8ba958')
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

    @test.attr(type='smoke')
    @test.idempotent_id('f211222c-5808-46cb-a961-983bbab6b852')
    def test_rule_create_rule_nonexistent_policy(self):
        self.assertRaises(
            exceptions.NotFound,
            self.admin_client.create_dscp_marking_rule,
            'policy', self.VALID_DSCP_MARK1)

    @test.attr(type='smoke')
    @test.idempotent_id('a4a2e7ad-786f-4927-a85a-e545a93bd274')
    def test_rule_create_forbidden_for_regular_tenants(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.create_dscp_marking_rule,
            'policy', self.VALID_DSCP_MARK1)

    @test.attr(type='smoke')
    @test.idempotent_id('33646b08-4f05-4493-a48a-bde768a18533')
    def test_invalid_rule_create(self):
        policy = self.create_qos_policy(name='test-policy',
                                        description='test policy',
                                        shared=False)
        self.assertRaises(
            exceptions.BadRequest,
            self.admin_client.create_dscp_marking_rule,
            policy['id'], 58)

    @test.attr(type='smoke')
    @test.idempotent_id('ce0bd0c2-54d9-4e29-85f1-cfb36ac3ebe2')
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
