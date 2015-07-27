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

from neutron.common import exceptions as n_exc
from neutron.db import api as db_api
from neutron.db import models_v2
from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api


class QosPolicyObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = policy.QosPolicy

    def setUp(self):
        super(QosPolicyObjectTestCase, self).setUp()
        self.db_qos_rules = [self.get_random_fields(rule.QosRule)
                             for _ in range(3)]

        # Tie qos rules with policies
        self.db_qos_rules[0]['qos_policy_id'] = self.db_objs[0]['id']
        self.db_qos_rules[1]['qos_policy_id'] = self.db_objs[0]['id']
        self.db_qos_rules[2]['qos_policy_id'] = self.db_objs[1]['id']

        self.db_qos_bandwidth_rules = [
            self.get_random_fields(rule.QosBandwidthLimitRule)
            for _ in range(3)]

        # Tie qos rules with qos bandwidth limit rules
        for i, qos_rule in enumerate(self.db_qos_rules):
            self.db_qos_bandwidth_rules[i]['id'] = qos_rule['id']

        self.model_map = {
            self._test_class.db_model: self.db_objs,
            rule.QosRule.base_db_model: self.db_qos_rules,
            rule.QosBandwidthLimitRule.db_model: self.db_qos_bandwidth_rules}

    def fake_get_objects(self, context, model, qos_policy_id=None):
        objs = self.model_map[model]
        if model is rule.QosRule.base_db_model and qos_policy_id:
            return [obj for obj in objs
                    if obj['qos_policy_id'] == qos_policy_id]
        return objs

    def fake_get_object(self, context, model, id):
        objects = self.model_map[model]
        return [obj for obj in objects if obj['id'] == id][0]

    def test_get_objects(self):
        with mock.patch.object(
                    db_api, 'get_objects',
                    side_effect=self.fake_get_objects),\
                mock.patch.object(
                    db_api, 'get_object',
                    side_effect=self.fake_get_object):
            objs = self._test_class.get_objects(self.context)
        self._validate_objects(self.db_objs, objs)


class QosPolicyDbObjectTestCase(test_base.BaseDbObjectTestCase,
                                testlib_api.SqlTestCase):

    _test_class = policy.QosPolicy

    def setUp(self):
        super(QosPolicyDbObjectTestCase, self).setUp()
        self._create_test_network()
        self._create_test_port(self._network)

    def _create_test_policy(self):
        policy_obj = policy.QosPolicy(self.context, **self.db_obj)
        policy_obj.create()
        return policy_obj

    def _create_test_policy_with_rule(self):
        policy_obj = self._create_test_policy()

        rule_fields = self.get_random_fields(
            obj_cls=rule.QosBandwidthLimitRule)
        rule_fields['qos_policy_id'] = policy_obj.id
        rule_fields['tenant_id'] = policy_obj.tenant_id

        rule_obj = rule.QosBandwidthLimitRule(self.context, **rule_fields)
        rule_obj.create()

        return policy_obj, rule_obj

    def _create_test_network(self):
        # TODO(ihrachys): replace with network.create() once we get an object
        # implementation for networks
        self._network = db_api.create_object(self.context, models_v2.Network,
                                             {'name': 'test-network1'})

    def _create_test_port(self, network):
        # TODO(ihrachys): replace with port.create() once we get an object
        # implementation for ports
        self._port = db_api.create_object(self.context, models_v2.Port,
                                          {'name': 'test-port1',
                                           'network_id': network['id'],
                                           'mac_address': 'fake_mac',
                                           'admin_state_up': True,
                                           'status': 'ACTIVE',
                                           'device_id': 'fake_device',
                                           'device_owner': 'fake_owner'})

    #TODO(QoS): give a thought on checking detach/attach for invalid values.
    def test_attach_network_get_network_policy(self):

        obj = self._create_test_policy()

        policy_obj = policy.QosPolicy.get_network_policy(self.context,
                                                         self._network['id'])
        self.assertIsNone(policy_obj)

        # Now attach policy and repeat
        obj.attach_network(self._network['id'])

        policy_obj = policy.QosPolicy.get_network_policy(self.context,
                                                         self._network['id'])
        self.assertEqual(obj, policy_obj)

    def test_attach_network_nonexistent_network(self):

        obj = self._create_test_policy()
        self.assertRaises(n_exc.NetworkQosBindingNotFound,
                          obj.attach_network, 'non-existent-network')

    def test_attach_port_nonexistent_port(self):

        obj = self._create_test_policy()
        self.assertRaises(n_exc.PortQosBindingNotFound,
                          obj.attach_port, 'non-existent-port')

    def test_attach_network_nonexistent_policy(self):

        policy_obj = policy.QosPolicy(self.context, **self.db_obj)
        self.assertRaises(n_exc.NetworkQosBindingNotFound,
                          policy_obj.attach_network, self._network['id'])

    def test_attach_port_nonexistent_policy(self):

        policy_obj = policy.QosPolicy(self.context, **self.db_obj)
        self.assertRaises(n_exc.PortQosBindingNotFound,
                          policy_obj.attach_port, self._port['id'])

    def test_attach_port_get_port_policy(self):

        obj = self._create_test_policy()

        policy_obj = policy.QosPolicy.get_network_policy(self.context,
                                                         self._network['id'])

        self.assertIsNone(policy_obj)

        # Now attach policy and repeat
        obj.attach_port(self._port['id'])

        policy_obj = policy.QosPolicy.get_port_policy(self.context,
                                                      self._port['id'])
        self.assertEqual(obj, policy_obj)

    def test_detach_port(self):
        obj = self._create_test_policy()
        obj.attach_port(self._port['id'])
        obj.detach_port(self._port['id'])

        policy_obj = policy.QosPolicy.get_port_policy(self.context,
                                                      self._port['id'])
        self.assertIsNone(policy_obj)

    def test_detach_network(self):
        obj = self._create_test_policy()
        obj.attach_network(self._network['id'])
        obj.detach_network(self._network['id'])

        policy_obj = policy.QosPolicy.get_network_policy(self.context,
                                                         self._network['id'])
        self.assertIsNone(policy_obj)

    def test_detach_port_nonexistent_port(self):
        obj = self._create_test_policy()
        self.assertRaises(n_exc.PortQosBindingNotFound,
                          obj.detach_port, 'non-existent-port')

    def test_detach_network_nonexistent_network(self):
        obj = self._create_test_policy()
        self.assertRaises(n_exc.NetworkQosBindingNotFound,
                          obj.detach_network, 'non-existent-port')

    def test_detach_port_nonexistent_policy(self):
        policy_obj = policy.QosPolicy(self.context, **self.db_obj)
        self.assertRaises(n_exc.PortQosBindingNotFound,
                          policy_obj.detach_port, self._port['id'])

    def test_detach_network_nonexistent_policy(self):
        policy_obj = policy.QosPolicy(self.context, **self.db_obj)
        self.assertRaises(n_exc.NetworkQosBindingNotFound,
                          policy_obj.detach_network, self._network['id'])

    def test_synthetic_rule_fields(self):
        policy_obj, rule_obj = self._create_test_policy_with_rule()
        policy_obj = policy.QosPolicy.get_by_id(self.context, policy_obj.id)
        self.assertEqual([rule_obj], policy_obj.bandwidth_limit_rules)

    def test_create_is_in_single_transaction(self):
        obj = self._test_class(self.context, **self.db_obj)
        with mock.patch('sqlalchemy.engine.'
                        'Transaction.commit') as mock_commit,\
                mock.patch.object(obj._context.session, 'add'):
            obj.create()
        self.assertEqual(1, mock_commit.call_count)

    def test_get_by_id_fetches_rules_non_lazily(self):
        policy_obj, rule_obj = self._create_test_policy_with_rule()
        policy_obj = policy.QosPolicy.get_by_id(self.context, policy_obj.id)

        primitive = policy_obj.obj_to_primitive()
        self.assertNotEqual([], (primitive['versioned_object.data']
                                          ['bandwidth_limit_rules']))

    def test_to_dict_returns_rules_as_dicts(self):
        policy_obj, rule_obj = self._create_test_policy_with_rule()
        policy_obj = policy.QosPolicy.get_by_id(self.context, policy_obj.id)

        obj_dict = policy_obj.to_dict()
        rule_dict = rule_obj.to_dict()

        # first make sure that to_dict() is still sane and does not return
        # objects
        for obj in (rule_dict, obj_dict):
            self.assertIsInstance(obj, dict)

        self.assertEqual(rule_dict,
                         obj_dict['bandwidth_limit_rules'][0])
