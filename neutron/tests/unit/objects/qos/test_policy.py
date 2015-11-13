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
        # qos_policy_ids will be incorrect, but we don't care in this test
        self.db_qos_bandwidth_rules = [
            self.get_random_fields(rule.QosBandwidthLimitRule)
            for _ in range(3)]

        self.model_map = {
            self._test_class.db_model: self.db_objs,
            rule.QosBandwidthLimitRule.db_model: self.db_qos_bandwidth_rules}

    def fake_get_objects(self, context, model, **kwargs):
        return self.model_map[model]

    def fake_get_object(self, context, model, id):
        objects = self.model_map[model]
        return [obj for obj in objects if obj['id'] == id][0]

    def test_get_objects(self):
        admin_context = self.context.elevated()
        with mock.patch.object(
            db_api, 'get_objects',
            side_effect=self.fake_get_objects) as get_objects_mock:

            with mock.patch.object(
                db_api, 'get_object',
                side_effect=self.fake_get_object):

                with mock.patch.object(
                    self.context,
                    'elevated',
                    return_value=admin_context) as context_mock:

                    objs = self._test_class.get_objects(self.context)
                    context_mock.assert_called_once_with()
            get_objects_mock.assert_any_call(
                admin_context, self._test_class.db_model)
        self._validate_objects(self.db_objs, objs)

    def test_get_objects_valid_fields(self):
        admin_context = self.context.elevated()

        with mock.patch.object(
            db_api, 'get_objects',
            return_value=[self.db_obj]) as get_objects_mock:

            with mock.patch.object(
                self.context,
                'elevated',
                return_value=admin_context) as context_mock:

                objs = self._test_class.get_objects(
                    self.context,
                    **self.valid_field_filter)
                context_mock.assert_called_once_with()
            get_objects_mock.assert_any_call(
                admin_context, self._test_class.db_model,
                **self.valid_field_filter)
        self._validate_objects([self.db_obj], objs)

    def test_get_by_id(self):
        admin_context = self.context.elevated()
        with mock.patch.object(db_api, 'get_object',
                               return_value=self.db_obj) as get_object_mock:
            with mock.patch.object(self.context,
                                   'elevated',
                                   return_value=admin_context) as context_mock:
                obj = self._test_class.get_by_id(self.context, id='fake_id')
                self.assertTrue(self._is_test_class(obj))
                self.assertEqual(self.db_obj, test_base.get_obj_db_fields(obj))
                context_mock.assert_called_once_with()
                get_object_mock.assert_called_once_with(
                    admin_context, self._test_class.db_model, id='fake_id')


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
        self.assertEqual([rule_obj], policy_obj.rules)

    def test_get_by_id_fetches_rules_non_lazily(self):
        policy_obj, rule_obj = self._create_test_policy_with_rule()
        policy_obj = policy.QosPolicy.get_by_id(self.context, policy_obj.id)

        primitive = policy_obj.obj_to_primitive()
        self.assertNotEqual([], (primitive['versioned_object.data']['rules']))

    def test_to_dict_returns_rules_as_dicts(self):
        policy_obj, rule_obj = self._create_test_policy_with_rule()
        policy_obj = policy.QosPolicy.get_by_id(self.context, policy_obj.id)

        obj_dict = policy_obj.to_dict()
        rule_dict = rule_obj.to_dict()

        # first make sure that to_dict() is still sane and does not return
        # objects
        for obj in (rule_dict, obj_dict):
            self.assertIsInstance(obj, dict)

        self.assertEqual(rule_dict, obj_dict['rules'][0])

    def test_shared_default(self):
        self.db_obj.pop('shared')
        obj = self._test_class(self.context, **self.db_obj)
        self.assertFalse(obj.shared)

    def test_delete_not_allowed_if_policy_in_use_by_port(self):
        obj = self._create_test_policy()
        obj.attach_port(self._port['id'])

        self.assertRaises(n_exc.QosPolicyInUse, obj.delete)

        obj.detach_port(self._port['id'])
        obj.delete()

    def test_delete_not_allowed_if_policy_in_use_by_network(self):
        obj = self._create_test_policy()
        obj.attach_network(self._network['id'])

        self.assertRaises(n_exc.QosPolicyInUse, obj.delete)

        obj.detach_network(self._network['id'])
        obj.delete()

    def test_reload_rules_reloads_rules(self):
        policy_obj, rule_obj = self._create_test_policy_with_rule()
        self.assertEqual([], policy_obj.rules)

        policy_obj.reload_rules()
        self.assertEqual([rule_obj], policy_obj.rules)
