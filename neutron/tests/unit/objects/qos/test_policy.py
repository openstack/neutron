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
from neutron.db import models_v2
from neutron.objects.db import api as db_api
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

        self.db_qos_dscp_rules = [
            self.get_random_fields(rule.QosDscpMarkingRule)
            for _ in range(3)]

        self.model_map = {
            self._test_class.db_model: self.db_objs,
            self._test_class.rbac_db_model: [],
            self._test_class.port_binding_model: [],
            self._test_class.network_binding_model: [],
            rule.QosBandwidthLimitRule.db_model: self.db_qos_bandwidth_rules,
            rule.QosDscpMarkingRule.db_model: self.db_qos_dscp_rules}

        self.get_object = mock.patch.object(
            db_api, 'get_object', side_effect=self.fake_get_object).start()
        self.get_objects = mock.patch.object(
            db_api, 'get_objects', side_effect=self.fake_get_objects).start()

    def fake_get_objects(self, context, model, **kwargs):
        return self.model_map[model]

    def fake_get_object(self, context, model, **kwargs):
        objects = self.model_map[model]
        if not objects:
            return None
        return [obj for obj in objects if obj['id'] == kwargs['id']][0]

    def test_get_objects(self):
        admin_context = self.context.elevated()
        with mock.patch.object(self.context, 'elevated',
                               return_value=admin_context) as context_mock:
            objs = self._test_class.get_objects(self.context)
        context_mock.assert_called_once_with()
        self.get_objects.assert_any_call(
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

    def test_get_object(self):
        admin_context = self.context.elevated()
        with mock.patch.object(db_api, 'get_object',
                               return_value=self.db_obj) as get_object_mock:
            with mock.patch.object(self.context,
                                   'elevated',
                                   return_value=admin_context) as context_mock:
                obj = self._test_class.get_object(self.context, id='fake_id')
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
        self.db_qos_bandwidth_rules = [
            self.get_random_fields(rule.QosBandwidthLimitRule)
            for _ in range(3)]

        self.model_map.update({
            rule.QosBandwidthLimitRule.db_model: self.db_qos_bandwidth_rules
        })

        self._create_test_network()
        self._create_test_port(self._network)

    def _create_test_policy(self):
        policy_obj = policy.QosPolicy(self.context, **self.db_obj)
        policy_obj.create()
        return policy_obj

    def _create_test_policy_with_bwrule(self):
        policy_obj = self._create_test_policy()

        rule_fields = self.get_random_fields(
            obj_cls=rule.QosBandwidthLimitRule)
        rule_fields['qos_policy_id'] = policy_obj.id

        rule_obj = rule.QosBandwidthLimitRule(self.context, **rule_fields)
        rule_obj.create()

        return policy_obj, rule_obj

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

    def test_attach_network_get_policy_network(self):

        obj = self._create_test_policy()
        obj.attach_network(self._network['id'])

        networks = obj.get_bound_networks()
        self.assertEqual(1, len(networks))
        self.assertEqual(self._network['id'], networks[0])

    def test_attach_and_get_multiple_policy_networks(self):

        net1_id = self._network['id']
        net2 = db_api.create_object(self.context,
                                    models_v2.Network,
                                    {'name': 'test-network2'})
        net2_id = net2['id']

        obj = self._create_test_policy()
        obj.attach_network(net1_id)
        obj.attach_network(net2_id)

        networks = obj.get_bound_networks()
        self.assertEqual(2, len(networks))
        self.assertTrue(net1_id in networks)
        self.assertTrue(net2_id in networks)

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

    def test_attach_and_get_multiple_policy_ports(self):

        port1_id = self._port['id']
        port2 = db_api.create_object(self.context, models_v2.Port,
                                     {'tenant_id': 'fake_tenant_id',
                                     'name': 'test-port2',
                                     'network_id': self._network['id'],
                                     'mac_address': 'fake_mac2',
                                     'admin_state_up': True,
                                     'status': 'ACTIVE',
                                     'device_id': 'fake_device',
                                     'device_owner': 'fake_owner'})
        port2_id = port2['id']

        obj = self._create_test_policy()
        obj.attach_port(port1_id)
        obj.attach_port(port2_id)

        ports = obj.get_bound_ports()
        self.assertEqual(2, len(ports))
        self.assertTrue(port1_id in ports)
        self.assertTrue(port2_id in ports)

    def test_attach_port_get_policy_port(self):

        obj = self._create_test_policy()
        obj.attach_port(self._port['id'])

        ports = obj.get_bound_ports()
        self.assertEqual(1, len(ports))
        self.assertEqual(self._port['id'], ports[0])

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
        policy_obj, rule_obj = self._create_test_policy_with_bwrule()
        policy_obj = policy.QosPolicy.get_object(self.context,
                                                 id=policy_obj.id)
        self.assertEqual([rule_obj], policy_obj.rules)

    def test_get_object_fetches_rules_non_lazily(self):
        policy_obj, rule_obj = self._create_test_policy_with_bwrule()
        policy_obj = policy.QosPolicy.get_object(self.context,
                                                 id=policy_obj.id)
        self.assertEqual([rule_obj], policy_obj.rules)

        primitive = policy_obj.obj_to_primitive()
        self.assertNotEqual([], (primitive['versioned_object.data']['rules']))

    def test_to_dict_returns_rules_as_dicts(self):
        policy_obj, rule_obj = self._create_test_policy_with_bwrule()
        policy_obj = policy.QosPolicy.get_object(self.context,
                                                 id=policy_obj.id)

        obj_dict = policy_obj.to_dict()
        rule_dict = rule_obj.to_dict()

        # first make sure that to_dict() is still sane and does not return
        # objects
        for obj in (rule_dict, obj_dict):
            self.assertIsInstance(obj, dict)

        self.assertEqual(rule_dict, obj_dict['rules'][0])

    def test_shared_default(self):
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
        policy_obj, rule_obj = self._create_test_policy_with_bwrule()
        self.assertEqual([], policy_obj.rules)

        policy_obj.reload_rules()
        self.assertEqual([rule_obj], policy_obj.rules)

    def test_get_bound_tenant_ids_returns_set_of_tenant_ids(self):
        obj = self._create_test_policy()
        obj.attach_port(self._port['id'])
        ids = self._test_class.get_bound_tenant_ids(self.context, obj['id'])
        self.assertEqual(ids.pop(), self._port['tenant_id'])
        self.assertEqual(len(ids), 0)

        obj.detach_port(self._port['id'])
        obj.delete()

    @staticmethod
    def _policy_through_version(obj, version):
        primitive = obj.obj_to_primitive(target_version=version)
        return policy.QosPolicy.clean_obj_from_primitive(primitive)

    def _create_test_policy_with_bw_and_dscp(self):
        policy_obj, rule_obj_band = self._create_test_policy_with_bwrule()

        rule_fields = self.get_random_fields(obj_cls=rule.QosDscpMarkingRule)
        rule_fields['qos_policy_id'] = policy_obj.id

        rule_obj_dscp = rule.QosDscpMarkingRule(self.context, **rule_fields)
        rule_obj_dscp.create()

        policy_obj.reload_rules()
        return policy_obj, rule_obj_band, rule_obj_dscp

    def test_object_version(self):
        policy_obj, rule_obj_band, rule_obj_dscp = (
            self._create_test_policy_with_bw_and_dscp())

        policy_obj_v1_1 = self._policy_through_version(policy_obj, '1.1')

        self.assertIn(rule_obj_band, policy_obj_v1_1.rules)
        self.assertIn(rule_obj_dscp, policy_obj_v1_1.rules)
        self.assertEqual(policy_obj.VERSION, '1.1')

    #TODO(davidsha) add testing for object version incrementation
    def test_object_version_degradation_1_1_to_1_0(self):
        policy_obj, rule_obj_band, rule_obj_dscp = (
            self._create_test_policy_with_bw_and_dscp())

        policy_obj_v1_0 = self._policy_through_version(policy_obj, '1.0')

        self.assertIn(rule_obj_band, policy_obj_v1_0.rules)
        self.assertNotIn(rule_obj_dscp, policy_obj_v1_0.rules)
        #NOTE(mangelajo): we should not check .VERSION, since that's the
        #                 local version on the class definition
