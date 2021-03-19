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

import random
from unittest import mock

from neutron_lib.exceptions import qos as qos_exc
from neutron_lib.services.qos import constants as qos_consts
from oslo_utils import uuidutils
from oslo_versionedobjects import exception

from neutron.common import utils as common_utils
from neutron.objects.db import api as db_api
from neutron.objects import network as net_obj
from neutron.objects import ports as port_obj
from neutron.objects.qos import binding
from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api


RULE_OBJ_CLS = {
    qos_consts.RULE_TYPE_BANDWIDTH_LIMIT: rule.QosBandwidthLimitRule,
    qos_consts.RULE_TYPE_DSCP_MARKING: rule.QosDscpMarkingRule,
    qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH: rule.QosMinimumBandwidthRule,
}


class _QosPolicyRBACBase(object):

    def get_random_object_fields(self, obj_cls=None):
        fields = (super(_QosPolicyRBACBase, self).
                  get_random_object_fields(obj_cls))
        rnd_actions = self._test_class.db_model.get_valid_actions()
        idx = random.randint(0, len(rnd_actions) - 1)
        fields['action'] = rnd_actions[idx]
        return fields


class QosPolicyRBACDbObjectTestCase(_QosPolicyRBACBase,
                                    test_base.BaseDbObjectTestCase,
                                    testlib_api.SqlTestCase):

    _test_class = policy.QosPolicyRBAC

    def setUp(self):
        super(QosPolicyRBACDbObjectTestCase, self).setUp()
        for obj in self.db_objs:
            policy_obj = policy.QosPolicy(self.context,
                                          id=obj['object_id'],
                                          project_id=obj['project_id'])
            policy_obj.create()

    def _create_test_qos_policy_rbac(self):
        self.objs[0].create()
        return self.objs[0]

    def test_object_version_degradation_1_1_to_1_0_no_id_no_project_id(self):
        qos_policy_rbac_obj = self._create_test_qos_policy_rbac()
        qos_policy_rbac_dict = qos_policy_rbac_obj.obj_to_primitive('1.0')
        self.assertNotIn('project_id',
                         qos_policy_rbac_dict['versioned_object.data'])
        self.assertNotIn('id', qos_policy_rbac_dict['versioned_object.data'])


class QosPolicyRBACIfaceObjectTestCase(_QosPolicyRBACBase,
                                       test_base.BaseObjectIfaceTestCase):
    _test_class = policy.QosPolicyRBAC


class QosPolicyObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = policy.QosPolicy

    def setUp(self):
        super(QosPolicyObjectTestCase, self).setUp()
        mock.patch.object(policy.QosPolicy, 'get_default').start()

        # qos_policy_ids will be incorrect, but we don't care in this test
        self.db_qos_bandwidth_rules = [
            self.get_random_db_fields(rule.QosBandwidthLimitRule)
            for _ in range(3)]

        self.db_qos_dscp_rules = [
            self.get_random_db_fields(rule.QosDscpMarkingRule)
            for _ in range(3)]

        self.db_qos_minimum_bandwidth_rules = [
            self.get_random_db_fields(rule.QosMinimumBandwidthRule)
            for _ in range(3)]

        self.model_map.update({
            self._test_class.db_model: self.db_objs,
            binding.QosPolicyPortBinding.db_model: [],
            binding.QosPolicyNetworkBinding.db_model: [],
            rule.QosBandwidthLimitRule.db_model: self.db_qos_bandwidth_rules,
            rule.QosDscpMarkingRule.db_model: self.db_qos_dscp_rules,
            rule.QosMinimumBandwidthRule.db_model:
                self.db_qos_minimum_bandwidth_rules})

    # TODO(ihrachys): stop overriding those test cases, instead base test cases
    # should be expanded if there are missing bits there to support QoS objects
    def test_get_objects(self):
        objs = self._test_class.get_objects(self.context)
        self.get_objects_mock.assert_any_call(
            self._test_class, self.context, _pager=None)
        self.assertItemsEqual(
            [test_base.get_obj_persistent_fields(obj) for obj in self.objs],
            [test_base.get_obj_persistent_fields(obj) for obj in objs])

    def test_get_objects_valid_fields(self):
        with mock.patch.object(db_api, 'get_objects',
                return_value=[self.db_objs[0]]) as get_objects_mock:
            objs = self._test_class.get_objects(
                self.context,
                **self.valid_field_filter)
            get_objects_mock.assert_any_call(
                self._test_class, self.context, _pager=None,
                **self.valid_field_filter)
        self._check_equal(self.objs[0], objs[0])

    def test_get_object(self):
        with mock.patch.object(db_api, 'get_object',
                return_value=self.db_objs[0]) as get_object_mock:
            obj = self._test_class.get_object(self.context, id='fake_id')
            self.assertTrue(self._is_test_class(obj))
            self._check_equal(self.objs[0], obj)
            get_object_mock.assert_called_once_with(
                self._test_class, self.context, id='fake_id')

    def test_to_dict_makes_primitive_field_value(self):
        # is_shared_with_tenant requires DB
        with mock.patch.object(self._test_class, 'is_shared_with_tenant',
                               return_value=False):
            (super(QosPolicyObjectTestCase, self).
             test_to_dict_makes_primitive_field_value())

    def test_get_policy_obj_not_found(self):
        context = common_utils.get_elevated_context(self.context)
        self.assertRaises(qos_exc.QosPolicyNotFound,
                          policy.QosPolicy.get_policy_obj,
                          context, "fake_id")


class QosPolicyDbObjectTestCase(test_base.BaseDbObjectTestCase,
                                testlib_api.SqlTestCase):

    _test_class = policy.QosPolicy

    def setUp(self):
        super(QosPolicyDbObjectTestCase, self).setUp()
        self._network_id = self._create_test_network_id()
        self._port = self._create_test_port(network_id=self._network_id)

    def _create_test_policy(self):
        self.objs[0].create()
        return self.objs[0]

    def _create_test_policy_with_rules(self, rule_type, reload_rules=False,
                                       bwlimit_direction=None):
        policy_obj = self._create_test_policy()
        rules = []
        for obj_cls in (RULE_OBJ_CLS.get(rule_type)
                        for rule_type in rule_type):
            rule_fields = self.get_random_object_fields(obj_cls=obj_cls)
            rule_fields['qos_policy_id'] = policy_obj.id
            if (obj_cls.rule_type == qos_consts.RULE_TYPE_BANDWIDTH_LIMIT and
                    bwlimit_direction is not None):
                rule_fields['direction'] = bwlimit_direction
            rule_obj = obj_cls(self.context, **rule_fields)
            rule_obj.create()
            rules.append(rule_obj)

        if reload_rules:
            policy_obj.obj_load_attr('rules')
        return policy_obj, rules

    def test_attach_network_get_network_policy(self):

        obj = self._create_test_policy()

        policy_obj = policy.QosPolicy.get_network_policy(self.context,
                                                         self._network_id)
        self.assertIsNone(policy_obj)

        # Now attach policy and repeat
        obj.attach_network(self._network_id)

        policy_obj = policy.QosPolicy.get_network_policy(self.context,
                                                         self._network_id)
        self.assertEqual(obj, policy_obj)

    def test_attach_network_nonexistent_network(self):

        obj = self._create_test_policy()
        self.assertRaises(qos_exc.NetworkQosBindingError,
                          obj.attach_network, uuidutils.generate_uuid())

    def test_attach_network_get_policy_network(self):

        obj = self._create_test_policy()
        obj.attach_network(self._network_id)

        networks = obj.get_bound_networks()
        self.assertEqual(1, len(networks))
        self.assertEqual(self._network_id, networks[0])

    def test_attach_and_get_multiple_policy_networks(self):

        net1_id = self._network_id
        net2 = net_obj.Network(self.context,
                               name='test-network2')
        net2.create()
        net2_id = net2['id']

        obj = self._create_test_policy()
        obj.attach_network(net1_id)
        obj.attach_network(net2_id)

        networks = obj.get_bound_networks()
        self.assertEqual(2, len(networks))
        self.assertIn(net1_id, networks)
        self.assertIn(net2_id, networks)

    def test_attach_port_nonexistent_port(self):

        obj = self._create_test_policy()
        self.assertRaises(qos_exc.PortQosBindingError,
                          obj.attach_port, uuidutils.generate_uuid())

    def test_attach_network_nonexistent_policy(self):

        policy_obj = self._make_object(self.obj_fields[0])
        self.assertRaises(qos_exc.NetworkQosBindingError,
                          policy_obj.attach_network, self._network_id)

    def test_attach_port_nonexistent_policy(self):

        policy_obj = self._make_object(self.obj_fields[0])
        self.assertRaises(qos_exc.PortQosBindingError,
                          policy_obj.attach_port, self._port['id'])

    def test_attach_port_get_port_policy(self):

        obj = self._create_test_policy()

        policy_obj = policy.QosPolicy.get_network_policy(self.context,
                                                         self._network_id)

        self.assertIsNone(policy_obj)

        # Now attach policy and repeat
        obj.attach_port(self._port['id'])

        policy_obj = policy.QosPolicy.get_port_policy(self.context,
                                                      self._port['id'])
        self.assertEqual(obj, policy_obj)

    def test_attach_and_get_multiple_policy_ports(self):

        port1_id = self._port['id']
        port2 = db_api.create_object(port_obj.Port, self.context,
                                     {'tenant_id': 'fake_tenant_id',
                                     'name': 'test-port2',
                                     'network_id': self._network_id,
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
        self.assertIn(port1_id, ports)
        self.assertIn(port2_id, ports)

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
        obj.attach_network(self._network_id)
        obj.detach_network(self._network_id)

        policy_obj = policy.QosPolicy.get_network_policy(self.context,
                                                         self._network_id)
        self.assertIsNone(policy_obj)

    def test_detach_port_nonexistent_port(self):
        obj = self._create_test_policy()
        self.assertRaises(qos_exc.PortQosBindingNotFound,
                          obj.detach_port, 'non-existent-port')

    def test_detach_network_nonexistent_network(self):
        obj = self._create_test_policy()
        self.assertRaises(qos_exc.NetworkQosBindingNotFound,
                          obj.detach_network, 'non-existent-port')

    def test_detach_port_nonexistent_policy(self):
        policy_obj = self._make_object(self.obj_fields[0])
        self.assertRaises(qos_exc.PortQosBindingNotFound,
                          policy_obj.detach_port, self._port['id'])

    def test_detach_network_nonexistent_policy(self):
        policy_obj = self._make_object(self.obj_fields[0])
        self.assertRaises(qos_exc.NetworkQosBindingNotFound,
                          policy_obj.detach_network, self._network_id)

    @mock.patch.object(policy.QosPolicyDefault, 'create')
    def test_set_default_no_default_policy_exists(self, mock_default_create):
        obj = self._create_test_policy()
        with mock.patch.object(obj, 'get_default', return_value=None):
            obj.set_default()
            mock_default_create.assert_called_once_with()

    def test_set_default_default_policy_exists(self):
        obj = self._create_test_policy()
        with mock.patch.object(obj, 'get_default', return_value=mock.Mock()):
            self.assertRaises(qos_exc.QoSPolicyDefaultAlreadyExists,
                              obj.set_default)

    def test_set_default_is_default_policy(self):
        obj = self._create_test_policy()
        with mock.patch.object(obj, 'get_default', return_value=obj.id), \
                mock.patch.object(obj, 'set_default'):
            obj.set_default()

    @mock.patch.object(policy.QosPolicyDefault, 'get_object')
    @mock.patch.object(policy.QosPolicyDefault, 'delete')
    def test_unset_default_default_policy_exists(self, mock_default_delete,
                                                 mock_default_get):
        obj = self._create_test_policy()
        with mock.patch.object(obj, 'get_default', return_value=obj.id):
            mock_default_get.return_value = policy.QosPolicyDefault()
            obj.unset_default()
            mock_default_get.assert_called_once_with(obj.obj_context,
                                                     project_id=obj.project_id)
            mock_default_delete.assert_called_once_with()

    def test_unset_default_no_default_policy_exists(self):
        obj = self._create_test_policy()
        with mock.patch.object(obj, 'get_default', return_value=None):
            obj.unset_default()

    def test_synthetic_rule_fields(self):
        policy_obj, rule_obj = self._create_test_policy_with_rules(
            [qos_consts.RULE_TYPE_BANDWIDTH_LIMIT])
        policy_obj = policy.QosPolicy.get_object(self.context,
                                                 id=policy_obj.id)
        self.assertEqual(rule_obj, policy_obj.rules)

    def test_get_object_fetches_rules_non_lazily(self):
        policy_obj, rule_obj = self._create_test_policy_with_rules(
            [qos_consts.RULE_TYPE_BANDWIDTH_LIMIT])
        policy_obj = policy.QosPolicy.get_object(self.context,
                                                 id=policy_obj.id)
        self.assertEqual(rule_obj, policy_obj.rules)

        primitive = policy_obj.obj_to_primitive()
        self.assertNotEqual([], (primitive['versioned_object.data']['rules']))

    def test_to_dict_returns_rules_as_dicts(self):
        policy_obj, rule_obj = self._create_test_policy_with_rules(
            [qos_consts.RULE_TYPE_BANDWIDTH_LIMIT])
        policy_obj = policy.QosPolicy.get_object(self.context,
                                                 id=policy_obj.id)

        obj_dict = policy_obj.to_dict()
        rule_dict = rule_obj[0].to_dict()

        # first make sure that to_dict() is still sane and does not return
        # objects
        for obj in (rule_dict, obj_dict):
            self.assertIsInstance(obj, dict)

        self.assertEqual(rule_dict, obj_dict['rules'][0])

    def test_shared_default(self):
        obj = self._make_object(self.obj_fields[0])
        self.assertFalse(obj.shared)

    def test_delete_not_allowed_if_policy_in_use_by_port(self):
        obj = self._create_test_policy()
        obj.attach_port(self._port['id'])

        self.assertRaises(qos_exc.QosPolicyInUse, obj.delete)

        obj.detach_port(self._port['id'])
        obj.delete()

    def test_delete_not_allowed_if_policy_in_use_by_network(self):
        obj = self._create_test_policy()
        obj.attach_network(self._network_id)

        self.assertRaises(qos_exc.QosPolicyInUse, obj.delete)

        obj.detach_network(self._network_id)
        obj.delete()

    def test_reload_rules_reloads_rules(self):
        policy_obj, rule_obj = self._create_test_policy_with_rules(
            [qos_consts.RULE_TYPE_BANDWIDTH_LIMIT])
        self.assertEqual([], policy_obj.rules)

        policy_obj._reload_rules()
        self.assertEqual(rule_obj, policy_obj.rules)

    def test_reload_is_default(self):
        policy_obj = self._create_test_policy()
        self.assertFalse(policy_obj.is_default)
        policy_obj.set_default()
        policy_obj._reload_is_default()
        self.assertTrue(policy_obj.is_default)

    def test_get_bound_tenant_ids_returns_set_of_tenant_ids(self):
        obj = self._create_test_policy()
        obj.attach_port(self._port['id'])
        ids = self._test_class.get_bound_tenant_ids(self.context, obj['id'])
        self.assertEqual(ids.pop(), self._port.project_id)
        self.assertEqual(len(ids), 0)

        obj.detach_port(self._port['id'])
        obj.delete()

    def test_object_version_degradation_less_than_1_8(self):
        policy_obj = self._create_test_policy()
        self.assertRaises(exception.IncompatibleObjectVersion,
                          policy_obj.obj_to_primitive, '1.7')

    @mock.patch.object(policy.QosPolicy, 'unset_default')
    def test_filter_by_shared(self, *mocks):
        project_id = uuidutils.generate_uuid()
        policy_obj = policy.QosPolicy(
            self.context, name='shared-policy', shared=True,
            project_id=project_id, is_default=False)
        policy_obj.create()

        policy_obj = policy.QosPolicy(
            self.context, name='private-policy', shared=False,
            project_id=project_id)
        policy_obj.create()

        shared_policies = policy.QosPolicy.get_objects(
            self.context, shared=True)
        self.assertEqual(1, len(shared_policies))
        self.assertEqual('shared-policy', shared_policies[0].name)

        private_policies = policy.QosPolicy.get_objects(
            self.context, shared=False)
        self.assertEqual(1, len(private_policies))
        self.assertEqual('private-policy', private_policies[0].name)

    def test_get_objects_queries_constant(self):
        # NOTE(korzen) QoSPolicy is using extra queries to reload rules.
        # QoSPolicy currently cannot be loaded using constant queries number.
        # It can be reworked in follow-up patch.
        pass


class QosPolicyDefaultObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = policy.QosPolicyDefault
