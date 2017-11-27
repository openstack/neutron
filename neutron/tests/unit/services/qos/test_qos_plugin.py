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
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.common import exceptions as n_exc
from neutron import context
from neutron import manager
from neutron.objects import base as base_object
from neutron.objects.qos import policy as policy_object
from neutron.objects.qos import rule as rule_object
from neutron.plugins.common import constants
from neutron.services.qos import qos_consts
from neutron.tests.unit.services.qos import base


DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class TestQosPlugin(base.BaseQosTestCase):

    def setUp(self):
        super(TestQosPlugin, self).setUp()
        self.setup_coreplugin(load_plugins=False)

        mock.patch('neutron.objects.db.api.create_object').start()
        mock.patch('neutron.objects.db.api.update_object').start()
        mock.patch('neutron.objects.db.api.delete_object').start()
        mock.patch('neutron.objects.db.api.get_object').start()
        mock.patch(
            'neutron.objects.qos.policy.QosPolicy.obj_load_attr').start()
        # We don't use real models as per mocks above. We also need to mock-out
        # methods that work with real data types
        mock.patch(
            'neutron.objects.base.NeutronDbObject.modify_fields_from_db'
        ).start()

        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        cfg.CONF.set_override("service_plugins", ["qos"])

        manager.init()
        self.qos_plugin = directory.get_plugin(constants.QOS)

        #TODO(mangelajo): Remove notification_driver_manager mock in Pike
        self.qos_plugin.notification_driver_manager = mock.Mock()
        self.qos_plugin.driver_manager = mock.Mock()

        self.rpc_push = mock.patch('neutron.api.rpc.handlers.resources_rpc'
                                   '.ResourcesPushRpcApi.push').start()

        self.ctxt = context.Context('fake_user', 'fake_tenant')
        mock.patch.object(self.ctxt.session, 'refresh').start()
        mock.patch.object(self.ctxt.session, 'expunge').start()

        self.policy_data = {
            'policy': {'id': uuidutils.generate_uuid(),
                       'project_id': uuidutils.generate_uuid(),
                       'name': 'test-policy',
                       'description': 'Test policy description',
                       'shared': True}}

        self.rule_data = {
            'bandwidth_limit_rule': {'id': uuidutils.generate_uuid(),
                                     'max_kbps': 100,
                                     'max_burst_kbps': 150},
            'dscp_marking_rule': {'id': uuidutils.generate_uuid(),
                                  'dscp_mark': 16}}

        self.policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])

        self.rule = rule_object.QosBandwidthLimitRule(
            self.ctxt, **self.rule_data['bandwidth_limit_rule'])

        self.dscp_rule = rule_object.QosDscpMarkingRule(
            self.ctxt, **self.rule_data['dscp_marking_rule'])

    def _validate_driver_params(self, method_name):
        method = getattr(self.qos_plugin.notification_driver_manager,
                         method_name)
        self.assertTrue(method.called)
        self.assertIsInstance(
            method.call_args[0][1], policy_object.QosPolicy)

        self.assertTrue(self.qos_plugin.driver_manager.call.called)
        self.assertEqual(self.qos_plugin.driver_manager.call.call_args[0][0],
                         method_name)
        self.assertIsInstance(
            self.qos_plugin.driver_manager.call.call_args[0][2],
            policy_object.QosPolicy
        )

    @mock.patch(
        'neutron.objects.rbac_db.RbacNeutronDbObjectMixin'
        '.create_rbac_policy')
    def test_add_policy(self, *mocks):
        self.qos_plugin.create_policy(self.ctxt, self.policy_data)
        self._validate_driver_params('create_policy')

    def test_add_policy_with_extra_tenant_keyword(self, *mocks):
        policy_id = uuidutils.generate_uuid()
        project_id = uuidutils.generate_uuid()
        tenant_policy = {
            'policy': {'id': policy_id,
                       'project_id': project_id,
                       'tenant_id': project_id,
                       'name': 'test-policy',
                       'description': 'Test policy description',
                       'shared': True}}

        policy_details = {'id': policy_id,
                          'project_id': project_id,
                          'name': 'test-policy',
                          'description': 'Test policy description',
                          'shared': True}

        with mock.patch('neutron.objects.qos.policy.QosPolicy') as QosMocked:
            self.qos_plugin.create_policy(self.ctxt, tenant_policy)

        QosMocked.assert_called_once_with(self.ctxt, **policy_details)

    @mock.patch.object(policy_object.QosPolicy, "get_object")
    @mock.patch(
        'neutron.objects.rbac_db.RbacNeutronDbObjectMixin'
        '.create_rbac_policy')
    def test_update_policy(self, *mocks):
        mock_qos_policy_get = mocks[1]
        mock_qos_policy_get.return_value = self.policy
        fields = base_object.get_updatable_fields(
            policy_object.QosPolicy, self.policy_data['policy'])
        self.qos_plugin.update_policy(
            self.ctxt, self.policy.id, {'policy': fields})
        self._validate_driver_params('update_policy')

    @mock.patch('neutron.objects.db.api.get_object', return_value=None)
    def test_delete_policy(self, *mocks):
        self.qos_plugin.delete_policy(self.ctxt, self.policy.id)
        self._validate_driver_params('delete_policy')

    def test_create_policy_rule(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=self.policy):
            self.qos_plugin.create_policy_bandwidth_limit_rule(
                self.ctxt, self.policy.id, self.rule_data)
            self._validate_driver_params('update_policy')

    def test_update_policy_rule(self):
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            setattr(_policy, "rules", [self.rule])
            self.qos_plugin.update_policy_bandwidth_limit_rule(
                self.ctxt, self.rule.id, self.policy.id, self.rule_data)
            self._validate_driver_params('update_policy')

    def test_update_policy_rule_bad_policy(self):
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            setattr(_policy, "rules", [])
            self.assertRaises(
                n_exc.QosRuleNotFound,
                self.qos_plugin.update_policy_bandwidth_limit_rule,
                self.ctxt, self.rule.id, self.policy.id,
                self.rule_data)

    def test_delete_policy_rule(self):
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            setattr(_policy, "rules", [self.rule])
            self.qos_plugin.delete_policy_bandwidth_limit_rule(
                        self.ctxt, self.rule.id, _policy.id)
            self._validate_driver_params('update_policy')

    def test_delete_policy_rule_bad_policy(self):
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            setattr(_policy, "rules", [])
            self.assertRaises(
                n_exc.QosRuleNotFound,
                self.qos_plugin.delete_policy_bandwidth_limit_rule,
                self.ctxt, self.rule.id, _policy.id)

    def test_get_policy_bandwidth_limit_rule(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=self.policy):
            with mock.patch('neutron.objects.qos.rule.'
                            'QosBandwidthLimitRule.'
                            'get_object') as get_object_mock:
                self.qos_plugin.get_policy_bandwidth_limit_rule(
                    self.ctxt, self.rule.id, self.policy.id)
                get_object_mock.assert_called_once_with(self.ctxt,
                    id=self.rule.id)

    def test_get_policy_bandwidth_limit_rules_for_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=self.policy):
            with mock.patch('neutron.objects.qos.rule.'
                            'QosBandwidthLimitRule.'
                            'get_objects') as get_objects_mock:
                self.qos_plugin.get_policy_bandwidth_limit_rules(
                    self.ctxt, self.policy.id)
                get_objects_mock.assert_called_once_with(
                    self.ctxt, _pager=mock.ANY, qos_policy_id=self.policy.id)

    def test_get_policy_bandwidth_limit_rules_for_policy_with_filters(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=self.policy):
            with mock.patch('neutron.objects.qos.rule.'
                            'QosBandwidthLimitRule.'
                            'get_objects') as get_objects_mock:

                filters = {'filter': 'filter_id'}
                self.qos_plugin.get_policy_bandwidth_limit_rules(
                    self.ctxt, self.policy.id, filters=filters)
                get_objects_mock.assert_called_once_with(
                    self.ctxt, _pager=mock.ANY,
                    qos_policy_id=self.policy.id,
                    filter='filter_id')

    def test_get_policy_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                n_exc.QosPolicyNotFound,
                self.qos_plugin.get_policy,
                self.ctxt, self.policy.id)

    def test_get_policy_bandwidth_limit_rule_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                n_exc.QosPolicyNotFound,
                self.qos_plugin.get_policy_bandwidth_limit_rule,
                self.ctxt, self.rule.id, self.policy.id)

    def test_get_policy_bandwidth_limit_rules_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                n_exc.QosPolicyNotFound,
                self.qos_plugin.get_policy_bandwidth_limit_rules,
                self.ctxt, self.policy.id)

    def test_create_policy_dscp_marking_rule(self):
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            setattr(_policy, "rules", [self.dscp_rule])
            self.qos_plugin.create_policy_dscp_marking_rule(
                self.ctxt, self.policy.id, self.rule_data)
            self._validate_driver_params('update_policy')

    def test_update_policy_dscp_marking_rule(self):
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            setattr(_policy, "rules", [self.dscp_rule])
            self.qos_plugin.update_policy_dscp_marking_rule(
                self.ctxt, self.dscp_rule.id, self.policy.id, self.rule_data)
            self._validate_driver_params('update_policy')

    def test_delete_policy_dscp_marking_rule(self):
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            setattr(_policy, "rules", [self.dscp_rule])
            self.qos_plugin.delete_policy_dscp_marking_rule(
                self.ctxt, self.dscp_rule.id, self.policy.id)
            self._validate_driver_params('update_policy')

    def test_get_policy_dscp_marking_rules(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=self.policy):
            with mock.patch('neutron.objects.qos.rule.'
                            'QosDscpMarkingRule.'
                            'get_objects') as get_objects_mock:
                self.qos_plugin.get_policy_dscp_marking_rules(
                    self.ctxt, self.policy.id)
                get_objects_mock.assert_called_once_with(
                    self.ctxt, _pager=mock.ANY, qos_policy_id=self.policy.id)

    def test_get_policy_dscp_marking_rules_for_policy_with_filters(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=self.policy):
            with mock.patch('neutron.objects.qos.rule.'
                            'QosDscpMarkingRule.'
                            'get_objects') as get_objects_mock:

                filters = {'filter': 'filter_id'}
                self.qos_plugin.get_policy_dscp_marking_rules(
                    self.ctxt, self.policy.id, filters=filters)
                get_objects_mock.assert_called_once_with(
                    self.ctxt, qos_policy_id=self.policy.id,
                    _pager=mock.ANY, filter='filter_id')

    def test_get_policy_dscp_marking_rule_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                n_exc.QosPolicyNotFound,
                self.qos_plugin.get_policy_dscp_marking_rule,
                self.ctxt, self.dscp_rule.id, self.policy.id)

    def test_get_policy_dscp_marking_rules_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                n_exc.QosPolicyNotFound,
                self.qos_plugin.get_policy_dscp_marking_rules,
                self.ctxt, self.policy.id)

    def test_get_policy_minimum_bandwidth_rule(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=self.policy):
            with mock.patch('neutron.objects.qos.rule.'
                            'QosMinimumBandwidthRule.'
                            'get_object') as get_object_mock:
                self.qos_plugin.get_policy_minimum_bandwidth_rule(
                    self.ctxt, self.rule.id, self.policy.id)
                get_object_mock.assert_called_once_with(self.ctxt,
                    id=self.rule.id)

    def test_get_policy_minimum_bandwidth_rules_for_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=self.policy):
            with mock.patch('neutron.objects.qos.rule.'
                            'QosMinimumBandwidthRule.'
                            'get_objects') as get_objects_mock:
                self.qos_plugin.get_policy_minimum_bandwidth_rules(
                    self.ctxt, self.policy.id)
                get_objects_mock.assert_called_once_with(
                    self.ctxt, _pager=mock.ANY, qos_policy_id=self.policy.id)

    def test_get_policy_minimum_bandwidth_rules_for_policy_with_filters(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=self.policy):
            with mock.patch('neutron.objects.qos.rule.'
                            'QosMinimumBandwidthRule.'
                            'get_objects') as get_objects_mock:

                filters = {'filter': 'filter_id'}
                self.qos_plugin.get_policy_minimum_bandwidth_rules(
                    self.ctxt, self.policy.id, filters=filters)
                get_objects_mock.assert_called_once_with(
                    self.ctxt, _pager=mock.ANY,
                    qos_policy_id=self.policy.id,
                    filter='filter_id')

    def test_get_policy_minimum_bandwidth_rule_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                n_exc.QosPolicyNotFound,
                self.qos_plugin.get_policy_minimum_bandwidth_rule,
                self.ctxt, self.rule.id, self.policy.id)

    def test_get_policy_minimum_bandwidth_rules_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                n_exc.QosPolicyNotFound,
                self.qos_plugin.get_policy_minimum_bandwidth_rules,
                self.ctxt, self.policy.id)

    def test_create_policy_rule_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                n_exc.QosPolicyNotFound,
                self.qos_plugin.create_policy_bandwidth_limit_rule,
                self.ctxt, self.policy.id, self.rule_data)

    def test_update_policy_rule_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                n_exc.QosPolicyNotFound,
                self.qos_plugin.update_policy_bandwidth_limit_rule,
                self.ctxt, self.rule.id, self.policy.id, self.rule_data)

    def test_delete_policy_rule_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                n_exc.QosPolicyNotFound,
                self.qos_plugin.delete_policy_bandwidth_limit_rule,
                self.ctxt, self.rule.id, self.policy.id)

    def test_verify_bad_method_call(self):
        self.assertRaises(AttributeError, getattr, self.qos_plugin,
                          'create_policy_bandwidth_limit_rules')

    def test_get_rule_types(self):
        core_plugin = directory.get_plugin()
        rule_types_mock = mock.PropertyMock(
            return_value=qos_consts.VALID_RULE_TYPES)
        filters = {'type': 'type_id'}
        with mock.patch.object(core_plugin, 'supported_qos_rule_types',
                               new_callable=rule_types_mock,
                               create=True):
            types = self.qos_plugin.get_rule_types(self.ctxt, filters=filters)
            self.assertEqual(sorted(qos_consts.VALID_RULE_TYPES),
                             sorted(type_['type'] for type_ in types))

    @mock.patch('neutron.objects.qos.policy.QosPolicy')
    def test_policy_notification_ordering(self, qos_policy_mock):

        policy_actions = {'create': [self.ctxt, {'policy': {}}],
                          'update': [self.ctxt, self.policy.id,
                                     {'policy': {}}],
                          'delete': [self.ctxt, self.policy.id]}

        self.qos_plugin.notification_driver_manager = mock.Mock()

        mock_manager = mock.Mock()
        mock_manager.attach_mock(qos_policy_mock, 'QosPolicy')
        mock_manager.attach_mock(self.qos_plugin.notification_driver_manager,
                                 'notification_driver')

        for action, arguments in policy_actions.items():
            mock_manager.reset_mock()

            method = getattr(self.qos_plugin, "%s_policy" % action)
            method(*arguments)

            # NOTE(slaweq): in case of update existing qos_policy_object
            # is taken with get_object() method so mocked call is different
            if action == "update":
                policy_mock_call = getattr(
                    mock.call.QosPolicy.get_object(), action)()
            else:
                policy_mock_call = getattr(mock.call.QosPolicy(), action)()
            notify_mock_call = getattr(mock.call.notification_driver,
                                       '%s_policy' % action)(self.ctxt,
                                                             mock.ANY)

            self.assertTrue(mock_manager.mock_calls.index(policy_mock_call) <
                            mock_manager.mock_calls.index(notify_mock_call))

    @mock.patch('neutron.objects.qos.policy.QosPolicy')
    def test_rule_notification_and_driver_ordering(self, qos_policy_mock):
        rule_cls_mock = mock.Mock()
        rule_cls_mock.rule_type = 'fake'

        rule_actions = {'create': [self.ctxt, rule_cls_mock,
                                   self.policy.id, {'fake_rule': {}}],
                        'update': [self.ctxt, rule_cls_mock,
                                   self.rule.id,
                                   self.policy.id, {'fake_rule': {}}],
                        'delete': [self.ctxt, rule_cls_mock,
                                   self.rule.id, self.policy.id]}

        # TODO(mangelajo): Remove notification_driver_manager checks in Pike
        #                  and rename this test
        self.qos_plugin.notification_driver_manager = mock.Mock()

        mock_manager = mock.Mock()
        mock_manager.attach_mock(qos_policy_mock, 'QosPolicy')
        mock_manager.attach_mock(rule_cls_mock, 'RuleCls')
        mock_manager.attach_mock(self.qos_plugin.notification_driver_manager,
                                 'notification_driver')
        mock_manager.attach_mock(self.qos_plugin.driver_manager, 'driver')

        for action, arguments in rule_actions.items():
            mock_manager.reset_mock()
            method = getattr(self.qos_plugin, "%s_policy_rule" % action)
            method(*arguments)

            # some actions get rule from policy
            get_rule_mock_call = getattr(
                mock.call.QosPolicy.get_object().get_rule_by_id(), action)()
            # some actions construct rule from class reference
            rule_mock_call = getattr(mock.call.RuleCls(), action)()

            notify_mock_call = mock.call.notification_driver.update_policy(
                    self.ctxt, mock.ANY)

            driver_mock_call = mock.call.driver.call('update_policy',
                                                     self.ctxt, mock.ANY)

            if rule_mock_call in mock_manager.mock_calls:
                action_index = mock_manager.mock_calls.index(rule_mock_call)
            else:
                action_index = mock_manager.mock_calls.index(
                    get_rule_mock_call)

            self.assertTrue(
                action_index < mock_manager.mock_calls.index(notify_mock_call))

            self.assertTrue(
                action_index < mock_manager.mock_calls.index(driver_mock_call))
