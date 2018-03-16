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
from neutron_lib.callbacks import events
from neutron_lib import context
from neutron_lib import exceptions as lib_exc
from neutron_lib.plugins import constants as plugins_constants
from neutron_lib.plugins import directory
from neutron_lib.services.qos import constants as qos_consts
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron import manager
from neutron.objects import base as base_object
from neutron.objects.qos import policy as policy_object
from neutron.objects.qos import rule as rule_object
from neutron.services.qos import qos_plugin
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
        _mock_qos_load_attr = mock.patch(
            'neutron.objects.qos.policy.QosPolicy.obj_load_attr')
        self.mock_qos_load_attr = _mock_qos_load_attr.start()
        # We don't use real models as per mocks above. We also need to mock-out
        # methods that work with real data types
        mock.patch(
            'neutron.objects.base.NeutronDbObject.modify_fields_from_db'
        ).start()
        mock.patch.object(policy_object.QosPolicy, 'unset_default').start()
        mock.patch.object(policy_object.QosPolicy, 'set_default').start()

        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        cfg.CONF.set_override("service_plugins", ["qos"])

        manager.init()
        self.qos_plugin = directory.get_plugin(plugins_constants.QOS)

        self.qos_plugin.driver_manager = mock.Mock()

        self.rpc_push = mock.patch('neutron.api.rpc.handlers.resources_rpc'
                                   '.ResourcesPushRpcApi.push').start()

        self.ctxt = context.Context('fake_user', 'fake_tenant')
        self.admin_ctxt = context.get_admin_context()
        mock.patch.object(self.ctxt.session, 'refresh').start()
        mock.patch.object(self.ctxt.session, 'expunge').start()

        self.policy_data = {
            'policy': {'id': uuidutils.generate_uuid(),
                       'project_id': uuidutils.generate_uuid(),
                       'name': 'test-policy',
                       'description': 'Test policy description',
                       'shared': True,
                       'is_default': False}}

        self.rule_data = {
            'bandwidth_limit_rule': {'id': uuidutils.generate_uuid(),
                                     'max_kbps': 100,
                                     'max_burst_kbps': 150},
            'dscp_marking_rule': {'id': uuidutils.generate_uuid(),
                                  'dscp_mark': 16},
            'minimum_bandwidth_rule': {
                'id': uuidutils.generate_uuid(),
                'min_kbps': 10}}

        self.policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])

        self.rule = rule_object.QosBandwidthLimitRule(
            self.ctxt, **self.rule_data['bandwidth_limit_rule'])

        self.dscp_rule = rule_object.QosDscpMarkingRule(
            self.ctxt, **self.rule_data['dscp_marking_rule'])

        self.min_rule = rule_object.QosMinimumBandwidthRule(
            self.ctxt, **self.rule_data['minimum_bandwidth_rule'])

    def _validate_driver_params(self, method_name, ctxt):
        call_args = self.qos_plugin.driver_manager.call.call_args[0]
        self.assertTrue(self.qos_plugin.driver_manager.call.called)
        self.assertEqual(call_args[0], method_name)
        self.assertEqual(call_args[1], ctxt)
        self.assertIsInstance(call_args[2], policy_object.QosPolicy)

    def test_get_ports_with_policy(self):
        network_ports = [
            mock.MagicMock(qos_policy_id=None),
            mock.MagicMock(qos_policy_id=uuidutils.generate_uuid()),
            mock.MagicMock(qos_policy_id=None)
        ]
        ports = [
            mock.MagicMock(qos_policy_id=self.policy.id),
        ]
        expected_network_ports = [
            port for port in network_ports if port.qos_policy_id is None]
        expected_ports = ports + expected_network_ports
        with mock.patch(
            'neutron.objects.ports.Port.get_objects',
            side_effect=[network_ports, ports]
        ), mock.patch.object(
            self.policy, "get_bound_networks"
        ), mock.patch.object(
            self.policy, "get_bound_ports"
        ):
            policy_ports = self.qos_plugin._get_ports_with_policy(
                self.ctxt, self.policy)
            self.assertEqual(
                len(expected_ports), len(policy_ports))
            for port in expected_ports:
                self.assertIn(port, policy_ports)

    def _test_validate_create_port_callback(self, policy_id=None,
                                            network_policy_id=None):
        port_id = uuidutils.generate_uuid()
        kwargs = {
            "context": self.ctxt,
            "port": {"id": port_id}
        }
        port_mock = mock.MagicMock(id=port_id, qos_policy_id=policy_id)
        network_mock = mock.MagicMock(
            id=uuidutils.generate_uuid(), qos_policy_id=network_policy_id)
        policy_mock = mock.MagicMock(id=policy_id)
        admin_ctxt = mock.Mock()
        expected_policy_id = policy_id or network_policy_id
        with mock.patch(
            'neutron.objects.ports.Port.get_object',
            return_value=port_mock
        ), mock.patch(
            'neutron.objects.network.Network.get_object',
            return_value=network_mock
        ), mock.patch(
            'neutron.objects.qos.policy.QosPolicy.get_object',
            return_value=policy_mock
        ) as get_policy, mock.patch.object(
            self.qos_plugin, "validate_policy_for_port"
        ) as validate_policy_for_port, mock.patch.object(
            self.ctxt, "elevated", return_value=admin_ctxt
        ):
            self.qos_plugin._validate_create_port_callback(
                "PORT", "precommit_create", "test_plugin", **kwargs)
            if policy_id or network_policy_id:
                get_policy.assert_called_once_with(admin_ctxt,
                                                   id=expected_policy_id)
                validate_policy_for_port.assert_called_once_with(policy_mock,
                                                                 port_mock)
            else:
                get_policy.assert_not_called()
                validate_policy_for_port.assert_not_called()

    def test_validate_create_port_callback_policy_on_port(self):
        self._test_validate_create_port_callback(
            policy_id=uuidutils.generate_uuid())

    def test_validate_create_port_callback_policy_on_port_and_network(self):
        self._test_validate_create_port_callback(
            policy_id=uuidutils.generate_uuid(),
            network_policy_id=uuidutils.generate_uuid())

    def test_validate_create_port_callback_policy_on_network(self):
        self._test_validate_create_port_callback(
            network_policy_id=uuidutils.generate_uuid())

    def test_validate_create_port_callback_no_policy(self):
        self._test_validate_create_port_callback()

    def _test_validate_update_port_callback(self, policy_id=None,
                                            original_policy_id=None):
        port_id = uuidutils.generate_uuid()
        kwargs = {
            "port": {
                "id": port_id,
                qos_consts.QOS_POLICY_ID: policy_id
            },
            "original_port": {
                "id": port_id,
                qos_consts.QOS_POLICY_ID: original_policy_id
            }
        }
        port_mock = mock.MagicMock(id=port_id, qos_policy_id=policy_id)
        policy_mock = mock.MagicMock(id=policy_id)
        admin_ctxt = mock.Mock()
        with mock.patch(
            'neutron.objects.ports.Port.get_object',
            return_value=port_mock
        ) as get_port, mock.patch(
            'neutron.objects.qos.policy.QosPolicy.get_object',
            return_value=policy_mock
        ) as get_policy, mock.patch.object(
            self.qos_plugin, "validate_policy_for_port"
        ) as validate_policy_for_port, mock.patch.object(
            self.ctxt, "elevated", return_value=admin_ctxt
        ):
            self.qos_plugin._validate_update_port_callback(
                "PORT", "precommit_update", "test_plugin",
                payload=events.DBEventPayload(
                    self.ctxt, desired_state=kwargs['port'],
                    states=(kwargs['original_port'],)))
            if policy_id is None or policy_id == original_policy_id:
                get_port.assert_not_called()
                get_policy.assert_not_called()
                validate_policy_for_port.assert_not_called()
            else:
                get_port.assert_called_once_with(self.ctxt, id=port_id)
                get_policy.assert_called_once_with(admin_ctxt, id=policy_id)
                validate_policy_for_port.assert_called_once_with(policy_mock,
                                                                 port_mock)

    def test_validate_update_port_callback_policy_changed(self):
        self._test_validate_update_port_callback(
            policy_id=uuidutils.generate_uuid())

    def test_validate_update_port_callback_policy_not_changed(self):
        policy_id = uuidutils.generate_uuid()
        self._test_validate_update_port_callback(
            policy_id=policy_id, original_policy_id=policy_id)

    def test_validate_update_port_callback_policy_removed(self):
        self._test_validate_update_port_callback(
            policy_id=None, original_policy_id=uuidutils.generate_uuid())

    def _test_validate_update_network_callback(self, policy_id=None,
                                               original_policy_id=None):
        network_id = uuidutils.generate_uuid()
        kwargs = {
            "context": self.ctxt,
            "network": {
                "id": network_id,
                qos_consts.QOS_POLICY_ID: policy_id
            },
            "original_network": {
                "id": network_id,
                qos_consts.QOS_POLICY_ID: original_policy_id
            }
        }
        port_mock_with_own_policy = mock.MagicMock(
            id=uuidutils.generate_uuid(),
            qos_policy_id=uuidutils.generate_uuid())
        port_mock_without_own_policy = mock.MagicMock(
            id=uuidutils.generate_uuid(), qos_policy_id=None)
        ports = [port_mock_with_own_policy, port_mock_without_own_policy]
        policy_mock = mock.MagicMock(id=policy_id)
        admin_ctxt = mock.Mock()
        with mock.patch(
            'neutron.objects.ports.Port.get_objects',
            return_value=ports
        ) as get_ports, mock.patch(
            'neutron.objects.qos.policy.QosPolicy.get_object',
            return_value=policy_mock
        ) as get_policy, mock.patch.object(
            self.qos_plugin, "validate_policy_for_ports"
        ) as validate_policy_for_ports, mock.patch.object(
            self.ctxt, "elevated", return_value=admin_ctxt
        ):
            self.qos_plugin._validate_update_network_callback(
                "NETWORK", "precommit_update", "test_plugin",
                payload=events.DBEventPayload(
                    self.ctxt, desired_state=kwargs['network'],
                    states=(kwargs['original_network'],)))
            if policy_id is None or policy_id == original_policy_id:
                get_policy.assert_not_called()
                get_ports.assert_not_called()
                validate_policy_for_ports.assert_not_called()
            else:
                get_policy.assert_called_once_with(admin_ctxt, id=policy_id)
                get_ports.assert_called_once_with(self.ctxt,
                                                  network_id=network_id)
                validate_policy_for_ports.assert_called_once_with(
                    policy_mock, [port_mock_without_own_policy])

    def test_validate_update_network_callback_policy_changed(self):
        self._test_validate_update_network_callback(
            policy_id=uuidutils.generate_uuid())

    def test_validate_update_network_callback_policy_not_changed(self):
        policy_id = uuidutils.generate_uuid()
        self._test_validate_update_network_callback(
            policy_id=policy_id, original_policy_id=policy_id)

    def test_validate_update_network_callback_policy_removed(self):
        self._test_validate_update_network_callback(
            policy_id=None, original_policy_id=uuidutils.generate_uuid())

    def test_validate_policy_for_port_rule_not_valid(self):
        port = {'id': uuidutils.generate_uuid()}
        with mock.patch.object(
            self.qos_plugin.driver_manager, "validate_rule_for_port",
            return_value=False
        ):
            self.policy.rules = [self.rule]
            self.assertRaises(
                n_exc.QosRuleNotSupported,
                self.qos_plugin.validate_policy_for_port,
                self.policy, port)

    def test_validate_policy_for_port_all_rules_valid(self):
        port = {'id': uuidutils.generate_uuid()}
        with mock.patch.object(
            self.qos_plugin.driver_manager, "validate_rule_for_port",
            return_value=True
        ):
            self.policy.rules = [self.rule]
            try:
                self.qos_plugin.validate_policy_for_port(self.policy, port)
            except n_exc.QosRuleNotSupported:
                self.fail("QosRuleNotSupported exception unexpectedly raised")

    @mock.patch(
        'neutron.objects.rbac_db.RbacNeutronDbObjectMixin'
        '.create_rbac_policy')
    @mock.patch('neutron.objects.qos.policy.QosPolicy')
    def test_add_policy(self, mock_qos_policy, mock_create_rbac_policy):
        mock_manager = mock.Mock()
        mock_manager.attach_mock(mock_qos_policy, 'QosPolicy')
        mock_manager.attach_mock(self.qos_plugin.driver_manager, 'driver')
        mock_manager.reset_mock()

        self.qos_plugin.create_policy(self.ctxt, self.policy_data)
        policy_mock_call = mock.call.QosPolicy().create()
        create_precommit_mock_call = mock.call.driver.call(
            'create_policy_precommit', self.ctxt, mock.ANY)
        create_mock_call = mock.call.driver.call(
            'create_policy', self.ctxt, mock.ANY)
        self.assertTrue(
            mock_manager.mock_calls.index(policy_mock_call) <
            mock_manager.mock_calls.index(create_precommit_mock_call) <
            mock_manager.mock_calls.index(create_mock_call))

    def test_add_policy_with_extra_tenant_keyword(self, *mocks):
        policy_id = uuidutils.generate_uuid()
        project_id = uuidutils.generate_uuid()
        tenant_policy = {
            'policy': {'id': policy_id,
                       'project_id': project_id,
                       'tenant_id': project_id,
                       'name': 'test-policy',
                       'description': 'Test policy description',
                       'shared': True,
                       'is_default': False}}

        policy_details = {'id': policy_id,
                          'project_id': project_id,
                          'name': 'test-policy',
                          'description': 'Test policy description',
                          'shared': True,
                          'is_default': False}

        with mock.patch('neutron.objects.qos.policy.QosPolicy') as QosMocked:
            self.qos_plugin.create_policy(self.ctxt, tenant_policy)

        QosMocked.assert_called_once_with(self.ctxt, **policy_details)

    @mock.patch.object(policy_object.QosPolicy, "get_object")
    @mock.patch(
        'neutron.objects.rbac_db.RbacNeutronDbObjectMixin'
        '.create_rbac_policy')
    @mock.patch.object(policy_object.QosPolicy, 'update')
    def test_update_policy(self, mock_qos_policy_update,
                           mock_create_rbac_policy, mock_qos_policy_get):
        mock_qos_policy_get.return_value = self.policy
        mock_manager = mock.Mock()
        mock_manager.attach_mock(mock_qos_policy_update, 'update')
        mock_manager.attach_mock(self.qos_plugin.driver_manager, 'driver')
        mock_manager.reset_mock()

        fields = base_object.get_updatable_fields(
            policy_object.QosPolicy, self.policy_data['policy'])
        self.qos_plugin.update_policy(
            self.ctxt, self.policy.id, {'policy': fields})
        self._validate_driver_params('update_policy', self.ctxt)

        policy_update_mock_call = mock.call.update()
        update_precommit_mock_call = mock.call.driver.call(
            'update_policy_precommit', self.ctxt, mock.ANY)
        update_mock_call = mock.call.driver.call(
            'update_policy', self.ctxt, mock.ANY)
        self.assertTrue(
            mock_manager.mock_calls.index(policy_update_mock_call) <
            mock_manager.mock_calls.index(update_precommit_mock_call) <
            mock_manager.mock_calls.index(update_mock_call))

    @mock.patch('neutron.objects.db.api.get_object', return_value=None)
    @mock.patch.object(policy_object.QosPolicy, 'delete')
    def test_delete_policy(self, mock_qos_policy_delete, mock_api_get_policy):
        mock_manager = mock.Mock()
        mock_manager.attach_mock(mock_qos_policy_delete, 'delete')
        mock_manager.attach_mock(self.qos_plugin.driver_manager, 'driver')
        mock_manager.reset_mock()

        self.qos_plugin.delete_policy(self.ctxt, self.policy.id)
        self._validate_driver_params('delete_policy', self.ctxt)

        policy_delete_mock_call = mock.call.delete()
        delete_precommit_mock_call = mock.call.driver.call(
            'delete_policy_precommit', self.ctxt, mock.ANY)
        delete_mock_call = mock.call.driver.call(
            'delete_policy', self.ctxt, mock.ANY)
        self.assertTrue(
            mock_manager.mock_calls.index(policy_delete_mock_call) <
            mock_manager.mock_calls.index(delete_precommit_mock_call) <
            mock_manager.mock_calls.index(delete_mock_call))

    @mock.patch.object(policy_object.QosPolicy, "get_object")
    @mock.patch.object(rule_object.QosBandwidthLimitRule, 'create')
    def test_create_policy_rule(self, mock_qos_rule_create,
                                mock_qos_policy_get):
        _policy = copy.copy(self.policy)
        setattr(_policy, "rules", [])
        mock_qos_policy_get.return_value = _policy
        mock_manager = mock.Mock()
        mock_manager.attach_mock(mock_qos_rule_create, 'create')
        mock_manager.attach_mock(self.qos_plugin.driver_manager, 'driver')
        mock_manager.reset_mock()
        with mock.patch(
                'neutron.objects.qos.qos_policy_validator'
                '.check_bandwidth_rule_conflict', return_value=None):
            self.qos_plugin.create_policy_bandwidth_limit_rule(
                self.ctxt, self.policy.id, self.rule_data)
            self._validate_driver_params('update_policy', self.ctxt)
            rule_create_mock_call = mock.call.create()
            update_precommit_mock_call = mock.call.driver.call(
                'update_policy_precommit', self.ctxt, mock.ANY)
            update_mock_call = mock.call.driver.call(
                'update_policy', self.ctxt, mock.ANY)
            self.assertTrue(
                mock_manager.mock_calls.index(rule_create_mock_call) <
                mock_manager.mock_calls.index(update_precommit_mock_call) <
                mock_manager.mock_calls.index(update_mock_call))

    def test_create_policy_rule_check_rule_min_less_than_max(self):
        _policy = self._get_policy()
        setattr(_policy, "rules", [self.rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy) as mock_qos_get_obj:
            self.qos_plugin.create_policy_minimum_bandwidth_rule(
                self.ctxt, _policy.id, self.rule_data)
            self._validate_driver_params('update_policy', self.ctxt)
            self.mock_qos_load_attr.assert_called_once_with('rules')
            mock_qos_get_obj.assert_called_once_with(self.ctxt, id=_policy.id)

    def test_create_policy_rule_check_rule_max_more_than_min(self):
        _policy = self._get_policy()
        setattr(_policy, "rules", [self.min_rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy) as mock_qos_get_obj:
            self.qos_plugin.create_policy_bandwidth_limit_rule(
                self.ctxt, _policy.id, self.rule_data)
            self._validate_driver_params('update_policy', self.ctxt)
            self.mock_qos_load_attr.assert_called_once_with('rules')
            mock_qos_get_obj.assert_called_once_with(self.ctxt, id=_policy.id)

    def test_create_policy_rule_check_rule_bwlimit_less_than_minbw(self):
        _policy = self._get_policy()
        self.rule_data['bandwidth_limit_rule']['max_kbps'] = 1
        setattr(_policy, "rules", [self.min_rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy) as mock_qos_get_obj:
            self.assertRaises(n_exc.QoSRuleParameterConflict,
                self.qos_plugin.create_policy_bandwidth_limit_rule,
                self.ctxt, self.policy.id, self.rule_data)
            mock_qos_get_obj.assert_called_once_with(self.ctxt, id=_policy.id)

    def test_create_policy_rule_check_rule_minbw_gr_than_bwlimit(self):
        _policy = self._get_policy()
        self.rule_data['minimum_bandwidth_rule']['min_kbps'] = 1000000
        setattr(_policy, "rules", [self.rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy) as mock_qos_get_obj:
            self.assertRaises(n_exc.QoSRuleParameterConflict,
                self.qos_plugin.create_policy_minimum_bandwidth_rule,
                self.ctxt, self.policy.id, self.rule_data)
            mock_qos_get_obj.assert_called_once_with(self.ctxt, id=_policy.id)

    def test_create_policy_rule_duplicates(self):
        _policy = self._get_policy()
        setattr(_policy, "rules", [self.rule])
        new_rule_data = {
            'bandwidth_limit_rule': {
                'max_kbps': 5000,
                'direction': self.rule.direction
            }
        }
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy) as mock_qos_get_obj:
            self.assertRaises(
                n_exc.QoSRulesConflict,
                self.qos_plugin.create_policy_bandwidth_limit_rule,
                self.ctxt, _policy.id, new_rule_data)
            mock_qos_get_obj.assert_called_once_with(self.ctxt, id=_policy.id)

    @mock.patch.object(rule_object.QosBandwidthLimitRule, 'update')
    def test_update_policy_rule(self, mock_qos_rule_update):
        mock_manager = mock.Mock()
        mock_manager.attach_mock(mock_qos_rule_update, 'update')
        mock_manager.attach_mock(self.qos_plugin.driver_manager, 'driver')
        mock_manager.reset_mock()

        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        setattr(_policy, "rules", [self.rule])
        with mock.patch('neutron.objects.qos.rule.get_rules',
                        return_value=[self.rule]), mock.patch(
            'neutron.objects.qos.policy.QosPolicy.get_object',
            return_value=_policy):
            self.rule_data['bandwidth_limit_rule']['max_kbps'] = 1
            self.qos_plugin.update_policy_bandwidth_limit_rule(
                self.ctxt, self.rule.id, self.policy.id, self.rule_data)
            self._validate_driver_params('update_policy', self.ctxt)

            rule_update_mock_call = mock.call.update()
            update_precommit_mock_call = mock.call.driver.call(
                'update_policy_precommit', self.ctxt, mock.ANY)
            update_mock_call = mock.call.driver.call(
                'update_policy', self.ctxt, mock.ANY)
            self.assertTrue(
                mock_manager.mock_calls.index(rule_update_mock_call) <
                mock_manager.mock_calls.index(update_precommit_mock_call) <
                mock_manager.mock_calls.index(update_mock_call))

    def test_update_policy_rule_check_rule_min_less_than_max(self):
        _policy = self._get_policy()
        setattr(_policy, "rules", [self.rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            self.qos_plugin.update_policy_bandwidth_limit_rule(
                self.ctxt, self.rule.id, self.policy.id, self.rule_data)
            self.mock_qos_load_attr.assert_called_once_with('rules')
            self._validate_driver_params('update_policy', self.ctxt)

        rules = [self.rule, self.min_rule]
        setattr(_policy, "rules", rules)
        self.mock_qos_load_attr.reset_mock()
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            self.qos_plugin.update_policy_minimum_bandwidth_rule(
                self.ctxt, self.min_rule.id,
                self.policy.id, self.rule_data)
            self.mock_qos_load_attr.assert_called_once_with('rules')
            self._validate_driver_params('update_policy', self.ctxt)

    def test_update_policy_rule_check_rule_bwlimit_less_than_minbw(self):
        _policy = self._get_policy()
        setattr(_policy, "rules", [self.rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            self.qos_plugin.update_policy_bandwidth_limit_rule(
                self.ctxt, self.rule.id, self.policy.id, self.rule_data)
            self.mock_qos_load_attr.assert_called_once_with('rules')
            self._validate_driver_params('update_policy', self.ctxt)
        self.rule_data['minimum_bandwidth_rule']['min_kbps'] = 1000
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            self.assertRaises(
                n_exc.QoSRuleParameterConflict,
                self.qos_plugin.update_policy_minimum_bandwidth_rule,
                self.ctxt, self.min_rule.id,
                self.policy.id, self.rule_data)

    def test_update_policy_rule_check_rule_minbw_gr_than_bwlimit(self):
        _policy = self._get_policy()
        setattr(_policy, "rules", [self.min_rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            self.qos_plugin.update_policy_minimum_bandwidth_rule(
                self.ctxt, self.min_rule.id, self.policy.id, self.rule_data)
            self.mock_qos_load_attr.assert_called_once_with('rules')
            self._validate_driver_params('update_policy', self.ctxt)
        self.rule_data['bandwidth_limit_rule']['max_kbps'] = 1
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            self.assertRaises(
                n_exc.QoSRuleParameterConflict,
                self.qos_plugin.update_policy_bandwidth_limit_rule,
                self.ctxt, self.rule.id,
                self.policy.id, self.rule_data)

    def _get_policy(self):
        return policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])

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

    @mock.patch.object(rule_object.QosBandwidthLimitRule, 'delete')
    def test_delete_policy_rule(self, mock_qos_rule_delete):
        mock_manager = mock.Mock()
        mock_manager.attach_mock(mock_qos_rule_delete, 'delete')
        mock_manager.attach_mock(self.qos_plugin.driver_manager, 'driver')
        mock_manager.reset_mock()

        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            setattr(_policy, "rules", [self.rule])
            self.qos_plugin.delete_policy_bandwidth_limit_rule(
                        self.ctxt, self.rule.id, _policy.id)
            self._validate_driver_params('update_policy', self.ctxt)

            rule_delete_mock_call = mock.call.delete()
            update_precommit_mock_call = mock.call.driver.call(
                'update_policy_precommit', self.ctxt, mock.ANY)
            update_mock_call = mock.call.driver.call(
                'update_policy', self.ctxt, mock.ANY)
            self.assertTrue(
                mock_manager.mock_calls.index(rule_delete_mock_call) <
                mock_manager.mock_calls.index(update_precommit_mock_call) <
                mock_manager.mock_calls.index(update_mock_call))

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
            self._validate_driver_params('update_policy', self.ctxt)

    def test_update_policy_dscp_marking_rule(self):
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            setattr(_policy, "rules", [self.dscp_rule])
            self.qos_plugin.update_policy_dscp_marking_rule(
                self.ctxt, self.dscp_rule.id, self.policy.id, self.rule_data)
            self._validate_driver_params('update_policy', self.ctxt)

    def test_delete_policy_dscp_marking_rule(self):
        _policy = policy_object.QosPolicy(
            self.ctxt, **self.policy_data['policy'])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy):
            setattr(_policy, "rules", [self.dscp_rule])
            self.qos_plugin.delete_policy_dscp_marking_rule(
                self.ctxt, self.dscp_rule.id, self.policy.id)
            self._validate_driver_params('update_policy', self.ctxt)

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

    def test_get_rule_type(self):
        admin_ctxt = context.get_admin_context()
        drivers_details = [{
            'name': 'fake-driver',
            'supported_parameters': [{
                'parameter_name': 'max_kbps',
                'parameter_type': constants.VALUES_TYPE_RANGE,
                'parameter_range': {'start': 0, 'end': 100}
            }]
        }]
        with mock.patch.object(
            qos_plugin.QoSPlugin, "supported_rule_type_details",
            return_value=drivers_details
        ):
            rule_type_details = self.qos_plugin.get_rule_type(
                admin_ctxt, qos_consts.RULE_TYPE_BANDWIDTH_LIMIT)
            self.assertEqual(
                qos_consts.RULE_TYPE_BANDWIDTH_LIMIT,
                rule_type_details['type'])
            self.assertEqual(
                drivers_details, rule_type_details['drivers'])

    def test_get_rule_type_as_user(self):
        self.assertRaises(
            lib_exc.NotAuthorized,
            self.qos_plugin.get_rule_type,
            self.ctxt, qos_consts.RULE_TYPE_BANDWIDTH_LIMIT)

    def test_get_rule_types(self):
        rule_types_mock = mock.PropertyMock(
            return_value=qos_consts.VALID_RULE_TYPES)
        filters = {'type': 'type_id'}
        with mock.patch.object(qos_plugin.QoSPlugin, 'supported_rule_types',
                               new_callable=rule_types_mock):
            types = self.qos_plugin.get_rule_types(self.ctxt, filters=filters)
            self.assertEqual(sorted(qos_consts.VALID_RULE_TYPES),
                             sorted(type_['type'] for type_ in types))

    @mock.patch('neutron.objects.ports.Port')
    @mock.patch('neutron.objects.qos.policy.QosPolicy')
    def test_rule_notification_and_driver_ordering(self, qos_policy_mock,
                                                   port_mock):
        rule_cls_mock = mock.Mock()
        rule_cls_mock.rule_type = 'fake'

        rule_actions = {'create': [self.ctxt, rule_cls_mock,
                                   self.policy.id, {'fake_rule': {}}],
                        'update': [self.ctxt, rule_cls_mock,
                                   self.rule.id,
                                   self.policy.id, {'fake_rule': {}}],
                        'delete': [self.ctxt, rule_cls_mock,
                                   self.rule.id, self.policy.id]}

        mock_manager = mock.Mock()
        mock_manager.attach_mock(qos_policy_mock, 'QosPolicy')
        mock_manager.attach_mock(port_mock, 'Port')
        mock_manager.attach_mock(rule_cls_mock, 'RuleCls')
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

            driver_mock_call = mock.call.driver.call('update_policy',
                                                     self.ctxt, mock.ANY)

            if rule_mock_call in mock_manager.mock_calls:
                action_index = mock_manager.mock_calls.index(rule_mock_call)
            else:
                action_index = mock_manager.mock_calls.index(
                    get_rule_mock_call)

            self.assertTrue(
                action_index < mock_manager.mock_calls.index(driver_mock_call))
