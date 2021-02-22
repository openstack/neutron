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
from unittest import mock

from keystoneauth1 import exceptions as ks_exc
import netaddr
from neutron_lib.api.definitions import qos
from neutron_lib.callbacks import events
from neutron_lib import constants as lib_constants
from neutron_lib import context
from neutron_lib import exceptions as lib_exc
from neutron_lib.exceptions import placement as pl_exc
from neutron_lib.exceptions import qos as qos_exc
from neutron_lib.objects import utils as obj_utils
from neutron_lib.placement import constants as pl_constants
from neutron_lib.plugins import constants as plugins_constants
from neutron_lib.plugins import directory
from neutron_lib.services.qos import constants as qos_consts
from neutron_lib.utils import net as net_utils
from oslo_config import cfg
from oslo_utils import uuidutils
import webob.exc

from neutron.extensions import qos_rules_alias
from neutron import manager
from neutron.objects import network as network_object
from neutron.objects import ports as ports_object
from neutron.objects.qos import policy as policy_object
from neutron.objects.qos import rule as rule_object
from neutron.services.qos import qos_plugin
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.services.qos import base


DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
SERVICE_PLUGIN_KLASS = 'neutron.services.qos.qos_plugin.QoSPlugin'


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

    def _create_and_extend_port(self, bw_rules, physical_network='public',
                                has_qos_policy=True, has_net_qos_policy=False):
        network_id = uuidutils.generate_uuid()

        self.port_data = {
            'port': {'id': uuidutils.generate_uuid(),
                     'network_id': network_id}
        }

        if has_qos_policy:
            self.port_data['port']['qos_policy_id'] = self.policy.id
        elif has_net_qos_policy:
            self.port_data['port']['qos_network_policy_id'] = self.policy.id

        self.port = ports_object.Port(
            self.ctxt, **self.port_data['port'])

        port_res = {"binding:vnic_type": "normal"}
        segment_mock = mock.MagicMock(network_id=network_id,
                                      physical_network=physical_network)

        with mock.patch('neutron.objects.network.NetworkSegment.get_objects',
                        return_value=[segment_mock]), \
                mock.patch(
                    'neutron.objects.qos.rule.QosMinimumBandwidthRule.'
                    'get_objects',
                    return_value=bw_rules):
            return qos_plugin.QoSPlugin._extend_port_resource_request(
                port_res, self.port)

    def test__extend_port_resource_request_min_bw_rule(self):
        self.min_rule.direction = lib_constants.EGRESS_DIRECTION
        port = self._create_and_extend_port([self.min_rule])

        self.assertEqual(
            ['CUSTOM_PHYSNET_PUBLIC', 'CUSTOM_VNIC_TYPE_NORMAL'],
            port['resource_request']['required']
        )
        self.assertEqual(
            {pl_constants.CLASS_NET_BW_EGRESS_KBPS: 10},
            port['resource_request']['resources'],
        )

    def test__extend_port_resource_request_mixed_rules(self):
        self.min_rule.direction = lib_constants.EGRESS_DIRECTION

        min_rule_ingress_data = {
            'id': uuidutils.generate_uuid(),
            'min_kbps': 20,
            'direction': lib_constants.INGRESS_DIRECTION}
        min_rule_ingress = rule_object.QosMinimumBandwidthRule(
            self.ctxt, **min_rule_ingress_data)

        port = self._create_and_extend_port([self.min_rule, min_rule_ingress])
        self.assertEqual(
            ['CUSTOM_PHYSNET_PUBLIC', 'CUSTOM_VNIC_TYPE_NORMAL'],
            port['resource_request']['required']
        )
        self.assertEqual(
            {
                pl_constants.CLASS_NET_BW_EGRESS_KBPS: 10,
                pl_constants.CLASS_NET_BW_INGRESS_KBPS: 20
            },
            port['resource_request']['resources'],
        )

    def test__extend_port_resource_request_non_min_bw_rule(self):
        port = self._create_and_extend_port([])

        self.assertIsNone(port.get('resource_request'))

    def test__extend_port_resource_request_non_provider_net(self):
        self.min_rule.direction = lib_constants.EGRESS_DIRECTION

        port = self._create_and_extend_port([self.min_rule],
                                            physical_network=None)
        self.assertIsNone(port.get('resource_request'))

    def test__extend_port_resource_request_no_qos_policy(self):
        port = self._create_and_extend_port([], physical_network='public',
                                            has_qos_policy=False)
        self.assertIsNone(port.get('resource_request'))

    def test__extend_port_resource_request_inherited_policy(self):
        self.min_rule.direction = lib_constants.EGRESS_DIRECTION
        self.min_rule.qos_policy_id = self.policy.id

        port = self._create_and_extend_port([self.min_rule],
                                            has_net_qos_policy=True)
        self.assertEqual(
            ['CUSTOM_PHYSNET_PUBLIC', 'CUSTOM_VNIC_TYPE_NORMAL'],
            port['resource_request']['required']
        )
        self.assertEqual(
            {pl_constants.CLASS_NET_BW_EGRESS_KBPS: 10},
            port['resource_request']['resources'],
        )

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
                validate_policy_for_port.assert_called_once_with(
                    self.ctxt, policy_mock, port_mock)

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
            self.qos_plugin, "validate_policy_for_network"
        ) as validate_policy_for_network, mock.patch.object(
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
                validate_policy_for_network.assert_not_called()
                get_ports.assert_not_called()
                validate_policy_for_ports.assert_not_called()
            else:
                get_policy.assert_called_once_with(admin_ctxt, id=policy_id)
                get_ports.assert_called_once_with(self.ctxt,
                                                  network_id=network_id)
                validate_policy_for_ports.assert_called_once_with(
                    self.ctxt, policy_mock, [port_mock_without_own_policy])

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
                qos_exc.QosRuleNotSupported,
                self.qos_plugin.validate_policy_for_port,
                self.ctxt, self.policy, port)

    def test_validate_policy_for_port_all_rules_valid(self):
        port = {'id': uuidutils.generate_uuid()}
        with mock.patch.object(
            self.qos_plugin.driver_manager, "validate_rule_for_port",
            return_value=True
        ):
            self.policy.rules = [self.rule]
            try:
                self.qos_plugin.validate_policy_for_port(
                    self.ctxt, self.policy, port)
            except qos_exc.QosRuleNotSupported:
                self.fail("QosRuleNotSupported exception unexpectedly raised")

    def test_validate_policy_for_network(self):
        network = uuidutils.generate_uuid()
        with mock.patch.object(
            self.qos_plugin.driver_manager, "validate_rule_for_network",
            return_value=True
        ):
            self.policy.rules = [self.rule]
            try:
                self.qos_plugin.validate_policy_for_network(
                    self.ctxt, self.policy, network_id=network)
            except qos_exc.QosRuleNotSupportedByNetwork:
                self.fail("QosRuleNotSupportedByNetwork "
                          "exception unexpectedly raised")

    def test_create_min_bw_rule_on_bound_port(self):
        policy = self._get_policy()
        policy.rules = [self.min_rule]
        segment = network_object.NetworkSegment(
            physical_network='fake physnet')
        net = network_object.Network(
            self.ctxt,
            segments=[segment])
        port = ports_object.Port(
            self.ctxt,
            id=uuidutils.generate_uuid(),
            network_id=uuidutils.generate_uuid(),
            device_owner='compute:fake-zone')
        with mock.patch(
                'neutron.objects.qos.policy.QosPolicy.get_object',
                return_value=policy), \
            mock.patch(
                'neutron.objects.network.Network.get_object',
                return_value=net), \
            mock.patch.object(
                self.qos_plugin,
                '_get_ports_with_policy',
                return_value=[port]):
            self.assertRaises(
                NotImplementedError,
                self.qos_plugin.create_policy_minimum_bandwidth_rule,
                self.ctxt, policy.id, self.rule_data)

    def test_create_min_bw_rule_on_unbound_port(self):
        policy = self._get_policy()
        policy.rules = [self.min_rule]
        segment = network_object.NetworkSegment(
            physical_network='fake physnet')
        net = network_object.Network(
            self.ctxt,
            segments=[segment])
        port = ports_object.Port(
            self.ctxt,
            id=uuidutils.generate_uuid(),
            network_id=uuidutils.generate_uuid(),
            device_owner='')
        with mock.patch(
                'neutron.objects.qos.policy.QosPolicy.get_object',
                return_value=policy), \
            mock.patch(
                'neutron.objects.network.Network.get_object',
                return_value=net), \
            mock.patch.object(
                self.qos_plugin,
                '_get_ports_with_policy',
                return_value=[port]):
            try:
                self.qos_plugin.create_policy_minimum_bandwidth_rule(
                    self.ctxt, policy.id, self.rule_data)
            except NotImplementedError:
                self.fail()

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

        fields = obj_utils.get_updatable_fields(
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
            self.assertRaises(qos_exc.QoSRuleParameterConflict,
                self.qos_plugin.create_policy_bandwidth_limit_rule,
                self.ctxt, self.policy.id, self.rule_data)
            mock_qos_get_obj.assert_called_once_with(self.ctxt, id=_policy.id)

    def test_create_policy_rule_check_rule_minbw_gr_than_bwlimit(self):
        _policy = self._get_policy()
        self.rule_data['minimum_bandwidth_rule']['min_kbps'] = 1000000
        setattr(_policy, "rules", [self.rule])
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=_policy) as mock_qos_get_obj:
            self.assertRaises(qos_exc.QoSRuleParameterConflict,
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
                qos_exc.QoSRulesConflict,
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
                qos_exc.QoSRuleParameterConflict,
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
                qos_exc.QoSRuleParameterConflict,
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
                qos_exc.QosRuleNotFound,
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
                qos_exc.QosRuleNotFound,
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
                qos_exc.QosPolicyNotFound,
                self.qos_plugin.get_policy,
                self.ctxt, self.policy.id)

    def test_get_policy_bandwidth_limit_rule_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                qos_exc.QosPolicyNotFound,
                self.qos_plugin.get_policy_bandwidth_limit_rule,
                self.ctxt, self.rule.id, self.policy.id)

    def test_get_policy_bandwidth_limit_rules_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                qos_exc.QosPolicyNotFound,
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
                qos_exc.QosPolicyNotFound,
                self.qos_plugin.get_policy_dscp_marking_rule,
                self.ctxt, self.dscp_rule.id, self.policy.id)

    def test_get_policy_dscp_marking_rules_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                qos_exc.QosPolicyNotFound,
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
                qos_exc.QosPolicyNotFound,
                self.qos_plugin.get_policy_minimum_bandwidth_rule,
                self.ctxt, self.rule.id, self.policy.id)

    def test_get_policy_minimum_bandwidth_rules_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                qos_exc.QosPolicyNotFound,
                self.qos_plugin.get_policy_minimum_bandwidth_rules,
                self.ctxt, self.policy.id)

    def test_create_policy_rule_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                qos_exc.QosPolicyNotFound,
                self.qos_plugin.create_policy_bandwidth_limit_rule,
                self.ctxt, self.policy.id, self.rule_data)

    def test_update_policy_rule_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                qos_exc.QosPolicyNotFound,
                self.qos_plugin.update_policy_bandwidth_limit_rule,
                self.ctxt, self.rule.id, self.policy.id, self.rule_data)

    def test_delete_policy_rule_for_nonexistent_policy(self):
        with mock.patch('neutron.objects.qos.policy.QosPolicy.get_object',
                        return_value=None):
            self.assertRaises(
                qos_exc.QosPolicyNotFound,
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
                'parameter_type': lib_constants.VALUES_TYPE_RANGE,
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
                mock.call.QosPolicy.get_policy_obj().get_rule_by_id(),
                action)()
            # some actions construct rule from class reference
            rule_mock_call = getattr(mock.call.RuleCls(), action)()

            driver_mock_call = mock.call.driver.call('update_policy',
                                                     self.ctxt, mock.ANY)

            if rule_mock_call in mock_manager.mock_calls:
                action_index = mock_manager.mock_calls.index(rule_mock_call)
            else:
                action_index = mock_manager.mock_calls.index(
                    get_rule_mock_call)

            self.assertLess(
                action_index, mock_manager.mock_calls.index(driver_mock_call))


class QoSRuleAliasTestExtensionManager(object):

    def get_resources(self):
        return qos_rules_alias.Qos_rules_alias.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestQoSRuleAlias(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self):
        # Remove MissingAuthPlugin exception from logs
        self.patch_notifier = mock.patch(
            'neutron.notifiers.batch_notifier.BatchNotifier._notify')
        self.patch_notifier.start()
        plugin = 'ml2'
        service_plugins = {'qos_plugin_name': SERVICE_PLUGIN_KLASS}
        ext_mgr = QoSRuleAliasTestExtensionManager()
        super(TestQoSRuleAlias, self).setUp(plugin=plugin, ext_mgr=ext_mgr,
                                            service_plugins=service_plugins)
        self.qos_plugin = directory.get_plugin(plugins_constants.QOS)

        self.ctxt = context.Context('fake_user', 'fake_tenant')
        self.rule_objects = {
            'bandwidth_limit': rule_object.QosBandwidthLimitRule,
            'dscp_marking': rule_object.QosDscpMarkingRule,
            'minimum_bandwidth': rule_object.QosMinimumBandwidthRule
        }

        self.qos_policy_id = uuidutils.generate_uuid()
        self.rule_data = {
            'bandwidth_limit_rule': {'max_kbps': 100,
                                     'max_burst_kbps': 150},
            'dscp_marking_rule': {'dscp_mark': 16},
            'minimum_bandwidth_rule': {'min_kbps': 10}
        }

    def _update_rule(self, rule_type, rule_id, **kwargs):
        data = {'alias_%s_rule' % rule_type: kwargs}
        resource = '%s/alias-%s-rules' % (qos.ALIAS,
                                          rule_type.replace('_', '-'))
        request = self.new_update_request(resource, data, rule_id, self.fmt)
        res = request.get_response(self.ext_api)
        if res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(self.fmt, res)

    def _show_rule(self, rule_type, rule_id):
        resource = '%s/alias-%s-rules' % (qos.ALIAS,
                                          rule_type.replace('_', '-'))
        request = self.new_show_request(resource, rule_id, self.fmt)
        res = request.get_response(self.ext_api)
        if res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(self.fmt, res)

    def _delete_rule(self, rule_type, rule_id):
        resource = '%s/alias-%s-rules' % (qos.ALIAS,
                                          rule_type.replace('_', '-'))
        request = self.new_delete_request(resource, rule_id, self.fmt)
        res = request.get_response(self.ext_api)
        if res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)

    @mock.patch.object(qos_plugin.QoSPlugin, "update_policy_rule")
    def test_update_rule(self, update_policy_rule_mock):
        calls = []
        for rule_type, rule_object_class in self.rule_objects.items():
            rule_id = uuidutils.generate_uuid()
            rule_data_name = '%s_rule' % rule_type
            data = self.rule_data[rule_data_name]
            rule = rule_object_class(self.ctxt, id=rule_id,
                                     qos_policy_id=self.qos_policy_id,
                                     **data)
            with mock.patch(
                'neutron.objects.qos.rule.QosRule.get_object',
                return_value=rule
            ), mock.patch.object(self.qos_plugin, 'get_policy_rule',
                                 return_value=rule.to_dict()):
                self._update_rule(rule_type, rule_id, **data)
            calls.append(mock.call(mock.ANY, rule_object_class, rule_id,
                                   self.qos_policy_id, {rule_data_name: data}))
        update_policy_rule_mock.assert_has_calls(calls, any_order=True)

    @mock.patch.object(qos_plugin.QoSPlugin, "get_policy_rule")
    def test_show_rule(self, get_policy_rule_mock):
        calls = []
        for rule_type, rule_object_class in self.rule_objects.items():
            rule_id = uuidutils.generate_uuid()
            rule_data_name = '%s_rule' % rule_type
            data = self.rule_data[rule_data_name]
            rule = rule_object_class(self.ctxt, id=rule_id,
                                     qos_policy_id=self.qos_policy_id,
                                     **data)
            with mock.patch('neutron.objects.qos.rule.QosRule.get_object',
                            return_value=rule):
                self._show_rule(rule_type, rule_id)
            calls.append(mock.call(mock.ANY, rule_object_class, rule_id,
                                   self.qos_policy_id))
        get_policy_rule_mock.assert_has_calls(calls, any_order=True)

    @mock.patch.object(qos_plugin.QoSPlugin, "delete_policy_rule")
    def test_delete_rule(self, delete_policy_rule_mock):
        calls = []
        for rule_type, rule_object_class in self.rule_objects.items():
            rule_id = uuidutils.generate_uuid()
            rule_data_name = '%s_rule' % rule_type
            data = self.rule_data[rule_data_name]
            rule = rule_object_class(self.ctxt, id=rule_id,
                                     qos_policy_id=self.qos_policy_id,
                                     **data)
            with mock.patch(
                'neutron.objects.qos.rule.QosRule.get_object',
                return_value=rule
            ), mock.patch.object(self.qos_plugin, 'get_policy_rule',
                                 return_value=rule.to_dict()):
                self._delete_rule(rule_type, rule_id)
            calls.append(mock.call(mock.ANY, rule_object_class, rule_id,
                                   self.qos_policy_id))
        delete_policy_rule_mock.assert_has_calls(calls, any_order=True)

    def test_show_non_existing_rule(self):
        for rule_type, rule_object_class in self.rule_objects.items():
            rule_id = uuidutils.generate_uuid()
            with mock.patch('neutron.objects.qos.rule.QosRule.get_object',
                            return_value=None):
                resource = '%s/alias-%s-rules' % (qos.ALIAS,
                                                  rule_type.replace('_', '-'))
                request = self.new_show_request(resource, rule_id, self.fmt)
                res = request.get_response(self.ext_api)
                self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)


class TestQosPluginDB(base.BaseQosTestCase):

    def setUp(self):
        super(TestQosPluginDB, self).setUp()
        self.setup_coreplugin(load_plugins=False)
        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        cfg.CONF.set_override("service_plugins", ["qos"])

        manager.init()
        self.qos_plugin = directory.get_plugin(plugins_constants.QOS)
        self.qos_plugin.driver_manager = mock.Mock()
        self.rpc_push = mock.patch('neutron.api.rpc.handlers.resources_rpc'
                                   '.ResourcesPushRpcApi.push').start()
        self.context = context.get_admin_context()
        self.project_id = uuidutils.generate_uuid()

    def _make_qos_policy(self):
        qos_policy = policy_object.QosPolicy(
            self.context, project_id=self.project_id, shared=False,
            is_default=False)
        qos_policy.create()
        return qos_policy

    def _make_qos_minbw_rule(self, policy_id, direction='ingress',
                             min_kbps=1000):
        qos_rule = rule_object.QosMinimumBandwidthRule(
            self.context, project_id=self.project_id,
            qos_policy_id=policy_id, direction=direction, min_kbps=min_kbps)
        qos_rule.create()
        return qos_rule

    def _make_port(self, network_id, qos_policy_id=None):
        base_mac = ['aa', 'bb', 'cc', 'dd', 'ee', 'ff']
        mac = netaddr.EUI(next(net_utils.random_mac_generator(base_mac)))
        port = ports_object.Port(
            self.context, network_id=network_id, device_owner='3',
            project_id=self.project_id, admin_state_up=True, status='DOWN',
            device_id='2', qos_policy_id=qos_policy_id, mac_address=mac)
        port.create()
        return port

    def _make_network(self, qos_policy_id=None):
        network = network_object.Network(self.context,
                                         qos_policy_id=qos_policy_id)
        network.create()
        return network

    def _test_validate_create_network_callback(self, network_qos=False):
        net_qos_obj = self._make_qos_policy()
        net_qos_id = net_qos_obj.id if network_qos else None
        network = self._make_network(qos_policy_id=net_qos_id)
        kwargs = {"context": self.context,
                  "network": network}

        with mock.patch.object(self.qos_plugin,
                               'validate_policy_for_network') \
                as mock_validate_policy:
            self.qos_plugin._validate_create_network_callback(
                'NETWORK', 'precommit_create', 'test_plugin', **kwargs)

        qos_policy = None
        if network_qos:
            qos_policy = net_qos_obj

        if qos_policy:
            mock_validate_policy.assert_called_once_with(
                self.context, qos_policy, network.id)
        else:
            mock_validate_policy.assert_not_called()

    def test_validate_create_network_callback(self):
        self._test_validate_create_network_callback(network_qos=True)

    def test_validate_create_network_callback_no_qos(self):
        self._test_validate_create_network_callback(network_qos=False)

    def _test_validate_create_port_callback(self, port_qos=False,
                                            network_qos=False):
        net_qos_obj = self._make_qos_policy()
        port_qos_obj = self._make_qos_policy()
        net_qos_id = net_qos_obj.id if network_qos else None
        port_qos_id = port_qos_obj.id if port_qos else None
        network = self._make_network(qos_policy_id=net_qos_id)
        port = self._make_port(network.id, qos_policy_id=port_qos_id)
        kwargs = {"context": self.context,
                  "port": {"id": port.id}}

        with mock.patch.object(self.qos_plugin, 'validate_policy_for_port') \
                as mock_validate_policy:
            self.qos_plugin._validate_create_port_callback(
                'PORT', 'precommit_create', 'test_plugin', **kwargs)

        qos_policy = None
        if port_qos:
            qos_policy = port_qos_obj
        elif network_qos:
            qos_policy = net_qos_obj

        if qos_policy:
            mock_validate_policy.assert_called_once_with(
                self.context, qos_policy, port)
        else:
            mock_validate_policy.assert_not_called()

    def test_validate_create_port_callback_policy_on_port(self):
        self._test_validate_create_port_callback(port_qos=True)

    def test_validate_create_port_callback_policy_on_port_and_network(self):
        self._test_validate_create_port_callback(port_qos=True,
                                                 network_qos=True)

    def test_validate_create_port_callback_policy_on_network(self):
        self._test_validate_create_port_callback(network_qos=True)

    def test_validate_create_port_callback_no_policy(self):
        self._test_validate_create_port_callback()

    def _prepare_for_port_placement_allocation_change(self, qos1, qos2):
        qos1_id = qos1.id if qos1 else None
        qos2_id = qos2.id if qos2 else None

        network = self._make_network()
        port = self._make_port(network.id, qos_policy_id=qos1_id)

        return {"context": self.context,
                "original_port": {
                      "id": port.id,
                      "device_owner": "compute:uu:id",
                      "qos_policy_id": qos1_id},
                "port": {"id": port.id, "qos_policy_id": qos2_id}}

    def test_check_port_for_placement_allocation_change_no_qos_change(self):
        qos1_obj = self._make_qos_policy()
        kwargs = self._prepare_for_port_placement_allocation_change(
            qos1=qos1_obj, qos2=qos1_obj)
        with mock.patch.object(
                self.qos_plugin,
                '_change_placement_allocation') as mock_alloc_change:
            self.qos_plugin._check_port_for_placement_allocation_change(
                'PORT', 'before_update', 'test_plugin', **kwargs)
        mock_alloc_change.assert_not_called()

    def test_check_port_for_placement_allocation_change(self):
        qos1_obj = self._make_qos_policy()
        qos2_obj = self._make_qos_policy()
        kwargs = self._prepare_for_port_placement_allocation_change(
            qos1=qos1_obj, qos2=qos2_obj)

        with mock.patch.object(
                self.qos_plugin,
                '_change_placement_allocation') as mock_alloc_change:
            self.qos_plugin._check_port_for_placement_allocation_change(
                'PORT', 'before_update', 'test_plugin', **kwargs)
        mock_alloc_change.assert_called_once_with(
            qos1_obj, qos2_obj, kwargs['original_port'])

    def test_check_port_for_placement_allocation_change_no_new_policy(self):
        qos1_obj = self._make_qos_policy()
        kwargs = self._prepare_for_port_placement_allocation_change(
            qos1=qos1_obj, qos2=None)

        with mock.patch.object(
                self.qos_plugin,
                '_change_placement_allocation') as mock_alloc_change:
            self.qos_plugin._check_port_for_placement_allocation_change(
                'PORT', 'before_update', 'test_plugin', **kwargs)
        mock_alloc_change.assert_called_once_with(
            qos1_obj, None, kwargs['original_port'])

    def test_check_port_for_placement_allocation_change_no_qos_update(self):
        qos1_obj = self._make_qos_policy()
        kwargs = self._prepare_for_port_placement_allocation_change(
            qos1=qos1_obj, qos2=None)
        kwargs['port'].pop('qos_policy_id')

        with mock.patch.object(
                self.qos_plugin,
                '_change_placement_allocation') as mock_alloc_change:
            self.qos_plugin._check_port_for_placement_allocation_change(
                'PORT', 'before_update', 'test_plugin', **kwargs)
        mock_alloc_change.assert_not_called()

    def _prepare_port_for_placement_allocation(self, qos1, qos2=None,
                                               min_kbps1=1000, min_kbps2=2000):
        rule1_obj = self._make_qos_minbw_rule(qos1.id, min_kbps=min_kbps1)
        qos1.rules = [rule1_obj]
        if qos2:
            rule2_obj = self._make_qos_minbw_rule(qos2.id, min_kbps=min_kbps2)
            qos2.rules = [rule2_obj]
        orig_port = {'binding:profile': {'allocation': 'rp:uu:id'},
                     'device_id': 'uu:id'}
        return orig_port

    def test_change_placement_allocation_increase(self):
        qos1 = self._make_qos_policy()
        qos2 = self._make_qos_policy()
        port = self._prepare_port_for_placement_allocation(qos1, qos2)
        with mock.patch.object(self.qos_plugin._placement_client,
                'update_qos_minbw_allocation') as mock_update_qos_alloc:
            self.qos_plugin._change_placement_allocation(qos1, qos2, port)
        mock_update_qos_alloc.assert_called_once_with(
            consumer_uuid='uu:id',
            minbw_alloc_diff={'NET_BW_IGR_KILOBIT_PER_SEC': 1000},
            rp_uuid='rp:uu:id')

    def test_test_change_placement_allocation_decrease(self):
        qos1 = self._make_qos_policy()
        qos2 = self._make_qos_policy()
        port = self._prepare_port_for_placement_allocation(qos2, qos1)
        with mock.patch.object(self.qos_plugin._placement_client,
                'update_qos_minbw_allocation') as mock_update_qos_alloc:
            self.qos_plugin._change_placement_allocation(qos1, qos2, port)
        mock_update_qos_alloc.assert_called_once_with(
            consumer_uuid='uu:id',
            minbw_alloc_diff={'NET_BW_IGR_KILOBIT_PER_SEC': -1000},
            rp_uuid='rp:uu:id')

    def test_change_placement_allocation_no_original_qos(self):
        qos1 = None
        qos2 = self._make_qos_policy()
        rule2_obj = self._make_qos_minbw_rule(qos2.id, min_kbps=1000)
        qos2.rules = [rule2_obj]
        orig_port = {'id': 'u:u', 'device_id': 'i:d', 'binding:profile': {}}
        with mock.patch.object(self.qos_plugin._placement_client,
                'update_qos_minbw_allocation') as mock_update_qos_alloc:
            self.qos_plugin._change_placement_allocation(
                qos1, qos2, orig_port)
        mock_update_qos_alloc.assert_not_called()

    def test_change_placement_allocation_no_original_allocation(self):
        qos1 = self._make_qos_policy()
        rule1_obj = self._make_qos_minbw_rule(qos1.id, min_kbps=500)
        qos1.rules = [rule1_obj]
        qos2 = self._make_qos_policy()
        rule2_obj = self._make_qos_minbw_rule(qos2.id, min_kbps=1000)
        qos2.rules = [rule2_obj]
        orig_port = {'id': 'u:u', 'device_id': 'i:d', 'binding:profile': {}}
        with mock.patch.object(self.qos_plugin._placement_client,
                'update_qos_minbw_allocation') as mock_update_qos_alloc:
            self.qos_plugin._change_placement_allocation(
                qos1, qos2, orig_port)
        mock_update_qos_alloc.assert_not_called()

    def test_change_placement_allocation_new_policy_empty(self):
        qos1 = self._make_qos_policy()
        port = self._prepare_port_for_placement_allocation(qos1)
        with mock.patch.object(self.qos_plugin._placement_client,
                'update_qos_minbw_allocation') as mock_update_qos_alloc:
            self.qos_plugin._change_placement_allocation(qos1, None, port)
        mock_update_qos_alloc.assert_called_once_with(
            consumer_uuid='uu:id',
            minbw_alloc_diff={'NET_BW_IGR_KILOBIT_PER_SEC': -1000},
            rp_uuid='rp:uu:id')

    def test_change_placement_allocation_no_min_bw(self):
        qos1 = self._make_qos_policy()
        qos2 = self._make_qos_policy()
        bw_limit_rule1 = rule_object.QosDscpMarkingRule(dscp_mark=16)
        bw_limit_rule2 = rule_object.QosDscpMarkingRule(dscp_mark=18)
        qos1.rules = [bw_limit_rule1]
        qos2.rules = [bw_limit_rule2]
        port = {'binding:profile': {'allocation': 'rp:uu:id'},
                'device_id': 'uu:id'}

        with mock.patch.object(self.qos_plugin._placement_client,
                'update_qos_minbw_allocation') as mock_update_qos_alloc:
            self.qos_plugin._change_placement_allocation(qos1, None, port)
        mock_update_qos_alloc.assert_not_called()

    def test_change_placement_allocation_old_rule_not_min_bw(self):
        qos1 = self._make_qos_policy()
        qos2 = self._make_qos_policy()
        bw_limit_rule = rule_object.QosDscpMarkingRule(dscp_mark=16)
        port = self._prepare_port_for_placement_allocation(qos1, qos2)
        qos1.rules = [bw_limit_rule]

        with mock.patch.object(self.qos_plugin._placement_client,
                'update_qos_minbw_allocation') as mock_update_qos_alloc:
            self.qos_plugin._change_placement_allocation(qos1, qos2, port)
        mock_update_qos_alloc.assert_not_called()

    def test_change_placement_allocation_new_rule_not_min_bw(self):
        qos1 = self._make_qos_policy()
        qos2 = self._make_qos_policy()
        bw_limit_rule = rule_object.QosDscpMarkingRule(dscp_mark=16)
        qos2.rules = [bw_limit_rule]
        port = self._prepare_port_for_placement_allocation(qos1)

        with mock.patch.object(self.qos_plugin._placement_client,
                'update_qos_minbw_allocation') as mock_update_qos_alloc:
            self.qos_plugin._change_placement_allocation(qos1, qos2, port)
        mock_update_qos_alloc.assert_not_called()

    def test_change_placement_allocation_equal_minkbps(self):
        qos1 = self._make_qos_policy()
        qos2 = self._make_qos_policy()
        port = self._prepare_port_for_placement_allocation(qos1, qos2, 1000,
                                                           1000)
        with mock.patch.object(self.qos_plugin._placement_client,
                'update_qos_minbw_allocation') as mock_update_qos_alloc:
            self.qos_plugin._change_placement_allocation(qos1, qos2, port)
        mock_update_qos_alloc.assert_not_called()

    def test_change_placement_allocation_update_conflict(self):
        qos1 = self._make_qos_policy()
        qos2 = self._make_qos_policy()
        port = self._prepare_port_for_placement_allocation(qos1, qos2)
        with mock.patch.object(self.qos_plugin._placement_client,
                'update_qos_minbw_allocation') as mock_update_qos_alloc:
            mock_update_qos_alloc.side_effect = ks_exc.Conflict(
                response={'errors': [{'code': 'placement.concurrent_update'}]}
            )
            self.assertRaises(
                qos_exc.QosPlacementAllocationConflict,
                self.qos_plugin._change_placement_allocation,
                qos1, qos2, port)

    def test_change_placement_allocation_update_generation_conflict(self):
        qos1 = self._make_qos_policy()
        qos2 = self._make_qos_policy()
        port = self._prepare_port_for_placement_allocation(qos1, qos2)
        with mock.patch.object(self.qos_plugin._placement_client,
                'update_qos_minbw_allocation') as mock_update_qos_alloc:
            mock_update_qos_alloc.side_effect = (
                pl_exc.PlacementAllocationGenerationConflict(
                    consumer='rp:uu:id'))
            self.assertRaises(
                pl_exc.PlacementAllocationGenerationConflict,
                self.qos_plugin._change_placement_allocation,
                qos1, qos2, port)
