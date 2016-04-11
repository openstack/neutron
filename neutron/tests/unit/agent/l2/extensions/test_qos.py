# Copyright (c) 2015 Mellanox Technologies, Ltd
# All Rights Reserved.
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

import mock
from oslo_utils import uuidutils

from neutron.agent.l2.extensions import qos
from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.common import exceptions
from neutron import context
from neutron.objects.qos import policy
from neutron.objects.qos import rule
from neutron.plugins.ml2.drivers.openvswitch.agent import (
        ovs_agent_extension_api as ovs_ext_api)
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl import (
    ovs_bridge)
from neutron.services.qos import qos_consts
from neutron.tests import base

BASE_TEST_POLICY = {'context': None,
                    'name': 'test1',
                    'id': uuidutils.generate_uuid()}

TEST_POLICY = policy.QosPolicy(**BASE_TEST_POLICY)

TEST_POLICY_DESCR = policy.QosPolicy(description='fake_descr',
                                     **BASE_TEST_POLICY)

TEST_POLICY2 = policy.QosPolicy(context=None,
                                name='test2', id=uuidutils.generate_uuid())

TEST_PORT = {'port_id': 'test_port_id',
             'qos_policy_id': TEST_POLICY.id}

TEST_PORT2 = {'port_id': 'test_port_id_2',
             'qos_policy_id': TEST_POLICY2.id}

FAKE_RULE_ID = uuidutils.generate_uuid()
REALLY_FAKE_RULE_ID = uuidutils.generate_uuid()


class FakeDriver(qos.QosAgentDriver):

    SUPPORTED_RULES = {qos_consts.RULE_TYPE_BANDWIDTH_LIMIT}

    def __init__(self):
        super(FakeDriver, self).__init__()
        self.create_bandwidth_limit = mock.Mock()
        self.update_bandwidth_limit = mock.Mock()
        self.delete_bandwidth_limit = mock.Mock()

    def initialize(self):
        pass


class QosFakeRule(rule.QosRule):

    rule_type = 'fake_type'


class QosAgentDriverTestCase(base.BaseTestCase):

    def setUp(self):
        super(QosAgentDriverTestCase, self).setUp()
        self.driver = FakeDriver()
        self.policy = TEST_POLICY
        self.rule = (
            rule.QosBandwidthLimitRule(context=None, id=FAKE_RULE_ID,
                                       qos_policy_id=self.policy.id,
                                       max_kbps=100, max_burst_kbps=200))
        self.policy.rules = [self.rule]
        self.port = {'qos_policy_id': None, 'network_qos_policy_id': None,
                     'device_owner': 'random-device-owner'}

        self.fake_rule = QosFakeRule(context=None, id=REALLY_FAKE_RULE_ID,
                                     qos_policy_id=self.policy.id)

    def test_create(self):
        self.driver.create(self.port, self.policy)
        self.driver.create_bandwidth_limit.assert_called_with(
            self.port, self.rule)

    def test_update(self):
        self.driver.update(self.port, self.policy)
        self.driver.update_bandwidth_limit.assert_called_with(
            self.port, self.rule)

    def test_delete(self):
        self.driver.delete(self.port, self.policy)
        self.driver.delete_bandwidth_limit.assert_called_with(self.port)

    def test_delete_no_policy(self):
        self.driver.delete(self.port, qos_policy=None)
        self.driver.delete_bandwidth_limit.assert_called_with(self.port)

    def test__iterate_rules_with_unknown_rule_type(self):
        self.policy.rules.append(self.fake_rule)
        rules = list(self.driver._iterate_rules(self.policy.rules))
        self.assertEqual(1, len(rules))
        self.assertIsInstance(rules[0], rule.QosBandwidthLimitRule)

    def test__handle_update_create_rules_checks_should_apply_to_port(self):
        self.rule.should_apply_to_port = mock.Mock(return_value=False)
        self.driver.create(self.port, self.policy)
        self.assertFalse(self.driver.create_bandwidth_limit.called)

        self.rule.should_apply_to_port = mock.Mock(return_value=True)
        self.driver.create(self.port, self.policy)
        self.assertTrue(self.driver.create_bandwidth_limit.called)


class QosExtensionBaseTestCase(base.BaseTestCase):

    def setUp(self):
        super(QosExtensionBaseTestCase, self).setUp()
        self.qos_ext = qos.QosAgentExtension()
        self.context = context.get_admin_context()
        self.connection = mock.Mock()
        self.agent_api = ovs_ext_api.OVSAgentExtensionAPI(
                         ovs_bridge.OVSAgentBridge('br-int'),
                         ovs_bridge.OVSAgentBridge('br-tun'))
        self.qos_ext.consume_api(self.agent_api)

        # Don't rely on used driver
        mock.patch(
            'neutron.manager.NeutronManager.load_class_for_provider',
            return_value=lambda: mock.Mock(spec=qos.QosAgentDriver)
        ).start()


class QosExtensionRpcTestCase(QosExtensionBaseTestCase):

    def setUp(self):
        super(QosExtensionRpcTestCase, self).setUp()
        self.qos_ext.initialize(
            self.connection, constants.EXTENSION_DRIVER_TYPE)

        self.pull_mock = mock.patch.object(
            self.qos_ext.resource_rpc, 'pull',
            return_value=TEST_POLICY).start()

    def _create_test_port_dict(self, qos_policy_id=None):
        return {'port_id': uuidutils.generate_uuid(),
                'qos_policy_id': qos_policy_id or TEST_POLICY.id}

    def test_handle_port_with_no_policy(self):
        port = self._create_test_port_dict()
        del port['qos_policy_id']
        self.qos_ext._process_reset_port = mock.Mock()
        self.qos_ext.handle_port(self.context, port)
        self.qos_ext._process_reset_port.assert_called_with(port)

    def test_handle_unknown_port(self):
        port = self._create_test_port_dict()
        qos_policy_id = port['qos_policy_id']
        port_id = port['port_id']
        self.qos_ext.handle_port(self.context, port)
        # we make sure the underlying qos driver is called with the
        # right parameters
        self.qos_ext.qos_driver.create.assert_called_once_with(
            port, TEST_POLICY)
        self.assertEqual(port,
            self.qos_ext.policy_map.qos_policy_ports[qos_policy_id][port_id])
        self.assertIn(port_id, self.qos_ext.policy_map.port_policies)
        self.assertEqual(TEST_POLICY,
            self.qos_ext.policy_map.known_policies[qos_policy_id])

    def test_handle_known_port(self):
        port_obj1 = self._create_test_port_dict()
        port_obj2 = dict(port_obj1)
        self.qos_ext.handle_port(self.context, port_obj1)
        self.qos_ext.qos_driver.reset_mock()
        self.qos_ext.handle_port(self.context, port_obj2)
        self.assertFalse(self.qos_ext.qos_driver.create.called)

    def test_handle_known_port_change_policy_id(self):
        port = self._create_test_port_dict()
        self.qos_ext.handle_port(self.context, port)
        self.qos_ext.resource_rpc.pull.reset_mock()
        port['qos_policy_id'] = uuidutils.generate_uuid()
        self.qos_ext.handle_port(self.context, port)
        self.pull_mock.assert_called_once_with(
             self.context, resources.QOS_POLICY,
             port['qos_policy_id'])

    def test_delete_known_port(self):
        port = self._create_test_port_dict()
        self.qos_ext.handle_port(self.context, port)
        self.qos_ext.qos_driver.reset_mock()
        self.qos_ext.delete_port(self.context, port)
        self.qos_ext.qos_driver.delete.assert_called_with(port)
        self.assertIsNone(self.qos_ext.policy_map.get_port_policy(port))

    def test_delete_unknown_port(self):
        port = self._create_test_port_dict()
        self.qos_ext.delete_port(self.context, port)
        self.assertFalse(self.qos_ext.qos_driver.delete.called)
        self.assertIsNone(self.qos_ext.policy_map.get_port_policy(port))

    def test__handle_notification_ignores_all_event_types_except_updated(self):
        with mock.patch.object(
            self.qos_ext, '_process_update_policy') as update_mock:

            for event_type in set(events.VALID) - {events.UPDATED}:
                self.qos_ext._handle_notification(object(), event_type)
                self.assertFalse(update_mock.called)

    def test__handle_notification_passes_update_events(self):
        with mock.patch.object(
            self.qos_ext, '_process_update_policy') as update_mock:

            policy_obj = mock.Mock()
            self.qos_ext._handle_notification(policy_obj, events.UPDATED)
            update_mock.assert_called_with(policy_obj)

    def test__process_update_policy(self):
        port1 = self._create_test_port_dict(qos_policy_id=TEST_POLICY.id)
        port2 = self._create_test_port_dict(qos_policy_id=TEST_POLICY2.id)
        self.qos_ext.policy_map.set_port_policy(port1, TEST_POLICY)
        self.qos_ext.policy_map.set_port_policy(port2, TEST_POLICY2)
        self.qos_ext._policy_rules_modified = mock.Mock(return_value=True)

        policy_obj = mock.Mock()
        policy_obj.id = port1['qos_policy_id']
        self.qos_ext._process_update_policy(policy_obj)
        self.qos_ext.qos_driver.update.assert_called_with(port1, policy_obj)

        self.qos_ext.qos_driver.update.reset_mock()
        policy_obj.id = port2['qos_policy_id']
        self.qos_ext._process_update_policy(policy_obj)
        self.qos_ext.qos_driver.update.assert_called_with(port2, policy_obj)

    def test__process_update_policy_descr_not_propagated_into_driver(self):
        port = self._create_test_port_dict(qos_policy_id=TEST_POLICY.id)
        self.qos_ext.policy_map.set_port_policy(port, TEST_POLICY)
        self.qos_ext._policy_rules_modified = mock.Mock(return_value=False)
        self.qos_ext._process_update_policy(TEST_POLICY_DESCR)
        self.qos_ext._policy_rules_modified.assert_called_with(TEST_POLICY,
            TEST_POLICY_DESCR)
        self.assertFalse(self.qos_ext.qos_driver.delete.called)
        self.assertFalse(self.qos_ext.qos_driver.update.called)
        self.assertEqual(TEST_POLICY_DESCR,
                         self.qos_ext.policy_map.get_policy(TEST_POLICY.id))

    def test__process_update_policy_not_known(self):
        self.qos_ext._policy_rules_modified = mock.Mock()
        self.qos_ext._process_update_policy(TEST_POLICY_DESCR)
        self.assertFalse(self.qos_ext._policy_rules_modified.called)
        self.assertFalse(self.qos_ext.qos_driver.delete.called)
        self.assertFalse(self.qos_ext.qos_driver.update.called)
        self.assertIsNone(self.qos_ext.policy_map.get_policy(
            TEST_POLICY_DESCR.id))

    def test__process_reset_port(self):
        port1 = self._create_test_port_dict(qos_policy_id=TEST_POLICY.id)
        port2 = self._create_test_port_dict(qos_policy_id=TEST_POLICY2.id)
        self.qos_ext.policy_map.set_port_policy(port1, TEST_POLICY)
        self.qos_ext.policy_map.set_port_policy(port2, TEST_POLICY2)

        self.qos_ext._process_reset_port(port1)
        self.qos_ext.qos_driver.delete.assert_called_with(port1)
        self.assertIsNone(self.qos_ext.policy_map.get_port_policy(port1))
        self.assertIsNotNone(self.qos_ext.policy_map.get_port_policy(port2))

        self.qos_ext.qos_driver.delete.reset_mock()
        self.qos_ext._process_reset_port(port2)
        self.qos_ext.qos_driver.delete.assert_called_with(port2)
        self.assertIsNone(self.qos_ext.policy_map.get_port_policy(port2))


class QosExtensionInitializeTestCase(QosExtensionBaseTestCase):

    @mock.patch.object(registry, 'subscribe')
    @mock.patch.object(resources_rpc, 'ResourcesPushRpcCallback')
    def test_initialize_subscribed_to_rpc(self, rpc_mock, subscribe_mock):
        self.qos_ext.initialize(
            self.connection, constants.EXTENSION_DRIVER_TYPE)
        self.connection.create_consumer.assert_has_calls(
            [mock.call(
                 resources_rpc.resource_type_versioned_topic(resource_type),
                 [rpc_mock()],
                 fanout=True)
             for resource_type in self.qos_ext.SUPPORTED_RESOURCES]
        )
        subscribe_mock.assert_called_with(mock.ANY, resources.QOS_POLICY)


class QosExtensionReflushRulesTestCase(QosExtensionBaseTestCase):

    def setUp(self):
        super(QosExtensionReflushRulesTestCase, self).setUp()
        self.qos_ext.initialize(
            self.connection, constants.EXTENSION_DRIVER_TYPE)

        self.pull_mock = mock.patch.object(
            self.qos_ext.resource_rpc, 'pull',
            return_value=TEST_POLICY).start()

        self.policy = policy.QosPolicy(**BASE_TEST_POLICY)
        self.rule = (
            rule.QosBandwidthLimitRule(context=None, id=FAKE_RULE_ID,
                                       qos_policy_id=self.policy.id,
                                       max_kbps=100, max_burst_kbps=10))
        self.policy.rules = [self.rule]
        self.port = {'port_id': uuidutils.generate_uuid(),
                     'qos_policy_id': TEST_POLICY.id}
        self.new_policy = policy.QosPolicy(description='descr',
                                           **BASE_TEST_POLICY)

    def test_is_reflush_required_change_policy_descr(self):
        self.qos_ext.policy_map.set_port_policy(self.port, self.policy)
        self.new_policy.rules = [self.rule]
        self.assertFalse(self.qos_ext._policy_rules_modified(self.policy,
                                                             self.new_policy))

    def test_is_reflush_required_change_policy_rule(self):
        self.qos_ext.policy_map.set_port_policy(self.port, self.policy)
        updated_rule = (rule.QosBandwidthLimitRule(context=None,
                                                id=FAKE_RULE_ID,
                                                qos_policy_id=self.policy.id,
                                                max_kbps=200,
                                                max_burst_kbps=20))
        self.new_policy.rules = [updated_rule]
        self.assertTrue(self.qos_ext._policy_rules_modified(self.policy,
                                                            self.new_policy))

    def test_is_reflush_required_remove_rules(self):
        self.qos_ext.policy_map.set_port_policy(self.port, self.policy)
        self.new_policy.rules = []
        self.assertTrue(self.qos_ext._policy_rules_modified(self.policy,
                                                            self.new_policy))

    def test_is_reflush_required_add_rules(self):
        self.qos_ext.policy_map.set_port_policy(self.port, self.policy)
        self.new_policy.rules = [self.rule]
        fake_rule = QosFakeRule(context=None, id=REALLY_FAKE_RULE_ID,
                                qos_policy_id=self.policy.id)
        self.new_policy.rules.append(fake_rule)
        self.assertTrue(self.qos_ext._policy_rules_modified(self.policy,
                                                            self.new_policy))


class PortPolicyMapTestCase(base.BaseTestCase):

    def setUp(self):
        super(PortPolicyMapTestCase, self).setUp()
        self.policy_map = qos.PortPolicyMap()

    def test_update_policy(self):
        self.policy_map.update_policy(TEST_POLICY)
        self.assertEqual(TEST_POLICY,
                         self.policy_map.known_policies[TEST_POLICY.id])

    def _set_ports(self):
        self.policy_map.set_port_policy(TEST_PORT, TEST_POLICY)
        self.policy_map.set_port_policy(TEST_PORT2, TEST_POLICY2)

    def test_set_port_policy(self):
        self._set_ports()
        self.assertEqual(TEST_POLICY,
                         self.policy_map.known_policies[TEST_POLICY.id])
        self.assertIn(TEST_PORT['port_id'],
                      self.policy_map.qos_policy_ports[TEST_POLICY.id])

    def test_get_port_policy(self):
        self._set_ports()
        self.assertEqual(TEST_POLICY,
                         self.policy_map.get_port_policy(TEST_PORT))
        self.assertEqual(TEST_POLICY2,
                         self.policy_map.get_port_policy(TEST_PORT2))

    def test_get_ports(self):
        self._set_ports()
        self.assertEqual([TEST_PORT],
                         list(self.policy_map.get_ports(TEST_POLICY)))

        self.assertEqual([TEST_PORT2],
                         list(self.policy_map.get_ports(TEST_POLICY2)))

    def test_clean_by_port(self):
        self._set_ports()
        self.policy_map.clean_by_port(TEST_PORT)
        self.assertNotIn(TEST_POLICY.id, self.policy_map.known_policies)
        self.assertNotIn(TEST_PORT['port_id'], self.policy_map.port_policies)
        self.assertIn(TEST_POLICY2.id, self.policy_map.known_policies)

    def test_clean_by_port_raises_exception_for_unknown_port(self):
        self.assertRaises(exceptions.PortNotFound,
                          self.policy_map.clean_by_port, TEST_PORT)

    def test_has_policy_changed(self):
        self._set_ports()
        self.assertTrue(
            self.policy_map.has_policy_changed(TEST_PORT, 'a_new_policy_id'))

        self.assertFalse(
            self.policy_map.has_policy_changed(TEST_PORT, TEST_POLICY.id))
