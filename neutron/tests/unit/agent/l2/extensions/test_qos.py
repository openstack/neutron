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
from neutron import context
from neutron.plugins.ml2.drivers.openvswitch.agent.common import config  # noqa
from neutron.tests import base


TEST_POLICY = object()


class QosExtensionBaseTestCase(base.BaseTestCase):

    def setUp(self):
        super(QosExtensionBaseTestCase, self).setUp()
        self.qos_ext = qos.QosAgentExtension()
        self.context = context.get_admin_context()
        self.connection = mock.Mock()

        # Don't rely on used driver
        mock.patch(
            'neutron.manager.NeutronManager.load_class_for_provider',
            return_value=lambda: mock.Mock(spec=qos.QosAgentDriver)
        ).start()


class QosExtensionRpcTestCase(QosExtensionBaseTestCase):

    def setUp(self):
        super(QosExtensionRpcTestCase, self).setUp()
        self.qos_ext.initialize(self.connection)

        self.pull_mock = mock.patch.object(
            self.qos_ext.resource_rpc, 'pull',
            return_value=TEST_POLICY).start()

    def _create_test_port_dict(self):
        return {'port_id': uuidutils.generate_uuid(),
                'qos_policy_id': uuidutils.generate_uuid()}

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
        # we make sure the underlaying qos driver is called with the
        # right parameters
        self.qos_ext.qos_driver.create.assert_called_once_with(
            port, TEST_POLICY)
        self.assertEqual(port,
            self.qos_ext.qos_policy_ports[qos_policy_id][port_id])
        self.assertTrue(port_id in self.qos_ext.known_ports)

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
        #TODO(QoS): handle qos_driver.update call check when
        #           we do that

    def test_delete_known_port(self):
        port = self._create_test_port_dict()
        port_id = port['port_id']
        self.qos_ext.handle_port(self.context, port)
        self.qos_ext.qos_driver.reset_mock()
        self.qos_ext.delete_port(self.context, port)
        self.qos_ext.qos_driver.delete.assert_called_with(port, None)
        self.assertNotIn(port_id, self.qos_ext.known_ports)

    def test_delete_unknown_port(self):
        port = self._create_test_port_dict()
        port_id = port['port_id']
        self.qos_ext.delete_port(self.context, port)
        self.assertFalse(self.qos_ext.qos_driver.delete.called)
        self.assertNotIn(port_id, self.qos_ext.known_ports)

    def test__handle_notification_ignores_all_event_types_except_updated(self):
        with mock.patch.object(
            self.qos_ext, '_process_update_policy') as update_mock:

            for event_type in set(events.VALID) - {events.UPDATED}:
                self.qos_ext._handle_notification(object(), event_type)
                self.assertFalse(update_mock.called)

    def test__handle_notification_passes_update_events(self):
        with mock.patch.object(
            self.qos_ext, '_process_update_policy') as update_mock:

            policy = mock.Mock()
            self.qos_ext._handle_notification(policy, events.UPDATED)
            update_mock.assert_called_with(policy)

    def test__process_update_policy(self):
        port1 = self._create_test_port_dict()
        port2 = self._create_test_port_dict()
        self.qos_ext.qos_policy_ports = {
            port1['qos_policy_id']: {port1['port_id']: port1},
            port2['qos_policy_id']: {port2['port_id']: port2},
        }
        policy = mock.Mock()
        policy.id = port1['qos_policy_id']
        self.qos_ext._process_update_policy(policy)
        self.qos_ext.qos_driver.update.assert_called_with(port1, policy)

        self.qos_ext.qos_driver.update.reset_mock()
        policy.id = port2['qos_policy_id']
        self.qos_ext._process_update_policy(policy)
        self.qos_ext.qos_driver.update.assert_called_with(port2, policy)

    def test__process_reset_port(self):
        port1 = self._create_test_port_dict()
        port2 = self._create_test_port_dict()
        port1_id = port1['port_id']
        port2_id = port2['port_id']
        self.qos_ext.qos_policy_ports = {
            port1['qos_policy_id']: {port1_id: port1},
            port2['qos_policy_id']: {port2_id: port2},
        }
        self.qos_ext.known_ports = {port1_id, port2_id}

        self.qos_ext._process_reset_port(port1)
        self.qos_ext.qos_driver.delete.assert_called_with(port1, None)
        self.assertNotIn(port1_id, self.qos_ext.known_ports)
        self.assertIn(port2_id, self.qos_ext.known_ports)

        self.qos_ext.qos_driver.delete.reset_mock()
        self.qos_ext._process_reset_port(port2)
        self.qos_ext.qos_driver.delete.assert_called_with(port2, None)
        self.assertNotIn(port2_id, self.qos_ext.known_ports)


class QosExtensionInitializeTestCase(QosExtensionBaseTestCase):

    @mock.patch.object(registry, 'subscribe')
    @mock.patch.object(resources_rpc, 'ResourcesPushRpcCallback')
    def test_initialize_subscribed_to_rpc(self, rpc_mock, subscribe_mock):
        self.qos_ext.initialize(self.connection)
        self.connection.create_consumer.assert_has_calls(
            [mock.call(
                 resources_rpc.resource_type_versioned_topic(resource_type),
                 [rpc_mock()],
                 fanout=True)
             for resource_type in self.qos_ext.SUPPORTED_RESOURCES]
        )
        subscribe_mock.assert_called_with(mock.ANY, resources.QOS_POLICY)
