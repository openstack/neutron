# Copyright (c) 2015 Red Hat Inc.
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

from neutron import context
from neutron.core_extensions import base as base_core
from neutron.core_extensions import qos as qos_core
from neutron.plugins.common import constants as plugin_constants
from neutron.services.qos import qos_consts
from neutron.tests import base


def _get_test_dbdata(qos_policy_id):
    return {'id': None, 'qos_policy_binding': {'policy_id': qos_policy_id,
                                               'network_id': 'fake_net_id'}}


class QosCoreResourceExtensionTestCase(base.BaseTestCase):

    def setUp(self):
        super(QosCoreResourceExtensionTestCase, self).setUp()
        self.core_extension = qos_core.QosCoreResourceExtension()
        policy_p = mock.patch('neutron.objects.qos.policy.QosPolicy')
        self.policy_m = policy_p.start()
        self.context = context.get_admin_context()

    def test_process_fields_no_qos_policy_id(self):
        self.core_extension.process_fields(
            self.context, base_core.PORT, {}, None)
        self.assertFalse(self.policy_m.called)

    def _mock_plugin_loaded(self, plugin_loaded):
        plugins = {}
        if plugin_loaded:
            plugins[plugin_constants.QOS] = None
        return mock.patch('neutron.manager.NeutronManager.get_service_plugins',
                          return_value=plugins)

    def test_process_fields_no_qos_plugin_loaded(self):
        with self._mock_plugin_loaded(False):
            self.core_extension.process_fields(
                self.context, base_core.PORT,
                {qos_consts.QOS_POLICY_ID: None}, None)
            self.assertFalse(self.policy_m.called)

    def test_process_fields_port_new_policy(self):
        with self._mock_plugin_loaded(True):
            qos_policy_id = mock.Mock()
            actual_port = {'id': mock.Mock(),
                           qos_consts.QOS_POLICY_ID: qos_policy_id}
            qos_policy = mock.MagicMock()
            self.policy_m.get_by_id = mock.Mock(return_value=qos_policy)
            self.core_extension.process_fields(
                self.context, base_core.PORT,
                {qos_consts.QOS_POLICY_ID: qos_policy_id},
                actual_port)

            qos_policy.attach_port.assert_called_once_with(actual_port['id'])

    def test_process_fields_port_updated_policy(self):
        with self._mock_plugin_loaded(True):
            qos_policy1_id = mock.Mock()
            qos_policy2_id = mock.Mock()
            port_id = mock.Mock()
            actual_port = {'id': port_id,
                           qos_consts.QOS_POLICY_ID: qos_policy1_id}
            old_qos_policy = mock.MagicMock()
            self.policy_m.get_port_policy = mock.Mock(
                return_value=old_qos_policy)
            new_qos_policy = mock.MagicMock()
            self.policy_m.get_by_id = mock.Mock(return_value=new_qos_policy)
            self.core_extension.process_fields(
                self.context, base_core.PORT,
                {qos_consts.QOS_POLICY_ID: qos_policy2_id},
                actual_port)

            old_qos_policy.detach_port.assert_called_once_with(port_id)
            new_qos_policy.attach_port.assert_called_once_with(port_id)
            self.assertEqual(qos_policy2_id, actual_port['qos_policy_id'])

    def test_process_resource_port_updated_no_policy(self):
        with self._mock_plugin_loaded(True):
            port_id = mock.Mock()
            qos_policy_id = mock.Mock()
            actual_port = {'id': port_id,
                           qos_consts.QOS_POLICY_ID: qos_policy_id}
            old_qos_policy = mock.MagicMock()
            self.policy_m.get_port_policy = mock.Mock(
                return_value=old_qos_policy)
            new_qos_policy = mock.MagicMock()
            self.policy_m.get_by_id = mock.Mock(return_value=new_qos_policy)
            self.core_extension.process_fields(
                self.context, base_core.PORT,
                {qos_consts.QOS_POLICY_ID: None},
                actual_port)

            old_qos_policy.detach_port.assert_called_once_with(port_id)
            self.assertIsNone(actual_port['qos_policy_id'])

    def test_process_resource_network_updated_no_policy(self):
        with self._mock_plugin_loaded(True):
            network_id = mock.Mock()
            qos_policy_id = mock.Mock()
            actual_network = {'id': network_id,
                              qos_consts.QOS_POLICY_ID: qos_policy_id}
            old_qos_policy = mock.MagicMock()
            self.policy_m.get_network_policy = mock.Mock(
                return_value=old_qos_policy)
            new_qos_policy = mock.MagicMock()
            self.policy_m.get_by_id = mock.Mock(return_value=new_qos_policy)
            self.core_extension.process_fields(
                self.context, base_core.NETWORK,
                {qos_consts.QOS_POLICY_ID: None},
                actual_network)

            old_qos_policy.detach_network.assert_called_once_with(network_id)
            self.assertIsNone(actual_network['qos_policy_id'])

    def test_process_fields_network_new_policy(self):
        with self._mock_plugin_loaded(True):
            qos_policy_id = mock.Mock()
            actual_network = {'id': mock.Mock(),
                              qos_consts.QOS_POLICY_ID: qos_policy_id}
            qos_policy = mock.MagicMock()
            self.policy_m.get_by_id = mock.Mock(return_value=qos_policy)
            self.core_extension.process_fields(
                self.context, base_core.NETWORK,
                {qos_consts.QOS_POLICY_ID: qos_policy_id}, actual_network)

            qos_policy.attach_network.assert_called_once_with(
                actual_network['id'])

    def test_process_fields_network_updated_policy(self):
        with self._mock_plugin_loaded(True):
            qos_policy_id = mock.Mock()
            network_id = mock.Mock()
            actual_network = {'id': network_id,
                              qos_consts.QOS_POLICY_ID: qos_policy_id}
            old_qos_policy = mock.MagicMock()
            self.policy_m.get_network_policy = mock.Mock(
                return_value=old_qos_policy)
            new_qos_policy = mock.MagicMock()
            self.policy_m.get_by_id = mock.Mock(return_value=new_qos_policy)
            self.core_extension.process_fields(
                self.context, base_core.NETWORK,
                {qos_consts.QOS_POLICY_ID: qos_policy_id}, actual_network)

            old_qos_policy.detach_network.assert_called_once_with(network_id)
            new_qos_policy.attach_network.assert_called_once_with(network_id)

    def test_extract_fields_plugin_not_loaded(self):
        with self._mock_plugin_loaded(False):
            fields = self.core_extension.extract_fields(None, None)
            self.assertEqual({}, fields)

    def _test_extract_fields_for_port(self, qos_policy_id):
        with self._mock_plugin_loaded(True):
            fields = self.core_extension.extract_fields(
                base_core.PORT, _get_test_dbdata(qos_policy_id))
            self.assertEqual({qos_consts.QOS_POLICY_ID: qos_policy_id}, fields)

    def test_extract_fields_no_port_policy(self):
        self._test_extract_fields_for_port(None)

    def test_extract_fields_port_policy_exists(self):
        qos_policy_id = mock.Mock()
        self._test_extract_fields_for_port(qos_policy_id)

    def _test_extract_fields_for_network(self, qos_policy_id):
        with self._mock_plugin_loaded(True):
            fields = self.core_extension.extract_fields(
                base_core.NETWORK, _get_test_dbdata(qos_policy_id))
            self.assertEqual({qos_consts.QOS_POLICY_ID: qos_policy_id}, fields)

    def test_extract_fields_no_network_policy(self):
        self._test_extract_fields_for_network(None)

    def test_extract_fields_network_policy_exists(self):
        qos_policy_id = mock.Mock()
        qos_policy = mock.Mock()
        qos_policy.id = qos_policy_id
        self._test_extract_fields_for_network(qos_policy_id)
