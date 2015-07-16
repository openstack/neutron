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

from neutron.agent.l2.extensions import qos_agent
from neutron.api.rpc.callbacks import resources
from neutron import context
from neutron.tests import base

# This is a minimalistic mock of rules to be passed/checked around
# which should be exteneded as needed to make real rules
TEST_GET_INFO_RULES = ['rule1', 'rule2']


class QosAgentExtensionTestCase(base.BaseTestCase):

    def setUp(self):
        super(QosAgentExtensionTestCase, self).setUp()
        self.qos_agent = qos_agent.QosAgentExtension()
        self.context = context.get_admin_context()

        # Don't rely on used driver
        mock.patch(
            'neutron.manager.NeutronManager.load_class_for_provider',
            return_value=mock.Mock(spec=qos_agent.QosAgentDriver)).start()

        self._create_fake_resource_rpc()
        self.qos_agent.initialize(self.resource_rpc_mock)

    def _create_fake_resource_rpc(self):
        self.get_info_mock = mock.Mock(return_value=TEST_GET_INFO_RULES)
        self.resource_rpc_mock = mock.Mock()
        self.resource_rpc_mock.get_info = self.get_info_mock

    def _create_test_port_dict(self):
        return {'port_id': uuidutils.generate_uuid(),
                'qos_policy_id': uuidutils.generate_uuid()}

    def test_handle_port_with_no_policy(self):
        port = self._create_test_port_dict()
        del port['qos_policy_id']
        self.qos_agent._process_rules_updates = mock.Mock()
        self.qos_agent.handle_port(self.context, port)
        self.assertFalse(self.qos_agent._process_rules_updates.called)

    def test_handle_unknown_port(self):
        port = self._create_test_port_dict()
        qos_policy_id = port['qos_policy_id']
        port_id = port['port_id']
        self.qos_agent.handle_port(self.context, port)
        # we make sure the underlaying qos driver is called with the
        # right parameters
        self.qos_agent.qos_driver.create.assert_called_once_with(
            port, TEST_GET_INFO_RULES)
        self.assertEqual(port,
            self.qos_agent.qos_policy_ports[qos_policy_id][port_id])
        self.assertTrue(port_id in self.qos_agent.known_ports)

    def test_handle_known_port(self):
        port_obj1 = self._create_test_port_dict()
        port_obj2 = dict(port_obj1)
        self.qos_agent.handle_port(self.context, port_obj1)
        self.qos_agent.qos_driver.reset_mock()
        self.qos_agent.handle_port(self.context, port_obj2)
        self.assertFalse(self.qos_agent.qos_driver.create.called)

    def test_handle_known_port_change_policy_id(self):
        port = self._create_test_port_dict()
        self.qos_agent.handle_port(self.context, port)
        self.resource_rpc_mock.get_info.reset_mock()
        port['qos_policy_id'] = uuidutils.generate_uuid()
        self.qos_agent.handle_port(self.context, port)
        self.get_info_mock.assert_called_once_with(
             self.context, resources.QOS_POLICY,
             port['qos_policy_id'])
        #TODO(QoS): handle qos_driver.update call check when
        #           we do that
