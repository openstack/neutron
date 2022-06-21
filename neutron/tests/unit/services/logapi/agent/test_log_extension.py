# Copyright (C) 2017 Fujitsu Limited
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

from unittest import mock

from neutron_lib import context
from neutron_lib.plugins.ml2 import ovs_constants
from oslo_utils import uuidutils

from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.plugins.ml2.drivers.openvswitch.agent import (
    ovs_agent_extension_api as ovs_ext_api)
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native import (
    ovs_bridge)
from neutron.services.logapi.agent import log_extension as log_ext
from neutron.tests import base


class FakeLogDriver(log_ext.LoggingDriver):

    SUPPORTED_LOGGING_TYPES = ['security_group']

    def initialize(self, resource_rpc, **kwargs):
        pass

    def start_logging(self, context, **kwargs):
        pass

    def stop_logging(self, context, **kwargs):
        pass


class LoggingExtensionBaseTestCase(base.BaseTestCase):

    def setUp(self):
        super(LoggingExtensionBaseTestCase, self).setUp()
        conn_patcher = mock.patch(
            'neutron.agent.ovsdb.impl_idl._connection')
        conn_patcher.start()
        self.agent_ext = log_ext.LoggingExtension()
        self.context = context.get_admin_context()
        self.connection = mock.Mock()
        os_ken_app = mock.Mock()
        agent_api = ovs_ext_api.OVSAgentExtensionAPI(
            ovs_bridge.OVSAgentBridge('br-int', os_ken_app=os_ken_app),
            ovs_bridge.OVSAgentBridge('br-tun', os_ken_app=os_ken_app),
            {'physnet1': ovs_bridge.OVSAgentBridge(
                'br-physnet1', os_ken_app=os_ken_app)})
        self.agent_ext.consume_api(agent_api)
        mock.patch(
            'neutron.manager.NeutronManager.load_class_for_provider').start()


class LoggingExtensionTestCase(LoggingExtensionBaseTestCase):

    def setUp(self):
        super(LoggingExtensionTestCase, self).setUp()
        self.agent_ext.initialize(
            self.connection, ovs_constants.EXTENSION_DRIVER_TYPE)
        self.log_driver = mock.Mock()
        log_driver_object = FakeLogDriver()
        self.log_driver.defer_apply.side_effect = log_driver_object.defer_apply
        self.agent_ext.log_driver = self.log_driver

    def _create_test_port_dict(self, device_owner):
        return {'port_id': uuidutils.generate_uuid(),
                'device_owner': device_owner}

    def test__handle_notification_passes_update_events_enabled_log(self):
        log_obj = mock.Mock()
        log_obj.enabled = True
        self.agent_ext._handle_notification(
            self.context, 'log', [log_obj], events.UPDATED)
        self.assertTrue(self.log_driver.start_logging.called)

    def test__handle_notification_passes_update_events_disabled_log(self):
        log_obj = mock.Mock()
        log_obj.enabled = False
        self.agent_ext._handle_notification(
            self.context, 'log', [log_obj], events.UPDATED)
        self.assertTrue(self.log_driver.stop_logging.called)

    def test__handle_notification_passes_create_events(self):
        log_obj = mock.Mock()
        self.agent_ext._handle_notification(
            self.context, 'log', [log_obj], events.CREATED)
        self.assertTrue(self.log_driver.start_logging.called)

    def test__handle_notification_passes_delete_events(self):
        log_obj = mock.Mock()
        self.agent_ext._handle_notification(
            self.context, 'log', [log_obj], events.DELETED)
        self.assertTrue(self.log_driver.stop_logging.called)

    def test_handle_port_vm(self):
        port = self._create_test_port_dict(device_owner='compute:nova')
        self.agent_ext.handle_port(self.context, port)
        self.assertTrue(self.log_driver.start_logging.called)

    def test_handle_not_port_vm(self):
        port = self._create_test_port_dict(
            device_owner='network:router_interface')
        self.agent_ext.handle_port(self.context, port)
        self.assertFalse(self.log_driver.start_logging.called)


class LoggingExtensionInitializeTestCase(LoggingExtensionBaseTestCase):
    @mock.patch.object(registry, 'register')
    @mock.patch.object(resources_rpc, 'ResourcesPushRpcCallback')
    def test_initialize_subscribed_to_rpc(self, rpc_mock, subscribe_mock):
        self.agent_ext.initialize(
            self.connection, ovs_constants.EXTENSION_DRIVER_TYPE)
        self.connection.create_consumer.assert_has_calls(
            [mock.call(
                resources_rpc.resource_type_versioned_topic(resource_type),
                [rpc_mock()],
                fanout=True)
             for resource_type in self.agent_ext.SUPPORTED_RESOURCE_TYPES]
        )
        subscribe_mock.assert_called_with(mock.ANY, resources.LOGGING_RESOURCE)
