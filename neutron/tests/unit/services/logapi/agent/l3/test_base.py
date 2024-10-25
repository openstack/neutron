# Copyright 2018 Fujitsu Limited
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

from neutron_lib.agent import l3_extension
from neutron_lib import context
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import l3_agent_extension_api as l3_ext_api
from neutron.agent.l3 import router_info as l3router
from neutron.api.rpc.callbacks import events
from neutron.services.logapi.agent.l3 import base as l3_base
from neutron.services.logapi.agent import log_extension as log_ext
from neutron.tests.unit.agent.l3 import test_agent

_uuid = uuidutils.generate_uuid


class FakeLogDriver(log_ext.LoggingDriver):

    SUPPORTED_LOGGING_TYPES = ('fake_resource',)

    def initialize(self, resource_rpc, **kwargs):
        pass

    def start_logging(self, context, **kwargs):
        pass

    def stop_logging(self, context, **kwargs):
        pass


class FakeL3LoggingExtension(l3_base.L3LoggingExtensionBase,
                             l3_extension.L3AgentExtension):

    def initialize(self, connection, driver_type):
        pass


class L3LoggingExtBaseTestCase(test_agent.BasicRouterOperationsFramework):

    def setUp(self):
        super().setUp()
        self.agent = l3_agent.L3NATAgent('test_host', self.conf)
        self.context = context.get_admin_context()
        self.connection = mock.Mock()
        self.ex_gw_port = {'id': _uuid()}
        self.router = {'id': _uuid(),
                       'gw_port': self.ex_gw_port,
                       'ha': False,
                       'distributed': False}

        self.router_info = l3router.RouterInfo(self.agent, _uuid(),
                                               self.router, **self.ri_kwargs)
        self.router_info.ex_gw_port = self.ex_gw_port
        self.agent.router_info[self.router['id']] = self.router_info

        def _mock_get_router_info(router_id):
            return self.router_info

        self.get_router_info = mock.patch(
            'neutron.agent.l3.l3_agent_extension_api.'
            'L3AgentExtensionAPI.get_router_info').start()
        self.get_router_info.side_effect = _mock_get_router_info
        self.agent_api = l3_ext_api.L3AgentExtensionAPI(None, None)
        mock.patch(
            'neutron.manager.NeutronManager.load_class_for_provider').start()


class TestL3LoggingExtBase(L3LoggingExtBaseTestCase):

    def setUp(self):
        super().setUp()
        self.agent_ext = FakeL3LoggingExtension()
        self.agent_ext.consume_api(self.agent_api)
        self.log_driver = mock.Mock()
        log_driver_object = FakeLogDriver()
        self.log_driver.defer_apply.side_effect = log_driver_object.defer_apply
        self.agent_ext.log_driver = self.log_driver

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

    def test_add_router(self):
        self.agent_ext.add_router(self.context, self.router)
        self.log_driver.start_logging.assert_called_once_with(
            self.context, router_info=self.router_info)

    def test_update_router(self):
        self.agent_ext.update_router(self.context, self.router)
        self.log_driver.start_logging.assert_called_once_with(
            self.context, router_info=self.router_info)

    def test_delete_router(self):
        router_delete = {'id': _uuid()}
        self.agent_ext.delete_router(self.context, router_delete)
        self.log_driver.stop_logging.assert_called_once_with(
            self.context, router_info=router_delete)
