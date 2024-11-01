# Copyright (c) 2017 Fujitsu Limited
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

from neutron_lib import rpc
from neutron_lib.services.logapi import constants as log_const
from oslo_config import cfg
import oslo_messaging

from neutron.api.rpc.callbacks import events
from neutron.api.rpc.handlers import resources_rpc
from neutron.services.logapi.rpc import server as server_rpc
from neutron.tests import base


class LoggingApiNotificationTestCase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.test_obj = server_rpc.LoggingApiNotification()

    def test___init__(self):
        self.assertIsInstance(self.test_obj.notification_api,
                              resources_rpc.ResourcesPushRpcApi)

    @mock.patch("neutron.api.rpc.handlers.resources_rpc.ResourcesPushRpcApi."
                "push")
    def test_create_log(self, mocked_push):
        m_context = mock.Mock()
        m_log_resource = mock.Mock()
        self.test_obj.create_log(m_context, m_log_resource)
        mocked_push.assert_called_with(m_context, [m_log_resource],
                                       events.CREATED)

    @mock.patch("neutron.api.rpc.handlers.resources_rpc.ResourcesPushRpcApi."
                "push")
    def test_update_log(self, mocked_push):
        m_context = mock.Mock()
        m_log_resource = mock.Mock()
        self.test_obj.update_log(m_context, m_log_resource)
        mocked_push.assert_called_with(m_context, [m_log_resource],
                                       events.UPDATED)

    @mock.patch("neutron.api.rpc.handlers.resources_rpc.ResourcesPushRpcApi."
                "push")
    def test_delete_log(self, mocked_push):
        m_context = mock.Mock()
        m_log_resource = mock.Mock()
        self.test_obj.delete_log(m_context, m_log_resource)
        mocked_push.assert_called_with(m_context, [m_log_resource],
                                       events.DELETED)


class TestRegisterValidateRPCMethods(base.BaseTestCase):

    def test_register_rpc_methods_method(self):
        resource_type = 'security_group'
        method = [{'fake_key1': 'fake_method1'},
                  {'fake_key2': 'fake_method2'}]
        expected = {resource_type: method}
        server_rpc.RPC_RESOURCES_METHOD_MAP.clear()
        server_rpc.register_rpc_methods(resource_type, method)
        self.assertEqual(expected, server_rpc.RPC_RESOURCES_METHOD_MAP)

    def test_get_rpc_method(self):
        resource_type = 'security_group'
        method = [{'fake_key1': 'fake_method1'},
                  {'fake_key2': 'fake_method2'}]
        server_rpc.RPC_RESOURCES_METHOD_MAP = {resource_type: method}
        actual = server_rpc.get_rpc_method('security_group', 'fake_key1')
        self.assertEqual('fake_method1', actual)


class LoggingApiSkeletonTestCase(base.BaseTestCase):

    @mock.patch.object(rpc, "get_server")
    def test___init__(self, mocked_get_server):
        test_obj = server_rpc.LoggingApiSkeleton()
        _target = oslo_messaging.Target(
            topic=log_const.LOGGING_PLUGIN,
            server=cfg.CONF.host,
            fanout=False)
        mocked_get_server.assert_called_with(_target, [test_obj])

    @mock.patch("neutron.services.logapi.common.db_api."
                "get_sg_log_info_for_port")
    def test_get_sg_log_info_for_port(self, mock_callback):
        with mock.patch.object(
                server_rpc,
                'get_rpc_method',
                return_value=server_rpc.get_sg_log_info_for_port
        ):
            test_obj = server_rpc.LoggingApiSkeleton()
            m_context = mock.Mock()
            port_id = '123'
            test_obj.get_sg_log_info_for_port(
                m_context,
                resource_type=log_const.SECURITY_GROUP,
                port_id=port_id)
            mock_callback.assert_called_with(m_context, port_id)

    @mock.patch("neutron.services.logapi.common.db_api."
                "get_sg_log_info_for_log_resources")
    def test_get_sg_log_info_for_log_resources(self, mock_callback):
        with mock.patch.object(
                server_rpc,
                'get_rpc_method',
                return_value=server_rpc.get_sg_log_info_for_log_resources
        ):
            test_obj = server_rpc.LoggingApiSkeleton()
            m_context = mock.Mock()
            log_resources = [mock.Mock()]
            test_obj.get_sg_log_info_for_log_resources(
                m_context,
                resource_type=log_const.SECURITY_GROUP,
                log_resources=log_resources)
            mock_callback.assert_called_with(m_context, log_resources)
