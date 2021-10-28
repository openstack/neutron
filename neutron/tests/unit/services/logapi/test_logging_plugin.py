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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import resources
from neutron_lib import context
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron import manager
from neutron.objects.logapi import logging_resource as log_object
from neutron.objects import ports
from neutron.objects import securitygroup as sg_object
from neutron.services.logapi.common import db_api as log_db_api
from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.common import sg_validate
from neutron.tests.unit.services.logapi import base

DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
SUPPORTED_LOGGING_TYPES = ['security_group']


class TestLoggingPlugin(base.BaseLogTestCase):
    def setUp(self):
        super(TestLoggingPlugin, self).setUp()
        self.setup_coreplugin(load_plugins=False)

        mock.patch('neutron.objects.db.api.create_object').start()
        mock.patch('neutron.objects.db.api.update_object').start()
        mock.patch('neutron.objects.db.api.delete_object').start()
        mock.patch('neutron.objects.db.api.get_object').start()
        # We don't use real models as per mocks above. We also need to mock-out
        # methods that work with real data types
        mock.patch(
            'neutron.objects.base.NeutronDbObject.modify_fields_from_db'
        ).start()

        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)
        cfg.CONF.set_override("service_plugins",
            ["neutron.services.logapi.logging_plugin.LoggingPlugin"])

        manager.init()
        mock.patch(
            'neutron.services.logapi.common.validators.'
            'ResourceValidateRequest.get_validated_method',
            return_value=sg_validate.validate_security_group_request
        ).start()

        self.log_plugin = directory.get_plugin(plugin_const.LOG_API)
        self.log_plugin.driver_manager = mock.Mock()
        log_types = mock.PropertyMock(return_value=SUPPORTED_LOGGING_TYPES)
        self.log_plugin.driver_manager.supported_logging_types = \
            mock.patch('neutron.services.logapi.drivers.manager.'
                       'LoggingServiceDriverManager.supported_logging_types',
                       new_callable=log_types).start()
        self.ctxt = context.Context('admin', 'fake_tenant')

    def test__clean_security_group_logs(self):
        logs = [
            {'id': uuidutils.generate_uuid()},
            {'id': uuidutils.generate_uuid()}]
        sg_id = uuidutils.generate_uuid()
        expected_delete_calls = [
            mock.call(mock.ANY, log['id']) for log in logs]
        with mock.patch.object(log_db_api, 'get_logs_bound_sg',
                               return_value=logs) as mock_get_logs, \
                mock.patch.object(
                    self.log_plugin, 'delete_log') as mock_delete_log:
            payload = mock.Mock(
                context=self.ctxt, resource_id=sg_id)
            self.log_plugin._clean_security_group_logs(
                resources.SECURITY_GROUP, events.AFTER_DELETE, None, payload)
            mock_get_logs.assert_called_once_with(
                mock.ANY, sg_id)
            mock_delete_log.assert_has_calls(expected_delete_calls)

    def test_get_logs(self):
        with mock.patch.object(log_object.Log, 'get_objects')\
                as get_objects_mock:
            filters = {'filter': 'filter_id'}
            self.log_plugin.get_logs(self.ctxt, filters=filters)
            get_objects_mock.assert_called_once_with(self.ctxt,
                _pager=mock.ANY, filter='filter_id')

    def test_get_log_without_return_value(self):
        with mock.patch.object(log_object.Log, 'get_object',
                               return_value=None):
            self.assertRaises(
                log_exc.LogResourceNotFound,
                self.log_plugin.get_log,
                self.ctxt,
                mock.ANY,
            )

    def test_get_log_with_return_value(self):
        log_id = uuidutils.generate_uuid()
        with mock.patch.object(log_object.Log, 'get_object')\
                as get_object_mock:
            self.log_plugin.get_log(self.ctxt, log_id)
            get_object_mock.assert_called_once_with(self.ctxt,
                                                    id=log_id)

    @mock.patch('neutron.db._utils.model_query')
    def test_create_log_full_options(self, query_mock):
        log = {'log': {'resource_type': 'security_group',
                       'enabled': True,
                       'resource_id': uuidutils.generate_uuid(),
                       'target_id': uuidutils.generate_uuid()}}
        port = mock.Mock()
        new_log = mock.Mock()
        with mock.patch.object(sg_object.SecurityGroup, 'count',
                               return_value=1):
            with mock.patch.object(ports.Port, 'get_object',
                                   return_value=port):
                with mock.patch('neutron.services.logapi.common.'
                                'validators.validate_log_type_for_port',
                                return_value=True):
                    with mock.patch('neutron.objects.logapi.'
                                    'logging_resource.Log',
                                    return_value=new_log) as init_log_mock:
                        self.log_plugin.create_log(self.ctxt, log)
                        init_log_mock.assert_called_once_with(
                            context=self.ctxt, **log['log'])
                        self.assertTrue(new_log.create.called)

                        calls = [
                            mock.call.call('create_log_precommit',
                                           self.ctxt, new_log),
                            mock.call.call('create_log', self.ctxt, new_log)
                        ]
                        self.log_plugin.driver_manager.assert_has_calls(calls)

    def test_create_log_without_sg_resource(self):
        log = {'log': {'resource_type': 'security_group',
                       'enabled': True,
                       'target_id': uuidutils.generate_uuid()}}
        new_log = mock.Mock()
        new_log.enabled = True
        port = mock.Mock()
        with mock.patch.object(ports.Port, 'get_object', return_value=port):
            with mock.patch('neutron.services.logapi.common.'
                            'validators.validate_log_type_for_port',
                            return_value=True):
                with mock.patch('neutron.objects.logapi.logging_resource.Log',
                                return_value=new_log) as init_log_mock:
                    self.log_plugin.create_log(self.ctxt, log)
                    init_log_mock.assert_called_once_with(
                        context=self.ctxt, **log['log'])
                    self.assertTrue(new_log.create.called)

                    calls = [
                        mock.call.call('create_log_precommit',
                                       self.ctxt, new_log),
                        mock.call.call('create_log', self.ctxt, new_log)
                    ]
                    self.log_plugin.driver_manager.assert_has_calls(calls)

    def test_create_log_without_parent_resource(self):
        log = {'log': {'resource_type': 'security_group',
                       'enabled': True,
                       'resource_id': uuidutils.generate_uuid()}}
        new_log = mock.Mock()
        new_log.enabled = True
        with mock.patch.object(sg_object.SecurityGroup, 'count',
                               return_value=1):
            with mock.patch('neutron.objects.logapi.logging_resource.Log',
                            return_value=new_log) as init_log_mock:
                self.log_plugin.create_log(self.ctxt, log)
                init_log_mock.assert_called_once_with(context=self.ctxt,
                                                      **log['log'])
                self.assertTrue(new_log.create.called)

                calls = [
                    mock.call.call('create_log_precommit', self.ctxt, new_log),
                    mock.call.call('create_log', self.ctxt, new_log)
                ]
                self.log_plugin.driver_manager.assert_has_calls(calls)

    def test_create_log_without_target(self):
        log = {'log': {'resource_type': 'security_group',
                       'enabled': True, }}
        new_log = mock.Mock()
        new_log.enabled = True
        with mock.patch('neutron.objects.logapi.'
                        'logging_resource.Log',
                        return_value=new_log) as init_log_mock:
            self.log_plugin.create_log(self.ctxt, log)
            init_log_mock.assert_called_once_with(context=self.ctxt,
                                                  **log['log'])
            self.assertTrue(new_log.create.called)

            calls = [
                mock.call.call('create_log_precommit', self.ctxt, new_log),
                mock.call.call('create_log', self.ctxt, new_log)
            ]
            self.log_plugin.driver_manager.assert_has_calls(calls)

    def test_create_log_nonexistent_sg_resource(self):
        log = {'log': {'resource_type': 'security_group',
                       'enabled': True,
                       'resource_id': uuidutils.generate_uuid()}}
        with mock.patch.object(sg_object.SecurityGroup, 'count',
                               return_value=0):
            self.assertRaises(
                log_exc.ResourceNotFound,
                self.log_plugin.create_log,
                self.ctxt,
                log)

    def test_create_log_nonexistent_target(self):
        log = {'log': {'resource_type': 'security_group',
                       'enabled': True,
                       'target_id': uuidutils.generate_uuid()}}
        with mock.patch.object(ports.Port, 'get_object',
                               return_value=None):
            self.assertRaises(
                log_exc.TargetResourceNotFound,
                self.log_plugin.create_log,
                self.ctxt,
                log)

    def test_create_log_not_bound_port(self):
        log = {'log': {'resource_type': 'security_group',
                       'enabled': True,
                       'resource_id': uuidutils.generate_uuid(),
                       'target_id': uuidutils.generate_uuid()}}
        port = mock.Mock()
        with mock.patch.object(sg_object.SecurityGroup, 'count',
                               return_value=1):
            with mock.patch.object(ports.Port, 'get_object',
                                   return_value=port):
                with mock.patch('neutron.services.logapi.common.'
                                'validators.validate_log_type_for_port',
                                return_value=True):
                    self.assertRaises(
                        log_exc.InvalidResourceConstraint,
                        self.log_plugin.create_log,
                        self.ctxt,
                        log)

    def test_create_log_disabled(self):
        log_data = {'log': {'resource_type': 'security_group',
                            'enabled': False}}
        new_log = mock.Mock()
        new_log.enabled = False
        with mock.patch('neutron.objects.logapi.'
                        'logging_resource.Log',
                        return_value=new_log) as init_log_mock:
            self.log_plugin.create_log(self.ctxt, log_data)
            init_log_mock.assert_called_once_with(
                context=self.ctxt, **log_data['log'])
            self.assertTrue(new_log.create.called)
        self.log_plugin.driver_manager.call.assert_not_called()

    def test_create_log_with_unsupported_logging_type(self):
        log = {'log': {'resource_type': 'fake_type',
                       'enabled': True}}
        self.assertRaises(
            log_exc.InvalidLogResourceType,
            self.log_plugin.create_log,
            self.ctxt,
            log)

    def test_create_log_with_unsupported_logging_type_on_port(self):
        log = {'log': {'resource_type': 'security_group',
                       'enabled': True,
                       'target_id': uuidutils.generate_uuid()}}

        port = mock.Mock()
        port.id = log['log']['target_id']
        with mock.patch.object(ports.Port, 'get_object',
                               return_value=port):
            with mock.patch('neutron.services.logapi.common.'
                            'validators.validate_log_type_for_port',
                            return_value=False):
                self.assertRaises(
                    log_exc.LoggingTypeNotSupported,
                    self.log_plugin.create_log,
                    self.ctxt,
                    log)

    def test_update_log(self):
        log_data = {'log': {'enabled': True}}
        new_log = mock.Mock()
        new_log.id = uuidutils.generate_uuid()
        with mock.patch('neutron.objects.logapi.'
                        'logging_resource.Log',
                        return_value=new_log) as update_log_mock:
            self.log_plugin.update_log(self.ctxt, new_log.id, log_data)
            update_log_mock.assert_called_once_with(self.ctxt,
                                                    id=new_log.id)
            new_log.update_fields.assert_called_once_with(log_data['log'],
                                                          reset_changes=True)
            self.assertTrue(new_log.update.called)

            calls = [
                mock.call.call('update_log_precommit', self.ctxt, new_log),
                mock.call.call('update_log', self.ctxt, new_log)
            ]
            self.log_plugin.driver_manager.assert_has_calls(calls)

    def test_update_log_none_enabled(self):
        log_data = {'log': {}}
        new_log = mock.Mock()
        new_log.id = uuidutils.generate_uuid()
        with mock.patch('neutron.objects.logapi.'
                        'logging_resource.Log',
                        return_value=new_log) as update_log_mock:
            self.log_plugin.update_log(self.ctxt, new_log.id, log_data)
            update_log_mock.assert_called_once_with(self.ctxt,
                                                    id=new_log.id)
            new_log.update_fields.assert_called_once_with(log_data['log'],
                                                          reset_changes=True)
            self.assertTrue(new_log.update.called)
        self.log_plugin.driver_manager.call.assert_not_called()

    def test_delete_log(self):
        delete_log = mock.Mock()
        delete_log.id = uuidutils.generate_uuid()
        with mock.patch.object(log_object.Log, 'get_object',
                               return_value=delete_log) as delete_log_mock:
            self.log_plugin.delete_log(self.ctxt, delete_log.id)
            delete_log_mock.assert_called_once_with(self.ctxt,
                                                    id=delete_log.id)
            self.assertTrue(delete_log.delete.called)

            calls = [
                mock.call.call('delete_log_precommit', self.ctxt, delete_log),
                mock.call.call('delete_log', self.ctxt, delete_log)
            ]
            self.log_plugin.driver_manager.assert_has_calls(calls)

    def test_delete_nonexistent_log(self):
        with mock.patch.object(log_object.Log, 'get_object',
                               return_value=None):
            self.assertRaises(
                log_exc.LogResourceNotFound,
                self.log_plugin.delete_log,
                self.ctxt,
                mock.ANY)
