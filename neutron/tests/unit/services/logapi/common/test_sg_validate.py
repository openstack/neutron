# Copyright (c) 2018 Fujitsu Limited
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
from neutron_lib.plugins import directory
from oslo_utils import importutils
from sqlalchemy.orm import exc as orm_exc

from neutron.objects import ports
from neutron.objects import securitygroup as sg_object
from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.common import validators
from neutron.tests import base


class FakePlugin(object):

    def __init__(self):
        self.validator_mgr = validators.ResourceValidateRequest.get_instance()
        self.supported_logging_types = ['security_group']


class TestSGLogRequestValidations(base.BaseTestCase):
    """Test validation for a request"""
    def setUp(self):
        self.log_plugin = FakePlugin()
        importutils.import_module('neutron.services.logapi.common.sg_validate')
        super(TestSGLogRequestValidations, self).setUp()

    def test_validate_request_resource_id_not_exists(self):
        log_data = {'resource_type': 'security_group',
                    'resource_id': 'fake_sg_id'}

        with mock.patch.object(directory, 'get_plugin',
                               return_value=self.log_plugin):
            with mock.patch.object(sg_object.SecurityGroup, 'count',
                                   return_value=0):
                self.assertRaises(
                    log_exc.ResourceNotFound,
                    self.log_plugin.validator_mgr.validate_request,
                    mock.ANY,
                    log_data)

    def test_validate_request_target_id_not_exists(self):
        log_data = {'resource_type': 'security_group',
                    'target_id': 'fake_port_id'}

        with mock.patch.object(directory, 'get_plugin',
                               return_value=self.log_plugin):
            with mock.patch.object(ports.Port, 'get_object',
                                   return_value=None):
                self.assertRaises(
                    log_exc.TargetResourceNotFound,
                    self.log_plugin.validator_mgr.validate_request,
                    mock.ANY,
                    log_data)

    def test_validate_request_unsupported_logging_type(self):
        log_data = {'resource_type': 'security_group',
                    'target_id': 'fake_port_id'}

        with mock.patch.object(directory, 'get_plugin',
                               return_value=self.log_plugin):
            with mock.patch.object(ports.Port, 'get_object',
                                   return_value=mock.ANY):
                with mock.patch.object(validators,
                                       'validate_log_type_for_port',
                                       return_value=False):
                    self.assertRaises(
                        log_exc.LoggingTypeNotSupported,
                        self.log_plugin.validator_mgr.validate_request,
                        mock.ANY,
                        log_data)

    def test_validate_request_invalid_resource_constraint(self):
        log_data = {'resource_type': 'security_group',
                    'resource_id': 'fake_sg_id',
                    'target_id': 'fake_port_id'}

        class FakeFiltered(object):
            def one(self):
                raise orm_exc.NoResultFound

        class FakeSGPortBinding(object):
            def filter_by(self, security_group_id, port_id):
                return FakeFiltered()

        with mock.patch.object(directory, 'get_plugin',
                               return_value=self.log_plugin):
            with mock.patch.object(
                    sg_object.SecurityGroup, 'count', return_value=1):
                with mock.patch.object(
                        ports.Port, 'get_object', return_value=mock.ANY):
                    with mock.patch.object(validators,
                                           'validate_log_type_for_port',
                                           return_value=True):
                        with mock.patch('neutron.db._utils.model_query',
                                        return_value=FakeSGPortBinding()):
                            self.assertRaises(
                                log_exc.InvalidResourceConstraint,
                                self.log_plugin.validator_mgr.validate_request,
                                mock.ANY,
                                log_data)
