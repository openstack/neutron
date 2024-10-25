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

from unittest import mock

from neutron_lib.plugins import directory
from oslo_utils import importutils

from neutron.objects import router as router_obj
from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.common import validators
from neutron.tests import base


class FakePlugin:

    def __init__(self):
        self.validator_mgr = validators.ResourceValidateRequest.get_instance()
        self.supported_logging_types = ['snat']


class TestSnatLogRequestValidations(base.BaseTestCase):
    """Test validation for SNAT log request"""
    def setUp(self):
        self.log_plugin = FakePlugin()
        importutils.import_module('neutron.services.logapi.common.'
                                  'snat_validate')
        super().setUp()

    def test_validate_request_resource_id_not_specific(self):
        log_data = {'resource_type': 'snat'}

        with mock.patch.object(directory, 'get_plugin',
                               return_value=self.log_plugin):
            with mock.patch.object(router_obj.Router, 'get_object',
                                   return_value=mock.ANY):
                self.assertRaises(
                    log_exc.ResourceIdNotSpecified,
                    self.log_plugin.validator_mgr.validate_request,
                    mock.ANY,
                    log_data)

    def test_validate_request_resource_id_not_exists(self):
        log_data = {'resource_type': 'snat',
                    'resource_id': 'fake_router_id'}

        with mock.patch.object(directory, 'get_plugin',
                               return_value=self.log_plugin):
            with mock.patch.object(router_obj.Router, 'get_object',
                                   return_value=None):
                self.assertRaises(
                    log_exc.ResourceNotFound,
                    self.log_plugin.validator_mgr.validate_request,
                    mock.ANY,
                    log_data)

    def test_validate_request_with_disable_events(self):
        log_data_1 = {'resource_type': 'snat',
                      'resource_id': 'fake_router_id_1',
                      'event': 'ACCEPT'}
        log_data_2 = {'resource_type': 'snat',
                      'resource_id': 'fake_router_id_2',
                      'event': 'DROP'}
        with mock.patch.object(directory, 'get_plugin',
                               return_value=self.log_plugin):
            with mock.patch.object(router_obj.Router, 'get_object',
                                   return_value=mock.ANY):
                self.assertRaises(
                    log_exc.EventsDisabled,
                    self.log_plugin.validator_mgr.validate_request,
                    mock.ANY,
                    log_data_1)

                self.assertRaises(
                    log_exc.EventsDisabled,
                    self.log_plugin.validator_mgr.validate_request,
                    mock.ANY,
                    log_data_2)

    def test_validate_request_with_snat_disable(self):
        log_data = {'resource_type': 'snat',
                    'resource_id': 'fake_router_id'}
        f_router = mock.Mock()
        f_router.enable_snat = False
        with mock.patch.object(directory, 'get_plugin',
                               return_value=self.log_plugin):
            with mock.patch.object(router_obj.Router, 'get_object',
                                   return_value=f_router):
                self.assertRaises(
                    log_exc.RouterNotEnabledSnat,
                    self.log_plugin.validator_mgr.validate_request,
                    mock.ANY,
                    log_data)

    def test_validate_request_with_not_set_gw_port(self):
        log_data = {'resource_type': 'snat',
                    'resource_id': 'fake_router_id'}
        f_router = mock.Mock()
        f_router.enable_snat = True
        f_router.gw_port_id = None
        with mock.patch.object(directory, 'get_plugin',
                               return_value=self.log_plugin):
            with mock.patch.object(router_obj.Router, 'get_object',
                                   return_value=f_router):
                self.assertRaises(
                    log_exc.RouterGatewayNotSet,
                    self.log_plugin.validator_mgr.validate_request,
                    mock.ANY,
                    log_data)
