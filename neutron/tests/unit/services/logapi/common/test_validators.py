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

import mock
from neutron_lib.api.definitions import portbindings
from neutron_lib import context
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from oslo_utils import uuidutils
from sqlalchemy.orm import exc as orm_exc

from neutron.objects import ports
from neutron.objects import securitygroup as sg_object
from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.common import validators
from neutron.tests import base
from neutron.tests.unit.services.logapi.drivers import (
    test_manager as drv_mgr)


class TestRequestValidations(base.BaseTestCase):
    """Test validation for a request"""

    def test_validate_request_resource_sg_not_exists(self):
        log_data = {'resource_type': 'security_group',
                    'resource_id': 'fake_sg_id'}
        with mock.patch.object(sg_object.SecurityGroup, 'count',
                               return_value=0):
            self.assertRaises(log_exc.ResourceNotFound,
                              validators.validate_request,
                              mock.ANY,
                              log_data)

    def test_validate_request_target_resource_port_not_exists(self):
        log_data = {'resource_type': 'security_group',
                    'target_id': 'fake_port_id'}
        with mock.patch.object(ports.Port, 'get_object', return_value=None):
            self.assertRaises(log_exc.TargetResourceNotFound,
                              validators.validate_request,
                              mock.ANY,
                              log_data)

    def test_validate_request_log_type_not_supported_on_port(self):
        log_data = {'resource_type': 'security_group',
                    'target_id': 'fake_port_id'}
        with mock.patch.object(ports.Port, 'get_object',
                               return_value=mock.ANY):
            with mock.patch.object(validators, 'validate_log_type_for_port',
                                   return_value=False):
                self.assertRaises(log_exc.LoggingTypeNotSupported,
                                  validators.validate_request,
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
                            validators.validate_request,
                            mock.ANY,
                            log_data)


class TestLogDriversLoggingTypeValidations(drv_mgr.TestLogDriversManagerBase):
    """Test validation of logging type for a port"""

    def setUp(self):
        super(TestLogDriversLoggingTypeValidations, self).setUp()
        self.ctxt = context.Context('fake_user', 'fake_tenant')

    def _get_port(self, vif_type, vnic_type):
        port_id = uuidutils.generate_uuid()
        port_binding = ports.PortBinding(
            self.ctxt, port_id=port_id, vif_type=vif_type, vnic_type=vnic_type)
        return ports.Port(
            self.ctxt, id=uuidutils.generate_uuid(), binding=port_binding)

    def _test_validate_log_type_for_port(self, port, expected_result):
        driver_manager = self._create_manager_with_drivers({
            'driver-A': {
                'is_loaded': True,
                'supported_logging_types': ['security_group'],
                'vif_types': [portbindings.VIF_TYPE_OVS],
                'vnic_types': [portbindings.VNIC_NORMAL]
            }
        })

        is_log_type_supported_mock = mock.Mock()
        if expected_result:
            is_log_type_supported_mock.return_value = expected_result
        log_driver = list(driver_manager.drivers)[0]
        log_driver.is_logging_type_supported = (
            is_log_type_supported_mock
        )

        class FakeLoggingPlugin(object):
            def __init__(self):
                self.driver_manager = driver_manager

        directory.add_plugin(plugin_const.LOG_API, FakeLoggingPlugin())

        self.assertEqual(
            expected_result,
            validators.validate_log_type_for_port('security_group', port))
        if expected_result:
            is_log_type_supported_mock.assert_called_once_with(
                'security_group')
        else:
            is_log_type_supported_mock.assert_not_called()

    def test_validate_log_type_for_port_vif_type_supported(self):
        port = self._get_port(
            portbindings.VIF_TYPE_OVS, portbindings.VNIC_NORMAL)
        self._test_validate_log_type_for_port(
            port, expected_result=True)

    def test_validate_log_type_for_port_vif_type_not_supported(self):
        port = self._get_port(
            portbindings.VIF_TYPE_OTHER, portbindings.VNIC_NORMAL)
        self._test_validate_log_type_for_port(
            port, expected_result=False)

    def test_validate_log_type_for_port_unbound_vnic_type_supported(self):
        port = self._get_port(
            portbindings.VIF_TYPE_UNBOUND, portbindings.VNIC_NORMAL)
        self._test_validate_log_type_for_port(
            port, expected_result=True)

    def test_validate_log_type_for_port_unbound_vnic_type_not_supported(self):
        port = self._get_port(
            portbindings.VIF_TYPE_UNBOUND, portbindings.VNIC_BAREMETAL)
        self._test_validate_log_type_for_port(
            port, expected_result=False)
