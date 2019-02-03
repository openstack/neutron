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
from neutron_lib import constants as lib_consts
from neutron_lib import context
from neutron_lib import exceptions
from neutron_lib.services.qos import base as qos_driver_base
from neutron_lib.services.qos import constants as qos_consts
from oslo_utils import uuidutils

from neutron.common import constants
from neutron.objects import ports as ports_object
from neutron.objects.qos import rule as rule_object
from neutron.services.qos.drivers import manager as driver_mgr
from neutron.tests.unit.services.qos import base


class TestQosDriversManagerBase(base.BaseQosTestCase):

    def setUp(self):
        super(TestQosDriversManagerBase, self).setUp()
        self.config_parse()
        self.setup_coreplugin(load_plugins=False)

    @staticmethod
    def _create_manager_with_drivers(drivers_details):
        for name, driver_details in drivers_details.items():

            class QoSDriver(qos_driver_base.DriverBase):
                @property
                def is_loaded(self):
                    return driver_details['is_loaded']

            # the new ad-hoc driver will register on the QOS_PLUGIN registry
            QoSDriver(name,
                      driver_details.get('vif_types', []),
                      driver_details.get('vnic_types', []),
                      driver_details.get('rules', []))

        return driver_mgr.QosServiceDriverManager()


class TestQosDriversManagerMulti(TestQosDriversManagerBase):
    """Test calls happen to all drivers"""
    def test_driver_manager_empty_with_no_drivers(self):
        driver_manager = self._create_manager_with_drivers({})
        self.assertEqual(len(driver_manager._drivers), 0)

    def test_driver_manager_empty_with_no_loaded_drivers(self):
        driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': False}})
        self.assertEqual(len(driver_manager._drivers), 0)

    def test_driver_manager_with_one_loaded_driver(self):
        driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': True}})
        self.assertEqual(len(driver_manager._drivers), 1)

    def test_driver_manager_with_two_loaded_drivers(self):
        driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': True},
             'driver-B': {'is_loaded': True}})
        self.assertEqual(len(driver_manager._drivers), 2)


class TestQoSDriversRulesValidations(TestQosDriversManagerBase):
    """Test validation of rules for port"""

    def setUp(self):
        super(TestQoSDriversRulesValidations, self).setUp()
        self.ctxt = context.Context('fake_user', 'fake_tenant')

    def _get_port(self, vif_type, vnic_type):
        port_id = uuidutils.generate_uuid()
        port_binding = ports_object.PortBinding(
            self.ctxt, port_id=port_id, vif_type=vif_type, vnic_type=vnic_type)
        return ports_object.Port(
            self.ctxt, id=uuidutils.generate_uuid(), bindings=[port_binding])

    def _test_validate_rule_for_port(self, port, expected_result):
        driver_manager = self._create_manager_with_drivers({
            'driver-A': {
                'is_loaded': True,
                'rules': {
                    qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH: {
                        "min_kbps": {'type:values': None},
                        'direction': {
                            'type:values': lib_consts.VALID_DIRECTIONS}
                    }
                },
                'vif_types': [portbindings.VIF_TYPE_OVS],
                'vnic_types': [portbindings.VNIC_NORMAL]
            }
        })
        rule = rule_object.QosMinimumBandwidthRule(
            self.ctxt, id=uuidutils.generate_uuid())

        is_rule_supported_mock = mock.Mock()
        if expected_result:
            is_rule_supported_mock.return_value = expected_result
        driver_manager._drivers[0].is_rule_supported = is_rule_supported_mock

        self.assertEqual(expected_result,
                         driver_manager.validate_rule_for_port(rule, port))
        if expected_result:
            is_rule_supported_mock.assert_called_once_with(rule)
        else:
            is_rule_supported_mock.assert_not_called()

    def test_validate_rule_for_port_rule_vif_type_supported(self):
        port = self._get_port(
            portbindings.VIF_TYPE_OVS, portbindings.VNIC_NORMAL)
        self._test_validate_rule_for_port(
            port, expected_result=True)

    def test_validate_rule_for_port_vif_type_not_supported(self):
        port = self._get_port(
            portbindings.VIF_TYPE_OTHER, portbindings.VNIC_NORMAL)
        self._test_validate_rule_for_port(
            port, expected_result=False)

    def test_validate_rule_for_port_unbound_vnic_type_supported(self):
        port = self._get_port(
            portbindings.VIF_TYPE_UNBOUND, portbindings.VNIC_NORMAL)
        self._test_validate_rule_for_port(
            port, expected_result=True)

    def test_validate_rule_for_port_unbound_vnic_type_not_supported(self):
        port = self._get_port(
            portbindings.VIF_TYPE_UNBOUND, portbindings.VNIC_BAREMETAL)
        self._test_validate_rule_for_port(
            port, expected_result=False)


class TestQosDriversManagerRules(TestQosDriversManagerBase):
    """Test supported rules"""
    def test_available_rules_one_in_common(self):
        driver_manager = self._create_manager_with_drivers({
            'driver-A': {
                'is_loaded': True,
                'rules': {
                    qos_consts.RULE_TYPE_BANDWIDTH_LIMIT: {
                        "max_kbps": {'type:values': None},
                        "max_burst_kbps": {'type:values': None}
                    },
                    qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH: {
                        "min_kbps": {'type:values': None},
                        'direction': {
                            'type:values': lib_consts.VALID_DIRECTIONS}
                    }
                }
            },
            'driver-B': {
                'is_loaded': True,
                'rules': {
                    qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH: {
                        "min_kbps": {'type:values': None},
                        'direction': {
                            'type:values': lib_consts.VALID_DIRECTIONS}
                    },
                    qos_consts.RULE_TYPE_DSCP_MARKING: {
                        "dscp_mark": {
                            'type:values': lib_consts.VALID_DSCP_MARKS}
                    }
                }
            }
        })
        self.assertEqual(driver_manager.supported_rule_types,
                         set([qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH]))

    def test_available_rules_no_rule_in_common(self):
        driver_manager = self._create_manager_with_drivers({
            'driver-A': {
                'is_loaded': True,
                'rules': {
                    qos_consts.RULE_TYPE_BANDWIDTH_LIMIT: {
                        "max_kbps": {'type:values': None},
                        "max_burst_kbps": {'type:values': None}
                    }
                }
            },
            'driver-B': {
                'is_loaded': True,
                'rules': {
                    qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH: {
                        "min_kbps": {'type:values': None},
                        'direction': {
                            'type:values': lib_consts.VALID_DIRECTIONS}
                    },
                    qos_consts.RULE_TYPE_DSCP_MARKING: {
                        "dscp_mark": {
                            'type:values': lib_consts.VALID_DSCP_MARKS}
                    }
                }
            }
        })
        self.assertEqual(driver_manager.supported_rule_types, set([]))

    def test__parse_parameter_values(self):
        range_parameter = {'type:range': [0, 10]}
        values_parameter = {'type:values': [1, 10, 100, 1000]}
        expected_parsed_range_parameter = {'start': 0, 'end': 10}
        expected_parsed_values_parameter = [1, 10, 100, 1000]

        parameter_values, parameter_type = (
            driver_mgr.QosServiceDriverManager._parse_parameter_values(
                range_parameter))
        self.assertEqual(
            expected_parsed_range_parameter, parameter_values)
        self.assertEqual(
            constants.VALUES_TYPE_RANGE, parameter_type)

        parameter_values, parameter_type = (
            driver_mgr.QosServiceDriverManager._parse_parameter_values(
                values_parameter))
        self.assertEqual(
            expected_parsed_values_parameter, parameter_values)
        self.assertEqual(
            constants.VALUES_TYPE_CHOICES, parameter_type)

    def test_supported_rule_type_details(self):
        driver_manager = self._create_manager_with_drivers({
            'driver-A': {
                'is_loaded': True,
                'rules': {
                    qos_consts.RULE_TYPE_BANDWIDTH_LIMIT: {
                        "max_kbps": {'type:range': [0, 1000]},
                        "max_burst_kbps": {'type:range': [0, 1000]}
                    }
                }
            },
            'driver-B': {
                'is_loaded': True,
                'rules': {
                    qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH: {
                        "min_kbps": {'type:range': [0, 1000]},
                        'direction': {
                            'type:values': lib_consts.VALID_DIRECTIONS}
                    },
                    qos_consts.RULE_TYPE_DSCP_MARKING: {
                        "dscp_mark": {
                            'type:values': lib_consts.VALID_DSCP_MARKS}
                    }
                }
            }
        })
        expected_rule_type_details = [{
            'name': 'driver-A',
            'supported_parameters': [{
                'parameter_name': 'max_kbps',
                'parameter_type': constants.VALUES_TYPE_RANGE,
                'parameter_values': {'start': 0, 'end': 1000}
            }, {
                'parameter_name': 'max_burst_kbps',
                'parameter_type': constants.VALUES_TYPE_RANGE,
                'parameter_values': {'start': 0, 'end': 1000}
            }]
        }]
        bandwidth_limit_details = driver_manager.supported_rule_type_details(
            qos_consts.RULE_TYPE_BANDWIDTH_LIMIT)
        self.assertEqual(
            len(expected_rule_type_details), len(bandwidth_limit_details))
        self.assertEqual(
            expected_rule_type_details[0]['name'],
            bandwidth_limit_details[0]['name'])
        self.assertEqual(
            len(expected_rule_type_details[0]['supported_parameters']),
            len(bandwidth_limit_details[0]['supported_parameters'])
        )
        for parameter in expected_rule_type_details[0]['supported_parameters']:
            self.assertIn(
                parameter,
                bandwidth_limit_details[0]['supported_parameters'])

    def test_supported_rule_type_details_no_drivers_loaded(self):
        driver_manager = self._create_manager_with_drivers({})
        self.assertEqual(
            [],
            driver_manager.supported_rule_type_details(
                qos_consts.RULE_TYPE_BANDWIDTH_LIMIT))


class TestQosDriversCalls(TestQosDriversManagerBase):
    """Test QoS driver calls"""

    def setUp(self):
        super(TestQosDriversCalls, self).setUp()
        self.driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': True}})

    def test_implemented_call_methods(self):
        for method in qos_consts.QOS_CALL_METHODS:
            with mock.patch.object(qos_driver_base.DriverBase, method) as \
                    method_fnc:
                context = mock.Mock()
                policy = mock.Mock()
                self.driver_manager.call(method, context, policy)
                method_fnc.assert_called_once_with(context, policy)

    def test_not_implemented_call_methods(self):
        self.assertRaises(exceptions.DriverCallError, self.driver_manager.call,
                          'wrong_method', mock.Mock(), mock.Mock())
