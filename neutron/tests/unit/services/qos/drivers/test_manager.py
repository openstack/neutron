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
from oslo_utils import uuidutils

from neutron.common import constants
from neutron.objects import ports as ports_object
from neutron.objects.qos import rule as rule_object
from neutron.services.qos.drivers import base as qos_driver_base
from neutron.services.qos.drivers import manager as driver_mgr
from neutron.services.qos import qos_consts
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
            self.ctxt, id=uuidutils.generate_uuid(), binding=port_binding)

    def _test_validate_rule_for_port(self, port, expected_result):
        driver_manager = self._create_manager_with_drivers({
            'driver-A': {
                'is_loaded': True,
                'rules': {
                    qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH: {
                        "min_kbps": {'type:values': None},
                        'direction': {
                            'type:values': constants.VALID_DIRECTIONS}
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
                            'type:values': constants.VALID_DIRECTIONS}
                    }
                }
            },
            'driver-B': {
                'is_loaded': True,
                'rules': {
                    qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH: {
                        "min_kbps": {'type:values': None},
                        'direction': {
                            'type:values': constants.VALID_DIRECTIONS}
                    },
                    qos_consts.RULE_TYPE_DSCP_MARKING: {
                        "dscp_mark": {
                            'type:values': constants.VALID_DSCP_MARKS}
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
                            'type:values': constants.VALID_DIRECTIONS}
                    },
                    qos_consts.RULE_TYPE_DSCP_MARKING: {
                        "dscp_mark": {
                            'type:values': constants.VALID_DSCP_MARKS}
                    }
                }
            }
        })
        self.assertEqual(driver_manager.supported_rule_types, set([]))
