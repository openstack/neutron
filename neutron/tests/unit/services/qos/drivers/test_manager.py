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

from oslo_config import cfg

from neutron.conf.services import qos_driver_manager as notif_driver_mgr_config
from neutron.services.qos.drivers import base as qos_driver_base
from neutron.services.qos.drivers import manager as driver_mgr
from neutron.services.qos import qos_consts
from neutron.tests.unit.services.qos import base


class TestQosDriversManagerBase(base.BaseQosTestCase):

    def setUp(self):
        super(TestQosDriversManagerBase, self).setUp()
        self.config_parse()
        self.setup_coreplugin(load_plugins=False)
        config = cfg.ConfigOpts()
        notif_driver_mgr_config.register_qos_plugin_opts(config)

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


class TestQosDriversManagerRules(TestQosDriversManagerBase):
    """Test supported rules"""
    def test_available_rules_one_in_common(self):
        driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': True,
                          'rules': [qos_consts.RULE_TYPE_BANDWIDTH_LIMIT,
                                    qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH]},
             'driver-B': {'is_loaded': True,
                          'rules': [qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH,
                                    qos_consts.RULE_TYPE_DSCP_MARKING]}
             })
        self.assertEqual(driver_manager.supported_rule_types,
                         set([qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH]))

    def test_available_rules_no_rule_in_common(self):
        driver_manager = self._create_manager_with_drivers(
            {'driver-A': {'is_loaded': True,
                          'rules': [qos_consts.RULE_TYPE_BANDWIDTH_LIMIT]},
             'driver-B': {'is_loaded': True,
                          'rules': [qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH,
                                    qos_consts.RULE_TYPE_DSCP_MARKING]}
             })
        self.assertEqual(driver_manager.supported_rule_types, set([]))
