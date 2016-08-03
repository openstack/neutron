# Copyright 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron_lib import constants
from oslo_config import cfg

from neutron.services.trunk.drivers.openvswitch import driver
from neutron.tests import base


class OVSDriverTestCase(base.BaseTestCase):

    def test_driver_creation(self):
        ovs_driver = driver.OVSDriver.create()
        self.assertFalse(ovs_driver.is_loaded)
        self.assertEqual(driver.NAME, ovs_driver.name)
        self.assertEqual(driver.SUPPORTED_INTERFACES, ovs_driver.interfaces)
        self.assertEqual(driver.SUPPORTED_SEGMENTATION_TYPES,
                         ovs_driver.segmentation_types)
        self.assertEqual(constants.AGENT_TYPE_OVS, ovs_driver.agent_type)
        self.assertFalse(ovs_driver.can_trunk_bound_port)

    def test_driver_is_loaded(self):
        cfg.CONF.set_override('mechanism_drivers',
                              'openvswitch', group='ml2')
        ovs_driver = driver.OVSDriver.create()
        self.assertTrue(ovs_driver.is_loaded)
