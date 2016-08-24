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

from neutron.services.trunk.drivers.linuxbridge import driver
from neutron.tests import base


class LinuxBridgeDriverTestCase(base.BaseTestCase):

    def test_driver_is_loaded(self):
        inst = driver.LinuxBridgeDriver.create()
        cfg.CONF.set_override('mechanism_drivers',
                              ['a', 'b', 'linuxbridge'], group='ml2')
        self.assertTrue(inst.is_loaded)
        cfg.CONF.set_override('mechanism_drivers',
                              ['a', 'b'], group='ml2')
        self.assertFalse(inst.is_loaded)
        cfg.CONF.set_override('core_plugin', 'my_foo_plugin')
        self.assertFalse(inst.is_loaded)

    def test_driver_properties(self):
        inst = driver.LinuxBridgeDriver.create()
        self.assertEqual(driver.NAME, inst.name)
        self.assertEqual(driver.SUPPORTED_INTERFACES, inst.interfaces)
        self.assertEqual(driver.SUPPORTED_SEGMENTATION_TYPES,
                         inst.segmentation_types)
        self.assertEqual(constants.AGENT_TYPE_LINUXBRIDGE, inst.agent_type)
        self.assertTrue(inst.can_trunk_bound_port)
