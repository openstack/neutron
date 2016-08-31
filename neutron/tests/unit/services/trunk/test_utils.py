# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock

from neutron.services.trunk import utils
from neutron.tests.unit.plugins.ml2 import test_plugin
from neutron.tests.unit.services.trunk import fakes


class UtilsTestCase(test_plugin.Ml2PluginV2TestCase):

    def test_get_agent_types_by_host_returns_empty(self):
        self.assertFalse(
            utils.get_agent_types_by_host(
                self.context, 'foo_host'))

    def test_get_agent_types_by_host_returns_agents(self):
        with mock.patch("neutron.db.agents_db.AgentDbMixin.get_agents") as f:
            f.return_value = [{'agent_type': 'foo_type'}]
            self.assertEqual(
                ['foo_type'],
                utils.get_agent_types_by_host(
                    self.context, 'foo_host'))

    def _test_is_driver_compatible(self, driver, interface, agent_types):
        return utils.is_driver_compatible(self.context,
                                          driver,
                                          interface,
                                          agent_types)

    def test_is_driver_compatible(self):
        driver = fakes.FakeDriverWithAgent.create()
        self.assertTrue(self._test_is_driver_compatible(
            driver, 'foo_intfs', ['foo_type']))

    def test_is_driver_compatible_agent_based_agent_mismatch(self):
        driver = fakes.FakeDriverWithAgent.create()
        self.assertFalse(self._test_is_driver_compatible(
            driver, 'foo_intfs', ['foo_type_unknown']))

    def test_is_driver_incompatible_because_of_interface_mismatch(self):
        driver = fakes.FakeDriverWithAgent.create()
        self.assertFalse(self._test_is_driver_compatible(
            driver, 'not_my_interface', ['foo_type']))

    def test_is_driver_compatible_agentless(self):
        driver = fakes.FakeDriver.create()
        self.assertTrue(self._test_is_driver_compatible(
            driver, 'foo_intfs', ['foo_type']))

    def test_is_driver_compatible_multiple_drivers(self):
        driver1 = fakes.FakeDriverWithAgent.create()
        driver2 = fakes.FakeDriver2.create()
        self.assertTrue(self._test_is_driver_compatible(
            driver1, 'foo_intfs', ['foo_type']))
        self.assertFalse(self._test_is_driver_compatible(
            driver2, 'foo_intfs', ['foo_type']))
