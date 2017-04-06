# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_config import cfg

from neutron.services.l3_router import l3_router_plugin as lrp
from neutron.tests import base


class TestL3PluginDvrConditional(base.BaseTestCase):

    def _test_dvr_alias_exposed(self, enabled):
        cfg.CONF.set_override('enable_dvr', enabled)
        plugin = lrp.L3RouterPlugin()
        exposed = 'dvr' in plugin.supported_extension_aliases
        self.assertEqual(enabled, exposed)

    def test_dvr_alias_exposed_enabled(self):
        self._test_dvr_alias_exposed(enabled=True)

    def test_dvr_alias_exposed_disabled(self):
        self._test_dvr_alias_exposed(enabled=False)
