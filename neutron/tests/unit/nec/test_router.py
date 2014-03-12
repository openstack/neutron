# Copyright (c) 2013 OpenStack Foundation.
#
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

from neutron import manager
from neutron.plugins.nec.common import config
from neutron.tests.unit.nec import test_nec_plugin
from neutron.tests.unit import test_extension_extraroute as test_ext_route


class NecRouterL3AgentTestCase(test_ext_route.ExtraRouteDBIntTestCase):

    _plugin_name = test_nec_plugin.PLUGIN_NAME

    def setUp(self):
        mock.patch(test_nec_plugin.OFC_MANAGER).start()
        super(NecRouterL3AgentTestCase, self).setUp(self._plugin_name)

        plugin = manager.NeutronManager.get_plugin()
        plugin.network_scheduler = None
        plugin.router_scheduler = None

    def test_floatingip_with_invalid_create_port(self):
        self._test_floatingip_with_invalid_create_port(self._plugin_name)


class NecRouterOpenFlowTestCase(NecRouterL3AgentTestCase):

    def setUp(self):
        config.CONF.set_override('default_router_provider',
                                 'openflow', 'PROVIDER')
        super(NecRouterOpenFlowTestCase, self).setUp()
