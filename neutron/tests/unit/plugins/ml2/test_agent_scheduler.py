# Copyright (c) 2013 OpenStack Foundation
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

from neutron.tests.unit.db import test_agentschedulers_db
from neutron.tests.unit.plugins.ml2 import test_plugin


class Ml2AgentSchedulerTestCase(
        test_agentschedulers_db.OvsAgentSchedulerTestCase):
    plugin_str = test_plugin.PLUGIN_NAME
    l3_plugin = ('neutron.services.l3_router.'
                 'l3_router_plugin.L3RouterPlugin')


class Ml2L3AgentNotifierTestCase(
        test_agentschedulers_db.OvsL3AgentNotifierTestCase):
    plugin_str = test_plugin.PLUGIN_NAME
    l3_plugin = ('neutron.services.l3_router.'
                 'l3_router_plugin.L3RouterPlugin')


class Ml2DhcpAgentNotifierTestCase(
        test_agentschedulers_db.OvsDhcpAgentNotifierTestCase):
    plugin_str = test_plugin.PLUGIN_NAME
