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

from neutron.tests.unit.linuxbridge import test_linuxbridge_plugin
from neutron.tests.unit.openvswitch import test_agent_scheduler


class LbAgentSchedulerTestCase(
    test_agent_scheduler.OvsAgentSchedulerTestCase):
    plugin_str = test_linuxbridge_plugin.PLUGIN_NAME
    l3_plugin = None


class LbL3AgentNotifierTestCase(
    test_agent_scheduler.OvsL3AgentNotifierTestCase):
    plugin_str = test_linuxbridge_plugin.PLUGIN_NAME
    l3_plugin = None


class LbDhcpAgentNotifierTestCase(
    test_agent_scheduler.OvsDhcpAgentNotifierTestCase):
    plugin_str = test_linuxbridge_plugin.PLUGIN_NAME
