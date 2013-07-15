# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 NEC Corporation.  All rights reserved.
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

import mox

from neutron.plugins.nec.common import ofc_client
from neutron.tests.unit.nec import test_nec_plugin
from neutron.tests.unit.openvswitch import test_agent_scheduler


class NecAgentSchedulerTestCase(
    test_agent_scheduler.OvsAgentSchedulerTestCase):
    plugin_str = test_nec_plugin.PLUGIN_NAME

    def setUp(self):
        super(NecAgentSchedulerTestCase, self).setUp()
        self.mox = mox.Mox()
        self.mox.StubOutWithMock(ofc_client.OFCClient, 'do_request')
        self.addCleanup(self.mox.UnsetStubs)


class NecDhcpAgentNotifierTestCase(
    test_agent_scheduler.OvsDhcpAgentNotifierTestCase):
    plugin_str = test_nec_plugin.PLUGIN_NAME

    def setUp(self):
        super(NecDhcpAgentNotifierTestCase, self).setUp()
        self.mox = mox.Mox()
        self.mox.StubOutWithMock(ofc_client.OFCClient, 'do_request')
        self.addCleanup(self.mox.UnsetStubs)


class NecL3AgentNotifierTestCase(
    test_agent_scheduler.OvsL3AgentNotifierTestCase):
    plugin_str = test_nec_plugin.PLUGIN_NAME

    def setUp(self):
        super(NecL3AgentNotifierTestCase, self).setUp()
        self.mox = mox.Mox()
        self.mox.StubOutWithMock(ofc_client.OFCClient, 'do_request')
        self.addCleanup(self.mox.UnsetStubs)
