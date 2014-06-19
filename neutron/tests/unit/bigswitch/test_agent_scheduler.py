# Copyright 2013 Big Switch Networks, Inc.
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


from neutron.tests.unit.bigswitch import test_base
from neutron.tests.unit.openvswitch import test_agent_scheduler


class BigSwitchDhcpAgentNotifierTestCase(
    test_agent_scheduler.OvsDhcpAgentNotifierTestCase,
    test_base.BigSwitchTestBase):

    plugin_str = ('%s.NeutronRestProxyV2' %
                  test_base.RESTPROXY_PKG_PATH)

    def setUp(self):
        self.setup_config_files()
        self.setup_patches()
        super(BigSwitchDhcpAgentNotifierTestCase, self).setUp()
        self.startHttpPatch()
