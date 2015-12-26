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

import mock
from oslo_config import cfg
import testtools

from neutron.plugins.ml2.drivers.linuxbridge.agent import \
    linuxbridge_neutron_agent
from neutron.tests.functional.agent.linux import test_ip_lib

lba = linuxbridge_neutron_agent


class LinuxBridgeAgentTests(test_ip_lib.IpLibTestFramework):

    def setUp(self):
        super(LinuxBridgeAgentTests, self).setUp()
        agent_rpc = ('neutron.agent.rpc.PluginApi')
        mock.patch(agent_rpc).start()
        mock.patch('neutron.agent.rpc.PluginReportStateAPI').start()
        cfg.CONF.set_override('enable_vxlan', False, 'VXLAN')

    def test_validate_interface_mappings(self):
        mappings = {'physnet1': 'int1', 'physnet2': 'int2'}
        with testtools.ExpectedException(SystemExit):
            lba.LinuxBridgeManager({}, mappings)
        self.manage_device(
            self.generate_device_details()._replace(namespace=None,
                                                    name='int1'))
        with testtools.ExpectedException(SystemExit):
            lba.LinuxBridgeManager({}, mappings)
        self.manage_device(
            self.generate_device_details()._replace(namespace=None,
                                                    name='int2'))
        lba.LinuxBridgeManager({}, mappings)

    def test_validate_bridge_mappings(self):
        mappings = {'physnet1': 'br-eth1'}
        with testtools.ExpectedException(SystemExit):
            lba.LinuxBridgeManager(mappings, {})
        self.manage_device(
            self.generate_device_details()._replace(namespace=None,
                                                    name='br-eth1'))
        lba.LinuxBridgeManager(mappings, {})
