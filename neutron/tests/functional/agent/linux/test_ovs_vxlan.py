# Copyright 2014 Cisco Systems, Inc.
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

from neutron.agent.linux import ovs_lib
from neutron.plugins.common import constants as p_const
from neutron.tests.functional.agent.linux import base as base_agent


PORT_PREFIX = 'testp-'
INVALID_OFPORT_ID = '-1'


class TestOVSAgentVXLAN(base_agent.BaseOVSLinuxTestCase):

    def setUp(self):
        super(TestOVSAgentVXLAN, self).setUp()

        self._check_test_requirements()

    def _check_test_requirements(self):
        self.check_sudo_enabled()
        self.check_command(['which', 'ovs-vsctl'],
                           'Exit code: 1', 'ovs-vsctl is not installed')
        self.check_command(['sudo', '-n', 'ovs-vsctl', 'show'],
                           'Exit code: 1',
                           'password-less sudo not granted for ovs-vsctl')

    def test_ovs_lib_vxlan_version_check(self):
        """Verify VXLAN versions match

        This function compares the return values of functionally checking if
        VXLAN is supported with the ovs_lib programmatic check. It will fail
        if the two do not align.
        """
        expected = self.is_vxlan_supported()
        actual = self.is_ovs_lib_vxlan_supported()
        self.assertEqual(actual, expected)

    def is_ovs_lib_vxlan_supported(self):
        try:
            ovs_lib.check_ovs_vxlan_version(self.root_helper)
        except SystemError:
            return False
        else:
            return True

    def is_vxlan_supported(self):
        bridge = self.create_ovs_bridge()
        vxlan_port = self.create_resource(
            PORT_PREFIX,
            bridge.add_tunnel_port,
            "10.10.10.10",
            "10.10.10.20",
            p_const.TYPE_VXLAN)

        return vxlan_port != INVALID_OFPORT_ID
