# Copyright 2017 OVH SAS
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

from unittest import mock

from neutron.plugins.ml2.drivers.linuxbridge.agent import \
    linuxbridge_agent_extension_api as ext_api
from neutron.tests import base


class TestLinuxbridgeAgentExtensionAPI(base.BaseTestCase):

    def setUp(self):
        super(TestLinuxbridgeAgentExtensionAPI, self).setUp()
        self.iptables_manager = mock.Mock()
        self.extension_api = ext_api.LinuxbridgeAgentExtensionAPI(
            self.iptables_manager)

    def test_get_iptables_manager(self):
        self.assertEqual(self.iptables_manager,
                         self.extension_api.get_iptables_manager())
