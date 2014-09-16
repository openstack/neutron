# Copyright (C) 2012 Midokura Japan K.K.
# Copyright (C) 2013 Midokura PTE LTD
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

from neutron.agent.common import config
from neutron.agent.linux import dhcp
from neutron.common import config as base_config
import neutron.plugins.midonet.agent.midonet_driver as driver
from neutron.tests import base


class FakeNetwork:
    id = 'aaaabbbb-cccc-dddd-eeee-ffff00001111'
    namespace = 'qdhcp-ns'


class TestDhcpNoOpDriver(base.BaseTestCase):
    def setUp(self):
        super(TestDhcpNoOpDriver, self).setUp()
        self.conf = config.setup_conf()
        config.register_interface_driver_opts_helper(self.conf)
        self.conf.register_opts(base_config.core_opts)
        self.conf.register_opts(dhcp.OPTS)
        self.conf.enable_isolated_metadata = True
        self.conf.use_namespaces = True
        instance = mock.patch("neutron.agent.linux.dhcp.DeviceManager")
        self.mock_mgr = instance.start()

    def test_disable_no_retain_port(self):
        dhcp_driver = driver.DhcpNoOpDriver(self.conf, FakeNetwork())
        dhcp_driver.disable(retain_port=False)
        self.assertTrue(self.mock_mgr.return_value.destroy.called)

    def test_disable_retain_port(self):
        dhcp_driver = driver.DhcpNoOpDriver(self.conf, FakeNetwork())
        dhcp_driver.disable(retain_port=True)
        self.assertFalse(self.mock_mgr.return_value.destroy.called)
