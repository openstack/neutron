# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
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

import mox
import os

from quantum.plugins.ryu.tests.unit import fake_plugin
from quantum.plugins.ryu.tests.unit import utils
from quantum.plugins.ryu.tests.unit.basetest import BaseRyuTest


class PluginBaseTest(BaseRyuTest):
    """Class conisting of OVSQuantumPluginBase unit tests"""
    def setUp(self):
        super(PluginBaseTest, self).setUp()
        self.ini_file = utils.create_fake_ryu_ini()

    def tearDown(self):
        os.unlink(self.ini_file)
        super(PluginBaseTest, self).tearDown()

    def test_create_delete_network(self):
        # mox.StubOutClassWithMocks can't be used for class with metaclass
        # overrided
        driver_mock = self.mox.CreateMock(fake_plugin.FakePluginDriver)
        self.mox.StubOutWithMock(fake_plugin, 'FakePluginDriver',
                                 use_mock_anything=True)

        fake_plugin.FakePluginDriver(mox.IgnoreArg()).AndReturn(driver_mock)
        driver_mock.create_network(mox.IgnoreArg())
        driver_mock.delete_network(mox.IgnoreArg())
        self.mox.ReplayAll()
        plugin = fake_plugin.FakePlugin(configfile=self.ini_file)

        tenant_id = 'tenant_id'
        net_name = 'net_name'
        ret = plugin.create_network(tenant_id, net_name)

        plugin.delete_network(tenant_id, ret['net-id'])
        self.mox.VerifyAll()
