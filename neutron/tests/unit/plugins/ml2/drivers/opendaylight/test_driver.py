# Copyright (c) 2013-2015 OpenStack Foundation
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

import sys

import mock
from neutron import context
from neutron.tests.unit.plugins.ml2 import test_plugin


with mock.patch.dict(sys.modules,
                     {'networking_odl': mock.Mock(),
                      'networking_odl.common': mock.Mock(),
                      'networking_odl.ml2': mock.Mock()}):
    from networking_odl.common import constants as const
    from neutron.plugins.ml2.drivers.opendaylight import driver


class TestODLShim(test_plugin.Ml2PluginV2TestCase):

    def setUp(self):
        super(TestODLShim, self).setUp()
        self.context = context.get_admin_context()
        self.plugin = mock.Mock()
        self.driver = driver.OpenDaylightMechanismDriver()
        self.driver.odl_drv = mock.Mock()

    def test_create_network_postcommit(self):
        self.driver.create_network_postcommit(self.context)
        self.driver.odl_drv.synchronize.assert_called_with('create',
                                                           const.ODL_NETWORKS,
                                                           self.context)

    def test_update_network_postcommit(self):
        self.driver.update_network_postcommit(self.context)
        self.driver.odl_drv.synchronize.assert_called_with('update',
                                                           const.ODL_NETWORKS,
                                                           self.context)

    def test_delete_network_postcommit(self):
        self.driver.delete_network_postcommit(self.context)
        self.driver.odl_drv.synchronize.assert_called_with('delete',
                                                           const.ODL_NETWORKS,
                                                           self.context)

    def test_create_subnet_postcommit(self):
        self.driver.create_subnet_postcommit(self.context)
        self.driver.odl_drv.synchronize.assert_called_with('create',
                                                           const.ODL_SUBNETS,
                                                           self.context)

    def test_update_subnet_postcommit(self):
        self.driver.update_subnet_postcommit(self.context)
        self.driver.odl_drv.synchronize.assert_called_with('update',
                                                           const.ODL_SUBNETS,
                                                           self.context)

    def test_delete_subnet_postcommit(self):
        self.driver.delete_subnet_postcommit(self.context)
        self.driver.odl_drv.synchronize.assert_called_with('delete',
                                                           const.ODL_SUBNETS,
                                                           self.context)

    def test_create_port_postcommit(self):
        self.driver.create_port_postcommit(self.context)
        self.driver.odl_drv.synchronize.assert_called_with('create',
                                                           const.ODL_PORTS,
                                                           self.context)

    def test_update_port_postcommit(self):
        self.driver.update_port_postcommit(self.context)
        self.driver.odl_drv.synchronize.assert_called_with('update',
                                                           const.ODL_PORTS,
                                                           self.context)

    def test_delete_port_postcommit(self):
        self.driver.delete_port_postcommit(self.context)
        self.driver.odl_drv.synchronize.assert_called_with('delete',
                                                           const.ODL_PORTS,
                                                           self.context)
