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

from neutron.plugins.ml2.drivers.cisco.ncs import driver
from neutron.tests.unit.plugins.ml2 import test_plugin


class NCSTestCase(test_plugin.Ml2PluginV2TestCase):
    _mechanism_drivers = ['logger', 'ncs']

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        super(NCSTestCase, self).setUp()
        self.port_create_status = 'DOWN'
        driver.NCSMechanismDriver.sendjson = self.check_sendjson

    def check_sendjson(self, method, urlpath, obj):
        # Confirm fix for bug #1224981
        self.assertFalse(urlpath.startswith("http://"))


class NCSMechanismTestBasicGet(test_plugin.TestMl2BasicGet, NCSTestCase):
    pass


class NCSMechanismTestNetworksV2(test_plugin.TestMl2NetworksV2, NCSTestCase):
    pass


class NCSMechanismTestPortsV2(test_plugin.TestMl2PortsV2, NCSTestCase):
    pass
