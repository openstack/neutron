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

from neutron.plugins.ml2 import config as config
from neutron.plugins.ml2.drivers import mechanism_ncs
from neutron.tests.unit import test_db_plugin as test_plugin

PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'


class NCSTestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'ncs'],
                                     'ml2')
        super(NCSTestCase, self).setUp(PLUGIN_NAME)
        self.port_create_status = 'DOWN'
        mechanism_ncs.NCSMechanismDriver.sendjson = self.check_sendjson

    def check_sendjson(self, method, urlpath, obj):
        # Confirm fix for bug #1224981
        self.assertFalse(urlpath.startswith("http://"))


class NCSMechanismTestBasicGet(test_plugin.TestBasicGet, NCSTestCase):
    pass


class NCSMechanismTestNetworksV2(test_plugin.TestNetworksV2, NCSTestCase):
    pass


class NCSMechanismTestPortsV2(test_plugin.TestPortsV2, NCSTestCase):
    pass
