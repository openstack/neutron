# Copyright 2014 Alcatel-Lucent USA Inc.
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

from neutron.plugins.ml2 import config as ml2_config
from neutron.tests.unit.ml2 import test_ml2_plugin
import neutron.tests.unit.nuage.test_nuage_plugin as tnp
from neutron.tests.unit import test_db_plugin


class TestNuageMechDriverBase(tnp.NuagePluginV2TestCase):
    def setUp(self):
        ml2_config.cfg.CONF.set_override('mechanism_drivers',
                                         ['nuage'],
                                         'ml2')

        super(TestNuageMechDriverBase,
              self).setUp(plugin=test_ml2_plugin.PLUGIN_NAME)


class TestNuageMechDriverNetworksV2(test_db_plugin.TestNetworksV2,
                                    TestNuageMechDriverBase):
    pass


class TestNuageMechDriverSubnetsV2(test_db_plugin.TestSubnetsV2,
                                   TestNuageMechDriverBase):
    pass


class TestNuageMechDriverPortsV2(test_db_plugin.TestPortsV2,
                                TestNuageMechDriverBase):

    def setUp(self):
        super(TestNuageMechDriverPortsV2, self).setUp()
        self.port_create_status = 'DOWN'
