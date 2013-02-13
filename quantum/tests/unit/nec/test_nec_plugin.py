# Copyright (c) 2012 OpenStack, LLC.
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

from quantum.extensions import portbindings
from quantum.tests.unit import _test_extension_portbindings as test_bindings
from quantum.tests.unit import test_db_plugin as test_plugin
from quantum.tests.unit import test_security_groups_rpc as test_sg_rpc


PLUGIN_NAME = 'quantum.plugins.nec.nec_plugin.NECPluginV2'


class NecPluginV2TestCase(test_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = PLUGIN_NAME

    def setUp(self):
        super(NecPluginV2TestCase, self).setUp(self._plugin_name)


class TestNecBasicGet(test_plugin.TestBasicGet, NecPluginV2TestCase):
    pass


class TestNecV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                            NecPluginV2TestCase):
    pass


class TestNecPortsV2(test_plugin.TestPortsV2, NecPluginV2TestCase):

    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = True


class TestNecNetworksV2(test_plugin.TestNetworksV2, NecPluginV2TestCase):
    pass


class TestNecPortBinding(test_bindings.PortBindingsTestCase,
                         NecPluginV2TestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS
    HAS_PORT_FILTER = True
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_HYBRID_DRIVER

    def setUp(self):
        test_sg_rpc.set_firewall_driver(self.FIREWALL_DRIVER)
        super(TestNecPortBinding, self).setUp()


class TestNecPortBindingNoSG(TestNecPortBinding):
    HAS_PORT_FILTER = False
    FIREWALL_DRIVER = test_sg_rpc.FIREWALL_NOOP_DRIVER
