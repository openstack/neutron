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

from quantum.tests.unit import test_db_plugin as test_plugin


class OpenvswitchPluginV2TestCase(test_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = ('quantum.plugins.openvswitch.'
                    'ovs_quantum_plugin.OVSQuantumPluginV2')

    def setUp(self):
        super(OpenvswitchPluginV2TestCase, self).setUp(self._plugin_name)


class TestOpenvswitchBasicGet(test_plugin.TestBasicGet,
                              OpenvswitchPluginV2TestCase):
    pass


class TestOpenvswitchV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                                    OpenvswitchPluginV2TestCase):
    pass


class TestOpenvswitchPortsV2(test_plugin.TestPortsV2,
                             OpenvswitchPluginV2TestCase):
    pass


class TestOpenvswitchNetworksV2(test_plugin.TestNetworksV2,
                                OpenvswitchPluginV2TestCase):
    pass
