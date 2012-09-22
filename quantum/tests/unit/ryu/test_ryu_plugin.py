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

import mock

from quantum.tests.unit import test_db_plugin as test_plugin


class RyuPluginV2TestCase(test_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = 'quantum.plugins.ryu.ryu_quantum_plugin.RyuQuantumPluginV2'

    def _patch_fake_ryu_client(self):
        ryu_mod = mock.Mock()
        ryu_app_mod = ryu_mod.app
        ryu_app_client = ryu_app_mod.client
        rest_nw_id = ryu_app_mod.rest_nw_id
        rest_nw_id.NW_ID_EXTERNAL = '__NW_ID_EXTERNAL__'
        rest_nw_id.NW_ID_UNKNOWN = '__NW_ID_UNKNOWN__'
        return mock.patch.dict('sys.modules',
                               {'ryu': ryu_mod,
                                'ryu.app': ryu_app_mod,
                                'ryu.app.client': ryu_app_client,
                                'ryu.app.rest_nw_id': rest_nw_id})

    def setUp(self):
        self.ryu_patcher = self._patch_fake_ryu_client()
        self.ryu_patcher.start()
        super(RyuPluginV2TestCase, self).setUp(self._plugin_name)


class TestRyuBasicGet(test_plugin.TestBasicGet, RyuPluginV2TestCase):
    pass


class TestRyuV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                            RyuPluginV2TestCase):
    pass


class TestRyuPortsV2(test_plugin.TestPortsV2, RyuPluginV2TestCase):
    pass


class TestRyuNetworksV2(test_plugin.TestNetworksV2, RyuPluginV2TestCase):
    pass
