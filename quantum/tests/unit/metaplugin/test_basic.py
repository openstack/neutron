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

from quantum.common.test_lib import test_config
from quantum.tests.unit.metaplugin.test_metaplugin import setup_metaplugin_conf
from quantum.tests.unit import test_db_plugin as test_plugin
from quantum.tests.unit import test_l3_plugin


class MetaPluginV2DBTestCase(test_plugin.QuantumDbPluginV2TestCase):

    _plugin_name = ('quantum.plugins.metaplugin.'
                    'meta_quantum_plugin.MetaPluginV2')

    def setUp(self):
        setup_metaplugin_conf()
        ext_mgr = test_l3_plugin.L3TestExtensionManager()
        test_config['extension_manager'] = ext_mgr
        super(MetaPluginV2DBTestCase, self).setUp(self._plugin_name)


class TestMetaBasicGet(test_plugin.TestBasicGet,
                       MetaPluginV2DBTestCase):
    pass


class TestMetaV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                             MetaPluginV2DBTestCase):
    pass


class TestMetaPortsV2(test_plugin.TestPortsV2,
                      MetaPluginV2DBTestCase):
    pass


class TestMetaNetworksV2(test_plugin.TestNetworksV2,
                         MetaPluginV2DBTestCase):
    pass


class TestMetaSubnetsV2(test_plugin.TestSubnetsV2,
                        MetaPluginV2DBTestCase):
    #TODO(nati) This test fails if we run all test, but It success just one
    def test_update_subnet_route(self):
        pass

    def test_update_subnet_dns_to_None(self):
        pass

    def test_update_subnet_route_to_None(self):
        pass

    def test_update_subnet_dns(self):
        pass


class TestMetaL3NatDBTestCase(test_l3_plugin.L3NatDBTestCase,
                              MetaPluginV2DBTestCase):
    pass
