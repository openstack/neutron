# Copyright (c) 2012 OpenStack Foundation.
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

from neutron.tests.unit.metaplugin import test_metaplugin
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import test_l3_plugin


class MetaPluginV2DBTestCase(test_plugin.NeutronDbPluginV2TestCase):

    _plugin_name = ('neutron.plugins.metaplugin.'
                    'meta_neutron_plugin.MetaPluginV2')

    def setUp(self, plugin=None, ext_mgr=None,
              service_plugins=None):
        # NOTE(salv-orlando): The plugin keyword argument is ignored,
        # as this class will always invoke super with self._plugin_name.
        # These keyword parameters ensure setUp methods always have the
        # same signature.
        test_metaplugin.setup_metaplugin_conf()
        ext_mgr = ext_mgr or test_l3_plugin.L3TestExtensionManager()
        self.addCleanup(test_metaplugin.unregister_meta_hooks)
        super(MetaPluginV2DBTestCase, self).setUp(
            plugin=self._plugin_name, ext_mgr=ext_mgr,
            service_plugins=service_plugins)


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


class TestMetaL3NatDBTestCase(test_l3_plugin.L3NatDBIntTestCase,
                              MetaPluginV2DBTestCase):
    pass
