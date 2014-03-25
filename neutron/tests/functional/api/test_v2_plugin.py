# Copyright 2014, Red Hat Inc.
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

"""
This module implements BaseNeutronClient for the programmatic plugin
api and configures the api tests with scenarios targeting individual
plugins.
"""

import testscenarios

from neutron.common import exceptions as q_exc
from neutron import context
from neutron import manager
from neutron.tests.api import base_v2
from neutron.tests.unit.ml2 import test_ml2_plugin
from neutron.tests.unit import testlib_api
from neutron.tests.unit import testlib_plugin


# Each plugin must add a class to plugin_configurations that can configure the
# plugin for use with PluginClient.  For a given plugin, the setup
# used for NeutronDbPluginV2TestCase can usually be reused.  See the
# configuration classes listed below for examples of this reuse.

#TODO(marun) Discover plugin conf via a metaclass
plugin_configurations = [
    test_ml2_plugin.Ml2PluginConf,
]


# Required to generate tests from scenarios.  Not compatible with nose.
load_tests = testscenarios.load_tests_apply_scenarios


class PluginClient(base_v2.BaseNeutronClient):

    @property
    def ctx(self):
        if not hasattr(self, '_ctx'):
            self._ctx = context.Context('', 'test-tenant')
        return self._ctx

    @property
    def plugin(self):
        return manager.NeutronManager.get_plugin()

    @property
    def NotFound(self):
        return q_exc.NetworkNotFound

    def create_network(self, **kwargs):
        # Supply defaults that are expected to be set by the api
        # framwork
        kwargs.setdefault('admin_state_up', True)
        kwargs.setdefault('shared', False)
        data = dict(network=kwargs)
        result = self.plugin.create_network(self.ctx, data)
        return base_v2.AttributeDict(result)

    def update_network(self, id_, **kwargs):
        data = dict(network=kwargs)
        result = self.plugin.update_network(self.ctx, id_, data)
        return base_v2.AttributeDict(result)

    def get_network(self, *args, **kwargs):
        result = self.plugin.get_network(self.ctx, *args, **kwargs)
        return base_v2.AttributeDict(result)

    def get_networks(self, *args, **kwargs):
        result = self.plugin.get_networks(self.ctx, *args, **kwargs)
        return [base_v2.AttributeDict(x) for x in result]

    def delete_network(self, id_):
        self.plugin.delete_network(self.ctx, id_)


def get_scenarios():
    scenarios = []
    client = PluginClient()
    for conf in plugin_configurations:
        name = conf.plugin_name
        class_name = name[name.rfind('.') + 1:]
        scenarios.append((class_name, {'client': client, 'plugin_conf': conf}))
    return scenarios


class TestPluginApi(base_v2.BaseTestApi,
                    testlib_api.SqlTestCase,
                    testlib_plugin.PluginSetupHelper):

    scenarios = get_scenarios()

    def setUp(self):
        # BaseTestApi is not based on BaseTestCase to avoid import
        # errors when importing Tempest.  When targeting the plugin
        # api, it is necessary to avoid calling BaseTestApi's parent
        # setUp, since that setup will be called by SqlTestCase.setUp.
        super(TestPluginApi, self).setUp(setup_parent=False)
        testlib_api.SqlTestCase.setUp(self)
        self.setup_coreplugin(self.plugin_conf.plugin_name)
        self.plugin_conf.setUp(self)
