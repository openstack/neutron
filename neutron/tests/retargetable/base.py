# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License. You may
# obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

"""
This module defines a base test case that uses testscenarios to
parametize the test methods of subclasses by varying the client
fixture used to target the Neutron API.

PluginClientFixture targets the Neutron API directly via the plugin
api, and will be executed by default.  testscenarios will ensure that
each test is run against all plugins defined in plugin_configurations.

RestClientFixture targets a deployed Neutron daemon, and will be used
instead of PluginClientFixture only if OS_TEST_API_WITH_REST is set to 1.

Reference: https://pypi.python.org/pypi/testscenarios/
"""

import testscenarios

from neutron.tests import base as tests_base
from neutron.tests.retargetable import client_fixtures
from neutron.tests.unit.plugins.ml2 import test_plugin


# Each plugin must add a class to plugin_configurations that can configure the
# plugin for use with PluginClient.  For a given plugin, the setup
# used for NeutronDbPluginV2TestCase can usually be reused.  See the
# configuration classes listed below for examples of this reuse.

# TODO(marun) Discover plugin conf via a metaclass
plugin_configurations = [
    test_plugin.Ml2ConfFixture(),
]


def rest_enabled():
    return tests_base.bool_from_env('OS_TEST_API_WITH_REST')


def get_plugin_scenarios():
    scenarios = []
    for conf in plugin_configurations:
        name = conf.plugin_name
        class_name = name.rsplit('.', 1)[-1]
        client = client_fixtures.PluginClientFixture(conf)
        scenarios.append((class_name, {'client': client}))
    return scenarios


def get_scenarios():
    if rest_enabled():
        # FIXME(marun) Remove local import once tempest config is safe
        # to import alonside neutron config
        from neutron.tests.retargetable import rest_fixture
        return [('tempest', {'client': rest_fixture.RestClientFixture()})]
    else:
        return get_plugin_scenarios()


class RetargetableApiTest(testscenarios.WithScenarios,
                          tests_base.BaseTestCase):

    scenarios = get_scenarios()

    def setUp(self):
        super(RetargetableApiTest, self).setUp()
        if rest_enabled():
            raise self.skipException(
                'Tempest fixture requirements prevent this test from running')
        else:
            raise self.skipException(
                "Fullstack's db fixture usage prevents this test from running")
        self.useFixture(self.client)
