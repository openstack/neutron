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

import neutron.tests.unit.db.grouppolicy.test_db_grouppolicy as tdb
import neutron.tests.unit.db.grouppolicy.test_db_grouppolicy_mapping as tdbm


GP_PLUGIN_KLASS = (
    "neutron.plugins.grouppolicy.plugin.GroupPolicyPlugin"
)


class GroupPolicyPluginTestCase(tdb.GroupPolicyDbTestCase):

    def setUp(self, core_plugin=None, gp_plugin=None, ext_mgr=None):
        super(GroupPolicyPluginTestCase, self).setUp(
            gp_plugin=GP_PLUGIN_KLASS
        )


class TestGroupPolicyPluginUnMappedResources(
    GroupPolicyPluginTestCase, tdb.TestGroupPolicyUnMappedResources):

    pass


class GroupPolicyPluginMappingTestCase(tdbm.GroupPolicyMappingDbTestCase):

    def setUp(self, core_plugin=None, gp_plugin=None, ext_mgr=None):
        super(GroupPolicyPluginMappingTestCase, self).setUp(
            gp_plugin=GP_PLUGIN_KLASS
        )


class TestGroupPolicyPluginMappedResources(
    GroupPolicyPluginMappingTestCase, tdbm.TestGroupPolicyMappedResources):

    pass


# TODO(Sumit): XML tests
