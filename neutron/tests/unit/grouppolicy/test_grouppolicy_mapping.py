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

from neutron.plugins.grouppolicy import config
import neutron.tests.unit.db.grouppolicy.test_db_grouppolicy_mapping as tdb


GP_PLUGIN_KLASS = (
    "neutron.plugins.grouppolicy.plugin.GroupPolicyPlugin"
)


class GroupPolicyMappingTestCase(tdb.GroupPolicyMappingDbTestCase):

    def setUp(self, core_plugin=None, gp_plugin=None, ext_mgr=None):
        config.cfg.CONF.set_override('policy_drivers',
                                     ['mapping'],
                                     group='group_policy')
        super(GroupPolicyMappingTestCase, self).setUp(
            gp_plugin=GP_PLUGIN_KLASS
        )


class TestGroupPolicyMapping(GroupPolicyMappingTestCase):

    def test_implicit_workflow(self, **kwargs):
        epg_name = "epg1"
        epg_attrs = self._get_test_endpoint_group_attrs(epg_name)
        with self.endpoint_group(name=epg_name) as epg:
            for k, v in epg_attrs.iteritems():
                self.assertEqual(epg['endpoint_group'][k], v)

            epg_id = epg['endpoint_group']['id']

            ep_name = "ep1"
            ep_attrs = self._get_test_endpoint_attrs(ep_name)
            with self.endpoint(name=ep_name,
                               endpoint_group_id=epg_id) as ep:
                for k, v in ep_attrs.iteritems():
                    self.assertEqual(ep['endpoint'][k], v)


# TODO(Sumit): XML tests
