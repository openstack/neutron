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

    # TODO(rkukura): Re-enable
    def _test_implicit_workflow(self, **kwargs):
        epg_name = "epg1"
        epg_attrs = self._get_test_endpoint_group_attrs(epg_name)
        with self.endpoint_group(name=epg_name) as epg:
            for k, v in epg_attrs.iteritems():
                self.assertEqual(epg['endpoint_group'][k], v)
            # TODO(rkukura): Verify RD and BD created with router and
            # network
            epg_id = epg['endpoint_group']['id']

            ep_name = "ep1"
            ep_attrs = self._get_test_endpoint_attrs(ep_name)
            with self.endpoint(name=ep_name,
                               endpoint_group_id=epg_id) as ep:
                for k, v in ep_attrs.iteritems():
                    self.assertEqual(ep['endpoint'][k], v)
                self.assertEqual(ep['endpoint']['endpoint_group_id'], epg_id)
                # TODO(rkukura): Verify port created

    def test_explicit_workflow(self, **kwargs):
        # REVISIT(rkukura): Mock core plugin?

        with self.routing_domain(name="rd1") as rd:
            # TODO(rkukura): Verify router created (not yet)
            rd_id = rd['routing_domain']['id']

            with self.bridge_domain(name="bd1",
                                    routing_domain_id=rd_id) as bd:
                self.assertEqual(bd['bridge_domain']['routing_domain_id'],
                                 rd_id)
                net_id = bd['bridge_domain']['neutron_network_id']
                self.assertIsNotNone(net_id)
                # TODO(rkukura): Verify network details
                bd_id = bd['bridge_domain']['id']

                with self.endpoint_group(name="epg1",
                                         bridge_domain_id=bd_id) as epg:
                    self.assertEqual(epg['endpoint_group']['bridge_domain_id'],
                                     bd_id)
                    subnets = epg['endpoint_group']['neutron_subnets']
                    self.assertIsNotNone(subnets)
                    self.assertEqual(len(subnets), 1)
                    # TODO(rkukura): Verify subnet details
                    epg_id = epg['endpoint_group']['id']

                    with self.endpoint(name="ep1",
                                       endpoint_group_id=epg_id) as ep:
                        self.assertEqual(ep['endpoint']['endpoint_group_id'],
                                         epg_id)
                        # TODO(rkukura): Verify port created


# TODO(Sumit): XML tests
