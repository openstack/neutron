# Copyright (c) 2016 Hewlett Packard Enterprise Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_config import cfg
from oslo_utils import importutils

from neutron.api.v2 import attributes
from neutron import context
from neutron.db import bgp_db
from neutron.db import bgp_dragentscheduler_db as bgp_dras_db
from neutron.extensions import agent
from neutron.extensions import bgp
from neutron.extensions import bgp_dragentscheduler as bgp_dras_ext
from neutron import manager
from neutron.tests.unit.db import test_bgp_db
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_db_base_plugin
from neutron.tests.unit.extensions import test_agent

from webob import exc


class BgpDrSchedulerTestExtensionManager(object):

    def get_resources(self):
        attributes.RESOURCE_ATTRIBUTE_MAP.update(
            agent.RESOURCE_ATTRIBUTE_MAP)
        resources = agent.Agent.get_resources()
        resources.extend(bgp_dras_ext.Bgp_dragentscheduler.get_resources())
        return resources

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestBgpDrSchedulerPlugin(bgp_db.BgpDbMixin,
                               bgp_dras_db.BgpDrAgentSchedulerDbMixin):

    bgp_drscheduler = importutils.import_object(
        cfg.CONF.bgp_drscheduler_driver)

    supported_extension_aliases = ["bgp_dragent_scheduler"]

    def get_plugin_description(self):
        return ("BGP dynamic routing service Plugin test class that test "
                "BGP speaker functionality, with scheduler.")


class BgpDrSchedulingTestCase(test_agent.AgentDBTestMixIn,
                              test_bgp_db.BgpEntityCreationMixin):

    def test_schedule_bgp_speaker(self):
        """Test happy path over full scheduling cycle."""
        with self.bgp_speaker(4, 1234) as ri:
            bgp_speaker_id = ri['id']
            self._register_bgp_dragent(host='host1')
            agent = self._list('agents')['agents'][0]
            agent_id = agent['id']

            data = {'bgp_speaker_id': bgp_speaker_id}
            req = self.new_create_request('agents', data, self.fmt,
                                          agent_id, 'bgp-drinstances')
            res = req.get_response(self.ext_api)
            self.assertEqual(exc.HTTPCreated.code, res.status_int)

            req_show = self.new_show_request('agents', agent_id, self.fmt,
                                             'bgp-drinstances')
            res = req_show.get_response(self.ext_api)
            self.assertEqual(exc.HTTPOk.code, res.status_int)
            res = self.deserialize(self.fmt, res)
            self.assertIn('bgp_speakers', res)
            self.assertTrue(bgp_speaker_id,
                            res['bgp_speakers'][0]['id'])

            req = self.new_delete_request('agents',
                                          agent_id,
                                          self.fmt,
                                          'bgp-drinstances',
                                          bgp_speaker_id)
            res = req.get_response(self.ext_api)
            self.assertEqual(exc.HTTPNoContent.code, res.status_int)

            res = req_show.get_response(self.ext_api)
            self.assertEqual(exc.HTTPOk.code, res.status_int)
            res = self.deserialize(self.fmt, res)
            self.assertIn('bgp_speakers', res)
            self.assertEqual([], res['bgp_speakers'])

    def test_schedule_bgp_speaker_on_invalid_agent(self):
        """Test error while scheduling BGP speaker on an invalid agent."""
        with self.bgp_speaker(4, 1234) as ri:
            bgp_speaker_id = ri['id']
            self._register_l3_agent(host='host1')  # Register wrong agent
            agent = self._list('agents')['agents'][0]
            data = {'bgp_speaker_id': bgp_speaker_id}
            req = self.new_create_request(
                'agents', data, self.fmt,
                agent['id'], 'bgp-drinstances')
            res = req.get_response(self.ext_api)

            # Raises an AgentNotFound exception if the agent is invalid
            self.assertEqual(exc.HTTPNotFound.code, res.status_int)

    def test_schedule_bgp_speaker_twice_on_same_agent(self):
        """Test error if a BGP speaker is scheduled twice on same agent"""
        with self.bgp_speaker(4, 1234) as ri:
            bgp_speaker_id = ri['id']
            self._register_bgp_dragent(host='host1')
            agent = self._list('agents')['agents'][0]
            data = {'bgp_speaker_id': bgp_speaker_id}
            req = self.new_create_request(
                'agents', data, self.fmt,
                agent['id'], 'bgp-drinstances')
            res = req.get_response(self.ext_api)
            self.assertEqual(exc.HTTPCreated.code, res.status_int)

            # Try second time, should raise conflict
            res = req.get_response(self.ext_api)
            self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_schedule_bgp_speaker_on_two_different_agents(self):
        """Test that a BGP speaker can be associated to two agents."""
        with self.bgp_speaker(4, 1234) as ri:
            bgp_speaker_id = ri['id']
            self._register_bgp_dragent(host='host1')
            self._register_bgp_dragent(host='host2')
            data = {'bgp_speaker_id': bgp_speaker_id}

            agent1 = self._list('agents')['agents'][0]
            req = self.new_create_request(
                'agents', data, self.fmt,
                agent1['id'], 'bgp-drinstances')
            res = req.get_response(self.ext_api)
            self.assertEqual(exc.HTTPCreated.code, res.status_int)

            agent2 = self._list('agents')['agents'][1]
            req = self.new_create_request(
                'agents', data, self.fmt,
                agent2['id'], 'bgp-drinstances')
            res = req.get_response(self.ext_api)
            self.assertEqual(exc.HTTPCreated.code, res.status_int)

    def test_schedule_multi_bgp_speaker_on_one_dragent(self):
        """Test only one BGP speaker can be associated to one dragent."""
        with self.bgp_speaker(4, 1) as ri1, self.bgp_speaker(4, 2) as ri2:
            self._register_bgp_dragent(host='host1')

            agent = self._list('agents')['agents'][0]
            data = {'bgp_speaker_id': ri1['id']}
            req = self.new_create_request(
                'agents', data, self.fmt,
                agent['id'], 'bgp-drinstances')
            res = req.get_response(self.ext_api)
            self.assertEqual(exc.HTTPCreated.code, res.status_int)

            data = {'bgp_speaker_id': ri2['id']}
            req = self.new_create_request(
                'agents', data, self.fmt,
                agent['id'], 'bgp-drinstances')
            res = req.get_response(self.ext_api)
            self.assertEqual(exc.HTTPConflict.code, res.status_int)

    def test_non_scheduled_bgp_speaker_binding_removal(self):
        """Test exception while removing an invalid binding."""
        with self.bgp_speaker(4, 1234) as ri1:
            self._register_bgp_dragent(host='host1')
            agent = self._list('agents')['agents'][0]
            agent_id = agent['id']
            self.assertRaises(bgp_dras_ext.DrAgentNotHostingBgpSpeaker,
                              self.bgp_plugin.remove_bgp_speaker_from_dragent,
                              self.context, agent_id, ri1['id'])


class BgpDrPluginSchedulerTests(test_db_base_plugin.NeutronDbPluginV2TestCase,
                                BgpDrSchedulingTestCase):

    def setUp(self, plugin=None, ext_mgr=None, service_plugins=None):
        if not plugin:
            plugin = ('neutron.tests.unit.db.'
                      'test_bgp_dragentscheduler_db.TestBgpDrSchedulerPlugin')
        if not service_plugins:
            service_plugins = {bgp.BGP_EXT_ALIAS:
                               'neutron.services.bgp.bgp_plugin.BgpPlugin'}

        ext_mgr = ext_mgr or BgpDrSchedulerTestExtensionManager()
        super(BgpDrPluginSchedulerTests, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr, service_plugins=service_plugins)
        self.bgp_plugin = manager.NeutronManager.get_service_plugins().get(
            bgp.BGP_EXT_ALIAS)
        self.context = context.get_admin_context()
