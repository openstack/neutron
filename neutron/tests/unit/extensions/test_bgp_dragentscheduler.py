# Copyright 2016 Huawei Technologies India Pvt. Ltd.
# All Rights Reserved.
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

import testscenarios

from oslo_utils import importutils

from neutron import context
from neutron.db import bgp_db
from neutron.db import bgp_dragentscheduler_db as bgp_dras_db
from neutron.services.bgp.scheduler import bgp_dragent_scheduler as bgp_dras
from neutron.tests.common import helpers
from neutron.tests.unit import testlib_api

# Required to generate tests from scenarios. Not compatible with nose.
load_tests = testscenarios.load_tests_apply_scenarios


class TestBgpDrAgentSchedulerBaseTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestBgpDrAgentSchedulerBaseTestCase, self).setUp()
        self.ctx = context.get_admin_context()
        self.bgp_speaker = {'id': 'foo_bgp_speaker_id'}
        self.bgp_speaker_id = 'foo_bgp_speaker_id'
        self._save_bgp_speaker(self.bgp_speaker_id)

    def _create_and_set_agents_down(self, hosts, down_agent_count=0,
                                    admin_state_up=True):
        agents = []
        for i, host in enumerate(hosts):
            is_alive = i >= down_agent_count
            agents.append(helpers.register_bgp_dragent(
                host,
                admin_state_up=admin_state_up,
                alive=is_alive))
        return agents

    def _save_bgp_speaker(self, bgp_speaker_id):
        cls = bgp_db.BgpDbMixin()
        bgp_speaker_body = {'bgp_speaker': {'ip_version': '4',
                                'name': 'test-speaker',
                                'local_as': '123',
                                'advertise_floating_ip_host_routes': '0',
                                'advertise_tenant_networks': '0',
                                'peers': [],
                                'networks': []}}
        cls._save_bgp_speaker(self.ctx, bgp_speaker_body, uuid=bgp_speaker_id)

    def _test_schedule_bind_bgp_speaker(self, agents, bgp_speaker_id):
        scheduler = bgp_dras.ChanceScheduler()
        scheduler.resource_filter.bind(self.ctx, agents, bgp_speaker_id)
        results = self.ctx.session.query(
            bgp_dras_db.BgpSpeakerDrAgentBinding).filter_by(
            bgp_speaker_id=bgp_speaker_id).all()

        for result in results:
            self.assertEqual(bgp_speaker_id, result.bgp_speaker_id)


class TestBgpDrAgentScheduler(TestBgpDrAgentSchedulerBaseTestCase,
                              bgp_db.BgpDbMixin):

    def test_schedule_bind_bgp_speaker_single_agent(self):
        agents = self._create_and_set_agents_down(['host-a'])
        self._test_schedule_bind_bgp_speaker(agents, self.bgp_speaker_id)

    def test_schedule_bind_bgp_speaker_multi_agents(self):
        agents = self._create_and_set_agents_down(['host-a', 'host-b'])
        self._test_schedule_bind_bgp_speaker(agents, self.bgp_speaker_id)


class TestBgpAgentFilter(TestBgpDrAgentSchedulerBaseTestCase,
                         bgp_db.BgpDbMixin,
                         bgp_dras_db.BgpDrAgentSchedulerDbMixin):

    def setUp(self):
        super(TestBgpAgentFilter, self).setUp()
        self.bgp_drscheduler = importutils.import_object(
            'neutron.services.bgp.scheduler'
            '.bgp_dragent_scheduler.ChanceScheduler'
        )
        self.plugin = self

    def _test_filter_agents_helper(self, bgp_speaker,
                                   expected_filtered_dragent_ids=None,
                                   expected_num_agents=1):
        if not expected_filtered_dragent_ids:
            expected_filtered_dragent_ids = []

        filtered_agents = (
            self.plugin.bgp_drscheduler.resource_filter.filter_agents(
                self.plugin, self.ctx, bgp_speaker))
        self.assertEqual(expected_num_agents,
                         filtered_agents['n_agents'])
        actual_filtered_dragent_ids = [
            agent.id for agent in filtered_agents['hostable_agents']]
        self.assertEqual(len(expected_filtered_dragent_ids),
                         len(actual_filtered_dragent_ids))
        for filtered_agent_id in actual_filtered_dragent_ids:
            self.assertIn(filtered_agent_id, expected_filtered_dragent_ids)

    def test_filter_agents_single_agent(self):
        agents = self._create_and_set_agents_down(['host-a'])
        expected_filtered_dragent_ids = [agents[0].id]
        self._test_filter_agents_helper(
            self.bgp_speaker,
            expected_filtered_dragent_ids=expected_filtered_dragent_ids)

    def test_filter_agents_no_agents(self):
        expected_filtered_dragent_ids = []
        self._test_filter_agents_helper(
            self.bgp_speaker,
            expected_filtered_dragent_ids=expected_filtered_dragent_ids,
            expected_num_agents=0)

    def test_filter_agents_two_agents(self):
        agents = self._create_and_set_agents_down(['host-a', 'host-b'])
        expected_filtered_dragent_ids = [agent.id for agent in agents]
        self._test_filter_agents_helper(
            self.bgp_speaker,
            expected_filtered_dragent_ids=expected_filtered_dragent_ids)

    def test_filter_agents_agent_already_scheduled(self):
        agents = self._create_and_set_agents_down(['host-a', 'host-b'])
        self._test_schedule_bind_bgp_speaker([agents[0]], self.bgp_speaker_id)
        self._test_filter_agents_helper(self.bgp_speaker,
                                        expected_num_agents=0)

    def test_filter_agents_multiple_agents_bgp_speakers(self):
        agents = self._create_and_set_agents_down(['host-a', 'host-b'])
        self._test_schedule_bind_bgp_speaker([agents[0]], self.bgp_speaker_id)
        bgp_speaker = {'id': 'bar-speaker-id'}
        self._save_bgp_speaker(bgp_speaker['id'])
        expected_filtered_dragent_ids = [agents[1].id]
        self._test_filter_agents_helper(
            bgp_speaker,
            expected_filtered_dragent_ids=expected_filtered_dragent_ids)


class TestAutoScheduleBgpSpeakers(TestBgpDrAgentSchedulerBaseTestCase):
    """Unit test scenarios for schedule_unscheduled_bgp_speakers.

    bgp_speaker_present
        BGP speaker is present or not

    scheduled_already
        BGP speaker is already scheduled to the agent or not

    agent_down
        BGP DRAgent is down or alive

    valid_host
        If true, then an valid host is passed to schedule BGP speaker,
        else an invalid host is passed.
    """
    scenarios = [
        ('BGP speaker present',
         dict(bgp_speaker_present=True,
              scheduled_already=False,
              agent_down=False,
              valid_host=True,
              expected_result=True)),

        ('No BGP speaker',
         dict(bgp_speaker_present=False,
              scheduled_already=False,
              agent_down=False,
              valid_host=True,
              expected_result=False)),

        ('BGP speaker already scheduled',
         dict(bgp_speaker_present=True,
              scheduled_already=True,
              agent_down=False,
              valid_host=True,
              expected_result=False)),

        ('BGP DR agent down',
         dict(bgp_speaker_present=True,
              scheduled_already=False,
              agent_down=True,
              valid_host=False,
              expected_result=False)),

        ('Invalid host',
         dict(bgp_speaker_present=True,
              scheduled_already=False,
              agent_down=False,
              valid_host=False,
              expected_result=False)),
    ]

    def test_auto_schedule_bgp_speaker(self):
        scheduler = bgp_dras.ChanceScheduler()
        if self.bgp_speaker_present:
            down_agent_count = 1 if self.agent_down else 0
            agents = self._create_and_set_agents_down(
                ['host-a'], down_agent_count=down_agent_count)
            if self.scheduled_already:
                self._test_schedule_bind_bgp_speaker(agents,
                                                     self.bgp_speaker_id)

        expected_hosted_agents = (1 if self.bgp_speaker_present and
                                  self.valid_host else 0)
        host = "host-a" if self.valid_host else "host-b"
        observed_ret_value = scheduler.schedule_unscheduled_bgp_speakers(
            self.ctx, host)
        self.assertEqual(self.expected_result, observed_ret_value)
        hosted_agents = self.ctx.session.query(
            bgp_dras_db.BgpSpeakerDrAgentBinding).all()
        self.assertEqual(expected_hosted_agents, len(hosted_agents))
