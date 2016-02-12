# Copyright 2016 Huawei Technologies India Pvt. Ltd.
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

import testscenarios

from neutron import context
from neutron.db import agents_db
from neutron.db import bgp_db
from neutron.db import bgp_dragentscheduler_db as bgp_dras_db
from neutron.db import common_db_mixin
from neutron.services.bgp.scheduler import bgp_dragent_scheduler as bgp_dras
from neutron.tests.common import helpers
from neutron.tests.unit import testlib_api

# Required to generate tests from scenarios. Not compatible with nose.
load_tests = testscenarios.load_tests_apply_scenarios


class TestAutoSchedule(testlib_api.SqlTestCase,
                       bgp_dras_db.BgpDrAgentSchedulerDbMixin,
                       agents_db.AgentDbMixin,
                       common_db_mixin.CommonDbMixin):
    """Test various scenarios for schedule_unscheduled_bgp_speakers.

        Below is the brief description of the scenario variables
        --------------------------------------------------------
        host_count
            number of hosts.

        agent_count
            number of BGP dynamic routing agents.

        down_agent_count
            number of DRAgents which are inactive.

        bgp_speaker_count
            Number of bgp_speakers.

        hosted_bgp_speakers
            A mapping of agent id to the ids of the bgp_speakers that they
            should be initially hosting.

        expected_schedule_return_value
            Expected return value of 'schedule_unscheduled_bgp_speakers'.

        expected_hosted_bgp_speakers
            This stores the expected bgp_speakers that should have been
            scheduled (or that could have already been scheduled) for each
            agent after the 'schedule_unscheduled_bgp_speakers' function is
            called.
    """

    scenarios = [
        ('No BgpDrAgent scheduled, if no DRAgent is present',
         dict(host_count=1,
              agent_count=0,
              down_agent_count=0,
              bgp_speaker_count=1,
              hosted_bgp_speakers={},
              expected_schedule_return_value=False)),

        ('No BgpDrAgent scheduled, if no BGP speaker are present',
         dict(host_count=1,
              agent_count=1,
              down_agent_count=0,
              bgp_speaker_count=0,
              hosted_bgp_speakers={},
              expected_schedule_return_value=False,
              expected_hosted_bgp_speakers={'agent-0': []})),

        ('No BgpDrAgent scheduled, if BGP speaker already hosted',
         dict(host_count=1,
              agent_count=1,
              down_agent_count=0,
              bgp_speaker_count=1,
              hosted_bgp_speakers={'agent-0': ['bgp-speaker-0']},
              expected_schedule_return_value=False,
              expected_hosted_bgp_speakers={'agent-0': ['bgp-speaker-0']})),

        ('BgpDrAgent scheduled to the speaker, if the speaker is not hosted',
         dict(host_count=1,
              agent_count=1,
              down_agent_count=0,
              bgp_speaker_count=1,
              hosted_bgp_speakers={},
              expected_schedule_return_value=True,
              expected_hosted_bgp_speakers={'agent-0': ['bgp-speaker-0']})),

        ('No BgpDrAgent scheduled, if all the agents are down',
         dict(host_count=2,
              agent_count=2,
              down_agent_count=2,
              bgp_speaker_count=1,
              hosted_bgp_speakers={},
              expected_schedule_return_value=False,
              expected_hosted_bgp_speakers={'agent-0': [],
                                            'agent-1': [], })),
    ]

    def _strip_host_index(self, name):
        """Strips the host index.

        Eg. if name = '2-agent-3', then 'agent-3' is returned.
        """
        return name[name.find('-') + 1:]

    def _extract_index(self, name):
        """Extracts the index number and returns.

        Eg. if name = '2-agent-3', then 3 is returned
        """
        return int(name.split('-')[-1])

    def _get_hosted_bgp_speakers_on_dragent(self, agent_id):
        query = self.ctx.session.query(
            bgp_dras_db.BgpSpeakerDrAgentBinding.bgp_speaker_id)
        query = query.filter(
            bgp_dras_db.BgpSpeakerDrAgentBinding.agent_id ==
            agent_id)

        return [item[0] for item in query]

    def _create_and_set_agents_down(self, hosts, agent_count=0,
                                    down_agent_count=0, admin_state_up=True):
        agents = []
        if agent_count:
            for i, host in enumerate(hosts):
                is_alive = i >= down_agent_count
                agents.append(helpers.register_bgp_dragent(
                    host,
                    admin_state_up=admin_state_up,
                    alive=is_alive))
        return agents

    def _save_bgp_speakers(self, bgp_speakers):
        cls = bgp_db.BgpDbMixin()
        bgp_speaker_body = {
            'bgp_speaker': {'name': 'fake_bgp_speaker',
                            'ip_version': '4',
                            'local_as': '123',
                            'advertise_floating_ip_host_routes': '0',
                            'advertise_tenant_networks': '0',
                            'peers': [],
                            'networks': []}}
        i = 1
        for bgp_speaker_id in bgp_speakers:
            bgp_speaker_body['bgp_speaker']['local_as'] = i
            cls._save_bgp_speaker(self.ctx, bgp_speaker_body,
                                  uuid=bgp_speaker_id)
            i = i + 1

    def _test_auto_schedule(self, host_index):
        scheduler = bgp_dras.ChanceScheduler()
        self.ctx = context.get_admin_context()
        msg = 'host_index = %s' % host_index

        # create hosts
        hosts = ['%s-agent-%s' % (host_index, i)
                 for i in range(self.host_count)]
        bgp_dragents = self._create_and_set_agents_down(hosts,
                                                        self.agent_count,
                                                        self.down_agent_count)

        # create bgp_speakers
        self._bgp_speakers = ['%s-bgp-speaker-%s' % (host_index, i)
                              for i in range(self.bgp_speaker_count)]
        self._save_bgp_speakers(self._bgp_speakers)

        # pre schedule the bgp_speakers to the agents defined in
        # self.hosted_bgp_speakers before calling auto_schedule_bgp_speaker
        for agent, bgp_speakers in self.hosted_bgp_speakers.items():
            agent_index = self._extract_index(agent)
            for bgp_speaker in bgp_speakers:
                bs_index = self._extract_index(bgp_speaker)
                scheduler.bind(self.ctx, [bgp_dragents[agent_index]],
                               self._bgp_speakers[bs_index])

        retval = scheduler.schedule_unscheduled_bgp_speakers(self.ctx,
                                                             hosts[host_index])
        self.assertEqual(self.expected_schedule_return_value, retval,
                         message=msg)

        if self.agent_count:
            agent_id = bgp_dragents[host_index].id
            hosted_bgp_speakers = self._get_hosted_bgp_speakers_on_dragent(
                agent_id)
            hosted_bs_ids = [self._strip_host_index(net)
                             for net in hosted_bgp_speakers]
            expected_hosted_bgp_speakers = self.expected_hosted_bgp_speakers[
                'agent-%s' % host_index]
            self.assertItemsEqual(hosted_bs_ids, expected_hosted_bgp_speakers,
                                  msg)

    def test_auto_schedule(self):
        for i in range(self.host_count):
            self._test_auto_schedule(i)
