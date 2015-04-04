# Copyright (c) 2013 OpenStack Foundation.
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

import datetime
import mock

from oslo_db import exception as exc
from oslo_utils import timeutils
import testscenarios

from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron import context
from neutron.db import agents_db
from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.tests.unit import testlib_api

# the below code is required for the following reason
# (as documented in testscenarios)
"""Multiply tests depending on their 'scenarios' attribute.

    This can be assigned to 'load_tests' in any test module to make this
    automatically work across tests in the module.
"""
load_tests = testscenarios.load_tests_apply_scenarios


class FakePlugin(base_plugin.NeutronDbPluginV2, agents_db.AgentDbMixin):
    """A fake plugin class containing all DB methods."""


class TestAgentsDbBase(testlib_api.SqlTestCase):
    def setUp(self):
        super(TestAgentsDbBase, self).setUp()
        self.context = context.get_admin_context()
        self.plugin = FakePlugin()

    def _get_agents(self, hosts, agent_type):
        return [
            agents_db.Agent(
                binary='foo-agent',
                host=host,
                agent_type=agent_type,
                topic='foo_topic',
                configurations="",
                created_at=timeutils.utcnow(),
                started_at=timeutils.utcnow(),
                heartbeat_timestamp=timeutils.utcnow())
            for host in hosts
        ]

    def _save_agents(self, agents):
        for agent in agents:
            with self.context.session.begin(subtransactions=True):
                self.context.session.add(agent)

    def _create_and_save_agents(self, hosts, agent_type, down_agents_count=0):
        agents = self._get_agents(hosts, agent_type)
        # bring down the specified agents
        for agent in agents[:down_agents_count]:
            agent['heartbeat_timestamp'] -= datetime.timedelta(minutes=60)

        self._save_agents(agents)
        return agents


class TestAgentsDbMixin(TestAgentsDbBase):
    def setUp(self):
        super(TestAgentsDbMixin, self).setUp()

        self.agent_status = {
            'agent_type': 'Open vSwitch agent',
            'binary': 'neutron-openvswitch-agent',
            'host': 'overcloud-notcompute',
            'topic': 'N/A'
        }

    def test_get_enabled_agent_on_host_found(self):
        agents = self._create_and_save_agents(['foo_host'],
                                              constants.AGENT_TYPE_L3)
        expected = self.plugin.get_enabled_agent_on_host(
            self.context, constants.AGENT_TYPE_L3, 'foo_host')
        self.assertEqual(expected, agents[0])

    def test_get_enabled_agent_on_host_not_found(self):
        with mock.patch.object(agents_db.LOG, 'debug') as mock_log:
            agent = self.plugin.get_enabled_agent_on_host(
                self.context, constants.AGENT_TYPE_L3, 'foo_agent')
        self.assertIsNone(agent)
        self.assertTrue(mock_log.called)

    def _assert_ref_fields_are_equal(self, reference, result):
        """Compare (key, value) pairs of a reference dict with the result

           Note: the result MAY have additional keys
        """

        for field, value in reference.items():
            self.assertEqual(value, result[field], field)

    def test_create_or_update_agent_new_entry(self):
        self.plugin.create_or_update_agent(self.context, self.agent_status)

        agent = self.plugin.get_agents(self.context)[0]
        self._assert_ref_fields_are_equal(self.agent_status, agent)

    def test_create_or_update_agent_existing_entry(self):
        self.plugin.create_or_update_agent(self.context, self.agent_status)
        self.plugin.create_or_update_agent(self.context, self.agent_status)
        self.plugin.create_or_update_agent(self.context, self.agent_status)

        agents = self.plugin.get_agents(self.context)
        self.assertEqual(len(agents), 1)

        agent = agents[0]
        self._assert_ref_fields_are_equal(self.agent_status, agent)

    def test_create_or_update_agent_concurrent_insert(self):
        # NOTE(rpodolyaka): emulate violation of the unique constraint caused
        #                   by a concurrent insert. Ensure we make another
        #                   attempt on fail
        with mock.patch('sqlalchemy.orm.Session.add') as add_mock:
            add_mock.side_effect = [
                exc.DBDuplicateEntry(),
                None
            ]

            self.plugin.create_or_update_agent(self.context, self.agent_status)

            self.assertEqual(add_mock.call_count, 2,
                             "Agent entry creation hasn't been retried")


class TestAgentsDbGetAgents(TestAgentsDbBase):
    scenarios = [
        ('Get all agents', dict(agents=5, down_agents=2,
                                agents_alive=None,
                                expected_agents=5)),

        ('Get alive agents (True)', dict(agents=5, down_agents=2,
                                         agents_alive='True',
                                         expected_agents=3)),

        ('Get down agents (False)', dict(agents=5, down_agents=2,
                                         agents_alive='False',
                                         expected_agents=2)),

        ('Get alive agents (true)', dict(agents=5, down_agents=2,
                                         agents_alive='true',
                                         expected_agents=3)),

        ('Get down agents (false)', dict(agents=5, down_agents=2,
                                         agents_alive='false',
                                         expected_agents=2)),

        ('Get agents invalid alive filter', dict(agents=5, down_agents=2,
                                                 agents_alive='invalid',
                                                 expected_agents=None)),
    ]

    def setUp(self):
        # ensure that the first scenario will execute with nosetests
        if not hasattr(self, 'agents'):
            self.__dict__.update(self.scenarios[0][1])
        super(TestAgentsDbGetAgents, self).setUp()

    def test_get_agents(self):
        hosts = ['host-%s' % i for i in range(self.agents)]
        self._create_and_save_agents(hosts, constants.AGENT_TYPE_L3,
                                     down_agents_count=self.down_agents)
        if self.agents_alive == 'invalid':
            self.assertRaises(n_exc.InvalidInput, self.plugin.get_agents,
                              self.context,
                              filters={'alive': [self.agents_alive]})
        else:
            returned_agents = self.plugin.get_agents(
                self.context, filters={'alive': [self.agents_alive]}
                if self.agents_alive else None)
            self.assertEqual(self.expected_agents, len(returned_agents))
            if self.agents_alive:
                alive = (self.agents_alive == 'True' or
                         self.agents_alive == 'true')
                for agent in returned_agents:
                    self.assertEqual(alive, agent['alive'])
