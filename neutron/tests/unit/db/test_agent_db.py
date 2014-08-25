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

import mock
from oslo.db import exception as exc

from neutron.common import constants
from neutron import context
from neutron.db import agents_db
from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.openstack.common import timeutils
from neutron.tests.unit import testlib_api


class FakePlugin(base_plugin.NeutronDbPluginV2, agents_db.AgentDbMixin):
    """A fake plugin class containing all DB methods."""


class TestAgentsDbMixin(testlib_api.SqlTestCase):
    def setUp(self):
        super(TestAgentsDbMixin, self).setUp()

        self.context = context.get_admin_context()
        self.plugin = FakePlugin()

        self.agent_status = {
            'agent_type': 'Open vSwitch agent',
            'binary': 'neutron-openvswitch-agent',
            'host': 'overcloud-notcompute',
            'topic': 'N/A'
        }

    def _add_agent(self, agent_id, agent_type, agent_host):
        with self.context.session.begin(subtransactions=True):
            now = timeutils.utcnow()
            agent = agents_db.Agent(id=agent_id,
                                    agent_type=agent_type,
                                    binary='foo_binary',
                                    topic='foo_topic',
                                    host=agent_host,
                                    created_at=now,
                                    started_at=now,
                                    admin_state_up=True,
                                    heartbeat_timestamp=now,
                                    configurations='')
            self.context.session.add(agent)
            return agent

    def test_get_enabled_agent_on_host_found(self):
        agent = self._add_agent('foo_id', constants.AGENT_TYPE_L3, 'foo_host')
        expected = self.plugin.get_enabled_agent_on_host(
            self.context, constants.AGENT_TYPE_L3, 'foo_host')
        self.assertEqual(expected, agent)

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
                exc.DBDuplicateEntry(columns=['agent_type', 'host']),
                None
            ]

            self.plugin.create_or_update_agent(self.context, self.agent_status)

            self.assertEqual(add_mock.call_count, 2,
                             "Agent entry creation hasn't been retried")
