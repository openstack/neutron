# pylint: disable=pointless-string-statement
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

import copy
import datetime

import mock
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_db import exception as exc
from oslo_utils import timeutils
import testscenarios

from neutron.db import agents_db
from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.objects import agent as agent_obj
from neutron.objects import base
from neutron.tests.unit import testlib_api

# the below code is required for the following reason
# (as documented in testscenarios)
"""Multiply tests depending on their 'scenarios' attribute.

    This can be assigned to 'load_tests' in any test module to make this
    automatically work across tests in the module.
"""
load_tests = testscenarios.load_tests_apply_scenarios


TEST_RESOURCE_VERSIONS = {"A": "1.0"}
AGENT_STATUS = {'agent_type': 'Open vSwitch agent',
                'binary': 'neutron-openvswitch-agent',
                'host': 'overcloud-notcompute',
                'topic': 'N/A',
                'resource_versions': TEST_RESOURCE_VERSIONS}
TEST_TIME = '2016-02-26T17:08:06.116'


class FakePlugin(base_plugin.NeutronDbPluginV2, agents_db.AgentDbMixin):
    """A fake plugin class containing all DB methods."""


class TestAgentsDbBase(testlib_api.SqlTestCase):
    def setUp(self):
        super(TestAgentsDbBase, self).setUp()
        self.context = context.get_admin_context()
        self.plugin = FakePlugin()

    def _get_agents(self, hosts, agent_type):
        return [
            agent_obj.Agent(
                context=self.context,
                binary='foo-agent',
                host=host,
                agent_type=agent_type,
                topic='foo_topic',
                configurations="{}",
                created_at=timeutils.utcnow(),
                started_at=timeutils.utcnow(),
                heartbeat_timestamp=timeutils.utcnow())
            for host in hosts
        ]

    def _create_and_save_agents(self, hosts, agent_type, down_agents_count=0,
                                down_but_version_considered=0):
        agents = self._get_agents(hosts, agent_type)
        # bring down the specified agents
        for agent in agents[:down_agents_count]:
            agent['heartbeat_timestamp'] -= datetime.timedelta(minutes=60)

        # bring down just enough so their version is still considered
        for agent in agents[down_agents_count:(
                down_but_version_considered + down_agents_count)]:
            agent['heartbeat_timestamp'] -= datetime.timedelta(
                seconds=(cfg.CONF.agent_down_time + 1))

        for agent in agents:
            agent.create()
        return agents


class TestAgentsDbMixin(TestAgentsDbBase):
    def setUp(self):
        super(TestAgentsDbMixin, self).setUp()

        self.agent_status = dict(AGENT_STATUS)

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

    def test_create_or_update_agent_logs_heartbeat(self):
        status = self.agent_status.copy()
        status['configurations'] = {'log_agent_heartbeats': True}

        with mock.patch.object(agents_db.LOG, 'info') as info:
            self.plugin.create_or_update_agent(self.context, status)
            self.assertTrue(info.called)
            status['configurations'] = {'log_agent_heartbeats': False}
            info.reset_mock()
            self.plugin.create_or_update_agent(self.context, status)
            self.assertFalse(info.called)

    def test_create_or_update_agent_concurrent_insert(self):
        # NOTE(rpodolyaka): emulate violation of the unique constraint caused
        #                   by a concurrent insert. Ensure we make another
        #                   attempt on fail
        mock.patch(
            'neutron.objects.base.NeutronDbObject.modify_fields_from_db'
        ).start()
        mock.patch.object(self.context.session, 'expunge').start()

        with mock.patch('neutron.objects.db.api.create_object') as add_mock:
            add_mock.side_effect = [
                exc.DBDuplicateEntry(),
                mock.Mock()
            ]
            self.plugin.create_or_update_agent(self.context, self.agent_status)

            self.assertEqual(add_mock.call_count, 2,
                             "Agent entry creation hasn't been retried")

    def test_create_or_update_agent_disable_new_agents(self):
        cfg.CONF.set_override('enable_new_agents', False)
        self.plugin.create_or_update_agent(self.context, self.agent_status)
        agent = self.plugin.get_agents(self.context)[0]
        self.assertFalse(agent['admin_state_up'])

    def test_agent_health_check(self):
        agents = [{'agent_type': "DHCP Agent",
                   'heartbeat_timestamp': '2015-05-06 22:40:40.432295',
                   'host': 'some.node',
                   'alive': True}]
        with mock.patch.object(self.plugin, 'get_agents',
                               return_value=agents),\
                mock.patch.object(agents_db.LOG, 'warning') as warn,\
                mock.patch.object(agents_db.LOG, 'debug') as debug:
            self.plugin.agent_health_check()
            self.assertTrue(debug.called)
            self.assertFalse(warn.called)
            agents[0]['alive'] = False
            self.plugin.agent_health_check()
            warn.assert_called_once_with(
                mock.ANY,
                {'count': 1, 'total': 1,
                 'data': "                Type       Last heartbeat host\n"
                 "          DHCP Agent 2015-05-06 22:40:40.432295 some.node"}
            )

    def test__get_dict(self):
        db_obj = mock.Mock(conf1='{"test": "1234"}')
        conf1 = self.plugin._get_dict(db_obj, 'conf1')
        self.assertIn('test', conf1)
        self.assertEqual("1234", conf1['test'])

    def test__get_dict_missing(self):
        with mock.patch.object(agents_db.LOG, 'warning') as warn:
            db_obj = mock.Mock(spec=['agent_type', 'host'])
            self.plugin._get_dict(db_obj, 'missing_conf')
            self.assertTrue(warn.called)

    def test__get_dict_ignore_missing(self):
        with mock.patch.object(agents_db.LOG, 'warning') as warn:
            db_obj = mock.Mock(spec=['agent_type', 'host'])
            missing_conf = self.plugin._get_dict(db_obj, 'missing_conf',
                                                 ignore_missing=True)
            self.assertEqual({}, missing_conf)
            warn.assert_not_called()

    def test__get_dict_broken(self):
        with mock.patch.object(agents_db.LOG, 'warning') as warn:
            db_obj = mock.Mock(conf1='{"test": BROKEN')
            conf1 = self.plugin._get_dict(db_obj, 'conf1', ignore_missing=True)
            self.assertEqual({}, conf1)
            self.assertTrue(warn.called)

    def get_configurations_dict(self):
        db_obj = mock.Mock(configurations='{"cfg1": "val1"}')
        cfg = self.plugin.get_configuration_dict(db_obj)
        self.assertIn('cfg', cfg)

    def test_get_agents_resource_versions(self):
        tracker = mock.Mock()
        self._create_and_save_agents(
            ['host-%d' % i for i in range(5)],
            constants.AGENT_TYPE_L3,
            down_agents_count=3,
            down_but_version_considered=2)
        self.plugin.get_agents_resource_versions(tracker)
        self.assertEqual(tracker.set_versions.call_count, 2)


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


class TestAgentExtRpcCallback(TestAgentsDbBase):

    def setUp(self):
        super(TestAgentExtRpcCallback, self).setUp()
        self.callback = agents_db.AgentExtRpcCallback(self.plugin)
        self.callback.server_versions_rpc = mock.Mock()
        self.versions_rpc = self.callback.server_versions_rpc
        self.callback.START_TIME = datetime.datetime(datetime.MINYEAR, 1, 1)
        self.update_versions = mock.patch(
            'neutron.api.rpc.callbacks.version_manager.'
            'update_versions').start()
        self.agent_state = {'agent_state': dict(AGENT_STATUS)}

    def test_create_or_update_agent_updates_version_manager(self):
        self.callback.report_state(self.context, agent_state=self.agent_state,
                                   time=TEST_TIME)
        self.update_versions.assert_called_once_with(
                mock.ANY, TEST_RESOURCE_VERSIONS)

    def test_create_or_update_agent_updates_other_servers(self):
        callback = self.callback
        callback.report_state(self.context, agent_state=self.agent_state,
                              time=TEST_TIME)
        report_agent_resource_versions = (
                self.versions_rpc.report_agent_resource_versions)
        report_agent_resource_versions.assert_called_once_with(
                mock.ANY, mock.ANY, mock.ANY, TEST_RESOURCE_VERSIONS)

    def test_no_version_updates_on_further_state_reports(self):
        self.test_create_or_update_agent_updates_version_manager()
        # agents include resource_versions only in the first report after
        # start so versions should not be updated on the second report
        second_agent_state = copy.deepcopy(self.agent_state)
        second_agent_state['agent_state'].pop('resource_versions')
        self.update_versions.reset_mock()
        report_agent_resource_versions = (
                self.versions_rpc.report_agent_resource_versions)
        report_agent_resource_versions.reset_mock()

        self.callback.report_state(self.context,
                                   agent_state=second_agent_state,
                                   time=TEST_TIME)
        self.assertFalse(self.update_versions.called)
        self.assertFalse(report_agent_resource_versions.called)

    def test_version_updates_on_agent_revival(self):
        self.test_create_or_update_agent_updates_version_manager()
        second_agent_state = copy.deepcopy(self.agent_state)
        second_agent_state['agent_state'].pop('resource_versions')
        self._take_down_agent()
        self.update_versions.reset_mock()
        report_agent_resource_versions = (
                self.versions_rpc.report_agent_resource_versions)
        report_agent_resource_versions.reset_mock()

        # agent didn't include resource_versions in report but server will
        # take them from db for the revived agent
        self.callback.report_state(self.context,
                                   agent_state=second_agent_state,
                                   time=TEST_TIME)
        self.update_versions.assert_called_once_with(
                mock.ANY, TEST_RESOURCE_VERSIONS)
        report_agent_resource_versions.assert_called_once_with(
                mock.ANY, mock.ANY, mock.ANY, TEST_RESOURCE_VERSIONS)

    def _take_down_agent(self):
        with self.context.session.begin(subtransactions=True):
            pager = base.Pager(limit=1)
            agent_objs = agent_obj.Agent.get_objects(self.context,
                                                     _pager=pager)
            agent_objs[0].heartbeat_timestamp = (
                agent_objs[0].heartbeat_timestamp - datetime.timedelta(
                    hours=1))
            agent_objs[0].update()
