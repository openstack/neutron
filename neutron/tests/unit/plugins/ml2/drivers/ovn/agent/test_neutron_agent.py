# Copyright 2022 Red Hat, Inc.
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

import collections
import datetime
import random
from unittest import mock

import eventlet
from oslo_utils import timeutils

from neutron.common.ovn import constants as ovn_const
from neutron.plugins.ml2.drivers.ovn.agent import neutron_agent
from neutron.tests import base
from neutron.tests.unit import fake_resources as fakes


class AgentCacheTestCase(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.agent_cache = neutron_agent.AgentCache(driver=mock.ANY)
        self.addCleanup(self._clean_agent_cache)
        self.agents = {}
        self.num_agents = 10  # Add 10 agents.
        for i in range(self.num_agents):
            agent_type = random.choice(ovn_const.OVN_AGENT_TYPES)
            other_config = {}
            if agent_type == ovn_const.OVN_CONTROLLER_GW_AGENT:
                # 'enable-chassis-as-gw' is mandatory if the controller is
                # a gateway chassis; if not, it will default to
                # 'OVN Controller agent'. Check ``ControllerGatewayAgent``
                # class.
                other_config = {'ovn-cms-options': 'enable-chassis-as-gw'}
            chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(
                attrs={'other_config': other_config,
                       'hostname': f'host{i:d}',
                       })
            ext_ids = {}
            if agent_type == ovn_const.OVN_METADATA_AGENT:
                ext_ids = {
                    ovn_const.OVN_AGENT_METADATA_ID_KEY: 'chassis' + str(i)}
            elif agent_type == ovn_const.OVN_NEUTRON_AGENT:
                ext_ids = {
                    ovn_const.OVN_AGENT_NEUTRON_ID_KEY: 'chassis' + str(i)}
            chassis_private = fakes.FakeOvsdbRow.create_one_ovsdb_row(
                attrs={'name': 'chassis' + str(i),
                       'other_config': {},
                       'chassis': [chassis],
                       'nb_cfg_timestamp': timeutils.utcnow_ts() * 1000,
                       'external_ids': ext_ids,
                       })
            self.agent_cache.update(agent_type, chassis_private)
            self.agents['chassis' + str(i)] = agent_type

        self.assertEqual(self.num_agents, len(list(self.agent_cache)))
        for agent_class in (neutron_agent.NeutronAgent,
                            neutron_agent.MetadataAgent,
                            neutron_agent.OVNNeutronAgent):
            mock.patch.object(agent_class, 'alive', return_value=True).start()

    def _clean_agent_cache(self):
        del self.agent_cache

    def _list_agents(self):
        self.names_read = []
        for idx, agent in enumerate(self.agent_cache):
            self.names_read.append(agent.agent_id)
            if idx == 5:  # Swap to "_add_and_delete_agents" thread.
                eventlet.sleep(0)

    def _add_and_delete_agents(self):
        self.agent_cache.delete('chassis8')
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'other_config': {}})
        chassis_private = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'chassis10',
                   'chassis': [chassis],
                   'nb_cfg_timestamp': timeutils.utcnow_ts() * 1000})
        self.agent_cache.update(ovn_const.OVN_CONTROLLER_AGENT,
                                chassis_private)

    def test_update_while_iterating_agents(self):
        pool = eventlet.GreenPool(2)
        pool.spawn(self._list_agents)
        pool.spawn(self._add_and_delete_agents)
        pool.waitall()
        self.assertEqual(list(self.agents.keys()), self.names_read)

    def test_agents_by_chassis_private(self):
        ext_ids = {ovn_const.OVN_AGENT_METADATA_ID_KEY: 'chassis5'}
        chassis_private = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'chassis5',
                   'external_ids': ext_ids})
        agents = self.agent_cache.agents_by_chassis_private(chassis_private)
        agents = list(agents)
        self.assertEqual(1, len(agents))
        self.assertEqual('chassis5', agents[0].agent_id)

    def test_heartbeat_timestamp_format(self):
        chassis_private = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'chassis5'})
        agents = self.agent_cache.agents_by_chassis_private(chassis_private)
        agent = list(agents)[0]
        agent.chassis.hostname = 'fake-hostname'
        agent.updated_at = datetime.datetime(
            year=2023, month=2, day=23, hour=1, minute=2, second=3,
            microsecond=456789).replace(tzinfo=datetime.timezone.utc)

        # Verify that both microseconds and timezone are dropped
        self.assertEqual(str(agent.as_dict()['heartbeat_timestamp']),
                         '2023-02-23 01:02:03')

    def test_list_agents_filtering_host_same_type(self):
        for idx in range(len(self.agents)):
            host = f'host{idx:d}'
            agents = self.agent_cache.get_agents(filters={'host': host})
            self.assertEqual(1, len(agents))
            self.assertEqual(host, agents[0].as_dict()['host'])

    def test_list_agents_filtering_host_as_iterable(self):
        hosts = []
        for idx in range(len(self.agents)):
            hosts.append(f'host{idx:d}')

        agents = self.agent_cache.get_agents(filters={'host': hosts})
        self.assertEqual(len(self.agents), len(agents))

    def test_list_agents_filtering_agent_type_same_type(self):
        agent_types = collections.defaultdict(int)
        for _type in self.agents.values():
            agent_types[_type] = agent_types[_type] + 1

        for _type in agent_types:
            agents = self.agent_cache.get_agents(
                filters={'agent_type': _type})
            self.assertEqual(agent_types[_type], len(agents))
            self.assertEqual(_type, agents[0].as_dict()['agent_type'])

    def test_list_agents_filtering_agent_type_as_iterable(self):
        agents = self.agent_cache.get_agents(
            filters={'agent_type': ovn_const.OVN_AGENT_TYPES})
        self.assertEqual(self.num_agents, len(agents))

    @mock.patch.object(neutron_agent, 'LOG')
    def test_list_agents_filtering_wrong_type(self, mock_log):
        agents = self.agent_cache.get_agents(filters={'host': 111})
        self.assertEqual(0, len(agents))
        mock_log.info.assert_called_once()

    def test_list_agents_filtering_same_string_in_filter(self):
        # As reported in LP#2110094, if two registers have the same substring,
        # the filter didn't work.
        # Chassis 1, hostname: compute-0
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'other_config': {},
                   'hostname': 'compute-0'})
        chassis_private = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'chassis1',
                   'other_config': {},
                   'chassis': [chassis],
                   'nb_cfg_timestamp': timeutils.utcnow_ts() * 1000,
                   'external_ids': {}})
        self.agent_cache.update(ovn_const.OVN_CONTROLLER_AGENT,
                                chassis_private)

        # Chassis 2, hostname: dcn1-compute-0
        chassis = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'other_config': {},
                   'hostname': 'dcn1-compute-0'})
        chassis_private = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'chassis2',
                   'other_config': {},
                   'chassis': [chassis],
                   'nb_cfg_timestamp': timeutils.utcnow_ts() * 1000,
                   'external_ids': {}})
        self.agent_cache.update(ovn_const.OVN_CONTROLLER_AGENT,
                                chassis_private)

        agents = self.agent_cache.get_agents(
            filters={'host': 'compute-0'})
        self.assertEqual(1, len(agents))

        agents = self.agent_cache.get_agents(
            filters={'host': 'dcn1-compute-0'})
        self.assertEqual(1, len(agents))

        agents = self.agent_cache.get_agents(
            filters={'host': ['compute-0', 'dcn1-compute-0']})
        self.assertEqual(2, len(agents))
