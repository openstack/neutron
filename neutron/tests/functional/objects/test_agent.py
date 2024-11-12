# Copyright 2021 Red Hat, Inc.
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

from collections import defaultdict

from neutron_lib import context as n_context
from neutron_lib.db import api as db_api
from oslo_utils import timeutils
from oslo_utils import uuidutils

from neutron.objects import agent as agent_obj
from neutron.tests.unit import testlib_api


class _AgentSql(testlib_api.SqlTestCase):

    def setUp(self):
        super().setUp()
        self.context = n_context.get_admin_context()

    @db_api.CONTEXT_WRITER
    def _create_agent(self, context, agent_type, az, host=None):
        host = host or uuidutils.generate_uuid()
        agent = agent_obj.Agent(context, agent_type=agent_type,
                                availability_zone=az, host=host,
                                binary=uuidutils.generate_uuid(),
                                topic=uuidutils.generate_uuid(),
                                admin_state_up=True,
                                created_at=timeutils.utcnow(),
                                started_at=timeutils.utcnow(),
                                heartbeat_timestamp=timeutils.utcnow(),
                                configurations='{}',
                                load=0,
                                )
        agent.create()

    def test_get_agents_by_availability_zones_and_agent_type(self):
        self.agents = defaultdict(dict)
        agent_types = ('dhcp', 'ovs', 'l3agent')
        azs = ('az1', 'az2', 'az3')
        for type_ in agent_types:
            for az in azs:
                # Create up to 5 agents per AZ and agent type. That will check
                # the query GROUP BY clause.
                for _ in range(5):
                    self._create_agent(self.context, type_, az)

        method = agent_obj.Agent.get_availability_zones_by_agent_type
        for type_ in agent_types:
            for az in azs:
                res_azs = method(self.context, type_, [az])
                self.assertEqual(1, len(res_azs))
                self.assertEqual(az, res_azs[0])

        # Non-existing types, correct AZs
        for type_ in ('type1', 'type2'):
            for az in azs:
                res_azs = method(self.context, type_, [az])
                self.assertEqual(0, len(res_azs))

        # Correct types, non-existing AZs
        for type_ in agent_types:
            for az in ('az23', 'az42'):
                res_azs = method(self.context, type_, [az])
                self.assertEqual(0, len(res_azs))


class TestAgentMySQL(testlib_api.MySQLTestCaseMixin, _AgentSql):
    pass


class TestAgentPostgreSQL(testlib_api.PostgreSQLTestCaseMixin, _AgentSql):
    pass
