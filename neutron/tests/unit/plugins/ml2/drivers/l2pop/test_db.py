# Copyright 2015 Red Hat, Inc.
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

from neutron.common import constants
from neutron import context
from neutron.plugins.ml2.drivers.l2pop import db as l2pop_db
from neutron.tests.common import helpers
from neutron.tests.unit import testlib_api


class TestL2PopulationDBTestCase(testlib_api.SqlTestCase):
    def setUp(self):
        super(TestL2PopulationDBTestCase, self).setUp()
        self.db_mixin = l2pop_db.L2populationDbMixin()

    def test_get_agent_by_host(self):
        # Register a L2 agent + A bunch of other agents on the same host
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        helpers.register_ovs_agent()
        agent = self.db_mixin.get_agent_by_host(
            context.get_admin_context().session, helpers.HOST)
        self.assertEqual(constants.AGENT_TYPE_OVS, agent.agent_type)

    def test_get_agent_by_host_no_candidate(self):
        # Register a bunch of non-L2 agents on the same host
        helpers.register_l3_agent()
        helpers.register_dhcp_agent()
        agent = self.db_mixin.get_agent_by_host(
            context.get_admin_context().session, helpers.HOST)
        self.assertIsNone(agent)
