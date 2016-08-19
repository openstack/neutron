# Copyright 2016 Business Cat is Very Serious 13.37
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
#

import collections

from oslo_db.sqlalchemy import utils as db_utils
from oslo_utils import uuidutils

from neutron.tests.functional.db import test_migrations


class HARouterPortMigrationMixin(object):
    """Validates binding_index for RouterL3AgentBinding migration."""

    def _create_so(self, o_type, values):
        """create standard attr object."""
        stan = db_utils.get_table(self.engine, 'standardattributes')
        # find next available id taking into account existing records
        rec_ids = [r.id for r in self.engine.execute(stan.select()).fetchall()]
        next_id = max([0] + rec_ids) + 1
        self.engine.execute(stan.insert().values({'id': next_id,
                                                  'resource_type': o_type}))
        values['standard_attr_id'] = next_id
        return self._create_rec(o_type, values)

    def _create_rec(self, o_type, values):
        otable = db_utils.get_table(self.engine, o_type)
        self.engine.execute(otable.insert().values(values))

    def _make_router_agents_and_bindings(self, router_id):
        self._create_so('routers', {'id': router_id})
        # each router gets a couple of agents
        for _ in range(2):
            agent_id = uuidutils.generate_uuid()
            timestamp = '2000-04-06T14:34:23'
            self._create_rec('agents', {'id': agent_id,
                                        'topic': 'x',
                                        'agent_type': 'L3',
                                        'binary': 'x',
                                        'host': agent_id,
                                        'created_at': timestamp,
                                        'started_at': timestamp,
                                        'heartbeat_timestamp': timestamp,
                                        'configurations': ''})
            self._create_rec('routerl3agentbindings',
                             {'router_id': router_id, 'l3_agent_id': agent_id})

    def _create_ha_routers(self, engine):
        for rid in [uuidutils.generate_uuid() for i in range(10)]:
            self._make_router_agents_and_bindings(rid)

    def _pre_upgrade_2e0d7a8a1586(self, engine):
        self._create_ha_routers(engine)
        return True  # return True so check function is invoked after migrate

    def _check_2e0d7a8a1586(self, engine, data):
        bindings_table = db_utils.get_table(engine, 'routerl3agentbindings')
        rows = engine.execute(bindings_table.select()).fetchall()

        routers_to_bindings = collections.defaultdict(list)
        for router_id, agent_id, binding_index in rows:
            routers_to_bindings[router_id].append(binding_index)

        for binding_indices in routers_to_bindings.values():
            self.assertEqual(list(range(1, 3)), sorted(binding_indices))


class TestHARouterPortMigrationMysql(HARouterPortMigrationMixin,
                                     test_migrations.TestWalkMigrationsMysql):
    pass


class TestHARouterPortMigrationPsql(HARouterPortMigrationMixin,
                                    test_migrations.TestWalkMigrationsPsql):
    pass
