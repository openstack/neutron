# Copyright 2016 Business Cat is Very Serious
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

from neutron_lib import constants
from oslo_db.sqlalchemy import utils as db_utils
from oslo_utils import uuidutils

from neutron.tests.functional.db import test_migrations


class HARouterPortMigrationMixin(object):
    """Validates HA port to router port migration."""

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

    def _make_router_agents_and_ports(self, router_id, network_id,
                                      add_binding):
        self._create_so('routers', {'id': router_id})
        # each router gets a couple of agents
        for _ in range(2):
            port_id = uuidutils.generate_uuid()
            self._create_so('ports', {'id': port_id, 'network_id': network_id,
                                      'mac_address': port_id[0:31],
                                      'admin_state_up': True,
                                      'device_id': router_id,
                                      'device_owner': 'network',
                                      'status': 'ACTIVE'})
            agent_id = uuidutils.generate_uuid()
            timestamp = '2000-04-06T14:34:23'
            self._create_rec('agents', {'id': agent_id, 'topic': 'x',
                                        'agent_type': 'L3',
                                        'binary': 'x',
                                        'host': agent_id,
                                        'created_at': timestamp,
                                        'started_at': timestamp,
                                        'heartbeat_timestamp': timestamp,
                                        'configurations': ''})
            self._create_rec('ha_router_agent_port_bindings',
                             {'port_id': port_id, 'router_id': router_id,
                              'l3_agent_id': agent_id})
            if add_binding:
                ptype = constants.DEVICE_OWNER_ROUTER_HA_INTF
                self._create_rec('routerports',
                                 {'router_id': router_id, 'port_id': port_id,
                                  'port_type': ptype})

    def _create_ha_routers_with_ports(self, engine):
        network_id = uuidutils.generate_uuid()
        self._create_so('networks', {'id': network_id})
        unpatched_router_ids = [uuidutils.generate_uuid() for i in range(10)]
        for rid in unpatched_router_ids:
            self._make_router_agents_and_ports(rid, network_id, False)
        # make half of the routers already have routerport bindings to simulate
        # a back-port of Ifd3e007aaf2a2ed8123275aa3a9f540838e3c003
        patched_router_ids = [uuidutils.generate_uuid() for i in range(10)]
        for rid in patched_router_ids:
            self._make_router_agents_and_ports(rid, network_id, True)

    def _pre_upgrade_a8b517cff8ab(self, engine):
        self._create_ha_routers_with_ports(engine)
        return True  # return True so check function is invoked after migrate

    def _check_a8b517cff8ab(self, engine, data):
        rp = db_utils.get_table(engine, 'routerports')
        # just ensuring the correct count of routerport records is enough.
        # 20 routers * 2 ports per router
        self.assertEqual(40, len(engine.execute(rp.select()).fetchall()))


class TestHARouterPortMigrationMysql(HARouterPortMigrationMixin,
                                     test_migrations.TestWalkMigrationsMysql):
    pass


class TestHARouterPortMigrationPsql(HARouterPortMigrationMixin,
                                    test_migrations.TestWalkMigrationsPsql):
    pass
