# Copyright (c) 2013 OpenStack Foundation
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
#
# @author: Sylvain Afchain, eNovance SAS
# @author: Emilien Macchi, eNovance SAS

import contextlib
import uuid

import mock
from oslo.config import cfg

from neutron.api.v2 import attributes as attr
from neutron.common import constants
from neutron.common import topics
from neutron import context as q_context
from neutron.db import agents_db
from neutron.db import l3_agentschedulers_db
from neutron.extensions import l3 as ext_l3
from neutron import manager
from neutron.openstack.common import timeutils
from neutron.tests.unit import test_db_plugin
from neutron.tests.unit import test_l3_plugin

HOST = 'my_l3_host'
FIRST_L3_AGENT = {
    'binary': 'neutron-l3-agent',
    'host': HOST,
    'topic': topics.L3_AGENT,
    'configurations': {},
    'agent_type': constants.AGENT_TYPE_L3,
    'start_flag': True
}

HOST_2 = 'my_l3_host_2'
SECOND_L3_AGENT = {
    'binary': 'neutron-l3-agent',
    'host': HOST_2,
    'topic': topics.L3_AGENT,
    'configurations': {},
    'agent_type': constants.AGENT_TYPE_L3,
    'start_flag': True
}

DB_PLUGIN_KLASS = ('neutron.plugins.openvswitch.ovs_neutron_plugin.'
                   'OVSNeutronPluginV2')


class L3SchedulerTestExtensionManager(object):

    def get_resources(self):
        attr.RESOURCE_ATTRIBUTE_MAP.update(ext_l3.RESOURCE_ATTRIBUTE_MAP)
        l3_res = ext_l3.L3.get_resources()
        return l3_res

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class L3SchedulerTestCase(l3_agentschedulers_db.L3AgentSchedulerDbMixin,
                          test_db_plugin.NeutronDbPluginV2TestCase,
                          test_l3_plugin.L3NatTestCaseMixin):

    def setUp(self):
        ext_mgr = L3SchedulerTestExtensionManager()
        super(L3SchedulerTestCase, self).setUp(plugin=DB_PLUGIN_KLASS,
                                               ext_mgr=ext_mgr)

        self.adminContext = q_context.get_admin_context()
        self.plugin = manager.NeutronManager.get_plugin()
        self._register_l3_agents()

    def _register_l3_agents(self):
        callback = agents_db.AgentExtRpcCallback()
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': FIRST_L3_AGENT},
                              time=timeutils.strtime())
        agent_db = self.plugin.get_agents_db(self.adminContext,
                                             filters={'host': [HOST]})
        self.agent_id1 = agent_db[0].id

        callback.report_state(self.adminContext,
                              agent_state={'agent_state': SECOND_L3_AGENT},
                              time=timeutils.strtime())
        agent_db = self.plugin.get_agents_db(self.adminContext,
                                             filters={'host': [HOST]})
        self.agent_id2 = agent_db[0].id

    def _set_l3_agent_admin_state(self, context, agent_id, state=True):
        update = {'agent': {'admin_state_up': state}}
        self.plugin.update_agent(context, agent_id, update)

    @contextlib.contextmanager
    def router_with_ext_gw(self, name='router1', admin_state_up=True,
                           fmt=None, tenant_id=str(uuid.uuid4()),
                           external_gateway_info=None,
                           subnet=None, set_context=False,
                           **kwargs):
        router = self._make_router(fmt or self.fmt, tenant_id, name,
                                   admin_state_up, external_gateway_info,
                                   set_context, **kwargs)
        self._add_external_gateway_to_router(
            router['router']['id'],
            subnet['subnet']['network_id'])

        yield router

        self._remove_external_gateway_from_router(
            router['router']['id'], subnet['subnet']['network_id'])
        self._delete('routers', router['router']['id'])


class L3AgentChanceSchedulerTestCase(L3SchedulerTestCase):

    def test_random_scheduling(self):
        random_patch = mock.patch('random.choice')
        random_mock = random_patch.start()

        def side_effect(seq):
            return seq[0]
        random_mock.side_effect = side_effect

        with self.subnet() as subnet:
            self._set_net_external(subnet['subnet']['network_id'])
            with self.router_with_ext_gw(name='r1', subnet=subnet) as r1:
                agents = self.get_l3_agents_hosting_routers(
                    self.adminContext, [r1['router']['id']],
                    admin_state_up=True)

                self.assertEqual(len(agents), 1)
                self.assertEqual(random_mock.call_count, 1)

                with self.router_with_ext_gw(name='r2', subnet=subnet) as r2:
                    agents = self.get_l3_agents_hosting_routers(
                        self.adminContext, [r2['router']['id']],
                        admin_state_up=True)

                    self.assertEqual(len(agents), 1)
                    self.assertEqual(random_mock.call_count, 2)

        random_patch.stop()


class L3AgentLeastRoutersSchedulerTestCase(L3SchedulerTestCase):
    def setUp(self):
        cfg.CONF.set_override('router_scheduler_driver',
                              'neutron.scheduler.l3_agent_scheduler.'
                              'LeastRoutersScheduler')

        super(L3AgentLeastRoutersSchedulerTestCase, self).setUp()

    def test_scheduler(self):
        # disable one agent to force the scheduling to the only one.
        self._set_l3_agent_admin_state(self.adminContext,
                                       self.agent_id2, False)

        with self.subnet() as subnet:
            self._set_net_external(subnet['subnet']['network_id'])
            with self.router_with_ext_gw(name='r1', subnet=subnet) as r1:
                agents = self.get_l3_agents_hosting_routers(
                    self.adminContext, [r1['router']['id']],
                    admin_state_up=True)
                self.assertEqual(len(agents), 1)

                agent_id1 = agents[0]['id']

                with self.router_with_ext_gw(name='r2', subnet=subnet) as r2:
                    agents = self.get_l3_agents_hosting_routers(
                        self.adminContext, [r2['router']['id']],
                        admin_state_up=True)
                    self.assertEqual(len(agents), 1)

                    agent_id2 = agents[0]['id']

                    self.assertEqual(agent_id1, agent_id2)

                    # re-enable the second agent to see whether the next router
                    # spawned will be on this one.
                    self._set_l3_agent_admin_state(self.adminContext,
                                                   self.agent_id2, True)

                    with self.router_with_ext_gw(name='r3',
                                                 subnet=subnet) as r3:
                        agents = self.get_l3_agents_hosting_routers(
                            self.adminContext, [r3['router']['id']],
                            admin_state_up=True)
                        self.assertEqual(len(agents), 1)

                        agent_id3 = agents[0]['id']

                        self.assertNotEqual(agent_id1, agent_id3)
