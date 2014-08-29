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
from sqlalchemy.orm import query

from neutron.api.v2 import attributes as attr
from neutron.common import constants
from neutron.common import topics
from neutron import context as q_context
from neutron.db import agents_db
from neutron.db import common_db_mixin
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_db
from neutron.db import l3_dvrscheduler_db
from neutron.extensions import l3 as ext_l3
from neutron import manager
from neutron.openstack.common import timeutils
from neutron.scheduler import l3_agent_scheduler
from neutron.tests import base
from neutron.tests.unit import test_db_plugin
from neutron.tests.unit import test_l3_plugin
from neutron.tests.unit import testlib_api
from neutron.tests.unit import testlib_plugin

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

HOST_DVR = 'my_l3_host_dvr'
DVR_L3_AGENT = {
    'binary': 'neutron-l3-agent',
    'host': HOST_DVR,
    'topic': topics.L3_AGENT,
    'configurations': {'agent_mode': 'dvr'},
    'agent_type': constants.AGENT_TYPE_L3,
    'start_flag': True
}

HOST_DVR_SNAT = 'my_l3_host_dvr_snat'
DVR_SNAT_L3_AGENT = {
    'binary': 'neutron-l3-agent',
    'host': HOST_DVR_SNAT,
    'topic': topics.L3_AGENT,
    'configurations': {'agent_mode': 'dvr_snat'},
    'agent_type': constants.AGENT_TYPE_L3,
    'start_flag': True
}

DB_PLUGIN_KLASS = ('neutron.plugins.openvswitch.ovs_neutron_plugin.'
                   'OVSNeutronPluginV2')


class FakeL3Scheduler(l3_agent_scheduler.L3Scheduler):

    def schedule(self):
        pass

    def _choose_router_agent(self):
        pass


class L3SchedulerBaseTestCase(base.BaseTestCase):

    def setUp(self):
        super(L3SchedulerBaseTestCase, self).setUp()
        self.scheduler = FakeL3Scheduler()
        self.plugin = mock.Mock()

    def test_auto_schedule_routers(self):
        self.plugin.get_enabled_agent_on_host.return_value = [mock.ANY]
        with contextlib.nested(
            mock.patch.object(self.scheduler, 'get_routers_to_schedule'),
            mock.patch.object(self.scheduler, 'get_routers_can_schedule')) as (
            gs, gr):
            result = self.scheduler.auto_schedule_routers(
                self.plugin, mock.ANY, mock.ANY, mock.ANY)
        self.assertTrue(self.plugin.get_enabled_agent_on_host.called)
        self.assertTrue(result)
        self.assertTrue(gs.called)
        self.assertTrue(gr.called)

    def test_auto_schedule_routers_no_agents(self):
        self.plugin.get_enabled_agent_on_host.return_value = None
        result = self.scheduler.auto_schedule_routers(
            self.plugin, mock.ANY, mock.ANY, mock.ANY)
        self.assertTrue(self.plugin.get_enabled_agent_on_host.called)
        self.assertFalse(result)

    def test_auto_schedule_routers_no_unscheduled_routers(self):
        with mock.patch.object(self.scheduler,
                               'get_routers_to_schedule') as mock_routers:
            mock_routers.return_value = None
            result = self.scheduler.auto_schedule_routers(
                self.plugin, mock.ANY, mock.ANY, mock.ANY)
        self.assertTrue(self.plugin.get_enabled_agent_on_host.called)
        self.assertFalse(result)

    def test_auto_schedule_routers_no_target_routers(self):
        self.plugin.get_enabled_agent_on_host.return_value = [mock.ANY]
        with contextlib.nested(
            mock.patch.object(self.scheduler, 'get_routers_to_schedule'),
            mock.patch.object(self.scheduler, 'get_routers_can_schedule')) as (
            mock_unscheduled_routers, mock_target_routers):
            mock_unscheduled_routers.return_value = mock.ANY
            mock_target_routers.return_value = None
            result = self.scheduler.auto_schedule_routers(
                self.plugin, mock.ANY, mock.ANY, mock.ANY)
        self.assertTrue(self.plugin.get_enabled_agent_on_host.called)
        self.assertFalse(result)

    def test_get_routers_to_schedule_with_router_ids(self):
        router_ids = ['foo_router_1', 'foo_router_2']
        expected_routers = [
            {'id': 'foo_router1'}, {'id': 'foo_router_2'}
        ]
        self.plugin.get_routers.return_value = expected_routers
        with mock.patch.object(self.scheduler,
                               'filter_unscheduled_routers') as mock_filter:
            mock_filter.return_value = expected_routers
            unscheduled_routers = self.scheduler.get_routers_to_schedule(
                mock.ANY, self.plugin, router_ids)
        mock_filter.assert_called_once_with(
            mock.ANY, self.plugin, expected_routers)
        self.assertEqual(expected_routers, unscheduled_routers)

    def test_get_routers_to_schedule_without_router_ids(self):
        expected_routers = [
            {'id': 'foo_router1'}, {'id': 'foo_router_2'}
        ]
        with mock.patch.object(self.scheduler,
                               'get_unscheduled_routers') as mock_get:
            mock_get.return_value = expected_routers
            unscheduled_routers = self.scheduler.get_routers_to_schedule(
                mock.ANY, self.plugin)
        mock_get.assert_called_once_with(mock.ANY, self.plugin)
        self.assertEqual(expected_routers, unscheduled_routers)

    def _test_get_routers_can_schedule(self, routers, agent, target_routers):
        self.plugin.get_l3_agent_candidates.return_value = agent
        result = self.scheduler.get_routers_can_schedule(
            mock.ANY, self.plugin, routers, mock.ANY)
        self.assertEqual(target_routers, result)

    def _test_filter_unscheduled_routers(self, routers, agents, expected):
        self.plugin.get_l3_agents_hosting_routers.return_value = agents
        unscheduled_routers = self.scheduler.filter_unscheduled_routers(
            mock.ANY, self.plugin, routers)
        self.assertEqual(expected, unscheduled_routers)

    def test_filter_unscheduled_routers_already_scheduled(self):
        self._test_filter_unscheduled_routers(
            [{'id': 'foo_router1'}, {'id': 'foo_router_2'}],
            [{'id': 'foo_agent_id'}], [])

    def test_filter_unscheduled_routers_non_scheduled(self):
        self._test_filter_unscheduled_routers(
            [{'id': 'foo_router1'}, {'id': 'foo_router_2'}],
            None, [{'id': 'foo_router1'}, {'id': 'foo_router_2'}])

    def test_get_routers_can_schedule_with_compat_agent(self):
        routers = [{'id': 'foo_router'}]
        self._test_get_routers_can_schedule(routers, mock.ANY, routers)

    def test_get_routers_can_schedule_with_no_compat_agent(self):
        routers = [{'id': 'foo_router'}]
        self._test_get_routers_can_schedule(routers, None, [])

    def test_bind_routers_centralized(self):
        routers = [{'id': 'foo_router'}]
        with mock.patch.object(self.scheduler, 'bind_router') as mock_bind:
            self.scheduler.bind_routers(mock.ANY, routers, mock.ANY)
        mock_bind.assert_called_once_with(mock.ANY, 'foo_router', mock.ANY)

    def test_bind_routers_dvr(self):
        routers = [{'id': 'foo_router', 'distributed': True}]
        agent = agents_db.Agent(id='foo_agent')
        with mock.patch.object(self.scheduler, 'dvr_has_binding') as mock_dvr:
            with mock.patch.object(self.scheduler, 'bind_router') as mock_bind:
                self.scheduler.bind_routers(mock.ANY, routers, agent)
        mock_dvr.assert_called_once_with(mock.ANY, 'foo_router', 'foo_agent')
        self.assertFalse(mock_bind.called)


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
                          l3_db.L3_NAT_db_mixin,
                          common_db_mixin.CommonDbMixin,
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
        self.agent1 = agent_db[0]

        callback.report_state(self.adminContext,
                              agent_state={'agent_state': SECOND_L3_AGENT},
                              time=timeutils.strtime())
        agent_db = self.plugin.get_agents_db(self.adminContext,
                                             filters={'host': [HOST]})
        self.agent_id2 = agent_db[0].id

    def _register_l3_dvr_agents(self):
        callback = agents_db.AgentExtRpcCallback()
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': DVR_L3_AGENT},
                              time=timeutils.strtime())
        agent_db = self.plugin.get_agents_db(self.adminContext,
                                             filters={'host': [HOST_DVR]})
        self.l3_dvr_agent = agent_db[0]

        callback.report_state(self.adminContext,
                              agent_state={'agent_state': DVR_SNAT_L3_AGENT},
                              time=timeutils.strtime())
        agent_db = self.plugin.get_agents_db(self.adminContext,
                                             filters={'host': [HOST_DVR_SNAT]})
        self.l3_dvr_snat_id = agent_db[0].id
        self.l3_dvr_snat_agent = agent_db[0]

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

    def _test_add_router_to_l3_agent(self,
                                     distributed=False,
                                     already_scheduled=False):
        agent_id = self.agent_id1
        agent = self.agent1
        if distributed:
            self._register_l3_dvr_agents()
            agent_id = self.l3_dvr_snat_id
            agent = self.l3_dvr_snat_agent
        router = self._make_router(self.fmt,
                                   tenant_id=str(uuid.uuid4()),
                                   name='r1')
        router['router']['distributed'] = distributed
        router['router']['external_gateway_info'] = None
        if already_scheduled:
            self._test_schedule_bind_router(agent, router)
        with contextlib.nested(
            mock.patch.object(self, "create_router_to_agent_binding"),
            mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.get_router',
                       return_value=router['router'])
        ) as (auto_s, gr):
            self.add_router_to_l3_agent(self.adminContext, agent_id,
                                        router['router']['id'])
            self.assertNotEqual(already_scheduled, auto_s.called)

    def test_add_router_to_l3_agent(self):
        self._test_add_router_to_l3_agent(distributed=False,
                                          already_scheduled=False)

    def test_add_distributed_router_to_l3_agent(self):
        self._test_add_router_to_l3_agent(distributed=True,
                                          already_scheduled=False)

    def test_add_router_to_l3_agent_already_scheduled(self):
        self._test_add_router_to_l3_agent(distributed=False,
                                          already_scheduled=True)

    def test_add_distributed_router_to_l3_agent_already_scheduled(self):
        self._test_add_router_to_l3_agent(distributed=True,
                                          already_scheduled=True)

    def test_schedule_router_distributed(self):
        scheduler = l3_agent_scheduler.ChanceScheduler()
        agent = agents_db.Agent()
        agent.admin_state_up = True
        agent.heartbeat_timestamp = timeutils.utcnow()
        sync_router = {
            'id': 'foo_router_id',
            'distributed': True
        }
        plugin = mock.Mock()
        plugin.get_router.return_value = sync_router
        plugin.get_l3_agents_hosting_routers.return_value = []
        plugin.get_l3_agents.return_value = [agent]
        plugin.get_l3_agent_candidates.return_value = [agent]
        with mock.patch.object(scheduler, 'bind_router'):
            scheduler._schedule_router(
                plugin, self.adminContext,
                'foo_router_id', None, {'gw_exists': True})
        expected_calls = [
            mock.call.get_router(mock.ANY, 'foo_router_id'),
            mock.call.schedule_snat_router(
                mock.ANY, 'foo_router_id', sync_router, True),
            mock.call.get_l3_agents_hosting_routers(
                mock.ANY, ['foo_router_id'], admin_state_up=True),
            mock.call.get_l3_agents(mock.ANY, active=True),
            mock.call.get_l3_agent_candidates(
                mock.ANY, sync_router, [agent], None),
        ]
        plugin.assert_has_calls(expected_calls)

    def _test_schedule_bind_router(self, agent, router):
        ctx = self.adminContext
        session = ctx.session
        db = l3_agentschedulers_db.RouterL3AgentBinding
        scheduler = l3_agent_scheduler.ChanceScheduler()

        rid = router['router']['id']
        scheduler.bind_router(ctx, rid, agent)
        results = (session.query(db).filter_by(router_id=rid).all())
        self.assertTrue(len(results) > 0)
        self.assertIn(agent.id, [bind.l3_agent_id for bind in results])

    def test_bind_new_router(self):
        router = self._make_router(self.fmt,
                                   tenant_id=str(uuid.uuid4()),
                                   name='r1')
        with mock.patch.object(l3_agent_scheduler.LOG, 'debug') as flog:
            self._test_schedule_bind_router(self.agent1, router)
            self.assertEqual(1, flog.call_count)
            args, kwargs = flog.call_args
            self.assertIn('is scheduled', args[0])

    def test_bind_existing_router(self):
        router = self._make_router(self.fmt,
                                   tenant_id=str(uuid.uuid4()),
                                   name='r2')
        self._test_schedule_bind_router(self.agent1, router)
        with mock.patch.object(l3_agent_scheduler.LOG, 'debug') as flog:
            self._test_schedule_bind_router(self.agent1, router)
            self.assertEqual(1, flog.call_count)
            args, kwargs = flog.call_args
            self.assertIn('has already been scheduled', args[0])

    def _check_get_l3_agent_candidates(self, router, agent_list, exp_host):
        candidates = self.get_l3_agent_candidates(self.adminContext,
                                                  router, agent_list,
                                                  subnet_id=None)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]['host'], exp_host)

    def test_get_l3_agent_candidates(self):
        self._register_l3_dvr_agents()
        router = self._make_router(self.fmt,
                                   tenant_id=str(uuid.uuid4()),
                                   name='r2')
        router['external_gateway_info'] = None
        router['id'] = str(uuid.uuid4())
        agent_list = [self.agent1, self.l3_dvr_agent]

        # test legacy agent_mode case: only legacy agent should be candidate
        router['distributed'] = False
        exp_host = FIRST_L3_AGENT.get('host')
        self._check_get_l3_agent_candidates(router, agent_list, exp_host)

        # test dvr agent_mode case only dvr agent should be candidate
        router['distributed'] = True
        exp_host = DVR_L3_AGENT.get('host')
        self._check_get_l3_agent_candidates(router, agent_list, exp_host)

        # test dvr_snat agent_mode cases: dvr_snat agent can host
        # centralized and distributed routers
        agent_list = [self.l3_dvr_snat_agent]
        exp_host = DVR_SNAT_L3_AGENT.get('host')
        self._check_get_l3_agent_candidates(router, agent_list, exp_host)
        router['distributed'] = False
        self._check_get_l3_agent_candidates(router, agent_list, exp_host)


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


class L3DvrScheduler(l3_db.L3_NAT_db_mixin,
                     l3_dvrscheduler_db.L3_DVRsch_db_mixin):
    pass


class L3DvrSchedulerTestCase(testlib_api.SqlTestCase,
                             testlib_plugin.PluginSetupHelper):

    def setUp(self):
        plugin = 'neutron.plugins.ml2.plugin.Ml2Plugin'
        self.setup_coreplugin(plugin)
        super(L3DvrSchedulerTestCase, self).setUp()
        self.adminContext = q_context.get_admin_context()
        self.dut = L3DvrScheduler()

    def test_dvr_update_router_addvm(self):
        port = {
                'device_id': 'abcd',
                'device_owner': 'compute:nova',
                'fixed_ips': [
                    {
                        'subnet_id': '80947d4a-fbc8-484b-9f92-623a6bfcf3e0',
                        'ip_address': '10.10.10.3'
                    }
                ]
        }
        dvr_port = {
                'id': 'dvr_port1',
                'device_id': 'r1',
                'device_owner': 'network:router_interface_distributed',
                'fixed_ips': [
                    {
                        'subnet_id': '80947d4a-fbc8-484b-9f92-623a6bfcf3e0',
                        'ip_address': '10.10.10.1'
                    }
                ]
        }
        r1 = {
              'id': 'r1',
              'distributed': True,
        }

        with contextlib.nested(
            mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
                       '.get_ports', return_value=[dvr_port]),
            mock.patch('neutron.manager.NeutronManager.get_service_plugins',
                       return_value=mock.Mock()),
            mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.get_router',
                       return_value=r1),
            mock.patch('neutron.api.rpc.agentnotifiers.l3_rpc_agent_api'
                       '.L3AgentNotifyAPI')):
            self.dut.dvr_update_router_addvm(self.adminContext, port)

    def test_get_dvr_routers_by_vmportid(self):
        dvr_port = {
                'id': 'dvr_port1',
                'device_id': 'r1',
                'device_owner': 'network:router_interface_distributed',
                'fixed_ips': [
                    {
                        'subnet_id': '80947d4a-fbc8-484b-9f92-623a6bfcf3e0',
                        'ip_address': '10.10.10.1'
                    }
                ]
        }
        r1 = {
              'id': 'r1',
              'distributed': True,
        }

        with contextlib.nested(
            mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
                       '.get_port', return_value=dvr_port),
            mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
                       '.get_ports', return_value=[dvr_port])):
            router_id = self.dut.get_dvr_routers_by_vmportid(self.adminContext,
                                                             dvr_port['id'])
            self.assertEqual(router_id.pop(), r1['id'])

    def test_get_subnet_ids_on_router(self):
        dvr_port = {
                'id': 'dvr_port1',
                'device_id': 'r1',
                'device_owner': 'network:router_interface_distributed',
                'fixed_ips': [
                    {
                        'subnet_id': '80947d4a-fbc8-484b-9f92-623a6bfcf3e0',
                        'ip_address': '10.10.10.1'
                    }
                ]
        }
        r1 = {
              'id': 'r1',
              'distributed': True,
        }

        with contextlib.nested(
            mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
                       '.get_ports', return_value=[dvr_port])):
            sub_ids = self.dut.get_subnet_ids_on_router(self.adminContext,
                                                        r1['id'])
            self.assertEqual(sub_ids.pop(),
                            dvr_port.get('fixed_ips').pop(0).get('subnet_id'))

    def test_check_ports_active_on_host_and_subnet(self):
        dvr_port = {
                'id': 'dvr_port1',
                'device_id': 'r1',
                'status': 'ACTIVE',
                'binding:host_id': 'thisHost',
                'device_owner': 'compute:nova',
                'fixed_ips': [
                    {
                        'subnet_id': '80947d4a-fbc8-484b-9f92-623a6bfcf3e0',
                        'ip_address': '10.10.10.1'
                    }
                ]
        }
        r1 = {
              'id': 'r1',
              'distributed': True,
        }
        with contextlib.nested(
            mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
                       '.get_ports', return_value=[dvr_port]),
            mock.patch('neutron.manager.NeutronManager.get_service_plugins',
                       return_value=mock.Mock()),
            mock.patch('neutron.db.l3_db.L3_NAT_db_mixin.get_router',
                       return_value=r1),
            mock.patch('neutron.api.rpc.agentnotifiers.l3_rpc_agent_api'
                       '.L3AgentNotifyAPI')):
            sub_ids = self.dut.get_subnet_ids_on_router(self.adminContext,
                                                        r1['id'])
            result = self.dut.check_ports_active_on_host_and_subnet(
                                                    self.adminContext,
                                                    'thisHost', 'dvr_port1',
                                                    sub_ids)
            self.assertFalse(result)

    def test_check_dvr_serviced_port_exists_on_subnet(self):
        vip_port = {
                'id': 'lbaas-vip-port1',
                'device_id': 'vip-pool-id',
                'status': 'ACTIVE',
                'binding:host_id': 'thisHost',
                'device_owner': constants.DEVICE_OWNER_LOADBALANCER,
                'fixed_ips': [
                    {
                        'subnet_id': 'my-subnet-id',
                        'ip_address': '10.10.10.1'
                    }
                ]
        }

        with contextlib.nested(
            mock.patch('neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
                       '.get_ports', return_value=[vip_port]),
            mock.patch('neutron.common.utils.is_dvr_serviced',
                       return_value=True)) as (get_ports_fn, dvr_serv_fn):
            result = self.dut.check_ports_active_on_host_and_subnet(
                                                    self.adminContext,
                                                    'thisHost',
                                                    'dvr1-intf-id',
                                                    'my-subnet-id')
            self.assertTrue(result)
            self.assertEqual(dvr_serv_fn.call_count, 1)

    def test_schedule_snat_router_with_snat_candidates(self):
        agent = agents_db.Agent()
        agent.admin_state_up = True
        agent.heartbeat_timestamp = timeutils.utcnow()
        with contextlib.nested(
            mock.patch.object(query.Query, 'first'),
            mock.patch.object(self.dut, 'get_l3_agents'),
            mock.patch.object(self.dut, 'get_snat_candidates'),
            mock.patch.object(self.dut, 'bind_snat_servicenode')) as (
                mock_query, mock_agents, mock_candidates, mock_bind):
            mock_query.return_value = []
            mock_agents.return_value = [agent]
            mock_candidates.return_value = [agent]
            self.dut.schedule_snat_router(
                self.adminContext, 'foo_router_id', mock.ANY, True)
        mock_bind.assert_called_once_with(
            self.adminContext, 'foo_router_id', [agent])

    def test_unbind_snat_servicenode(self):
        router_id = 'foo_router_id'
        core_plugin = mock.PropertyMock()
        type(self.dut)._core_plugin = core_plugin
        (self.dut._core_plugin.get_compute_ports_on_host_by_subnet.
         return_value) = []
        core_plugin.reset_mock()
        l3_notifier = mock.PropertyMock()
        type(self.dut).l3_rpc_notifier = l3_notifier
        binding = l3_dvrscheduler_db.CentralizedSnatL3AgentBinding(
            router_id=router_id, l3_agent_id='foo_l3_agent_id',
            l3_agent=agents_db.Agent())
        with contextlib.nested(
            mock.patch.object(query.Query, 'one'),
            mock.patch.object(self.adminContext.session, 'delete'),
            mock.patch.object(query.Query, 'delete'),
            mock.patch.object(self.dut, 'get_subnet_ids_on_router')) as (
                mock_query, mock_session, mock_delete, mock_get_subnets):
            mock_query.return_value = binding
            mock_get_subnets.return_value = ['foo_subnet_id']
            self.dut.unbind_snat_servicenode(self.adminContext, router_id)
        mock_get_subnets.assert_called_with(self.adminContext, router_id)
        self.assertTrue(mock_session.call_count)
        self.assertTrue(mock_delete.call_count)
        core_plugin.assert_called_once_with()
        l3_notifier.assert_called_once_with()
