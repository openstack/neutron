# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import mock
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import orm
import testtools

from neutron.api.rpc.handlers import l3_rpc
from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron import context
from neutron.db import agents_db
from neutron.db import common_db_mixin
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_hamode_db
from neutron.extensions import external_net
from neutron.extensions import l3
from neutron.extensions import l3_ext_ha_mode
from neutron.extensions import portbindings
from neutron.extensions import providernet
from neutron import manager
from neutron.scheduler import l3_agent_scheduler
from neutron.tests.common import helpers
from neutron.tests.unit import testlib_api

_uuid = uuidutils.generate_uuid


class FakeL3PluginWithAgents(common_db_mixin.CommonDbMixin,
                             l3_hamode_db.L3_HA_NAT_db_mixin,
                             l3_agentschedulers_db.L3AgentSchedulerDbMixin,
                             agents_db.AgentDbMixin):
    pass


class L3HATestFramework(testlib_api.SqlTestCase):
    def setUp(self):
        super(L3HATestFramework, self).setUp()

        self.admin_ctx = context.get_admin_context()
        self.setup_coreplugin('neutron.plugins.ml2.plugin.Ml2Plugin')
        self.core_plugin = manager.NeutronManager.get_plugin()
        notif_p = mock.patch.object(l3_hamode_db.L3_HA_NAT_db_mixin,
                                    '_notify_ha_interfaces_updated')
        self.notif_m = notif_p.start()
        cfg.CONF.set_override('allow_overlapping_ips', True)

        self.plugin = FakeL3PluginWithAgents()
        self.plugin.router_scheduler = l3_agent_scheduler.ChanceScheduler()
        self.agent1 = helpers.register_l3_agent()
        self.agent2 = helpers.register_l3_agent(
            'host_2', constants.L3_AGENT_MODE_DVR_SNAT)

    def _create_router(self, ha=True, tenant_id='tenant1', distributed=None,
                       ctx=None, admin_state_up=True):
        if ctx is None:
            ctx = self.admin_ctx
        ctx.tenant_id = tenant_id
        router = {'name': 'router1',
                  'admin_state_up': admin_state_up,
                  'tenant_id': tenant_id}
        if ha is not None:
            router['ha'] = ha
        if distributed is not None:
            router['distributed'] = distributed
        return self.plugin.create_router(ctx, {'router': router})

    def _migrate_router(self, router_id, ha):
        self._update_router(router_id, admin_state=False)
        self._update_router(router_id, ha=ha)
        return self._update_router(router_id, admin_state=True)

    def _update_router(self, router_id, ha=None, distributed=None, ctx=None,
                       admin_state=None):
        if ctx is None:
            ctx = self.admin_ctx
        data = {'ha': ha} if ha is not None else {}
        if distributed is not None:
            data['distributed'] = distributed
        if admin_state is not None:
            data['admin_state_up'] = admin_state
        return self.plugin._update_router_db(ctx, router_id, data)


class L3HATestCase(L3HATestFramework):

    def test_verify_configuration_succeed(self):
        # Default configuration should pass
        self.plugin._verify_configuration()

    def test_verify_configuration_l3_ha_net_cidr_is_not_a_cidr(self):
        cfg.CONF.set_override('l3_ha_net_cidr', 'not a cidr')
        self.assertRaises(
            l3_ext_ha_mode.HANetworkCIDRNotValid,
            self.plugin._verify_configuration)

    def test_verify_configuration_l3_ha_net_cidr_is_not_a_subnet(self):
        cfg.CONF.set_override('l3_ha_net_cidr', '10.0.0.1/8')
        self.assertRaises(
            l3_ext_ha_mode.HANetworkCIDRNotValid,
            self.plugin._verify_configuration)

    def test_verify_configuration_min_l3_agents_per_router_below_minimum(self):
        cfg.CONF.set_override('min_l3_agents_per_router', 0)
        self.assertRaises(
            l3_ext_ha_mode.HAMinimumAgentsNumberNotValid,
            self.plugin._check_num_agents_per_router)

    def test_verify_configuration_max_l3_agents_below_min_l3_agents(self):
        cfg.CONF.set_override('max_l3_agents_per_router', 3)
        cfg.CONF.set_override('min_l3_agents_per_router', 4)
        self.assertRaises(
            l3_ext_ha_mode.HAMaximumAgentsNumberNotValid,
            self.plugin._check_num_agents_per_router)

    def test_verify_configuration_max_l3_agents_unlimited(self):
        cfg.CONF.set_override('max_l3_agents_per_router',
                              l3_hamode_db.UNLIMITED_AGENTS_PER_ROUTER)
        self.plugin._check_num_agents_per_router()

    def test_get_ha_router_port_bindings(self):
        router = self._create_router()
        bindings = self.plugin.get_ha_router_port_bindings(
            self.admin_ctx, [router['id']])
        binding_dicts = [{'router_id': binding['router_id'],
                          'l3_agent_id': binding['l3_agent_id']}
                         for binding in bindings]
        self.assertIn({'router_id': router['id'],
                       'l3_agent_id': self.agent1['id']}, binding_dicts)
        self.assertIn({'router_id': router['id'],
                       'l3_agent_id': self.agent2['id']}, binding_dicts)

    def test_get_l3_bindings_hosting_router_with_ha_states_ha_router(self):
        router = self._create_router()
        self.plugin.update_routers_states(
            self.admin_ctx, {router['id']: 'active'}, self.agent1['host'])
        bindings = self.plugin.get_l3_bindings_hosting_router_with_ha_states(
            self.admin_ctx, router['id'])
        agent_ids = [(agent[0]['id'], agent[1]) for agent in bindings]
        self.assertIn((self.agent1['id'], 'active'), agent_ids)
        self.assertIn((self.agent2['id'], 'standby'), agent_ids)

    def test_get_l3_bindings_hosting_router_with_ha_states_agent_none(self):
        with mock.patch.object(self.plugin, 'schedule_router'):
            # Do not bind router to leave agents as None
            router = self._create_router()

        res = self.admin_ctx.session.query(
            l3_hamode_db.L3HARouterAgentPortBinding).filter(
            l3_hamode_db.L3HARouterAgentPortBinding.router_id == router['id']
        ).all()
        # Check that agents are None
        self.assertEqual([None, None], [r.agent for r in res])
        bindings = self.plugin.get_l3_bindings_hosting_router_with_ha_states(
            self.admin_ctx, router['id'])
        self.assertEqual([], bindings)

    def test_get_l3_bindings_hosting_router_with_ha_states_not_scheduled(self):
        router = self._create_router(ha=False)
        # Check that there no L3 agents scheduled for this router
        res = self.admin_ctx.session.query(
            l3_hamode_db.L3HARouterAgentPortBinding).filter(
            l3_hamode_db.L3HARouterAgentPortBinding.router_id == router['id']
        ).all()
        self.assertEqual([], [r.agent for r in res])
        bindings = self.plugin.get_l3_bindings_hosting_router_with_ha_states(
            self.admin_ctx, router['id'])
        self.assertEqual([], bindings)

    def test_get_l3_bindings_hosting_router_with_ha_states_active_and_dead(
            self):
        router = self._create_router()
        with mock.patch.object(agents_db.Agent, 'is_active',
                               new_callable=mock.PropertyMock,
                               return_value=False):
            self.plugin.update_routers_states(
                self.admin_ctx, {router['id']: 'active'}, self.agent1['host'])
            bindings = (
                self.plugin.get_l3_bindings_hosting_router_with_ha_states(
                    self.admin_ctx, router['id']))
            agent_ids = [(agent[0]['id'], agent[1]) for agent in bindings]
            self.assertIn((self.agent1['id'], 'standby'), agent_ids)

    def test_router_created_in_active_state(self):
        router = self._create_router()
        self.assertEqual(constants.ROUTER_STATUS_ACTIVE, router['status'])

    def test_router_update_stay_active(self):
        router = self._create_router()
        router['name'] = 'test_update'
        router_updated = self.plugin._update_router_db(self.admin_ctx,
                                                       router['id'], router)
        self.assertEqual(constants.ROUTER_STATUS_ACTIVE,
                         router_updated['status'])

    def test_allocating_router_hidden_from_sync(self):
        r1, r2 = self._create_router(), self._create_router()
        r1['status'] = constants.ROUTER_STATUS_ALLOCATING
        self.plugin._update_router_db(self.admin_ctx, r1['id'], r1)
        # store shorter name for readability
        get_method = self.plugin._get_active_l3_agent_routers_sync_data
        # r1 should be hidden
        expected = [self.plugin.get_router(self.admin_ctx, r2['id'])]
        self.assertEqual(expected, get_method(self.admin_ctx, None, None,
                                              [r1['id'], r2['id']]))
        # but once it transitions back, all is well in the world again!
        r1['status'] = constants.ROUTER_STATUS_ACTIVE
        self.plugin._update_router_db(self.admin_ctx, r1['id'], r1)
        expected.append(self.plugin.get_router(self.admin_ctx, r1['id']))
        # just compare ids since python3 won't let us sort dicts
        expected = sorted([r['id'] for r in expected])
        result = sorted([r['id'] for r in get_method(
              self.admin_ctx, None, None, [r1['id'], r2['id']])])
        self.assertEqual(expected, result)

    def test_router_ha_update_allocating_then_active(self):
        router = self._create_router()
        _orig = self.plugin._delete_ha_interfaces

        def check_state(context, router_id):
            self.assertEqual(
                constants.ROUTER_STATUS_ALLOCATING,
                self.plugin._get_router(context, router_id)['status'])
            return _orig(context, router_id)
        with mock.patch.object(self.plugin, '_delete_ha_interfaces',
                               side_effect=check_state) as ha_mock:
            router = self._migrate_router(router['id'], ha=False)
            self.assertTrue(ha_mock.called)
        self.assertEqual(constants.ROUTER_STATUS_ACTIVE,
                         router['status'])

    def test_router_created_allocating_state_during_interface_create(self):
        _orig = self.plugin._create_ha_interfaces

        def check_state(context, router_db, ha_network):
            self.assertEqual(constants.ROUTER_STATUS_ALLOCATING,
                             router_db.status)
            return _orig(context, router_db, ha_network)
        with mock.patch.object(self.plugin, '_create_ha_interfaces',
                               side_effect=check_state) as ha_mock:
            router = self._create_router()
            self.assertTrue(ha_mock.called)
        self.assertEqual(constants.ROUTER_STATUS_ACTIVE, router['status'])

    def test_ha_router_create(self):
        router = self._create_router()
        self.assertTrue(router['ha'])

    def test_ha_router_create_with_distributed(self):
        router = self._create_router(ha=True, distributed=True)
        self.assertTrue(router['ha'])
        self.assertTrue(router['distributed'])
        ha_network = self.plugin.get_ha_network(self.admin_ctx,
                                                router['tenant_id'])
        self.assertIsNotNone(ha_network)

    def test_no_ha_router_create(self):
        router = self._create_router(ha=False)
        self.assertFalse(router['ha'])

    def test_add_ha_network_settings(self):
        cfg.CONF.set_override('l3_ha_network_type', 'abc')
        cfg.CONF.set_override('l3_ha_network_physical_name', 'def')

        network = {}
        self.plugin._add_ha_network_settings(network)

        self.assertEqual('abc', network[providernet.NETWORK_TYPE])
        self.assertEqual('def', network[providernet.PHYSICAL_NETWORK])

    def test_router_create_with_ha_conf_enabled(self):
        cfg.CONF.set_override('l3_ha', True)

        router = self._create_router(ha=None)
        self.assertTrue(router['ha'])

    def test_ha_router_delete_with_distributed(self):
        router = self._create_router(ha=True, distributed=True)
        self.plugin.delete_router(self.admin_ctx, router['id'])
        self.assertRaises(l3.RouterNotFound, self.plugin._get_router,
                          self.admin_ctx, router['id'])

    def test_migration_from_ha(self):
        router = self._create_router()
        self.assertTrue(router['ha'])

        router = self._migrate_router(router['id'], False)
        self.assertFalse(router.extra_attributes['ha'])
        self.assertIsNone(router.extra_attributes['ha_vr_id'])

    def test_migration_to_ha(self):
        router = self._create_router(ha=False)
        self.assertFalse(router['ha'])

        router = self._migrate_router(router['id'], True)
        self.assertTrue(router.extra_attributes['ha'])
        self.assertIsNotNone(router.extra_attributes['ha_vr_id'])

    def test_migration_requires_admin_state_down(self):
        router = self._create_router(ha=False)
        self.assertRaises(n_exc.BadRequest,
                          self._update_router,
                          router['id'],
                          ha=True)

    def test_migrate_ha_router_to_distributed_and_ha(self):
        router = self._create_router(ha=True, admin_state_up=False,
                                     distributed=False)
        self.assertTrue(router['ha'])
        self.assertRaises(l3_ext_ha_mode.DVRmodeUpdateOfHaNotSupported,
                          self._update_router,
                          router['id'],
                          ha=True,
                          distributed=True)

    def test_migrate_ha_router_to_distributed_and_not_ha(self):
        router = self._create_router(ha=True, admin_state_up=False,
                                     distributed=False)
        self.assertTrue(router['ha'])
        self.assertRaises(l3_ext_ha_mode.DVRmodeUpdateOfHaNotSupported,
                          self._update_router,
                          router['id'],
                          ha=False,
                          distributed=True)

    def test_migrate_dvr_router_to_ha_and_not_dvr(self):
        router = self._create_router(ha=False, admin_state_up=False,
                                     distributed=True)
        self.assertTrue(router['distributed'])
        self.assertRaises(l3_ext_ha_mode.HAmodeUpdateOfDvrNotSupported,
                          self._update_router,
                          router['id'],
                          ha=True,
                          distributed=True)

    def test_migrate_dvr_router_to_ha_and_dvr(self):
        router = self._create_router(ha=False, admin_state_up=False,
                                     distributed=True)
        self.assertTrue(router['distributed'])
        self.assertRaises(l3_ext_ha_mode.HAmodeUpdateOfDvrNotSupported,
                          self._update_router,
                          router['id'],
                          ha=True,
                          distributed=True)

    def test_migrate_distributed_router_to_ha(self):
        router = self._create_router(ha=False, distributed=True)
        self.assertFalse(router['ha'])
        self.assertTrue(router['distributed'])

        self.assertRaises(l3_ext_ha_mode.HAmodeUpdateOfDvrNotSupported,
                          self._update_router,
                          router['id'],
                          ha=True)

    def test_migrate_legacy_router_to_distributed_and_ha(self):
        router = self._create_router(ha=False, distributed=False)
        self.assertFalse(router['ha'])
        self.assertFalse(router['distributed'])

        self.assertRaises(l3_ext_ha_mode.UpdateToDvrHamodeNotSupported,
                          self._update_router,
                          router['id'],
                          ha=True,
                          distributed=True)

    def test_unbind_ha_router(self):
        router = self._create_router()

        bound_agents = self.plugin.get_l3_agents_hosting_routers(
            self.admin_ctx, [router['id']])
        self.assertEqual(2, len(bound_agents))

        with mock.patch.object(manager.NeutronManager,
                               'get_service_plugins') as mock_manager:
            self.plugin._unbind_ha_router(self.admin_ctx, router['id'])

        bound_agents = self.plugin.get_l3_agents_hosting_routers(
            self.admin_ctx, [router['id']])
        self.assertEqual(0, len(bound_agents))
        self.assertEqual(2, mock_manager.call_count)

    def test_get_ha_sync_data_for_host_with_non_dvr_agent(self):
        with mock.patch.object(self.plugin,
                               '_get_dvr_sync_data') as mock_get_sync:
            self.plugin.supported_extension_aliases = ['dvr', 'l3-ha']
            self.plugin.get_ha_sync_data_for_host(self.admin_ctx,
                                                  self.agent1['host'],
                                                  self.agent1)
            self.assertFalse(mock_get_sync.called)

    def test_get_ha_sync_data_for_host_with_dvr_agent(self):
        with mock.patch.object(self.plugin,
                               '_get_dvr_sync_data') as mock_get_sync:
            self.plugin.supported_extension_aliases = ['dvr', 'l3-ha']
            self.plugin.get_ha_sync_data_for_host(self.admin_ctx,
                                                  self.agent2['host'],
                                                  self.agent2)
            self.assertTrue(mock_get_sync.called)

    def test_l3_agent_routers_query_interface(self):
        router = self._create_router()
        routers = self.plugin.get_ha_sync_data_for_host(self.admin_ctx,
                                                        self.agent1['host'],
                                                        self.agent1)
        self.assertEqual(1, len(routers))
        router = routers[0]

        self.assertIsNotNone(router.get('ha'))

        interface = router.get(constants.HA_INTERFACE_KEY)
        self.assertIsNotNone(interface)

        self.assertEqual(constants.DEVICE_OWNER_ROUTER_HA_INTF,
                         interface['device_owner'])

        subnets = interface['subnets']
        self.assertEqual(1, len(subnets))
        self.assertEqual(cfg.CONF.l3_ha_net_cidr, subnets[0]['cidr'])

    def test_unique_ha_network_per_tenant(self):
        tenant1 = _uuid()
        tenant2 = _uuid()
        self._create_router(tenant_id=tenant1)
        self._create_router(tenant_id=tenant2)
        ha_network1 = self.plugin.get_ha_network(self.admin_ctx, tenant1)
        ha_network2 = self.plugin.get_ha_network(self.admin_ctx, tenant2)
        self.assertNotEqual(
            ha_network1['network_id'], ha_network2['network_id'])

    def _deployed_router_change_ha_flag(self, to_ha):
        router1 = self._create_router(ha=not to_ha)
        routers = self.plugin.get_ha_sync_data_for_host(
            self.admin_ctx, self.agent1['host'], self.agent1)
        router = routers[0]
        interface = router.get(constants.HA_INTERFACE_KEY)
        if to_ha:
            self.assertIsNone(interface)
        else:
            self.assertIsNotNone(interface)

        self._migrate_router(router['id'], to_ha)
        self.plugin.schedule_router(self.admin_ctx, router1['id'])
        routers = self.plugin.get_ha_sync_data_for_host(
            self.admin_ctx, self.agent1['host'], self.agent1)
        router = routers[0]
        interface = router.get(constants.HA_INTERFACE_KEY)
        if to_ha:
            self.assertIsNotNone(interface)
        else:
            self.assertIsNone(interface)

    def test_deployed_router_can_have_ha_enabled(self):
        self._deployed_router_change_ha_flag(to_ha=True)

    def test_deployed_router_can_have_ha_disabled(self):
        self._deployed_router_change_ha_flag(to_ha=False)

    def test_create_ha_router_notifies_agent(self):
        self._create_router()
        self.assertTrue(self.notif_m.called)

    def test_update_router_to_ha_notifies_agent(self):
        router = self._create_router(ha=False)
        self.notif_m.reset_mock()
        self._migrate_router(router['id'], True)
        self.assertTrue(self.notif_m.called)

    def test_unique_vr_id_between_routers(self):
        self._create_router()
        self._create_router()
        routers = self.plugin.get_ha_sync_data_for_host(
            self.admin_ctx, self.agent1['host'], self.agent1)
        self.assertEqual(2, len(routers))
        self.assertNotEqual(routers[0]['ha_vr_id'], routers[1]['ha_vr_id'])

    @mock.patch('neutron.db.l3_hamode_db.VR_ID_RANGE', new=set(range(1, 1)))
    def test_vr_id_depleted(self):
        self.assertRaises(l3_ext_ha_mode.NoVRIDAvailable, self._create_router)

    @mock.patch('neutron.db.l3_hamode_db.VR_ID_RANGE', new=set(range(1, 2)))
    def test_vr_id_unique_range_per_tenant(self):
        self._create_router()
        self._create_router(tenant_id=_uuid())
        routers = self.plugin.get_ha_sync_data_for_host(
            self.admin_ctx, self.agent1['host'], self.agent1)
        self.assertEqual(2, len(routers))
        self.assertEqual(routers[0]['ha_vr_id'], routers[1]['ha_vr_id'])

    @mock.patch('neutron.db.l3_hamode_db.MAX_ALLOCATION_TRIES', new=2)
    def test_vr_id_allocation_contraint_conflict(self):
        router = self._create_router()
        network = self.plugin.get_ha_network(self.admin_ctx,
                                             router['tenant_id'])

        with mock.patch.object(self.plugin, '_get_allocated_vr_id',
                               return_value=set()) as alloc:
            self.assertRaises(l3_ext_ha_mode.MaxVRIDAllocationTriesReached,
                              self.plugin._allocate_vr_id, self.admin_ctx,
                              network.network_id, router['id'])
            self.assertEqual(2, len(alloc.mock_calls))

    def test_vr_id_allocation_delete_router(self):
        router = self._create_router()
        network = self.plugin.get_ha_network(self.admin_ctx,
                                             router['tenant_id'])

        allocs_before = self.plugin._get_allocated_vr_id(self.admin_ctx,
                                                         network.network_id)
        router = self._create_router()
        allocs_current = self.plugin._get_allocated_vr_id(self.admin_ctx,
                                                          network.network_id)
        self.assertNotEqual(allocs_before, allocs_current)

        self.plugin.delete_router(self.admin_ctx, router['id'])
        allocs_after = self.plugin._get_allocated_vr_id(self.admin_ctx,
                                                        network.network_id)
        self.assertEqual(allocs_before, allocs_after)

    def test_vr_id_allocation_router_migration(self):
        router = self._create_router()
        network = self.plugin.get_ha_network(self.admin_ctx,
                                             router['tenant_id'])

        allocs_before = self.plugin._get_allocated_vr_id(self.admin_ctx,
                                                         network.network_id)
        router = self._create_router()
        self._migrate_router(router['id'], False)
        allocs_after = self.plugin._get_allocated_vr_id(self.admin_ctx,
                                                        network.network_id)
        self.assertEqual(allocs_before, allocs_after)

    def test_one_ha_router_one_not(self):
        self._create_router(ha=False)
        self._create_router()
        routers = self.plugin.get_ha_sync_data_for_host(
            self.admin_ctx, self.agent1['host'], self.agent1)

        ha0 = routers[0]['ha']
        ha1 = routers[1]['ha']

        self.assertNotEqual(ha0, ha1)

    def test_add_ha_port_subtransactions_blocked(self):
        with self.admin_ctx.session.begin():
            self.assertRaises(RuntimeError, self.plugin.add_ha_port,
                              self.admin_ctx, 'id', 'id', 'id')

    def test_add_ha_port_binding_failure_rolls_back_port(self):
        router = self._create_router()
        device_filter = {'device_id': [router['id']]}
        ports_before = self.core_plugin.get_ports(
            self.admin_ctx, filters=device_filter)
        network = self.plugin.get_ha_network(self.admin_ctx,
                                             router['tenant_id'])

        with mock.patch.object(l3_hamode_db, 'L3HARouterAgentPortBinding',
                               side_effect=ValueError):
            self.assertRaises(ValueError, self.plugin.add_ha_port,
                              self.admin_ctx, router['id'], network.network_id,
                              router['tenant_id'])

        ports_after = self.core_plugin.get_ports(
            self.admin_ctx, filters=device_filter)

        self.assertEqual(ports_before, ports_after)

    def test_create_ha_network_binding_failure_rolls_back_network(self):
        networks_before = self.core_plugin.get_networks(self.admin_ctx)

        with mock.patch.object(l3_hamode_db,
                               'L3HARouterNetwork',
                               side_effect=ValueError):
            self.assertRaises(ValueError, self.plugin._create_ha_network,
                              self.admin_ctx, _uuid())

        networks_after = self.core_plugin.get_networks(self.admin_ctx)
        self.assertEqual(networks_before, networks_after)

    def test_create_ha_network_subnet_failure_rolls_back_network(self):
        networks_before = self.core_plugin.get_networks(self.admin_ctx)

        with mock.patch.object(self.plugin, '_create_ha_subnet',
                               side_effect=ValueError):
                self.assertRaises(ValueError, self.plugin._create_ha_network,
                                  self.admin_ctx, _uuid())

        networks_after = self.core_plugin.get_networks(self.admin_ctx)
        self.assertEqual(networks_before, networks_after)

    def test_create_ha_interfaces_and_ensure_network_net_exists(self):
        router = self._create_router()
        router_db = self.plugin._get_router(self.admin_ctx, router['id'])
        with mock.patch.object(self.plugin, '_create_ha_network') as create:
            self.plugin._create_ha_interfaces_and_ensure_network(
                self.admin_ctx, router_db)
            self.assertFalse(create.called)

    def test_create_ha_interfaces_and_ensure_network_concurrent_create(self):
        # create a non-ha router so we can manually invoke the create ha
        # interfaces call down below
        router = self._create_router(ha=False)
        router_db = self.plugin._get_router(self.admin_ctx, router['id'])
        orig_create = self.plugin._create_ha_network
        created_nets = []

        def _create_ha_network(*args, **kwargs):
            # create the network and then raise the error to simulate another
            # worker creating the network before us.
            created_nets.append(orig_create(*args, **kwargs))
            raise db_exc.DBDuplicateEntry(columns=['tenant_id'])
        with mock.patch.object(self.plugin, '_create_ha_network',
                               new=_create_ha_network):
            net = self.plugin._create_ha_interfaces_and_ensure_network(
                self.admin_ctx, router_db)[1]
        # ensure that it used the concurrently created network
        self.assertEqual([net], created_nets)

    def _test_ensure_with_patched_int_create(self, _create_ha_interfaces):
        # create a non-ha router so we can manually invoke the create ha
        # interfaces call down below
        router = self._create_router(ha=False)
        router_db = self.plugin._get_router(self.admin_ctx, router['id'])
        with mock.patch.object(self.plugin, '_create_ha_interfaces',
                               new=_create_ha_interfaces):
            self.plugin._create_ha_interfaces_and_ensure_network(
                self.admin_ctx, router_db)
            self.assertTrue(_create_ha_interfaces.called)

    def test_create_ha_interfaces_and_ensure_network_concurrent_delete(self):
        orig_create = self.plugin._create_ha_interfaces

        def _create_ha_interfaces(ctx, rdb, ha_net):
            # concurrent delete on the first attempt
            if not getattr(_create_ha_interfaces, 'called', False):
                setattr(_create_ha_interfaces, 'called', True)
                self.core_plugin.delete_network(self.admin_ctx,
                                                ha_net['network_id'])
            return orig_create(ctx, rdb, ha_net)
        self._test_ensure_with_patched_int_create(_create_ha_interfaces)

    def test_create_ha_interfaces_and_ensure_network_concurrent_swap(self):
        orig_create = self.plugin._create_ha_interfaces

        def _create_ha_interfaces(ctx, rdb, ha_net):
            # concurrent delete on the first attempt
            if not getattr(_create_ha_interfaces, 'called', False):
                setattr(_create_ha_interfaces, 'called', True)
                self.core_plugin.delete_network(self.admin_ctx,
                                                ha_net['network_id'])
                self.plugin._create_ha_network(self.admin_ctx,
                                               rdb.tenant_id)
            return orig_create(ctx, rdb, ha_net)

        self._test_ensure_with_patched_int_create(_create_ha_interfaces)

    def test_create_ha_network_tenant_binding_raises_duplicate(self):
        router = self._create_router()
        network = self.plugin.get_ha_network(self.admin_ctx,
                                             router['tenant_id'])
        self.plugin._create_ha_network_tenant_binding(
            self.admin_ctx, 't1', network['network_id'])
        with testtools.ExpectedException(db_exc.DBDuplicateEntry):
            self.plugin._create_ha_network_tenant_binding(
                self.admin_ctx, 't1', network['network_id'])

    def test_create_ha_interfaces_binding_failure_rolls_back_ports(self):
        router = self._create_router()
        network = self.plugin.get_ha_network(self.admin_ctx,
                                             router['tenant_id'])
        device_filter = {'device_id': [router['id']]}
        ports_before = self.core_plugin.get_ports(
            self.admin_ctx, filters=device_filter)

        router_db = self.plugin._get_router(self.admin_ctx, router['id'])
        with mock.patch.object(l3_hamode_db, 'L3HARouterAgentPortBinding',
                               side_effect=ValueError):
            self.assertRaises(ValueError, self.plugin._create_ha_interfaces,
                              self.admin_ctx, router_db, network)

        ports_after = self.core_plugin.get_ports(
            self.admin_ctx, filters=device_filter)
        self.assertEqual(ports_before, ports_after)

    def test_create_router_db_ha_attribute_failure_rolls_back_router(self):
        routers_before = self.plugin.get_routers(self.admin_ctx)

        for method in ('_set_vr_id',
                       '_create_ha_interfaces',
                       '_notify_ha_interfaces_updated'):
            with mock.patch.object(self.plugin, method,
                                   side_effect=ValueError):
                self.assertRaises(ValueError, self._create_router)

        routers_after = self.plugin.get_routers(self.admin_ctx)
        self.assertEqual(routers_before, routers_after)

    def test_get_active_host_for_ha_router(self):
        router = self._create_router()
        self.assertEqual(
            None,
            self.plugin.get_active_host_for_ha_router(
                self.admin_ctx, router['id']))
        self.plugin.update_routers_states(
            self.admin_ctx, {router['id']: 'active'}, self.agent2['host'])
        self.assertEqual(
            self.agent2['host'],
            self.plugin.get_active_host_for_ha_router(
                self.admin_ctx, router['id']))

    def test_update_routers_states(self):
        router1 = self._create_router()
        router2 = self._create_router()

        routers = self.plugin.get_ha_sync_data_for_host(
            self.admin_ctx, self.agent1['host'], self.agent1)
        for router in routers:
            self.assertEqual('standby', router[constants.HA_ROUTER_STATE_KEY])

        states = {router1['id']: 'active',
                  router2['id']: 'standby'}
        self.plugin.update_routers_states(
            self.admin_ctx, states, self.agent1['host'])

        routers = self.plugin.get_ha_sync_data_for_host(
            self.admin_ctx, self.agent1['host'], self.agent1)
        for router in routers:
            self.assertEqual(states[router['id']],
                             router[constants.HA_ROUTER_STATE_KEY])

    def test_set_router_states_handles_concurrently_deleted_router(self):
        router1 = self._create_router()
        router2 = self._create_router()
        bindings = self.plugin.get_ha_router_port_bindings(
            self.admin_ctx, [router1['id'], router2['id']])
        self.plugin.delete_router(self.admin_ctx, router1['id'])
        self.plugin._set_router_states(
            self.admin_ctx, bindings, {router1['id']: 'active',
                                       router2['id']: 'active'})
        routers = self.plugin.get_ha_sync_data_for_host(
            self.admin_ctx, self.agent1['host'], self.agent1)
        self.assertEqual('active', routers[0][constants.HA_ROUTER_STATE_KEY])

    def test_update_routers_states_port_not_found(self):
        router1 = self._create_router()
        port = {'id': 'foo', 'device_id': router1['id']}
        with mock.patch.object(self.core_plugin, 'get_ports',
                               return_value=[port]):
            with mock.patch.object(
                    self.core_plugin, 'update_port',
                    side_effect=n_exc.PortNotFound(port_id='foo')):
                states = {router1['id']: 'active'}
                self.plugin.update_routers_states(
                    self.admin_ctx, states, self.agent1['host'])

    def test_exclude_dvr_agents_for_ha_candidates(self):
        """Test dvr agents configured with "dvr" only, as opposed to "dvr_snat",
        are excluded.
        This test case tests that when get_number_of_agents_for_scheduling
        is called, it does not count dvr only agents.
        """
        # Test setup registers two l3 agents.
        # Register another l3 agent with dvr mode and assert that
        # get_number_of_ha_agent_candidates return 2.
        helpers.register_l3_agent('host_3', constants.L3_AGENT_MODE_DVR)
        num_ha_candidates = self.plugin.get_number_of_agents_for_scheduling(
            self.admin_ctx)
        self.assertEqual(2, num_ha_candidates)

    def test_include_dvr_snat_agents_for_ha_candidates(self):
        """Test dvr agents configured with "dvr_snat" are excluded.
        This test case tests that when get_number_of_agents_for_scheduling
        is called, it ounts dvr_snat agents.
        """
        # Test setup registers two l3 agents.
        # Register another l3 agent with dvr mode and assert that
        # get_number_of_ha_agent_candidates return 2.
        helpers.register_l3_agent('host_3', constants.L3_AGENT_MODE_DVR_SNAT)
        num_ha_candidates = self.plugin.get_number_of_agents_for_scheduling(
            self.admin_ctx)
        self.assertEqual(3, num_ha_candidates)

    def test_get_number_of_agents_for_scheduling_not_enough_agents(self):
        cfg.CONF.set_override('min_l3_agents_per_router', 3)
        helpers.kill_agent(helpers.register_l3_agent(host='l3host_3')['id'])
        self.assertRaises(l3_ext_ha_mode.HANotEnoughAvailableAgents,
                          self.plugin.get_number_of_agents_for_scheduling,
                          self.admin_ctx)

    def test_ha_network_deleted_if_no_ha_router_present_two_tenants(self):
        # Create two routers in different tenants.
        router1 = self._create_router()
        router2 = self._create_router(tenant_id='tenant2')
        nets_before = [net['name'] for net in
                       self.core_plugin.get_networks(self.admin_ctx)]
        # Check that HA networks created for each tenant
        self.assertIn('HA network tenant %s' % router1['tenant_id'],
                      nets_before)
        self.assertIn('HA network tenant %s' % router2['tenant_id'],
                      nets_before)
        # Delete router1
        self.plugin.delete_router(self.admin_ctx, router1['id'])
        nets_after = [net['name'] for net in
                      self.core_plugin.get_networks(self.admin_ctx)]
        # Check that HA network for tenant1 is deleted and for tenant2 is not.
        self.assertNotIn('HA network tenant %s' % router1['tenant_id'],
                         nets_after)
        self.assertIn('HA network tenant %s' % router2['tenant_id'],
                      nets_after)

    def test_ha_network_is_not_delete_if_ha_router_is_present(self):
        # Create 2 routers in one tenant and check if one is deleted, HA
        # network still exists.
        router1 = self._create_router()
        router2 = self._create_router()
        nets_before = [net['name'] for net in
                       self.core_plugin.get_networks(self.admin_ctx)]
        self.assertIn('HA network tenant %s' % router1['tenant_id'],
                      nets_before)
        self.plugin.delete_router(self.admin_ctx, router2['id'])
        nets_after = [net['name'] for net in
                      self.core_plugin.get_networks(self.admin_ctx)]
        self.assertIn('HA network tenant %s' % router1['tenant_id'],
                      nets_after)

    def test_ha_network_delete_ha_and_non_ha_router(self):
        # Create HA and non-HA router. Check after deletion HA router HA
        # network is deleted.
        router1 = self._create_router(ha=False)
        router2 = self._create_router()
        nets_before = [net['name'] for net in
                       self.core_plugin.get_networks(self.admin_ctx)]
        self.assertIn('HA network tenant %s' % router1['tenant_id'],
                      nets_before)
        self.plugin.delete_router(self.admin_ctx, router2['id'])
        nets_after = [net['name'] for net in
                      self.core_plugin.get_networks(self.admin_ctx)]
        self.assertNotIn('HA network tenant %s' % router1['tenant_id'],
                         nets_after)

    def _test_ha_network_is_not_deleted_raise_exception(self, exception):
        router1 = self._create_router()
        nets_before = [net['name'] for net in
                       self.core_plugin.get_networks(self.admin_ctx)]
        self.assertIn('HA network tenant %s' % router1['tenant_id'],
                      nets_before)
        with mock.patch.object(self.plugin, '_delete_ha_network',
                               side_effect=exception):
            self.plugin.delete_router(self.admin_ctx, router1['id'])
            nets_after = [net['name'] for net in
                          self.core_plugin.get_networks(self.admin_ctx)]
            self.assertIn('HA network tenant %s' % router1['tenant_id'],
                          nets_after)

    def test_ha_network_is_not_deleted_if_another_ha_router_is_created(self):
        # If another router was created during deletion of current router,
        # _delete_ha_network will fail with InvalidRequestError. Check that HA
        # network won't be deleted.
        self._test_ha_network_is_not_deleted_raise_exception(
            sa.exc.InvalidRequestError)

    def test_ha_network_is_not_deleted_if_network_in_use(self):
        self._test_ha_network_is_not_deleted_raise_exception(
            n_exc.NetworkInUse(net_id="foo_net_id"))

    def test_ha_network_is_not_deleted_if_db_deleted_error(self):
        self._test_ha_network_is_not_deleted_raise_exception(
            orm.exc.ObjectDeletedError(None))

    def test_ha_router_create_failed_no_ha_network_delete(self):
        tenant_id = "foo_tenant_id"
        nets_before = self.core_plugin.get_networks(self.admin_ctx)
        self.assertNotIn('HA network tenant %s' % tenant_id,
                         nets_before)

        # Unable to create HA network
        with mock.patch.object(self.core_plugin, 'create_network',
                               side_effect=n_exc.NoNetworkAvailable):
            self.assertRaises(n_exc.NoNetworkAvailable,
                              self._create_router,
                              True,
                              tenant_id)
            nets_after = self.core_plugin.get_networks(self.admin_ctx)
            self.assertEqual(nets_before, nets_after)
            self.assertNotIn('HA network tenant %s' % tenant_id,
                             nets_after)

    def test_update_port_status_port_bingding_deleted_concurrently(self):
        router1 = self._create_router()
        states = {router1['id']: 'active'}
        with mock.patch.object(self.plugin, 'get_ha_router_port_bindings'):
            (self.admin_ctx.session.query(
                 l3_hamode_db.L3HARouterAgentPortBinding).
             filter_by(router_id=router1['id']).delete())
            self.plugin.update_routers_states(
                self.admin_ctx, states, self.agent1['host'])


class L3HAModeDbTestCase(L3HATestFramework):

    def _create_network(self, plugin, ctx, name='net',
                        tenant_id='tenant1', external=False):
        network = {'network': {'name': name,
                               'shared': False,
                               'admin_state_up': True,
                               'tenant_id': tenant_id,
                               external_net.EXTERNAL: external}}
        return plugin.create_network(ctx, network)['id']

    def _create_subnet(self, plugin, ctx, network_id, cidr='10.0.0.0/8',
                       name='subnet', tenant_id='tenant1'):
        subnet = {'subnet': {'name': name,
                  'ip_version': 4,
                  'network_id': network_id,
                  'cidr': cidr,
                  'gateway_ip': attributes.ATTR_NOT_SPECIFIED,
                  'allocation_pools': attributes.ATTR_NOT_SPECIFIED,
                  'dns_nameservers': attributes.ATTR_NOT_SPECIFIED,
                  'host_routes': attributes.ATTR_NOT_SPECIFIED,
                  'tenant_id': tenant_id,
                  'enable_dhcp': True,
                  'ipv6_ra_mode': attributes.ATTR_NOT_SPECIFIED}}
        created_subnet = plugin.create_subnet(ctx, subnet)
        return created_subnet

    def test_remove_ha_in_use(self):
        router = self._create_router(ctx=self.admin_ctx)
        network_id = self._create_network(self.core_plugin, self.admin_ctx)
        subnet = self._create_subnet(self.core_plugin, self.admin_ctx,
                                     network_id)
        interface_info = {'subnet_id': subnet['id']}
        self.plugin.add_router_interface(self.admin_ctx,
                                         router['id'],
                                         interface_info)
        self.assertRaises(l3.RouterInUse, self.plugin.delete_router,
                          self.admin_ctx, router['id'])
        bindings = self.plugin.get_ha_router_port_bindings(
            self.admin_ctx, [router['id']])
        self.assertEqual(2, len(bindings))

    def test_update_router_port_bindings_no_ports(self):
        self.plugin._update_router_port_bindings(
            self.admin_ctx, {}, self.agent1['host'])

    def _get_first_interface(self, router_id):
        device_filter = {'device_id': [router_id],
                         'device_owner':
                         [constants.DEVICE_OWNER_ROUTER_INTF]}
        return self.core_plugin.get_ports(
            self.admin_ctx,
            filters=device_filter)[0]

    def test_update_router_port_bindings_updates_host(self):
        network_id = self._create_network(self.core_plugin, self.admin_ctx)
        subnet = self._create_subnet(self.core_plugin, self.admin_ctx,
                                     network_id)
        interface_info = {'subnet_id': subnet['id']}

        router = self._create_router()
        self.plugin.add_router_interface(self.admin_ctx,
                                         router['id'],
                                         interface_info)
        self.plugin._update_router_port_bindings(
            self.admin_ctx, {router['id']: 'active'}, self.agent1['host'])

        port = self._get_first_interface(router['id'])
        self.assertEqual(self.agent1['host'], port[portbindings.HOST_ID])

        self.plugin._update_router_port_bindings(
            self.admin_ctx, {router['id']: 'active'}, self.agent2['host'])
        port = self._get_first_interface(router['id'])
        self.assertEqual(self.agent2['host'], port[portbindings.HOST_ID])

    def test_ensure_host_set_on_ports_dvr_ha_binds_to_active(self):
        agent3 = helpers.register_l3_agent('host_3',
                                           constants.L3_AGENT_MODE_DVR_SNAT)
        ext_net = self._create_network(self.core_plugin, self.admin_ctx,
                                       external=True)
        int_net = self._create_network(self.core_plugin, self.admin_ctx)
        subnet = self._create_subnet(self.core_plugin, self.admin_ctx,
                                     int_net)
        interface_info = {'subnet_id': subnet['id']}
        router = self._create_router(ha=True, distributed=True)
        self.plugin._update_router_gw_info(self.admin_ctx, router['id'],
                                           {'network_id': ext_net})
        self.plugin.add_router_interface(self.admin_ctx,
                                         router['id'],
                                         interface_info)
        bindings = self.plugin.get_ha_router_port_bindings(
            self.admin_ctx, router_ids=[router['id']],
            host=self.agent2['host'])
        self.plugin._set_router_states(self.admin_ctx, bindings,
                                       {router['id']: 'active'})
        callback = l3_rpc.L3RpcCallback()
        callback._l3plugin = self.plugin
        # Get router with interfaces
        router = self.plugin._get_dvr_sync_data(self.admin_ctx,
                                                self.agent2['host'],
                                                self.agent2, [router['id']])[0]

        callback._ensure_host_set_on_ports(self.admin_ctx, agent3['host'],
                                           [router])
        device_filter = {'device_id': [router['id']],
                         'device_owner':
                             [constants.DEVICE_OWNER_ROUTER_SNAT]
                         }
        port = self.core_plugin.get_ports(self.admin_ctx,
                                          filters=device_filter)[0]
        self.assertNotEqual(agent3['host'], port[portbindings.HOST_ID])

        callback._ensure_host_set_on_ports(self.admin_ctx,
                                           self.agent2['host'], [router])
        port = self.core_plugin.get_ports(self.admin_ctx,
                                          filters=device_filter)[0]
        self.assertEqual(self.agent2['host'], port[portbindings.HOST_ID])

    def test_ensure_host_set_on_ports_binds_correctly(self):
        network_id = self._create_network(self.core_plugin, self.admin_ctx)
        subnet = self._create_subnet(self.core_plugin, self.admin_ctx,
                                     network_id)
        interface_info = {'subnet_id': subnet['id']}

        router = self._create_router()
        self.plugin.add_router_interface(self.admin_ctx,
                                         router['id'],
                                         interface_info)
        port = self._get_first_interface(router['id'])
        self.assertEqual('', port[portbindings.HOST_ID])

        # Update the router object to include the first interface
        router = (
            self.plugin.list_active_sync_routers_on_active_l3_agent(
                self.admin_ctx, self.agent1['host'], [router['id']]))[0]

        # ensure_host_set_on_ports binds an unbound port
        callback = l3_rpc.L3RpcCallback()
        callback._l3plugin = self.plugin
        callback._ensure_host_set_on_ports(
            self.admin_ctx, self.agent1['host'], [router])
        port = self._get_first_interface(router['id'])
        self.assertEqual(self.agent1['host'], port[portbindings.HOST_ID])

        # ensure_host_set_on_ports does not rebind a bound port
        router = (
            self.plugin.list_active_sync_routers_on_active_l3_agent(
                self.admin_ctx, self.agent1['host'], [router['id']]))[0]
        callback._ensure_host_set_on_ports(
            self.admin_ctx, self.agent2['host'], [router])
        port = self._get_first_interface(router['id'])
        self.assertEqual(self.agent1['host'], port[portbindings.HOST_ID])


class L3HAUserTestCase(L3HATestFramework):

    def setUp(self):
        super(L3HAUserTestCase, self).setUp()
        self.user_ctx = context.Context('', _uuid())

    def test_create_ha_router(self):
        self._create_router(ctx=self.user_ctx)

    def test_update_router(self):
        router = self._create_router(ctx=self.user_ctx)
        self._update_router(router['id'], ctx=self.user_ctx)

    def test_delete_router(self):
        router = self._create_router(ctx=self.user_ctx)
        self.plugin.delete_router(self.user_ctx, router['id'])
