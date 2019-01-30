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

from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as providernet
from neutron_lib.callbacks import events
from neutron_lib.callbacks import exceptions as c_exc
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.exceptions import l3_ext_ha_mode as l3ha_exc
from neutron_lib.objects import exceptions
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import orm
import testtools

from neutron.agent.common import utils as agent_utils
from neutron.api.rpc.handlers import l3_rpc
from neutron.common import constants as n_const
from neutron.db import agents_db
from neutron.db import common_db_mixin
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_hamode_db
from neutron.db.models import l3ha as l3ha_model
from neutron.objects import l3_hamode
from neutron.scheduler import l3_agent_scheduler
from neutron.services.revisions import revision_plugin
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

        self.setup_coreplugin('ml2')
        self.core_plugin = directory.get_plugin()
        notif_p = mock.patch.object(l3_hamode_db.L3_HA_NAT_db_mixin,
                                    '_notify_router_updated')
        self.notif_m = notif_p.start()
        cfg.CONF.set_override('allow_overlapping_ips', True)

        self.plugin = FakeL3PluginWithAgents()
        directory.add_plugin(plugin_constants.L3, self.plugin)
        self.plugin.router_scheduler = l3_agent_scheduler.ChanceScheduler()
        self.agent1 = helpers.register_l3_agent()
        self.agent2 = helpers.register_l3_agent(
            'host_2', constants.L3_AGENT_MODE_DVR_SNAT)

    @property
    def admin_ctx(self):
        # Property generates a new session on each reference so different
        # API calls don't share a session with possible stale objects
        return context.get_admin_context()

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
        self.plugin.update_router(ctx, router_id, {'router': data})
        return self.plugin._get_router(ctx, router_id)


class L3HATestCase(L3HATestFramework):

    def test_verify_configuration_succeed(self):
        # Default configuration should pass
        self.plugin._verify_configuration()

    def test_verify_configuration_l3_ha_net_cidr_is_not_a_cidr(self):
        cfg.CONF.set_override('l3_ha_net_cidr', 'not a cidr')
        self.assertRaises(
            l3ha_exc.HANetworkCIDRNotValid,
            self.plugin._verify_configuration)

    def test_verify_configuration_l3_ha_net_cidr_is_not_a_subnet(self):
        cfg.CONF.set_override('l3_ha_net_cidr', '10.0.0.1/8')
        self.assertRaises(
            l3ha_exc.HANetworkCIDRNotValid,
            self.plugin._verify_configuration)

    def test_verify_configuration_max_l3_agents_below_0(self):
        cfg.CONF.set_override('max_l3_agents_per_router', -5)
        self.assertRaises(
            l3ha_exc.HAMaximumAgentsNumberNotValid,
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

    def test_get_l3_bindings_hosting_router_with_ha_states_not_scheduled(self):
        router = self._create_router(ha=False)
        # Check that there no L3 agents scheduled for this router
        res = l3_hamode.L3HARouterAgentPortBinding.get_objects(
            self.admin_ctx, router_id=router['id'])
        self.assertEqual([], [r.agent for r in res])
        bindings = self.plugin.get_l3_bindings_hosting_router_with_ha_states(
            self.admin_ctx, router['id'])
        self.assertEqual([], bindings)

    def _assert_ha_state_for_agent(self, router, agent,
                                   state=n_const.HA_ROUTER_STATE_STANDBY):
        bindings = (
            self.plugin.get_l3_bindings_hosting_router_with_ha_states(
                self.admin_ctx, router['id']))
        agent_ids = [(a[0]['id'], a[1]) for a in bindings]
        self.assertIn((agent['id'], state), agent_ids)

    def test_get_l3_bindings_hosting_router_with_ha_states_active_and_dead(
            self):
        router = self._create_router()
        self.plugin.update_routers_states(
            self.admin_ctx, {router['id']: n_const.HA_ROUTER_STATE_ACTIVE},
            self.agent1['host'])
        self.plugin.update_routers_states(
            self.admin_ctx, {router['id']: n_const.HA_ROUTER_STATE_ACTIVE},
            self.agent2['host'])
        with mock.patch.object(agent_utils, 'is_agent_down',
                               return_value=True):
            self._assert_ha_state_for_agent(router, self.agent1)

    def test_get_l3_bindings_hosting_router_agents_admin_state_up_is_false(
            self):
        router = self._create_router()
        self.plugin.update_routers_states(
            self.admin_ctx, {router['id']: n_const.HA_ROUTER_STATE_ACTIVE},
            self.agent1['host'])
        self.plugin.update_routers_states(
            self.admin_ctx, {router['id']: n_const.HA_ROUTER_STATE_ACTIVE},
            self.agent2['host'])
        helpers.set_agent_admin_state(self.agent1['id'])
        self._assert_ha_state_for_agent(router, self.agent1)

    def test_get_l3_bindings_hosting_router_with_ha_states_one_dead(self):
        router = self._create_router()
        self.plugin.update_routers_states(
            self.admin_ctx, {router['id']: n_const.HA_ROUTER_STATE_ACTIVE},
            self.agent1['host'])
        self.plugin.update_routers_states(
            self.admin_ctx, {router['id']: n_const.HA_ROUTER_STATE_STANDBY},
            self.agent2['host'])
        with mock.patch.object(agent_utils, 'is_agent_down',
                               return_value=True):
            self._assert_ha_state_for_agent(
                router, self.agent1, state=n_const.HA_ROUTER_STATE_ACTIVE)

    def test_ha_router_create(self):
        router = self._create_router()
        self.assertTrue(router['ha'])

    def test_ha_router_create_with_distributed(self):
        helpers.register_l3_agent(
            'host_3', constants.L3_AGENT_MODE_DVR_SNAT)
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

    def test_ha_interface_concurrent_create_on_delete(self):
        # this test depends on protection from the revision plugin so
        # we have to initialize it
        revision_plugin.RevisionPlugin()
        router = self._create_router(ha=True)

        def jam_in_interface(*args, **kwargs):
            ctx = context.get_admin_context()
            net = self.plugin._ensure_vr_id_and_network(
                ctx, self.plugin._get_router(ctx, router['id']))
            self.plugin.add_ha_port(
                ctx, router['id'], net.network_id, router['tenant_id'])
            registry.unsubscribe(jam_in_interface, resources.ROUTER,
                                 events.PRECOMMIT_DELETE)
        registry.subscribe(jam_in_interface, resources.ROUTER,
                           events.PRECOMMIT_DELETE)
        self.plugin.delete_router(self.admin_ctx, router['id'])

    def test_ha_router_delete_with_distributed(self):
        router = self._create_router(ha=True, distributed=True)
        self.plugin.delete_router(self.admin_ctx, router['id'])
        self.assertRaises(l3_exc.RouterNotFound, self.plugin._get_router,
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
        e = self.assertRaises(c_exc.CallbackFailure,
                              self._update_router,
                              router['id'],
                              ha=True)
        self.assertIsInstance(e.inner_exceptions[0],
                              n_exc.BadRequest)

    def test_migrate_ha_router_to_distributed_and_ha(self):
        router = self._create_router(ha=True, admin_state_up=False,
                                     distributed=False)
        self.assertTrue(router['ha'])

        after_update = self._update_router(router['id'],
                                           ha=True, distributed=True)
        self.assertTrue(after_update.extra_attributes.ha)
        self.assertTrue(after_update.extra_attributes.distributed)

    def test_migrate_ha_router_to_distributed_and_not_ha(self):
        router = self._create_router(ha=True, admin_state_up=False,
                                     distributed=False)
        self.assertTrue(router['ha'])

        after_update = self._update_router(router['id'],
                                           ha=False, distributed=True)
        self.assertFalse(after_update.extra_attributes.ha)
        self.assertTrue(after_update.extra_attributes.distributed)

    def test_migrate_dvr_router_to_ha_and_not_dvr(self):
        router = self._create_router(ha=False, admin_state_up=False,
                                     distributed=True)
        self.assertTrue(router['distributed'])

        after_update = self._update_router(router['id'],
                                           ha=True, distributed=False)
        self.assertTrue(after_update.extra_attributes.ha)
        self.assertFalse(after_update.extra_attributes.distributed)

    def test_migrate_dvr_router_to_ha_and_dvr(self):
        router = self._create_router(ha=False, admin_state_up=False,
                                     distributed=True)
        self.assertTrue(router['distributed'])

        after_update = self._update_router(router['id'],
                                           ha=True, distributed=True)
        self.assertTrue(after_update.extra_attributes.ha)
        self.assertTrue(after_update.extra_attributes.distributed)

    def test_migrate_distributed_router_to_ha(self):
        router = self._create_router(ha=False, admin_state_up=False,
                                     distributed=True)
        self.assertFalse(router['ha'])
        self.assertTrue(router['distributed'])

        after_update = self._update_router(router['id'],
                                           ha=True, distributed=False)
        self.assertTrue(after_update.extra_attributes.ha)
        self.assertFalse(after_update.extra_attributes.distributed)

    def test_migrate_legacy_router_to_distributed_and_ha(self):
        router = self._create_router(ha=False, admin_state_up=False,
                                     distributed=False)
        self.assertFalse(router['ha'])
        self.assertFalse(router['distributed'])

        after_update = self._update_router(router['id'],
                                           ha=True, distributed=True)
        self.assertTrue(after_update.extra_attributes.ha)
        self.assertTrue(after_update.extra_attributes.distributed)

    def test_unbind_ha_router(self):
        router = self._create_router()

        bound_agents = self.plugin.get_l3_agents_hosting_routers(
            self.admin_ctx, [router['id']])
        self.assertEqual(2, len(bound_agents))

        self.plugin._unbind_ha_router(self.admin_ctx, router['id'])
        bound_agents = self.plugin.get_l3_agents_hosting_routers(
            self.admin_ctx, [router['id']])
        self.assertEqual(0, len(bound_agents))

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

    def test_l3_agent_routers_query_interface_includes_dvrsnat(self):
        router = self._create_router(distributed=True)
        routers = self.plugin.get_ha_sync_data_for_host(self.admin_ctx,
                                                        'a-dvr_snat-host',
                                                        self.agent2)
        self.assertEqual(1, len(routers))
        router = routers[0]

        self.assertTrue(router.get('ha'))

        interface = router.get(constants.HA_INTERFACE_KEY)
        self.assertIsNone(interface)

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
        self.assertEqual(constants.ERROR,
                         self._create_router()['status'])

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

        router_db = self.plugin._get_router(self.admin_ctx, router['id'])
        self.assertIsNone(self.plugin._ensure_vr_id(self.admin_ctx,
                                                    router_db, network))

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

    def test_migration_delete_ha_network_if_last_router(self):
        router = self._create_router()

        self._migrate_router(router['id'], False)
        self.assertIsNone(
            self.plugin.get_ha_network(self.admin_ctx, router['tenant_id']))

    def test_migration_no_delete_ha_network_if_not_last_router(self):
        router = self._create_router()
        router2 = self._create_router()

        network = self.plugin.get_ha_network(self.admin_ctx,
                                             router['tenant_id'])
        network2 = self.plugin.get_ha_network(self.admin_ctx,
                                              router2['tenant_id'])
        self.assertEqual(network.network_id, network2.network_id)

        self._migrate_router(router['id'], False)
        self.assertIsNotNone(
            self.plugin.get_ha_network(self.admin_ctx, router2['tenant_id']))

    def test_one_ha_router_one_not(self):
        self._create_router(ha=False)
        self._create_router()
        routers = self.plugin.get_ha_sync_data_for_host(
            self.admin_ctx, self.agent1['host'], self.agent1)

        ha0 = routers[0]['ha']
        ha1 = routers[1]['ha']

        self.assertNotEqual(ha0, ha1)

    def test_add_ha_port_subtransactions_blocked(self):
        ctx = self.admin_ctx
        with ctx.session.begin():
            self.assertRaises(RuntimeError, self.plugin.add_ha_port,
                              ctx, 'id', 'id', 'id')

    def test_add_ha_port_binding_failure_rolls_back_port(self):
        router = self._create_router()
        device_filter = {'device_id': [router['id']]}
        ports_before = self.core_plugin.get_ports(
            self.admin_ctx, filters=device_filter)
        network = self.plugin.get_ha_network(self.admin_ctx,
                                             router['tenant_id'])

        with mock.patch.object(l3ha_model, 'L3HARouterAgentPortBinding',
                               side_effect=ValueError):
            self.assertRaises(ValueError, self.plugin.add_ha_port,
                              self.admin_ctx, router['id'], network.network_id,
                              router['tenant_id'])

        ports_after = self.core_plugin.get_ports(
            self.admin_ctx, filters=device_filter)

        self.assertEqual(ports_before, ports_after)

    def test_create_ha_network_binding_failure_rolls_back_network(self):
        networks_before = self.core_plugin.get_networks(self.admin_ctx)

        with mock.patch.object(l3_hamode, 'L3HARouterNetwork',
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

    def test_ensure_vr_id_and_network_net_exists(self):
        router = self._create_router()
        router_db = self.plugin._get_router(self.admin_ctx, router['id'])
        with mock.patch.object(self.plugin, '_create_ha_network') as create:
            self.plugin._ensure_vr_id_and_network(
                self.admin_ctx, router_db)
            self.assertFalse(create.called)

    def test_ensure_vr_id_and_network_concurrent_create(self):
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
            net = self.plugin._ensure_vr_id_and_network(
                self.admin_ctx, router_db)
        # ensure that it used the concurrently created network
        self.assertEqual([net], created_nets)

    def _test_ensure_with_patched_ensure_vr_id(self, _ensure_vr_id):
        # create a non-ha router so we can manually invoke the create ha
        # interfaces call down below
        router = self._create_router(ha=False)
        router_db = self.plugin._get_router(self.admin_ctx, router['id'])
        with mock.patch.object(self.plugin, '_ensure_vr_id',
                               new=_ensure_vr_id):
            self.plugin._ensure_vr_id_and_network(
                self.admin_ctx, router_db)
            self.assertTrue(_ensure_vr_id.called)

    def test_ensure_vr_id_and_network_interface_failure(self):

        def _ensure_vr_id(ctx, rdb, ha_net):
            raise ValueError('broken')
        with testtools.ExpectedException(ValueError):
            self._test_ensure_with_patched_ensure_vr_id(_ensure_vr_id)
        self.assertEqual([], self.core_plugin.get_networks(self.admin_ctx))

    def test_ensure_vr_id_and_network_concurrent_delete(self):
        orig_create = self.plugin._ensure_vr_id

        def _ensure_vr_id(ctx, rdb, ha_net):
            # concurrent delete on the first attempt
            if not getattr(_ensure_vr_id, 'called', False):
                setattr(_ensure_vr_id, 'called', True)
                self.core_plugin.delete_network(self.admin_ctx,
                                                ha_net['network_id'])
            return orig_create(ctx, rdb, ha_net)
        self._test_ensure_with_patched_ensure_vr_id(_ensure_vr_id)

    def test_ensure_vr_id_and_network_concurrent_swap(self):
        orig_create = self.plugin._ensure_vr_id

        def _ensure_vr_id(ctx, rdb, ha_net):
            # concurrent delete on the first attempt
            if not getattr(_ensure_vr_id, 'called', False):
                setattr(_ensure_vr_id, 'called', True)
                self.core_plugin.delete_network(self.admin_ctx,
                                                ha_net['network_id'])
                self.plugin._create_ha_network(self.admin_ctx,
                                               rdb.tenant_id)
            return orig_create(ctx, rdb, ha_net)

        self._test_ensure_with_patched_ensure_vr_id(_ensure_vr_id)

    def test_create_ha_network_tenant_binding_raises_duplicate(self):
        router = self._create_router()
        network = self.plugin.get_ha_network(self.admin_ctx,
                                             router['tenant_id'])
        self.plugin._create_ha_network_tenant_binding(
            self.admin_ctx, 't1', network['network_id'])
        with testtools.ExpectedException(
                exceptions.NeutronDbObjectDuplicateEntry):
            self.plugin._create_ha_network_tenant_binding(
                self.admin_ctx, 't1', network['network_id'])

    def test_create_router_db_vr_id_allocation_goes_to_error(self):
        for method in ('_ensure_vr_id',
                       '_notify_router_updated'):
            with mock.patch.object(self.plugin, method,
                                   side_effect=ValueError):
                self.assertEqual(constants.ERROR,
                                 self._create_router()['status'])

    def test_get_active_host_for_ha_router(self):
        router = self._create_router()
        self.assertIsNone(
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
            self.assertEqual('standby', router[n_const.HA_ROUTER_STATE_KEY])

        states = {router1['id']: 'active',
                  router2['id']: 'standby'}
        self.plugin.update_routers_states(
            self.admin_ctx, states, self.agent1['host'])

        routers = self.plugin.get_ha_sync_data_for_host(
            self.admin_ctx, self.agent1['host'], self.agent1)
        for router in routers:
            self.assertEqual(states[router['id']],
                             router[n_const.HA_ROUTER_STATE_KEY])

    def test_sync_ha_router_info_ha_interface_port_concurrently_deleted(self):
        ctx = self.admin_ctx
        router1 = self._create_router()
        router2 = self._create_router()

        # retrieve all router ha port bindings
        bindings = self.plugin.get_ha_router_port_bindings(
            ctx, [router1['id'], router2['id']])
        self.assertEqual(4, len(bindings))

        routers = self.plugin.get_ha_sync_data_for_host(
            self.admin_ctx, self.agent1['host'], self.agent1)
        self.assertEqual(2, len(routers))

        bindings = self.plugin.get_ha_router_port_bindings(
            ctx, [router1['id'], router2['id']],
            self.agent1['host'])
        self.assertEqual(2, len(bindings))

        fake_binding = mock.Mock()
        fake_binding.router_id = bindings[1].router_id
        fake_binding.port = None
        with mock.patch.object(
                self.plugin, "get_ha_router_port_bindings",
                return_value=[bindings[0], fake_binding]):
            routers = self.plugin.get_ha_sync_data_for_host(
                ctx, self.agent1['host'], self.agent1)
            self.assertEqual(1, len(routers))
            self.assertIsNotNone(routers[0].get(constants.HA_INTERFACE_KEY))

    def test_sync_ha_router_info_router_concurrently_deleted(self):
        self._create_router()

        with mock.patch.object(
                self.plugin, "get_ha_router_port_bindings",
                return_value=[]):
            routers = self.plugin.get_ha_sync_data_for_host(
                self.admin_ctx, self.agent1['host'], self.agent1)
            self.assertEqual(0, len(routers))

    def test_sync_ha_router_info_router_concurrently_deleted_agent_dvr(self):
        self._create_router()
        orig_func = self.plugin._process_sync_ha_data

        def process_sync_ha_data(context, routers, host, agent_mode):
            return orig_func(context, routers, host, is_any_dvr_agent=True)

        with mock.patch.object(self.plugin, '_process_sync_ha_data',
                               side_effect=process_sync_ha_data):
            routers = self.plugin.get_ha_sync_data_for_host(
                self.admin_ctx, self.agent1['host'], self.agent1)
            self.assertEqual(1, len(routers))

    def test_set_router_states_handles_concurrently_deleted_router(self):
        router1 = self._create_router()
        router2 = self._create_router()
        ctx = self.admin_ctx
        bindings = self.plugin.get_ha_router_port_bindings(
            ctx, [router1['id'], router2['id']])
        self.plugin.delete_router(self.admin_ctx, router1['id'])
        self.plugin._set_router_states(
            ctx, bindings, {router1['id']: 'active',
                            router2['id']: 'active'})
        routers = self.plugin.get_ha_sync_data_for_host(
            self.admin_ctx, self.agent1['host'], self.agent1)
        self.assertEqual('active', routers[0][n_const.HA_ROUTER_STATE_KEY])

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
        """Test dvr agents configured with "dvr" only, as opposed to
        "dvr_snat", are excluded.
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
        ha_network = self.plugin.get_ha_network(self.admin_ctx,
                                                router1['tenant_id'])
        with mock.patch.object(self.plugin, '_delete_ha_network',
                               side_effect=exception):
            self.plugin.safe_delete_ha_network(self.admin_ctx,
                                               ha_network,
                                               router1['tenant_id'])
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
            e = self.assertRaises(c_exc.CallbackFailure,
                                  self._create_router,
                                  True,
                                  tenant_id)
            self.assertIsInstance(e.inner_exceptions[0],
                                  n_exc.NoNetworkAvailable)
            nets_after = self.core_plugin.get_networks(self.admin_ctx)
            self.assertEqual(nets_before, nets_after)
            self.assertNotIn('HA network tenant %s' % tenant_id,
                             nets_after)

    def test_update_port_status_port_bingding_deleted_concurrently(self):
        router1 = self._create_router()
        states = {router1['id']: 'active'}
        with mock.patch.object(self.plugin, 'get_ha_router_port_bindings'):
            (l3_hamode.L3HARouterAgentPortBinding.delete_objects(
                self.admin_ctx, router_id=router1['id']))
            self.plugin.update_routers_states(
                self.admin_ctx, states, self.agent1['host'])


class L3HAModeDbTestCase(L3HATestFramework):

    def _create_network(self, plugin, ctx, name='net',
                        tenant_id='tenant1', external=False):
        network = {'network': {'name': name,
                               'shared': False,
                               'admin_state_up': True,
                               'tenant_id': tenant_id,
                               extnet_apidef.EXTERNAL: external}}
        return plugin.create_network(ctx, network)['id']

    def _create_subnet(self, plugin, ctx, network_id, cidr='10.0.0.0/8',
                       name='subnet', tenant_id='tenant1'):
        subnet = {'subnet': {'name': name,
                  'ip_version': 4,
                  'network_id': network_id,
                  'cidr': cidr,
                  'gateway_ip': constants.ATTR_NOT_SPECIFIED,
                  'allocation_pools': constants.ATTR_NOT_SPECIFIED,
                  'dns_nameservers': constants.ATTR_NOT_SPECIFIED,
                  'host_routes': constants.ATTR_NOT_SPECIFIED,
                  'tenant_id': tenant_id,
                  'enable_dhcp': True,
                  'ipv6_ra_mode': constants.ATTR_NOT_SPECIFIED}}
        created_subnet = plugin.create_subnet(ctx, subnet)
        return created_subnet

    def _test_device_owner(self, router_id, dvr, ha):
        if dvr:
            device_owner = constants.DEVICE_OWNER_DVR_INTERFACE
        elif ha:
            device_owner = constants.DEVICE_OWNER_HA_REPLICATED_INT
        else:
            device_owner = constants.DEVICE_OWNER_ROUTER_INTF
        filters = {'device_id': [router_id], 'device_owner': [device_owner]}
        ports = self.core_plugin.get_ports(self.admin_ctx, filters=filters)
        self.assertEqual(1, len(ports))

    def _test_device_owner_during_router_migration(
            self, before_ha=False, before_dvr=False,
            after_ha=False, after_dvr=False):
        # As HA router is supported only in this test file,
        # we test all migrations here
        router = self._create_router(
            ctx=self.admin_ctx, ha=before_ha, distributed=before_dvr)
        network_id = self._create_network(self.core_plugin, self.admin_ctx)
        subnet = self._create_subnet(
            self.core_plugin, self.admin_ctx, network_id)
        interface_info = {'subnet_id': subnet['id']}
        self.plugin.add_router_interface(
            self.admin_ctx, router['id'], interface_info)
        self._test_device_owner(router['id'], before_dvr, before_ha)

        self.plugin.update_router(
            self.admin_ctx, router['id'],
            {'router': {'admin_state_up': False}})
        self.plugin.update_router(
            self.admin_ctx, router['id'],
            {'router': {'distributed': after_dvr, 'ha': after_ha}})
        self._test_device_owner(router['id'], after_dvr, after_ha)

    def test_device_owner_during_router_migration_from_dvr_to_ha(self):
        self._test_device_owner_during_router_migration(
            before_dvr=True, after_ha=True)

    def test_device_owner_during_router_migration_from_dvr_to_dvrha(self):
        self._test_device_owner_during_router_migration(
            before_dvr=True, after_ha=True, after_dvr=True)

    def test_device_owner_during_router_migration_from_dvr_to_legacy(self):
        self._test_device_owner_during_router_migration(before_dvr=True)

    def test_device_owner_during_router_migration_from_ha_to_legacy(self):
        self._test_device_owner_during_router_migration(before_ha=True)

    def test_device_owner_during_router_migration_from_ha_to_dvr(self):
        self._test_device_owner_during_router_migration(
            before_ha=True, after_dvr=True)

    def test_device_owner_during_router_migration_from_ha_to_dvrha(self):
        self._test_device_owner_during_router_migration(
            before_ha=True, after_ha=True, after_dvr=True)

    def test_device_owner_during_router_migration_from_legacy_to_dvr(self):
        self._test_device_owner_during_router_migration(after_dvr=True)

    def test_device_owner_during_router_migration_from_legacy_to_ha(self):
        self._test_device_owner_during_router_migration(after_ha=True)

    def test_remove_ha_in_use(self):
        router = self._create_router(ctx=self.admin_ctx)
        network_id = self._create_network(self.core_plugin, self.admin_ctx)
        subnet = self._create_subnet(self.core_plugin, self.admin_ctx,
                                     network_id)
        interface_info = {'subnet_id': subnet['id']}
        self.plugin.add_router_interface(self.admin_ctx,
                                         router['id'],
                                         interface_info)
        self.assertRaises(l3_exc.RouterInUse, self.plugin.delete_router,
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
                         [constants.DEVICE_OWNER_HA_REPLICATED_INT]}
        return self.core_plugin.get_ports(
            self.admin_ctx,
            filters=device_filter)[0]

    def _get_router_port_bindings(self, router_id):
        device_filter = {'device_id': [router_id],
                         'device_owner':
                         [constants.DEVICE_OWNER_HA_REPLICATED_INT,
                          constants.DEVICE_OWNER_ROUTER_SNAT,
                          constants.DEVICE_OWNER_ROUTER_GW]}
        return self.core_plugin.get_ports(
            self.admin_ctx,
            filters=device_filter)

    def test_update_router_port_bindings_updates_host(self):
        ext_net = self._create_network(self.core_plugin, self.admin_ctx,
                                       external=True)
        network_id = self._create_network(self.core_plugin, self.admin_ctx)
        subnet = self._create_subnet(self.core_plugin, self.admin_ctx,
                                     network_id)
        interface_info = {'subnet_id': subnet['id']}

        router = self._create_router()
        self.plugin._update_router_gw_info(self.admin_ctx, router['id'],
                                           {'network_id': ext_net})
        self.plugin.add_router_interface(self.admin_ctx,
                                         router['id'],
                                         interface_info)
        self.plugin._update_router_port_bindings(
            self.admin_ctx, {router['id']: 'active'}, self.agent1['host'])

        for port in self._get_router_port_bindings(router['id']):
            self.assertEqual(self.agent1['host'], port[portbindings.HOST_ID])

        self.plugin._update_router_port_bindings(
            self.admin_ctx, {router['id']: 'active'}, self.agent2['host'])

        for port in self._get_router_port_bindings(router['id']):
            self.assertEqual(self.agent2['host'], port[portbindings.HOST_ID])

    def test_update_router_port_bindings_updates_host_only(self):
        ext_net = self._create_network(self.core_plugin, self.admin_ctx,
                                       external=True)
        network_id = self._create_network(self.core_plugin, self.admin_ctx)
        subnet = self._create_subnet(self.core_plugin, self.admin_ctx,
                                     network_id)
        interface_info = {'subnet_id': subnet['id']}

        router = self._create_router()
        self.plugin._update_router_gw_info(self.admin_ctx, router['id'],
                                           {'network_id': ext_net})
        iface = self.plugin.add_router_interface(self.admin_ctx,
                                                 router['id'],
                                                 interface_info)
        with mock.patch.object(
                self.plugin._core_plugin, 'update_port') as update_port_mock:
            self.plugin._update_router_port_bindings(
                self.admin_ctx, {router['id']: 'active'}, self.agent1['host'])
            port_payload = {
                port_def.RESOURCE_NAME: {
                    portbindings.HOST_ID: self.agent1['host']
                }
            }
            update_port_mock.assert_called_with(
                mock.ANY, iface['port_id'], port_payload)

    def test_update_all_ha_network_port_statuses(self):
        router = self._create_router(ha=True)
        callback = l3_rpc.L3RpcCallback()
        callback._l3plugin = self.plugin
        host = self.agent1['host']
        ctx = self.admin_ctx
        bindings = self.plugin.get_ha_router_port_bindings(
            ctx, [router['id']])
        binding = [binding for binding in bindings
            if binding.l3_agent_id == self.agent1['id']][0]
        port = self.core_plugin.get_port(ctx, binding.port_id)

        # As network segments are not available, mock bind_port
        # to avoid binding failures
        def bind_port(context):
            binding = context._binding
            binding.vif_type = portbindings.VIF_TYPE_OVS
        with mock.patch.object(self.core_plugin.mechanism_manager,
                               'bind_port', side_effect=bind_port):
            callback._ensure_host_set_on_port(
                ctx, host, port, router_id=router['id'])
            # Port status will be DOWN by default as we are not having
            # l2 agent in test, so update it to ACTIVE.
            self.core_plugin.update_port_status(
                ctx, port['id'], constants.PORT_STATUS_ACTIVE, host=host)
            port = self.core_plugin.get_port(ctx, port['id'])
            self.assertEqual(constants.PORT_STATUS_ACTIVE, port['status'])
            callback.update_all_ha_network_port_statuses(ctx, host)
            port = self.core_plugin.get_port(ctx, port['id'])
            self.assertEqual(constants.PORT_STATUS_DOWN, port['status'])

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
        ctx = self.admin_ctx
        bindings = self.plugin.get_ha_router_port_bindings(
            ctx, router_ids=[router['id']],
            host=self.agent2['host'])
        self.plugin._set_router_states(ctx, bindings,
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

    def test_is_ha_router_port(self):
        network_id = self._create_network(self.core_plugin, self.admin_ctx)
        subnet = self._create_subnet(self.core_plugin, self.admin_ctx,
                                     network_id)
        interface_info = {'subnet_id': subnet['id']}

        router = self._create_router()
        self.plugin.add_router_interface(self.admin_ctx,
                                         router['id'],
                                         interface_info)
        port = self._get_first_interface(router['id'])
        self.assertTrue(l3_hamode_db.is_ha_router_port(
            self.admin_ctx, port['device_owner'], port['device_id']))

    def test_is_ha_router_port_for_normal_port(self):
        network_id = self._create_network(self.core_plugin, self.admin_ctx)
        subnet = self._create_subnet(self.core_plugin, self.admin_ctx,
                                     network_id)
        interface_info = {'subnet_id': subnet['id']}

        router = self._create_router(ha=False)
        self.plugin.add_router_interface(self.admin_ctx,
                                         router['id'],
                                         interface_info)
        device_filter = {'device_id': [router['id']],
                         'device_owner':
                         [constants.DEVICE_OWNER_ROUTER_INTF]}
        port = self.core_plugin.get_ports(
            self.admin_ctx, filters=device_filter)[0]

        self.assertFalse(l3_hamode_db.is_ha_router_port(
            self.admin_ctx, port['device_owner'], port['device_id']))

    def test_migration_from_ha(self):
        router = self._create_router()
        self.assertTrue(router['ha'])

        network_id = self._create_network(self.core_plugin, self.admin_ctx)
        subnet = self._create_subnet(self.core_plugin, self.admin_ctx,
                                     network_id)
        interface_info = {'subnet_id': subnet['id']}
        self.plugin.add_router_interface(self.admin_ctx,
                                         router['id'],
                                         interface_info)

        router = self._migrate_router(router['id'], False)

        self.assertFalse(router.extra_attributes['ha'])
        for routerport in router.attached_ports:
            self.assertEqual(constants.DEVICE_OWNER_ROUTER_INTF,
                             routerport.port_type)
            self.assertEqual(constants.DEVICE_OWNER_ROUTER_INTF,
                             routerport.port.device_owner)

    def test__get_sync_routers_with_state_change_and_check_gw_port_host(self):
        ext_net = self._create_network(self.core_plugin, self.admin_ctx,
                                       external=True)
        network_id = self._create_network(self.core_plugin, self.admin_ctx)
        subnet = self._create_subnet(self.core_plugin, self.admin_ctx,
                                     network_id)
        interface_info = {'subnet_id': subnet['id']}

        router = self._create_router()
        self.plugin._update_router_gw_info(self.admin_ctx, router['id'],
                                           {'network_id': ext_net})
        self.plugin.add_router_interface(self.admin_ctx,
                                         router['id'],
                                         interface_info)

        self.plugin.update_routers_states(
            self.admin_ctx, {router['id']: n_const.HA_ROUTER_STATE_ACTIVE},
            self.agent1['host'])
        self.plugin.update_routers_states(
            self.admin_ctx, {router['id']: n_const.HA_ROUTER_STATE_STANDBY},
            self.agent2['host'])

        routers = self.plugin._get_sync_routers(self.admin_ctx,
                                                router_ids=[router['id']])
        self.assertEqual(self.agent1['host'], routers[0]['gw_port_host'])

        self.plugin.update_routers_states(
            self.admin_ctx, {router['id']: n_const.HA_ROUTER_STATE_STANDBY},
            self.agent1['host'])
        self.plugin.update_routers_states(
            self.admin_ctx, {router['id']: n_const.HA_ROUTER_STATE_ACTIVE},
            self.agent2['host'])
        routers = self.plugin._get_sync_routers(self.admin_ctx,
                                                router_ids=[router['id']])
        self.assertEqual(self.agent2['host'], routers[0]['gw_port_host'])


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
