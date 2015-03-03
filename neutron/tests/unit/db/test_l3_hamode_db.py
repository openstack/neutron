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

import datetime
import mock
from oslo_config import cfg
from oslo_utils import timeutils
from oslo_utils import uuidutils

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron import context
from neutron.db import agents_db
from neutron.db import common_db_mixin
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_hamode_db
from neutron.extensions import l3
from neutron.extensions import l3_ext_ha_mode
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
        self.agent1 = helpers.register_l3_agent()
        self.agent2 = helpers.register_l3_agent(
            'host_2', constants.L3_AGENT_MODE_DVR_SNAT)

    def _bring_down_agent(self, agent_id):
        update = {
            'agent': {
                'heartbeat_timestamp':
                timeutils.utcnow() - datetime.timedelta(hours=1)}}
        self.plugin.update_agent(self.admin_ctx, agent_id, update)

    def _create_router(self, ha=True, tenant_id='tenant1', distributed=None,
                       ctx=None):
        if ctx is None:
            ctx = self.admin_ctx
        ctx.tenant_id = tenant_id
        router = {'name': 'router1', 'admin_state_up': True}
        if ha is not None:
            router['ha'] = ha
        if distributed is not None:
            router['distributed'] = distributed
        return self.plugin.create_router(ctx, {'router': router})

    def _update_router(self, router_id, ha=True, distributed=None, ctx=None):
        if ctx is None:
            ctx = self.admin_ctx
        data = {'ha': ha} if ha is not None else {}
        if distributed is not None:
            data['distributed'] = distributed
        return self.plugin._update_router_db(ctx, router_id,
                                             data, None)

    def _bind_router(self, router_id):
        with self.admin_ctx.session.begin(subtransactions=True):
            scheduler = l3_agent_scheduler.ChanceScheduler()
            agents_db = self.plugin.get_agents_db(self.admin_ctx)
            scheduler._bind_ha_router_to_agents(
                self.plugin,
                self.admin_ctx,
                router_id,
                agents_db)


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
        self._bind_router(router['id'])
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
        self._bind_router(router['id'])
        self.plugin.update_routers_states(
            self.admin_ctx, {router['id']: 'active'}, self.agent1['host'])
        bindings = self.plugin.get_l3_bindings_hosting_router_with_ha_states(
            self.admin_ctx, router['id'])
        agent_ids = [(agent[0]['id'], agent[1]) for agent in bindings]
        self.assertIn((self.agent1['id'], 'active'), agent_ids)
        self.assertIn((self.agent2['id'], 'standby'), agent_ids)

    def test_get_l3_bindings_hosting_router_with_ha_states_not_scheduled(self):
        router = self._create_router(ha=False)
        bindings = self.plugin.get_l3_bindings_hosting_router_with_ha_states(
            self.admin_ctx, router['id'])
        self.assertEqual([], bindings)

    def test_ha_router_create(self):
        router = self._create_router()
        self.assertTrue(router['ha'])

    def test_ha_router_create_with_distributed(self):
        self.assertRaises(l3_ext_ha_mode.DistributedHARouterNotSupported,
                          self._create_router,
                          distributed=True)

    def test_no_ha_router_create(self):
        router = self._create_router(ha=False)
        self.assertFalse(router['ha'])

    def test_router_create_with_ha_conf_enabled(self):
        cfg.CONF.set_override('l3_ha', True)

        router = self._create_router(ha=None)
        self.assertTrue(router['ha'])

    def test_migration_from_ha(self):
        router = self._create_router()
        self.assertTrue(router['ha'])

        router = self._update_router(router['id'], ha=False)
        self.assertFalse(router.extra_attributes['ha'])
        self.assertIsNone(router.extra_attributes['ha_vr_id'])

    def test_migration_to_ha(self):
        router = self._create_router(ha=False)
        self.assertFalse(router['ha'])

        router = self._update_router(router['id'], ha=True)
        self.assertTrue(router.extra_attributes['ha'])
        self.assertIsNotNone(router.extra_attributes['ha_vr_id'])

    def test_migrate_ha_router_to_distributed(self):
        router = self._create_router()
        self.assertTrue(router['ha'])

        self.assertRaises(l3_ext_ha_mode.DistributedHARouterNotSupported,
                          self._update_router,
                          router['id'],
                          distributed=True)

    def test_l3_agent_routers_query_interface(self):
        router = self._create_router()
        self._bind_router(router['id'])
        routers = self.plugin.get_ha_sync_data_for_host(self.admin_ctx,
                                                        self.agent1['host'])
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
        self._create_router(ha=not to_ha)
        routers = self.plugin.get_ha_sync_data_for_host(self.admin_ctx)
        router = routers[0]
        interface = router.get(constants.HA_INTERFACE_KEY)
        if to_ha:
            self.assertIsNone(interface)
        else:
            self.assertIsNotNone(interface)

        self._update_router(router['id'], to_ha)
        routers = self.plugin.get_ha_sync_data_for_host(self.admin_ctx)
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
        self._update_router(router['id'], ha=True)
        self.assertTrue(self.notif_m.called)

    def test_unique_vr_id_between_routers(self):
        self._create_router()
        self._create_router()
        routers = self.plugin.get_ha_sync_data_for_host(self.admin_ctx)
        self.assertEqual(2, len(routers))
        self.assertNotEqual(routers[0]['ha_vr_id'], routers[1]['ha_vr_id'])

    @mock.patch('neutron.db.l3_hamode_db.VR_ID_RANGE', new=set(range(1, 1)))
    def test_vr_id_depleted(self):
        self.assertRaises(l3_ext_ha_mode.NoVRIDAvailable, self._create_router)

    @mock.patch('neutron.db.l3_hamode_db.VR_ID_RANGE', new=set(range(1, 2)))
    def test_vr_id_unique_range_per_tenant(self):
        self._create_router()
        self._create_router(tenant_id=_uuid())
        routers = self.plugin.get_ha_sync_data_for_host(self.admin_ctx)
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
        self._update_router(router['id'], ha=False)
        allocs_after = self.plugin._get_allocated_vr_id(self.admin_ctx,
                                                        network.network_id)
        self.assertEqual(allocs_before, allocs_after)

    def test_one_ha_router_one_not(self):
        self._create_router(ha=False)
        self._create_router()
        routers = self.plugin.get_ha_sync_data_for_host(self.admin_ctx)

        ha0 = routers[0]['ha']
        ha1 = routers[1]['ha']

        self.assertNotEqual(ha0, ha1)

    def test_add_ha_port_binding_failure_rolls_back_port(self):
        router = self._create_router()
        device_filter = {'device_id': [router['id']]}
        ports_before = self.core_plugin.get_ports(
            self.admin_ctx, filters=device_filter)
        network = self.plugin.get_ha_network(self.admin_ctx,
                                             router['tenant_id'])

        with mock.patch.object(self.plugin, '_create_ha_port_binding',
                               side_effect=ValueError):
            self.assertRaises(ValueError, self.plugin.add_ha_port,
                              self.admin_ctx, router['id'], network.network_id,
                              router['tenant_id'])

        ports_after = self.core_plugin.get_ports(
            self.admin_ctx, filters=device_filter)

        self.assertEqual(ports_before, ports_after)

    def test_create_ha_network_binding_failure_rolls_back_network(self):
        networks_before = self.core_plugin.get_networks(self.admin_ctx)

        with mock.patch.object(self.plugin,
                               '_create_ha_network_tenant_binding',
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

    def test_create_ha_interfaces_binding_failure_rolls_back_ports(self):
        router = self._create_router()
        network = self.plugin.get_ha_network(self.admin_ctx,
                                             router['tenant_id'])
        device_filter = {'device_id': [router['id']]}
        ports_before = self.core_plugin.get_ports(
            self.admin_ctx, filters=device_filter)

        router_db = self.plugin._get_router(self.admin_ctx, router['id'])
        with mock.patch.object(self.plugin, '_create_ha_port_binding',
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

    def test_update_routers_states(self):
        router1 = self._create_router()
        self._bind_router(router1['id'])
        router2 = self._create_router()
        self._bind_router(router2['id'])

        routers = self.plugin.get_ha_sync_data_for_host(self.admin_ctx,
                                                        self.agent1['host'])
        for router in routers:
            self.assertEqual('standby', router[constants.HA_ROUTER_STATE_KEY])

        states = {router1['id']: 'active',
                  router2['id']: 'standby'}
        self.plugin.update_routers_states(
            self.admin_ctx, states, self.agent1['host'])

        routers = self.plugin.get_ha_sync_data_for_host(self.admin_ctx,
                                                        self.agent1['host'])
        for router in routers:
            self.assertEqual(states[router['id']],
                             router[constants.HA_ROUTER_STATE_KEY])

    def test_set_router_states_handles_concurrently_deleted_router(self):
        router1 = self._create_router()
        self._bind_router(router1['id'])
        router2 = self._create_router()
        self._bind_router(router2['id'])
        bindings = self.plugin.get_ha_router_port_bindings(
            self.admin_ctx, [router1['id'], router2['id']])
        self.plugin.delete_router(self.admin_ctx, router1['id'])
        self.plugin._set_router_states(
            self.admin_ctx, bindings, {router1['id']: 'active',
                                       router2['id']: 'active'})
        routers = self.plugin.get_ha_sync_data_for_host(self.admin_ctx,
                                                        self.agent1['host'])
        self.assertEqual('active', routers[0][constants.HA_ROUTER_STATE_KEY])

    def test_exclude_dvr_agents_for_ha_candidates(self):
        """Test dvr agents are not counted in the ha candidates.

        This test case tests that when get_number_of_agents_for_scheduling
        is called, it doesn't count dvr agents.
        """
        # Test setup registers two l3 agents.
        # Register another l3 agent with dvr mode and assert that
        # get_number_of_ha_agent_candidates return 2.
        helpers.register_l3_agent('host_3', constants.L3_AGENT_MODE_DVR)
        num_ha_candidates = self.plugin.get_number_of_agents_for_scheduling(
            self.admin_ctx)
        self.assertEqual(2, num_ha_candidates)

    def test_get_number_of_agents_for_scheduling_not_enough_agents(self):
        cfg.CONF.set_override('min_l3_agents_per_router', 3)
        agent_to_bring_down = helpers.register_l3_agent(host='l3host_3')
        self._bring_down_agent(agent_to_bring_down['id'])
        self.assertRaises(l3_ext_ha_mode.HANotEnoughAvailableAgents,
                          self.plugin.get_number_of_agents_for_scheduling,
                          self.admin_ctx)


class L3HAModeDbTestCase(L3HATestFramework):

    def _create_network(self, plugin, ctx, name='net',
                        tenant_id='tenant1'):
        network = {'network': {'name': name,
                               'shared': False,
                               'admin_state_up': True,
                               'tenant_id': tenant_id}}
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


class L3HAUserTestCase(L3HATestFramework):

    def setUp(self):
        super(L3HAUserTestCase, self).setUp()
        self.user_ctx = context.Context('', _uuid())

    def test_create_ha_router(self):
        self._create_router(ctx=self.user_ctx)

    def test_update_router(self):
        router = self._create_router(ctx=self.user_ctx)
        self._update_router(router['id'], ha=False, ctx=self.user_ctx)

    def test_delete_router(self):
        router = self._create_router(ctx=self.user_ctx)
        self.plugin.delete_router(self.user_ctx, router['id'])
