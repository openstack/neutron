# Copyright (c) 2014 Red Hat, Inc.
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

import copy

import mock
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as lib_constants

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import namespace_manager
from neutron.agent.l3 import namespaces
from neutron.agent.l3 import router_info
from neutron.agent.linux import ip_lib
from neutron.common import utils
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.l3 import framework


class L3AgentTestCase(framework.L3AgentTestFramework):

    def _test_agent_notifications_for_router_events(self, enable_ha=False):
        """Test notifications for router create, update, and delete.

        Make sure that when the agent sends notifications of router events
        for router create, update, and delete, that the correct handler is
        called with the right resource, event, and router information.
        """
        event_handler = mock.Mock()
        registry.subscribe(event_handler,
                           resources.ROUTER, events.BEFORE_CREATE)
        registry.subscribe(event_handler,
                           resources.ROUTER, events.AFTER_CREATE)
        registry.subscribe(event_handler,
                           resources.ROUTER, events.BEFORE_UPDATE)
        registry.subscribe(event_handler,
                           resources.ROUTER, events.AFTER_UPDATE)
        registry.subscribe(event_handler,
                           resources.ROUTER, events.BEFORE_DELETE)
        registry.subscribe(event_handler,
                           resources.ROUTER, events.AFTER_DELETE)

        router_info = self.generate_router_info(enable_ha=enable_ha)
        router = self.manage_router(self.agent, router_info)
        with mock.patch.object(self.agent,
                               'check_ha_state_for_router') as check:
            self.agent._process_updated_router(router.router)
            self._delete_router(self.agent, router.router_id)
            if enable_ha:
                check.assert_called_once_with(router.router_id, None)

        expected_calls = [
            mock.call('router', 'before_create', self.agent, router=router),
            mock.call('router', 'after_create', self.agent, router=router),
            mock.call('router', 'before_update', self.agent, router=router),
            mock.call('router', 'after_update', self.agent, router=router),
            mock.call('router', 'before_delete', self.agent, payload=mock.ANY),
            mock.call('router', 'after_delete', self.agent, router=router)]
        event_handler.assert_has_calls(expected_calls)

    def test_agent_notifications_for_router_events(self):
        self._test_agent_notifications_for_router_events()

    def test_agent_notifications_for_router_events_ha(self):
        self._test_agent_notifications_for_router_events(enable_ha=True)

    def test_legacy_router_update_floatingip_statuses(self):
        self._test_update_floatingip_statuses(
            self.generate_router_info(enable_ha=False))

    def test_legacy_router_lifecycle(self):
        self._router_lifecycle(enable_ha=False, dual_stack=True)

    def test_legacy_router_lifecycle_with_no_gateway_subnet(self):
        self.agent.conf.set_override('ipv6_gateway',
                                     'fe80::f816:3eff:fe2e:1')
        self._router_lifecycle(enable_ha=False, dual_stack=True,
                               v6_ext_gw_with_sub=False)

    def test_legacy_router_gateway_update_to_none(self):
        router_info = self.generate_router_info(False)
        router = self.manage_router(self.agent, router_info)
        gw_port = router.get_ex_gw_port()
        interface_name = router.get_external_device_name(gw_port['id'])
        device = ip_lib.IPDevice(interface_name, namespace=router.ns_name)
        self.assertIn('gateway', device.route.get_gateway())

        # Make this copy, so that the agent will think there is change in
        # external gateway port.
        router.ex_gw_port = copy.deepcopy(router.ex_gw_port)
        for subnet in gw_port['subnets']:
            subnet['gateway_ip'] = None
        router.process()

        self.assertIsNone(device.route.get_gateway())

    def test_router_processing_pool_size(self):
        mock.patch.object(router_info.RouterInfo, 'initialize').start()
        mock.patch.object(router_info.RouterInfo, 'process').start()
        self.agent.l3_ext_manager = mock.Mock()
        mock.patch.object(router_info.RouterInfo, 'delete').start()
        mock.patch.object(registry, 'notify').start()

        router_info_1 = self.generate_router_info(False)
        r1 = self.manage_router(self.agent, router_info_1)
        self.assertEqual(l3_agent.ROUTER_PROCESS_GREENLET_MIN,
                         self.agent._pool.size)

        router_info_2 = self.generate_router_info(False)
        r2 = self.manage_router(self.agent, router_info_2)
        self.assertEqual(l3_agent.ROUTER_PROCESS_GREENLET_MIN,
                         self.agent._pool.size)

        router_info_list = [r1, r2]
        for _i in range(l3_agent.ROUTER_PROCESS_GREENLET_MAX + 1):
            ri = self.generate_router_info(False)
            rtr = self.manage_router(self.agent, ri)
            router_info_list.append(rtr)

        self.assertEqual(l3_agent.ROUTER_PROCESS_GREENLET_MAX,
                         self.agent._pool.size)

        for router in router_info_list:
            self.agent._safe_router_removed(router.router_id)

        agent_router_info_len = len(self.agent.router_info)
        if agent_router_info_len < l3_agent.ROUTER_PROCESS_GREENLET_MIN:
            self.assertEqual(l3_agent.ROUTER_PROCESS_GREENLET_MIN,
                             self.agent._pool.size)
        elif (l3_agent.ROUTER_PROCESS_GREENLET_MIN <= agent_router_info_len <=
                l3_agent.ROUTER_PROCESS_GREENLET_MAX):
            self.assertEqual(agent_router_info_len,
                             self.agent._pool.size)
        else:
            self.assertEqual(l3_agent.ROUTER_PROCESS_GREENLET_MAX,
                             self.agent._pool.size)

    def _make_bridge(self):
        bridge = framework.get_ovs_bridge(utils.get_rand_name())
        bridge.create()
        self.addCleanup(bridge.destroy)
        return bridge

    def test_legacy_router_ns_rebuild(self):
        router_info = self.generate_router_info(False)
        router = self.manage_router(self.agent, router_info)
        gw_port = router.router['gw_port']
        gw_inf_name = router.get_external_device_name(gw_port['id'])
        gw_device = ip_lib.IPDevice(gw_inf_name, namespace=router.ns_name)
        router_ports = [gw_device]
        for i_port in router_info.get(lib_constants.INTERFACE_KEY, []):
            interface_name = router.get_internal_device_name(i_port['id'])
            router_ports.append(
                ip_lib.IPDevice(interface_name, namespace=router.ns_name))

        namespaces.Namespace.delete(router.router_namespace)

        # l3 agent should be able to rebuild the ns when it is deleted
        self.manage_router(self.agent, router_info)
        # Assert the router ports are there in namespace
        self.assertTrue(all([port.exists() for port in router_ports]))

        self._delete_router(self.agent, router.router_id)

    def test_conntrack_disassociate_fip_legacy_router(self):
        self._test_conntrack_disassociate_fip(ha=False)

    def _test_periodic_sync_routers_task(self,
                                         routers_to_keep,
                                         routers_deleted,
                                         routers_deleted_during_resync):
        ns_names_to_retrieve = set()
        deleted_routers_info = []
        for r in routers_to_keep:
            ri = self.manage_router(self.agent, r)
            ns_names_to_retrieve.add(ri.ns_name)
        for r in routers_deleted + routers_deleted_during_resync:
            ri = self.manage_router(self.agent, r)
            deleted_routers_info.append(ri)
            ns_names_to_retrieve.add(ri.ns_name)

        mocked_get_router_ids = self.mock_plugin_api.get_router_ids
        mocked_get_router_ids.return_value = [r['id'] for r in
                                              routers_to_keep +
                                              routers_deleted_during_resync]
        mocked_get_routers = self.mock_plugin_api.get_routers
        mocked_get_routers.return_value = (routers_to_keep +
                                           routers_deleted_during_resync)
        # clear agent router_info as it will be after restart
        self.agent.router_info = {}

        # Synchronize the agent with the plug-in
        with mock.patch.object(namespace_manager.NamespaceManager, 'list_all',
                               return_value=ns_names_to_retrieve):
            self.agent.periodic_sync_routers_task(self.agent.context)

        # Mock the plugin RPC API so a known external network id is returned
        # when the router updates are processed by the agent
        external_network_id = framework._uuid()
        self.mock_plugin_api.get_external_network_id.return_value = (
            external_network_id)

        # Plug external_gateway_info in the routers that are not going to be
        # deleted by the agent when it processes the updates. Otherwise,
        # _process_router_if_compatible in the agent fails
        for r in routers_to_keep:
            r['external_gateway_info'] = {'network_id': external_network_id}

        # while sync updates are still in the queue, higher priority
        # router_deleted events may be added there as well
        for r in routers_deleted_during_resync:
            self.agent.router_deleted(self.agent.context, r['id'])

        # make sure all events are processed
        while not self.agent._queue._queue.empty():
            self.agent._process_router_update()

        for r in routers_to_keep:
            self.assertIn(r['id'], self.agent.router_info)
            self.assertTrue(self._namespace_exists(namespaces.NS_PREFIX +
                                                   r['id']))
        for ri in deleted_routers_info:
            self.assertNotIn(ri.router_id,
                             self.agent.router_info)
            self._assert_router_does_not_exist(ri)

    def test_periodic_sync_routers_task(self):
        routers_to_keep = []
        for i in range(2):
            routers_to_keep.append(self.generate_router_info(False))
        self._test_periodic_sync_routers_task(routers_to_keep,
                                              routers_deleted=[],
                                              routers_deleted_during_resync=[])

    def test_periodic_sync_routers_task_routers_deleted_while_agent_down(self):
        routers_to_keep = []
        routers_deleted = []
        for i in range(2):
            routers_to_keep.append(self.generate_router_info(False))
        for i in range(2):
            routers_deleted.append(self.generate_router_info(False))
        self._test_periodic_sync_routers_task(routers_to_keep,
                                              routers_deleted,
                                              routers_deleted_during_resync=[])

    def test_periodic_sync_routers_task_routers_deleted_while_agent_sync(self):
        routers_to_keep = []
        routers_deleted_during_resync = []
        for i in range(2):
            routers_to_keep.append(self.generate_router_info(False))
        for i in range(2):
            routers_deleted_during_resync.append(
                self.generate_router_info(False))
        self._test_periodic_sync_routers_task(
            routers_to_keep,
            routers_deleted=[],
            routers_deleted_during_resync=routers_deleted_during_resync)

    def _setup_fip_with_fixed_ip_from_same_subnet(self, enable_snat):
        """Setup 2 FakeMachines from same subnet, one with floatingip
        associated.
        """
        router_info = self.generate_router_info(enable_ha=False,
                                                enable_snat=enable_snat)
        router = self.manage_router(self.agent, router_info)
        router_ip_cidr = self._port_first_ip_cidr(router.internal_ports[0])
        router_ip = router_ip_cidr.partition('/')[0]

        br_int = framework.get_ovs_bridge(
            self.agent.conf.ovs_integration_bridge)

        src_machine, dst_machine = self.useFixture(
            machine_fixtures.PeerMachines(
                br_int,
                net_helpers.increment_ip_cidr(router_ip_cidr),
                router_ip)).machines

        dst_fip = '19.4.4.10'
        router.router[lib_constants.FLOATINGIP_KEY] = []
        self._add_fip(router, dst_fip, fixed_address=dst_machine.ip)
        router.process()

        return src_machine, dst_machine, dst_fip

    def test_fip_connection_from_same_subnet(self):
        '''Test connection to floatingip which is associated with
           fixed_ip on the same subnet of the source fixed_ip.
           In other words it confirms that return packets surely
           go through the router.
        '''
        src_machine, dst_machine, dst_fip = (
            self._setup_fip_with_fixed_ip_from_same_subnet(enable_snat=True))
        protocol_port = net_helpers.get_free_namespace_port(
            lib_constants.PROTO_NAME_TCP, dst_machine.namespace)
        # client sends to fip
        netcat = net_helpers.NetcatTester(
            src_machine.namespace, dst_machine.namespace,
            dst_fip, protocol_port,
            protocol=net_helpers.NetcatTester.TCP)
        self.addCleanup(netcat.stop_processes)
        self.assertTrue(netcat.test_connectivity())

    def test_ping_floatingip_reply_with_floatingip(self):
        src_machine, _, dst_fip = (
            self._setup_fip_with_fixed_ip_from_same_subnet(enable_snat=False))

        # Verify that the ping replys with fip
        ns_ip_wrapper = ip_lib.IPWrapper(src_machine.namespace)
        result = ns_ip_wrapper.netns.execute(
            ['ping', '-c', 1, '-W', 5, dst_fip])
        self._assert_ping_reply_from_expected_address(result, dst_fip)

    def _setup_address_scope(self, internal_address_scope1,
                             internal_address_scope2, gw_address_scope=None):
        router_info = self.generate_router_info(enable_ha=False,
                                                num_internal_ports=2)
        address_scope1 = {
            str(lib_constants.IP_VERSION_4): internal_address_scope1}
        address_scope2 = {
            str(lib_constants.IP_VERSION_4): internal_address_scope2}
        if gw_address_scope:
            router_info['gw_port']['address_scopes'] = {
                str(lib_constants.IP_VERSION_4): gw_address_scope}
        router_info[lib_constants.INTERFACE_KEY][0]['address_scopes'] = (
            address_scope1)
        router_info[lib_constants.INTERFACE_KEY][1]['address_scopes'] = (
            address_scope2)

        router = self.manage_router(self.agent, router_info)
        router_ip_cidr1 = self._port_first_ip_cidr(router.internal_ports[0])
        router_ip1 = router_ip_cidr1.partition('/')[0]
        router_ip_cidr2 = self._port_first_ip_cidr(router.internal_ports[1])
        router_ip2 = router_ip_cidr2.partition('/')[0]

        br_int = framework.get_ovs_bridge(
            self.agent.conf.ovs_integration_bridge)
        test_machine1 = self.useFixture(
            machine_fixtures.FakeMachine(
                br_int,
                net_helpers.increment_ip_cidr(router_ip_cidr1),
                router_ip1))
        test_machine2 = self.useFixture(
            machine_fixtures.FakeMachine(
                br_int,
                net_helpers.increment_ip_cidr(router_ip_cidr2),
                router_ip2))

        return test_machine1, test_machine2, router

    def test_connection_from_same_address_scope(self):
        test_machine1, test_machine2, _ = self._setup_address_scope(
            'scope1', 'scope1')
        # Internal networks that are in the same address scope can connected
        # each other
        net_helpers.assert_ping(test_machine1.namespace, test_machine2.ip)
        net_helpers.assert_ping(test_machine2.namespace, test_machine1.ip)

    def test_connection_from_diff_address_scope(self):
        test_machine1, test_machine2, _ = self._setup_address_scope(
            'scope1', 'scope2')
        # Internal networks that are not in the same address scope should
        # not reach each other
        test_machine1.assert_no_ping(test_machine2.ip)
        test_machine2.assert_no_ping(test_machine1.ip)

    def test_fip_connection_for_address_scope(self):
        (machine_same_scope, machine_diff_scope,
            router) = self._setup_address_scope('scope1', 'scope2', 'scope1')

        router.router[lib_constants.FLOATINGIP_KEY] = []
        fip_same_scope = '19.4.4.10'
        self._add_fip(router, fip_same_scope,
                      fixed_address=machine_same_scope.ip,
                      fixed_ip_address_scope='scope1')
        fip_diff_scope = '19.4.4.11'
        self._add_fip(router, fip_diff_scope,
                      fixed_address=machine_diff_scope.ip,
                      fixed_ip_address_scope='scope2')
        router.process()

        br_int = framework.get_ovs_bridge(
            self.agent.conf.ovs_integration_bridge)
        src_machine = self.useFixture(
            machine_fixtures.FakeMachine(br_int, '19.4.4.12/24'))
        # Floating ip should work no matter of address scope
        net_helpers.assert_ping(src_machine.namespace, fip_same_scope)
        net_helpers.assert_ping(src_machine.namespace, fip_diff_scope)

    def test_direct_route_for_address_scope(self):
        (machine_same_scope, machine_diff_scope,
            router) = self._setup_address_scope('scope1', 'scope2', 'scope1')

        gw_port = router.get_ex_gw_port()
        gw_ip = self._port_first_ip_cidr(gw_port).partition('/')[0]
        br_int = framework.get_ovs_bridge(
            self.agent.conf.ovs_integration_bridge)

        src_machine = self.useFixture(
            machine_fixtures.FakeMachine(br_int, '19.4.4.12/24', gw_ip))
        # For the internal networks that are in the same address scope as
        # external network, they can directly route to external network
        net_helpers.assert_ping(src_machine.namespace, machine_same_scope.ip)
        # For the internal networks that are not in the same address scope as
        # external networks. SNAT will be used. Direct route will not work
        # here.
        src_machine.assert_no_ping(machine_diff_scope.ip)

    def test_connection_from_diff_address_scope_with_fip(self):
        (machine_same_scope, machine_diff_scope,
            router) = self._setup_address_scope('scope1', 'scope2', 'scope1')

        router.router[lib_constants.FLOATINGIP_KEY] = []
        fip = '19.4.4.11'
        self._add_fip(router, fip,
                      fixed_address=machine_diff_scope.ip,
                      fixed_ip_address_scope='scope2')
        router.process()

        # For the internal networks that are in the same address scope as
        # external network, they should be able to reach the floating ip
        net_helpers.assert_ping(machine_same_scope.namespace, fip)
        # For the port with fip, it should be able to reach the internal
        # networks that are in the same address scope as external network
        net_helpers.assert_ping(machine_diff_scope.namespace,
                                machine_same_scope.ip)
