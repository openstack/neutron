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


import mock

from neutron.agent.l3 import namespace_manager
from neutron.agent.l3 import namespaces
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import constants as l3_constants
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.l3 import framework


class L3AgentTestCase(framework.L3AgentTestFramework):

    def test_agent_notifications_for_router_events(self):
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

        router_info = self.generate_router_info(enable_ha=False)
        router = self.manage_router(self.agent, router_info)
        self.agent._process_updated_router(router.router)
        self._delete_router(self.agent, router.router_id)

        expected_calls = [
            mock.call('router', 'before_create', self.agent, router=router),
            mock.call('router', 'after_create', self.agent, router=router),
            mock.call('router', 'before_update', self.agent, router=router),
            mock.call('router', 'after_update', self.agent, router=router),
            mock.call('router', 'before_delete', self.agent, router=router),
            mock.call('router', 'after_delete', self.agent, router=router)]
        event_handler.assert_has_calls(expected_calls)

    def test_legacy_router_lifecycle(self):
        self._router_lifecycle(enable_ha=False, dual_stack=True)

    def test_legacy_router_lifecycle_with_no_gateway_subnet(self):
        self.agent.conf.set_override('ipv6_gateway',
                                     'fe80::f816:3eff:fe2e:1')
        self._router_lifecycle(enable_ha=False, dual_stack=True,
                               v6_ext_gw_with_sub=False)

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

    def test_fip_connection_from_same_subnet(self):
        '''Test connection to floatingip which is associated with
           fixed_ip on the same subnet of the source fixed_ip.
           In other words it confirms that return packets surely
           go through the router.
        '''
        router_info = self.generate_router_info(enable_ha=False)
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
        router.router[l3_constants.FLOATINGIP_KEY] = []
        self._add_fip(router, dst_fip, fixed_address=dst_machine.ip)
        router.process(self.agent)

        protocol_port = net_helpers.get_free_namespace_port(
            l3_constants.PROTO_NAME_TCP, dst_machine.namespace)
        # client sends to fip
        netcat = net_helpers.NetcatTester(
            src_machine.namespace, dst_machine.namespace,
            dst_fip, protocol_port,
            protocol=net_helpers.NetcatTester.TCP)
        self.addCleanup(netcat.stop_processes)
        self.assertTrue(netcat.test_connectivity())
