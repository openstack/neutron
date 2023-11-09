# Copyright 2018 Red Hat, Inc.
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

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from oslo_utils import uuidutils

from neutron.common import utils as common_utils
from neutron.tests.common.exclusive_resources import ip_network
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests


class TestPortsRebind(base.BaseFullStackTestCase):

    scenarios = [
        ('Open vSwitch Agent', {
            'l2_agent_type': constants.AGENT_TYPE_OVS,
            'l2_mechdriver_name': 'openvswitch',
        })]

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(
                l2_agent_type=self.l2_agent_type,
                l3_agent=self.use_l3_agent)]
        env = environment.Environment(
            environment.EnvironmentDescription(
                agent_down_time=10),
            host_descriptions)

        super(TestPortsRebind, self).setUp(env)

        self.l2_agent_process = self.environment.hosts[0].l2_agent
        self.l2_agent = self.safe_client.client.list_agents(
            agent_type=self.l2_agent_type)['agents'][0]

        self.tenant_id = uuidutils.generate_uuid()
        self.network = self.safe_client.create_network(self.tenant_id)
        self.subnet = self.safe_client.create_subnet(
            self.tenant_id, self.network['id'], '20.0.0.0/24')

    def _ensure_port_bound(self, port_id):
        port = None

        def port_bound():
            nonlocal port
            port = self.safe_client.client.show_port(port_id)['port']
            return (
                port[portbindings.VIF_TYPE] not in
                    [portbindings.VIF_TYPE_UNBOUND,
                     portbindings.VIF_TYPE_BINDING_FAILED])

        common_utils.wait_until_true(port_bound)
        bound_drivers = {'0': self.l2_mechdriver_name}
        self.assertEqual(bound_drivers,
                         port[portbindings.VIF_DETAILS][
                             portbindings.VIF_DETAILS_BOUND_DRIVERS])

    def _ensure_port_binding_failed(self, port_id):

        def port_binding_failed():
            port = self.safe_client.client.show_port(port_id)['port']
            return (port[portbindings.VIF_TYPE] ==
                    portbindings.VIF_TYPE_BINDING_FAILED)

        common_utils.wait_until_true(port_binding_failed)


class TestVMPortRebind(TestPortsRebind):

    use_l3_agent = False

    def test_vm_port_rebound_when_L2_agent_revived(self):
        """Test scenario

        1. Create port which will be properly bound to host
        2. Stop L2 agent and wait until it will be DEAD
        3. Create another port - it should have "binding_failed"
        4. Turn on L2 agent
        5. Port from p.3 should be bound properly after L2 agent will be UP
        """

        vm_1 = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[0],
                self.network['id'],
                self.tenant_id,
                self.safe_client))
        vm_1.block_until_boot()
        self._ensure_port_bound(vm_1.neutron_port['id'])
        vm_1_port = self.safe_client.client.show_port(
            vm_1.neutron_port['id'])['port']

        self.l2_agent_process = self.environment.hosts[0].l2_agent
        self.l2_agent = self.safe_client.client.list_agents(
            agent_type=self.l2_agent_type)['agents'][0]

        self.l2_agent_process.stop()
        self._wait_until_agent_down(self.l2_agent['id'])

        vm_2 = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[0],
                self.network['id'],
                self.tenant_id,
                self.safe_client))
        self._ensure_port_binding_failed(vm_2.neutron_port['id'])
        vm_2_port = self.safe_client.client.show_port(
            vm_2.neutron_port['id'])['port']

        # check if vm_1 port is still bound as it was before
        self._ensure_port_bound(vm_1.neutron_port['id'])
        # and that revision number of vm_1's port wasn't changed
        self.assertEqual(
            vm_1_port['revision_number'],
            self.safe_client.client.show_port(
                vm_1_port['id'])['port']['revision_number'])

        self.l2_agent_process.start()
        self._wait_until_agent_up(self.l2_agent['id'])

        self._ensure_port_bound(vm_2_port['id'])


class TestRouterPortRebind(TestPortsRebind):

    use_l3_agent = True

    def setUp(self):
        super(TestRouterPortRebind, self).setUp()

        self.tenant_id = uuidutils.generate_uuid()
        self.ext_net = self.safe_client.create_network(
            self.tenant_id, external=True)
        ext_cidr = self.useFixture(
            ip_network.ExclusiveIPNetwork(
                "240.0.0.0", "240.255.255.255", "24")).network
        self.safe_client.create_subnet(
            self.tenant_id, self.ext_net['id'], ext_cidr)
        self.router = self.safe_client.create_router(
            self.tenant_id, external_network=self.ext_net['id'])

    def test_vm_port_rebound_when_L2_agent_revived(self):
        """Test scenario

        1. Ensure that router gateway port is bound properly
        2. Stop L2 agent and wait until it will be DEAD
        3. Create router interface and check that it's port is "binding_failed"
        4. Turn on L2 agent
        5. Router's port created in p.3 should be now bound properly
        """

        gw_port = self.safe_client.client.list_ports(
            device_id=self.router['id'],
            device_owner=constants.DEVICE_OWNER_ROUTER_GW)['ports'][0]
        self._ensure_port_bound(gw_port['id'])

        self.l2_agent_process.stop()
        self._wait_until_agent_down(self.l2_agent['id'])

        router_interface_info = self.safe_client.add_router_interface(
            self.router['id'], self.subnet['id'])
        self._ensure_port_binding_failed(router_interface_info['port_id'])

        self.l2_agent_process.start()
        self._wait_until_agent_up(self.l2_agent['id'])

        self._ensure_port_bound(router_interface_info['port_id'])
