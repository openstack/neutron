# Copyright 2015 Red Hat, Inc.
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

import functools
import netaddr

from neutron_lib import constants
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.common import utils as common_utils
from neutron.tests.common.exclusive_resources import ip_network
from neutron.tests.common import machine_fixtures
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests


class TestL3Agent(base.BaseFullStackTestCase):

    def _create_external_network_and_subnet(self, tenant_id):
        network = self.safe_client.create_network(
            tenant_id, name='public', external=True)
        cidr = self.useFixture(
            ip_network.ExclusiveIPNetwork(
                "240.0.0.0", "240.255.255.255", "24")).network
        subnet = self.safe_client.create_subnet(
            tenant_id, network['id'], cidr,
            enable_dhcp=False)
        return network, subnet

    def block_until_port_status_active(self, port_id):
        def is_port_status_active():
            port = self.client.show_port(port_id)
            return port['port']['status'] == 'ACTIVE'
        common_utils.wait_until_true(lambda: is_port_status_active(), sleep=1)

    def _create_net_subnet_and_vm(self, tenant_id, subnet_cidrs, host, router):
        network = self.safe_client.create_network(tenant_id)
        for cidr in subnet_cidrs:
            # For IPv6 subnets, enable_dhcp should be set to true.
            enable_dhcp = (netaddr.IPNetwork(cidr).version ==
                constants.IP_VERSION_6)
            subnet = self.safe_client.create_subnet(
                tenant_id, network['id'], cidr, enable_dhcp=enable_dhcp)

            router_interface_info = self.safe_client.add_router_interface(
                router['id'], subnet['id'])
            self.block_until_port_status_active(
                router_interface_info['port_id'])

        vm = self.useFixture(
            machine.FakeFullstackMachine(
                host, network['id'], tenant_id, self.safe_client))
        vm.block_until_boot()
        return vm


class TestLegacyL3Agent(TestL3Agent):

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(l3_agent=True),
            environment.HostDescription()]
        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type='vlan', l2_pop=False),
            host_descriptions)
        super(TestLegacyL3Agent, self).setUp(env)

    def _get_namespace(self, router_id):
        return namespaces.build_ns_name(l3_agent.NS_PREFIX, router_id)

    def _assert_namespace_exists(self, ns_name):
        ip = ip_lib.IPWrapper(ns_name)
        common_utils.wait_until_true(lambda: ip.netns.exists(ns_name))

    def test_namespace_exists(self):
        tenant_id = uuidutils.generate_uuid()

        router = self.safe_client.create_router(tenant_id)
        network = self.safe_client.create_network(tenant_id)
        subnet = self.safe_client.create_subnet(
            tenant_id, network['id'], '20.0.0.0/24', gateway_ip='20.0.0.1')
        self.safe_client.add_router_interface(router['id'], subnet['id'])

        namespace = "%s@%s" % (
            self._get_namespace(router['id']),
            self.environment.hosts[0].l3_agent.get_namespace_suffix(), )
        self._assert_namespace_exists(namespace)

    def test_east_west_traffic(self):
        tenant_id = uuidutils.generate_uuid()
        router = self.safe_client.create_router(tenant_id)

        vm1 = self._create_net_subnet_and_vm(
            tenant_id, ['20.0.0.0/24', '2001:db8:aaaa::/64'],
            self.environment.hosts[0], router)
        vm2 = self._create_net_subnet_and_vm(
            tenant_id, ['21.0.0.0/24', '2001:db8:bbbb::/64'],
            self.environment.hosts[1], router)

        vm1.block_until_ping(vm2.ip)
        # Verify ping6 from vm2 to vm1 IPv6 Address
        vm2.block_until_ping(vm1.ipv6)

    def test_snat_and_floatingip(self):
        # This function creates external network and boots an extrenal vm
        # on it with gateway ip and connected to central_external_bridge.
        # Later it creates a tenant vm on tenant network, with tenant router
        # connected to tenant network and external network.
        # To test snat and floatingip, try ping between tenant and external vms
        tenant_id = uuidutils.generate_uuid()
        ext_net, ext_sub = self._create_external_network_and_subnet(tenant_id)
        external_vm = self.useFixture(
            machine_fixtures.FakeMachine(
                self.environment.central_external_bridge,
                common_utils.ip_to_cidr(ext_sub['gateway_ip'], 24)))

        router = self.safe_client.create_router(tenant_id,
                                                external_network=ext_net['id'])
        vm = self._create_net_subnet_and_vm(
            tenant_id, ['20.0.0.0/24'],
            self.environment.hosts[1], router)

        # ping external vm to test snat
        vm.block_until_ping(external_vm.ip)

        fip = self.safe_client.create_floatingip(
            tenant_id, ext_net['id'], vm.ip, vm.neutron_port['id'])

        # ping floating ip from external vm
        external_vm.block_until_ping(fip['floating_ip_address'])


class TestHAL3Agent(base.BaseFullStackTestCase):

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(l3_agent=True) for _ in range(2)]
        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type='vxlan', l2_pop=True),
            host_descriptions)
        super(TestHAL3Agent, self).setUp(env)

    def _is_ha_router_active_on_one_agent(self, router_id):
        agents = self.client.list_l3_agent_hosting_routers(router_id)
        return (
            agents['agents'][0]['ha_state'] != agents['agents'][1]['ha_state'])

    def test_ha_router(self):
        # TODO(amuller): Test external connectivity before and after a
        # failover, see: https://review.openstack.org/#/c/196393/

        tenant_id = uuidutils.generate_uuid()
        router = self.safe_client.create_router(tenant_id, ha=True)
        agents = self.client.list_l3_agent_hosting_routers(router['id'])
        self.assertEqual(2, len(agents['agents']),
                         'HA router must be scheduled to both nodes')

        common_utils.wait_until_true(
            functools.partial(
                self._is_ha_router_active_on_one_agent,
                router['id']),
            timeout=90)
