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
import os
import time

import netaddr
from neutron_lib import constants
from oslo_utils import uuidutils

from neutron.agent.l3 import ha_router
from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.common import utils as common_utils
from neutron.tests.common.exclusive_resources import ip_network
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
        subnet = self.safe_client.create_subnet(tenant_id, network['id'], cidr)
        return network, subnet

    def block_until_port_status_active(self, port_id):
        def is_port_status_active():
            port = self.client.show_port(port_id)
            return port['port']['status'] == 'ACTIVE'
        common_utils.wait_until_true(lambda: is_port_status_active(), sleep=1)

    def _create_and_attach_subnet(
            self, tenant_id, subnet_cidr, network_id, router_id):
        subnet = self.safe_client.create_subnet(
            tenant_id, network_id, subnet_cidr)

        router_interface_info = self.safe_client.add_router_interface(
            router_id, subnet['id'])
        self.block_until_port_status_active(
            router_interface_info['port_id'])

    def _boot_fake_vm_in_network(self, host, tenant_id, network_id, wait=True):
        vm = self.useFixture(
            machine.FakeFullstackMachine(
                host, network_id, tenant_id, self.safe_client, use_dhcp=True))
        if wait:
            vm.block_until_boot()
        return vm

    def _create_net_subnet_and_vm(self, tenant_id, subnet_cidrs, host, router):
        network = self.safe_client.create_network(tenant_id)
        for cidr in subnet_cidrs:
            self._create_and_attach_subnet(
                tenant_id, cidr, network['id'], router['id'])

        return self._boot_fake_vm_in_network(host, tenant_id, network['id'])

    def _test_gateway_ip_changed(self):
        tenant_id = uuidutils.generate_uuid()
        ext_net, ext_sub = self._create_external_network_and_subnet(tenant_id)
        external_vm = self._create_external_vm(ext_net, ext_sub)

        router = self.safe_client.create_router(tenant_id,
                                                external_network=ext_net['id'])

        vm = self._create_net_subnet_and_vm(
            tenant_id, ['20.0.0.0/24', '2001:db8:aaaa::/64'],
            self.environment.hosts[1], router)
        # ping external vm to test snat
        vm.block_until_ping(external_vm.ip)

        fip = self.safe_client.create_floatingip(
            tenant_id, ext_net['id'], vm.ip, vm.neutron_port['id'])
        # ping floating ip from external vm
        external_vm.block_until_ping(fip['floating_ip_address'])

        # ping router gateway IP
        old_gw_ip = router['external_gateway_info'][
            'external_fixed_ips'][0]['ip_address']
        external_vm.block_until_ping(old_gw_ip)

        gateway_port = self.safe_client.list_ports(
            device_id=router['id'],
            device_owner=constants.DEVICE_OWNER_ROUTER_GW)[0]
        ip_1, ip_2 = self._find_available_ips(ext_net, ext_sub, 2)
        self.safe_client.update_port(gateway_port['id'], fixed_ips=[
            {'ip_address': ip_1},
            {'ip_address': ip_2}])
        # ping router gateway new IPs
        external_vm.block_until_ping(ip_1)
        external_vm.block_until_ping(ip_2)

        # ping router old gateway IP, should fail now
        external_vm.block_until_no_ping(old_gw_ip)


class TestLegacyL3Agent(TestL3Agent):

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(l3_agent=True, dhcp_agent=True),
            environment.HostDescription()]
        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type='vlan', l2_pop=False),
            host_descriptions)
        super(TestLegacyL3Agent, self).setUp(env)

    def _get_namespace(self, router_id):
        return namespaces.build_ns_name(namespaces.NS_PREFIX, router_id)

    def _assert_namespace_exists(self, ns_name):
        common_utils.wait_until_true(
            lambda: ip_lib.network_namespace_exists(ns_name))

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

    def test_mtu_update(self):
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

        ip = ip_lib.IPWrapper(namespace)
        common_utils.wait_until_true(lambda: ip.get_devices())

        devices = ip.get_devices()
        self.assertEqual(1, len(devices))

        ri_dev = devices[0]
        mtu = ri_dev.link.mtu
        self.assertEqual(1500, mtu)

        mtu -= 1
        network = self.safe_client.update_network(network['id'], mtu=mtu)
        common_utils.wait_until_true(lambda: ri_dev.link.mtu == mtu)

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

    def test_north_south_traffic(self):
        # This function creates an external network which is connected to
        # central_bridge and spawns an external_vm on it.
        # The external_vm is configured with the gateway_ip (both v4 & v6
        # addresses) of external subnet. Later, it creates a tenant router,
        # a tenant network and two tenant subnets (v4 and v6). The tenant
        # router is associated with tenant network and external network to
        # provide north-south connectivity to the VMs.
        # We validate the following in this testcase.
        # 1. SNAT support: using ping from tenant VM to external_vm
        # 2. Floating IP support: using ping from external_vm to VM floating ip
        # 3. IPv6 ext connectivity: using ping6 from tenant vm to external_vm.
        tenant_id = uuidutils.generate_uuid()
        ext_net, ext_sub = self._create_external_network_and_subnet(tenant_id)
        external_vm = self._create_external_vm(ext_net, ext_sub)
        # Create an IPv6 subnet in the external network
        v6network = self.useFixture(
            ip_network.ExclusiveIPNetwork(
                "2001:db8:1234::1", "2001:db8:1234::10", "64")).network
        ext_v6sub = self.safe_client.create_subnet(
            tenant_id, ext_net['id'], v6network)

        router = self.safe_client.create_router(tenant_id,
                                                external_network=ext_net['id'])

        # Configure the gateway_ip of external v6subnet on the external_vm.
        external_vm.ipv6_cidr = common_utils.ip_to_cidr(
            ext_v6sub['gateway_ip'], 64)

        # Configure an IPv6 downstream route to the v6Address of router gw port
        for fixed_ip in router['external_gateway_info']['external_fixed_ips']:
            if netaddr.IPNetwork(fixed_ip['ip_address']).version == 6:
                external_vm.set_default_gateway(fixed_ip['ip_address'])

        vm = self._create_net_subnet_and_vm(
            tenant_id, ['20.0.0.0/24', '2001:db8:aaaa::/64'],
            self.environment.hosts[1], router)

        # ping external vm to test snat
        vm.block_until_ping(external_vm.ip)

        fip = self.safe_client.create_floatingip(
            tenant_id, ext_net['id'], vm.ip, vm.neutron_port['id'])

        # ping floating ip from external vm
        external_vm.block_until_ping(fip['floating_ip_address'])

        # Verify VM is able to reach the router interface.
        vm.block_until_ping(vm.gateway_ipv6)
        # Verify north-south connectivity using ping6 to external_vm.
        vm.block_until_ping(external_vm.ipv6)

        # Now let's remove and create again phys bridge and check connectivity
        # once again
        br_phys = self.environment.hosts[0].br_phys
        br_phys.destroy()
        br_phys.create()
        self.environment.hosts[0].connect_to_central_network_via_vlans(
            br_phys)

        # ping floating ip from external vm
        external_vm.block_until_ping(fip['floating_ip_address'])

        # Verify VM is able to reach the router interface.
        vm.block_until_ping(vm.gateway_ipv6)
        # Verify north-south connectivity using ping6 to external_vm.
        vm.block_until_ping(external_vm.ipv6)

    def test_gateway_ip_changed(self):
        self._test_gateway_ip_changed()


class TestHAL3Agent(TestL3Agent):

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(l3_agent=True, dhcp_agent=True)
            for _ in range(2)]
        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type='vlan', l2_pop=True),
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

        common_utils.wait_until_true(
            lambda:
            len(self.client.list_l3_agent_hosting_routers(
                router['id'])['agents']) == 2,
            timeout=90)

        common_utils.wait_until_true(
            functools.partial(
                self._is_ha_router_active_on_one_agent,
                router['id']),
            timeout=90)

    def _get_keepalived_state(self, keepalived_state_file):
        with open(keepalived_state_file, "r") as fd:
            return fd.read()

    def _get_state_file_for_master_agent(self, router_id):
        for host in self.environment.hosts:
            keepalived_state_file = os.path.join(
                host.neutron_config.state_path, "ha_confs", router_id, "state")

            if self._get_keepalived_state(keepalived_state_file) == "master":
                return keepalived_state_file

    def _get_l3_agents_with_ha_state(self, l3_agents, router_id, ha_state):
        found_agents = []
        agents_hosting_router = self.client.list_l3_agent_hosting_routers(
            router_id)['agents']
        for agent in l3_agents:
            agent_host = agent.neutron_cfg_fixture.get_host()
            for agent_hosting_router in agents_hosting_router:
                if (agent_hosting_router['host'] == agent_host and
                        agent_hosting_router['ha_state'] == ha_state):
                    found_agents.append(agent)
                    break
        return found_agents

    def test_keepalived_multiple_sighups_does_not_forfeit_mastership(self):
        """Setup a complete "Neutron stack" - both an internal and an external
           network+subnet, and a router connected to both.
        """
        tenant_id = uuidutils.generate_uuid()
        ext_net, ext_sub = self._create_external_network_and_subnet(tenant_id)
        router = self.safe_client.create_router(tenant_id, ha=True,
                                                external_network=ext_net['id'])
        common_utils.wait_until_true(
            lambda:
            len(self.client.list_l3_agent_hosting_routers(
                router['id'])['agents']) == 2,
            timeout=90)
        common_utils.wait_until_true(
            functools.partial(
                self._is_ha_router_active_on_one_agent,
                router['id']),
            timeout=90)
        keepalived_state_file = self._get_state_file_for_master_agent(
            router['id'])
        self.assertIsNotNone(keepalived_state_file)
        network = self.safe_client.create_network(tenant_id)
        self._create_and_attach_subnet(
            tenant_id, '13.37.0.0/24', network['id'], router['id'])

        # Create 10 fake VMs, each with a floating ip. Each floating ip
        # association should send a SIGHUP to the keepalived's parent process,
        # unless the Throttler works.
        host = self.environment.hosts[0]
        vms = [self._boot_fake_vm_in_network(host, tenant_id, network['id'],
                                             wait=False)
               for i in range(10)]
        for vm in vms:
            self.safe_client.create_floatingip(
                tenant_id, ext_net['id'], vm.ip, vm.neutron_port['id'])

        # Check that the keepalived's state file has not changed and is still
        # master. This will indicate that the Throttler works. We want to check
        # for ha_vrrp_advert_int (the default is 2 seconds), plus a bit more.
        time_to_stop = (time.time() +
                        (common_utils.DEFAULT_THROTTLER_VALUE *
                         ha_router.THROTTLER_MULTIPLIER * 1.3))
        while True:
            if time.time() > time_to_stop:
                break
            self.assertEqual(
                "master",
                self._get_keepalived_state(keepalived_state_file))

    def test_ha_router_restart_agents_no_packet_lost(self):
        tenant_id = uuidutils.generate_uuid()
        ext_net, ext_sub = self._create_external_network_and_subnet(tenant_id)
        router = self.safe_client.create_router(tenant_id, ha=True,
                                                external_network=ext_net['id'])

        external_vm = self._create_external_vm(ext_net, ext_sub)

        common_utils.wait_until_true(
            lambda:
            len(self.client.list_l3_agent_hosting_routers(
                router['id'])['agents']) == 2,
            timeout=90)

        common_utils.wait_until_true(
            functools.partial(
                self._is_ha_router_active_on_one_agent,
                router['id']),
            timeout=90)

        router_ip = router['external_gateway_info'][
            'external_fixed_ips'][0]['ip_address']
        # Let's check first if connectivity from external_vm to router's
        # external gateway IP is possible before we restart agents
        external_vm.block_until_ping(router_ip)

        l3_agents = [host.agents['l3'] for host in self.environment.hosts]
        l3_standby_agents = self._get_l3_agents_with_ha_state(
            l3_agents, router['id'], 'standby')
        l3_active_agents = self._get_l3_agents_with_ha_state(
            l3_agents, router['id'], 'active')

        self._assert_ping_during_agents_restart(
            l3_standby_agents, external_vm.namespace, [router_ip], count=60)

        self._assert_ping_during_agents_restart(
            l3_active_agents, external_vm.namespace, [router_ip], count=60)

    def test_gateway_ip_changed(self):
        self._test_gateway_ip_changed()
