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

from datetime import datetime

from neutron_lib import constants
from neutronclient.common import exceptions
from oslo_log import log as logging
from oslo_utils import uuidutils

from neutron.agent.l3 import ha_router
from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.agent.linux import l3_tc_lib
from neutron.common import utils as common_utils
from neutron.tests import base as tests_base
from neutron.tests.common.exclusive_resources import ip_network
from neutron.tests.common import net_helpers
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests

LOG = logging.getLogger(__name__)


class TestL3Agent(base.BaseFullStackTestCase):

    def _create_external_network_and_subnet(self, tenant_id):
        network = self.safe_client.create_network(
            tenant_id, name='public', external=True)
        subnet = self._create_external_subnet(tenant_id, network['id'])
        return network, subnet

    def _create_external_subnet(self, tenant_id, network_id):
        cidr = self.useFixture(
            ip_network.ExclusiveIPNetwork(
                "240.0.0.0", "240.255.255.255", "24")).network
        subnet = self.safe_client.create_subnet(tenant_id, network_id, cidr)
        return subnet

    def block_until_port_status_active(self, port_id):
        def is_port_status_active():
            port = self.client.show_port(port_id)
            return port['port']['status'] == 'ACTIVE'
        base.wait_until_true(lambda: is_port_status_active(), sleep=1)

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
                host, network_id, tenant_id, self.safe_client,
                use_dhcp=self.use_dhcp))
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

    def _test_external_subnet_changed(self):
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

        # ping router gateway IP
        gw_ip = router['external_gateway_info'][
            'external_fixed_ips'][0]['ip_address']
        external_vm.block_until_ping(gw_ip)

        # create second external subnet and external vm on it
        ext_sub_2 = self._create_external_subnet(tenant_id, ext_net['id'])
        external_vm_2 = self._create_external_vm(ext_net, ext_sub_2)

        # move original router gateway IP to be on second subnet
        ip_1, ip_2 = self._find_available_ips(ext_net, ext_sub_2, 2)
        ext_info = {
            'network_id': ext_net['id'],
            'external_fixed_ips':
                [{'ip_address': ip_2, 'subnet_id': ext_sub_2['id']}]}
        self.safe_client.update_router(router['id'],
                                       external_gateway_info=ext_info)

        # ping external vm_2 to test snat
        vm.block_until_ping(external_vm_2.ip)

        # ping router gateway new IP
        external_vm_2.block_until_ping(ip_2)

        # ping original router old gateway IP, should fail now
        external_vm.block_until_no_ping(gw_ip)

        # clear the external gateway so ext_sub_2 can be deleted
        self.safe_client.update_router(router['id'],
                                       external_gateway_info={})

    def _get_namespace(self, router_id, agent=None):
        namespace = namespaces.build_ns_name(namespaces.NS_PREFIX, router_id)
        if agent:
            suffix = agent.get_namespace_suffix()
        else:
            suffix = self.environment.hosts[0].l3_agent.get_namespace_suffix()
        return "{}@{}".format(namespace, suffix)

    def _get_l3_agents_with_ha_state(
            self, router_id, ha_state=None):
        l3_agents = [host.agents['l3'] for host in self.environment.hosts
                     if 'l3' in host.agents]
        found_agents = []
        agents_hosting_router = self.client.list_l3_agent_hosting_routers(
            router_id)['agents']

        for agent in l3_agents:
            agent_host = agent.neutron_cfg_fixture.get_host()
            for agent_hosting_router in agents_hosting_router:
                if (agent_hosting_router['host'] == agent_host and
                        ((ha_state is None) or (
                             agent_hosting_router['ha_state'] == ha_state))):
                    found_agents.append(agent)
                    break
        return found_agents

    def _get_hosts_with_ha_state(
            self, router_id, ha_state=None):
        return [
            self.environment.get_host_by_name(agent.hostname)
            for agent in self._get_l3_agents_with_ha_state(router_id, ha_state)
        ]

    def _router_fip_qos_after_admin_state_down_up(self, ha=False):
        def get_router_gw_interface():
            devices = ip.get_devices()
            return [dev.name for dev in devices if dev.name.startswith('qg-')]

        tenant_id = uuidutils.generate_uuid()
        ext_net, ext_sub = self._create_external_network_and_subnet(tenant_id)
        external_vm = self._create_external_vm(ext_net, ext_sub)

        router = self.safe_client.create_router(tenant_id,
                                                ha=ha,
                                                external_network=ext_net['id'])

        vm = self._create_net_subnet_and_vm(
            tenant_id, ['20.0.0.0/24', '2001:db8:aaaa::/64'],
            self.environment.hosts[1], router)
        # ping external vm to test snat
        vm.block_until_ping(external_vm.ip)

        qos_policy = self.safe_client.create_qos_policy(
            tenant_id, 'fs_policy', 'Fullstack testing policy',
            shared='False', is_default='False')
        self.safe_client.create_bandwidth_limit_rule(
            qos_policy['id'], 1111, 2222, constants.INGRESS_DIRECTION)
        self.safe_client.create_bandwidth_limit_rule(
            qos_policy['id'], 3333, 4444, constants.EGRESS_DIRECTION)

        fip = self.safe_client.create_floatingip(
            tenant_id, ext_net['id'], vm.ip, vm.neutron_port['id'],
            qos_policy_id=qos_policy['id'])
        # ping floating ip from external vm
        external_vm.block_until_ping(fip['floating_ip_address'])

        self.safe_client.update_router(router['id'], admin_state_up=False)
        external_vm.block_until_no_ping(fip['floating_ip_address'])

        self.safe_client.update_router(router['id'], admin_state_up=True)
        external_vm.block_until_ping(fip['floating_ip_address'])

        if ha:
            router_agent = self._get_l3_agents_with_ha_state(router['id'])[0]
            qrouter_ns = self._get_namespace(
                            router['id'],
                            router_agent)
        else:
            qrouter_ns = self._get_namespace(router['id'])
        ip = ip_lib.IPWrapper(qrouter_ns)
        try:
            base.wait_until_true(get_router_gw_interface)
        except common_utils.WaitTimeout:
            self.fail('Router gateway interface "qg-*" not found')

        interface_name = get_router_gw_interface()[0]
        tc_wrapper = l3_tc_lib.FloatingIPTcCommand(
            interface_name,
            namespace=qrouter_ns)
        base.wait_until_true(
            functools.partial(
                self._wait_until_filters_set,
                tc_wrapper),
            timeout=60)

    def _wait_until_filters_set(self, tc_wrapper):

        def _is_filter_set(direction):
            filter_ids = tc_wrapper.get_existing_filter_ids(
                direction)
            if not filter_ids:
                return False
            return 1 == len(filter_ids)
        return (_is_filter_set(constants.INGRESS_DIRECTION) and
                _is_filter_set(constants.EGRESS_DIRECTION))

    def _test_concurrent_router_subnet_attachment_overlapping_cidr(self,
                                                                   ha=False):
        tenant_id = uuidutils.generate_uuid()
        subnet_cidr = '10.200.0.0/24'
        # to have many port interactions where race conditions would happen
        # deleting ports meanwhile find operations to evaluate the overlapping
        subnets = 10

        funcs = []
        args = []
        router = self.safe_client.create_router(tenant_id, ha=ha)

        for i in range(subnets):
            network_tmp = self.safe_client.create_network(
                tenant_id, name='foo-network' + str(i))
            subnet_tmp = self.safe_client.create_subnet(
                tenant_id, network_tmp['id'], subnet_cidr)
            funcs.append(self.safe_client.add_router_interface)
            args.append((router['id'], subnet_tmp['id']))

        exception_requests = self._simulate_concurrent_requests_process(
            funcs, args)

        if not all(isinstance(e, exceptions.BadRequest)
                   for e in exception_requests):
            self.fail('Unexpected exception adding interfaces to router from '
                      'different subnets overlapping')

        if len(exception_requests) < subnets - 1:
            self.fail('If we have tried to associate %s subnets overlapping '
                      'cidr to the router, we should have received at least '
                      '%s or %s rejected requests, but we have only received '
                      '%s' % (str(subnets), str(subnets - 1), str(subnets),
                              str(len(exception_requests))))


class TestLegacyL3Agent(TestL3Agent):

    # NOTE(slaweq): don't use dhcp agents due to the oslo.privsep bug
    # https://review.opendev.org/c/openstack/neutron/+/794994
    # When it will be fixed DHCP can be used here again.
    use_dhcp = False

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(l3_agent=True,
                                        dhcp_agent=self.use_dhcp,
                                        l3_agent_extensions="fip_qos"),
            environment.HostDescription()]
        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type='vlan', l2_pop=False,
                qos=True),
            host_descriptions)
        super().setUp(env)

    def test_mtu_update(self):
        tenant_id = uuidutils.generate_uuid()

        router = self.safe_client.create_router(tenant_id)
        network = self.safe_client.create_network(tenant_id)
        subnet = self.safe_client.create_subnet(
            tenant_id, network['id'], '20.0.0.0/24', gateway_ip='20.0.0.1')
        self.safe_client.add_router_interface(router['id'], subnet['id'])

        namespace = self._get_namespace(router['id'])
        self.assert_namespace_exists(namespace)

        ip = ip_lib.IPWrapper(namespace)
        base.wait_until_true(lambda: ip.get_devices())

        devices = ip.get_devices()
        self.assertEqual(1, len(devices))

        ri_dev = devices[0]
        mtu = ri_dev.link.mtu
        self.assertEqual(1500, mtu)

        mtu -= 1
        network = self.safe_client.update_network(network['id'], mtu=mtu)
        base.wait_until_true(lambda: ri_dev.link.mtu == mtu)

    def test_gateway_ip_changed(self):
        self._test_gateway_ip_changed()

    def test_external_subnet_changed(self):
        self._test_external_subnet_changed()

    def test_router_fip_qos_after_admin_state_down_up(self):
        self._router_fip_qos_after_admin_state_down_up()

    def test_concurrent_router_subnet_attachment_overlapping_cidr(self):
        self._test_concurrent_router_subnet_attachment_overlapping_cidr()


class TestHAL3Agent(TestL3Agent):

    # NOTE(slaweq): don't use dhcp agents due to the oslo.privsep bug
    # https://review.opendev.org/c/openstack/neutron/+/794994
    # When it will be fixed DHCP can be used here again.
    use_dhcp = False

    def setUp(self):
        # Two hosts with L3 agent to host HA routers
        host_descriptions = [
            environment.HostDescription(l3_agent=True,
                                        dhcp_agent=self.use_dhcp,
                                        l3_agent_extensions="fip_qos")
            for _ in range(2)]

        # Add two hosts for FakeFullstackMachines
        host_descriptions.extend([
            environment.HostDescription()
            for _ in range(2)
        ])

        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type='vlan', l2_pop=True,
                agent_down_time=30,
                qos=True),
            host_descriptions)
        super().setUp(env)

    def _is_ha_router_active_on_one_agent(self, router_id):
        agents = self.client.list_l3_agent_hosting_routers(router_id)
        return (
            agents['agents'][0]['ha_state'] != agents['agents'][1]['ha_state'])

    def test_ha_router(self):
        tenant_id = uuidutils.generate_uuid()
        router = self.safe_client.create_router(tenant_id, ha=True)

        base.wait_until_true(
            lambda:
            len(self.client.list_l3_agent_hosting_routers(
                router['id'])['agents']) == 2,
            timeout=90)

        base.wait_until_true(
            functools.partial(
                self._is_ha_router_active_on_one_agent,
                router['id']),
            timeout=90)

    def _test_ha_router_failover(self, method):
        tenant_id = uuidutils.generate_uuid()

        # Create router
        router = self.safe_client.create_router(tenant_id, ha=True)
        router_id = router['id']
        agents = self.client.list_l3_agent_hosting_routers(router_id)
        self.assertEqual(2, len(agents['agents']),
                         'HA router must be scheduled to both nodes')

        # Create internal subnet
        network = self.safe_client.create_network(tenant_id)
        subnet = self.safe_client.create_subnet(
            tenant_id, network['id'], '20.0.0.0/24')
        self.safe_client.add_router_interface(router_id, subnet['id'])

        # Create external network
        external_network = self.safe_client.create_network(
            tenant_id, external=True)
        self.safe_client.create_subnet(
            tenant_id, external_network['id'], '42.0.0.0/24',
            enable_dhcp=False)
        self.safe_client.add_gateway_router(
            router_id,
            external_network['id'])

        # Create internal VM
        vm = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[2],
                network['id'],
                tenant_id,
                self.safe_client))
        vm.block_until_boot()

        # Create external VM
        external = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[3],
                external_network['id'],
                tenant_id,
                self.safe_client))
        external.block_until_boot()

        base.wait_until_true(
            functools.partial(
                self._is_ha_router_active_on_one_agent,
                router_id),
            timeout=90)

        # Test external connectivity, failover, test again
        pinger = net_helpers.Pinger(vm.namespace, external.ip, interval=0.1)
        netcat_tcp = net_helpers.NetcatTester(
            vm.namespace,
            external.namespace,
            external.ip,
            3333,
            net_helpers.NetcatTester.TCP,
        )
        netcat_udp = net_helpers.NetcatTester(
            vm.namespace,
            external.namespace,
            external.ip,
            3334,
            net_helpers.NetcatTester.UDP,
        )

        pinger.start()

        # Ensure connectivity before disconnect
        vm.block_until_ping(external.ip)
        netcat_tcp.establish_connection()
        netcat_udp.establish_connection()

        get_active_hosts = functools.partial(
            self._get_hosts_with_ha_state,
            router_id,
            'active',
        )

        def is_one_host_active_for_router():
            active_hosts = get_active_hosts()
            return len(active_hosts) == 1

        try:
            base.wait_until_true(
                is_one_host_active_for_router, timeout=15)
        except common_utils.WaitTimeout:
            pass

        # Test one last time:
        active_hosts = get_active_hosts()
        if len(active_hosts) != 1:
            self.fail('Number of active hosts for router: {}\n'
                      'Hosts: {}\n'
                      'Router: {}'.format(
                          len(active_hosts), active_hosts, router_id))
        active_host = active_hosts[0]
        backup_host = next(
            h for h in self.environment.hosts if h != active_host)

        start = datetime.now()

        if method == 'disconnect':
            active_host.disconnect()
        elif method == 'kill':
            active_host.kill(parent=self.environment)
        elif method == 'shutdown':
            active_host.shutdown(parent=self.environment)

        # Ensure connectivity is restored
        vm.block_until_ping(external.ip)
        LOG.debug(f'Connectivity restored after {datetime.now() - start}')

        # Ensure connection tracking states are synced to now active router
        netcat_tcp.test_connectivity()
        netcat_udp.test_connectivity()
        LOG.debug(f'Connections restored after {datetime.now() - start}')

        # Assert the backup host got active
        timeout = self.environment.env_desc.agent_down_time * 1.2
        base.wait_until_true(
            lambda: backup_host in get_active_hosts(),
            timeout=timeout,
        )
        LOG.debug(f'Active host asserted after {datetime.now() - start}')

        if method in ('kill', 'shutdown'):
            # Assert the previously active host is no longer active if it was
            # killed or shutdown. In the disconnect case both hosts will stay
            # active, but one host is disconnected from the data plane.
            base.wait_until_true(
                lambda: active_host not in get_active_hosts(),
                timeout=timeout,
            )
            LOG.debug(f'Inactive host asserted after {datetime.now() - start}')

        # Stop probing processes
        pinger.stop()
        netcat_tcp.stop_processes()
        netcat_udp.stop_processes()

        # With the default advert_int of 2s the keepalived master timeout is
        # about 6s. Assert less than 90 lost packets (9 seconds) plus 30 to
        # account for CI infrastructure variability
        threshold = 120

        lost = pinger.sent - pinger.received
        message = (f'Sent {pinger.sent} packets, received {pinger.received} '
                   f'packets, lost {lost} packets')

        self.assertLess(lost, threshold, message)

    def test_ha_router_failover_graceful(self):
        self._test_ha_router_failover('shutdown')

    def test_ha_router_failover_host_failure(self):
        self._test_ha_router_failover('kill')

    def test_ha_router_failover_disconnect(self):
        self._test_ha_router_failover('disconnect')

    def _get_keepalived_state(self, keepalived_state_file):
        with open(keepalived_state_file) as fd:
            return fd.read()

    def _get_state_file_for_primary_agent(self, router_id):
        for host in self.environment.hosts:
            keepalived_state_file = os.path.join(
                host.neutron_config.config.DEFAULT.state_path,
                "ha_confs", router_id, "state")

            if self._get_keepalived_state(keepalived_state_file) == "primary":
                return keepalived_state_file

    def test_keepalived_multiple_sighups_does_not_forfeit_primary(self):
        """Setup a complete "Neutron stack" - both an internal and an external
           network+subnet, and a router connected to both.
        """
        tenant_id = uuidutils.generate_uuid()
        ext_net, ext_sub = self._create_external_network_and_subnet(tenant_id)
        router = self.safe_client.create_router(tenant_id, ha=True,
                                                external_network=ext_net['id'])
        base.wait_until_true(
            lambda:
            len(self.client.list_l3_agent_hosting_routers(
                router['id'])['agents']) == 2,
            timeout=90)
        base.wait_until_true(
            functools.partial(
                self._is_ha_router_active_on_one_agent,
                router['id']),
            timeout=90)
        keepalived_state_file = self._get_state_file_for_primary_agent(
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
        # primary. This will indicate that the Throttler works. We want to
        # check for ha_vrrp_advert_int (the default is 2 seconds), plus a bit
        # more.
        time_to_stop = (time.time() +
                        (common_utils.DEFAULT_THROTTLER_VALUE *
                         ha_router.THROTTLER_MULTIPLIER * 1.3))
        while True:
            if time.time() > time_to_stop:
                break
            self.assertEqual(
                "primary",
                self._get_keepalived_state(keepalived_state_file))

    @tests_base.unstable_test("bug 1798475")
    def test_ha_router_restart_agents_no_packet_lost(self):
        tenant_id = uuidutils.generate_uuid()
        ext_net, ext_sub = self._create_external_network_and_subnet(tenant_id)
        router = self.safe_client.create_router(tenant_id, ha=True,
                                                external_network=ext_net['id'])

        external_vm = self._create_external_vm(ext_net, ext_sub)

        base.wait_until_true(
            lambda:
            len(self.client.list_l3_agent_hosting_routers(
                router['id'])['agents']) == 2,
            timeout=90)

        base.wait_until_true(
            functools.partial(
                self._is_ha_router_active_on_one_agent,
                router['id']),
            timeout=90)

        router_ip = router['external_gateway_info'][
            'external_fixed_ips'][0]['ip_address']

        l3_standby_agents = self._get_l3_agents_with_ha_state(
            router['id'], 'standby')
        l3_active_agents = self._get_l3_agents_with_ha_state(
            router['id'], 'active')
        self.assertEqual(1, len(l3_active_agents))

        # Let's check first if connectivity from external_vm to router's
        # external gateway IP is possible before we restart agents
        external_vm.block_until_ping(router_ip)

        self._assert_ping_during_agents_restart(
            l3_standby_agents, external_vm.namespace, [router_ip], count=60)

        self._assert_ping_during_agents_restart(
            l3_active_agents, external_vm.namespace, [router_ip], count=60)

    def test_gateway_ip_changed(self):
        self._test_gateway_ip_changed()

    def test_external_subnet_changed(self):
        self._test_external_subnet_changed()

    def test_router_fip_qos_after_admin_state_down_up(self):
        self._router_fip_qos_after_admin_state_down_up(ha=True)

    def test_concurrent_router_subnet_attachment_overlapping_cidr(self):
        self._test_concurrent_router_subnet_attachment_overlapping_cidr(
            ha=True)
