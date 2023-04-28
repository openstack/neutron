# Copyright 2016 OVH SAS
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

import random

from neutron_lib import constants
from oslo_utils import uuidutils

from neutron.agent.linux import ip_lib
from neutron.common import utils as common_utils
from neutron.tests.fullstack.agents import dhcp_agent
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests


class BaseDhcpAgentTest(base.BaseFullStackTestCase):

    scenarios = [
        (constants.AGENT_TYPE_OVS,
         {'l2_agent_type': constants.AGENT_TYPE_OVS}),
        (constants.AGENT_TYPE_LINUXBRIDGE,
         {'l2_agent_type': constants.AGENT_TYPE_LINUXBRIDGE})
    ]
    boot_vm_for_test = True
    dhcp_scheduler_class = None
    api_workers = 1

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(
                dhcp_agent=True,
                l2_agent_type=self.l2_agent_type
            ) for _ in range(self.number_of_hosts)]

        env = environment.Environment(
            environment.EnvironmentDescription(
                l2_pop=False,
                arp_responder=False,
                agent_down_time=self.agent_down_time,
                dhcp_scheduler_class=self.dhcp_scheduler_class,
                api_workers=self.api_workers,
            ),
            host_descriptions)

        super(BaseDhcpAgentTest, self).setUp(env)
        self.project_id = uuidutils.generate_uuid()
        if self.boot_vm_for_test:
            self._create_network_subnet_and_vm()

    def _spawn_vm(self):
        host = random.choice(self.environment.hosts)
        vm = self.useFixture(
            machine.FakeFullstackMachine(
                host,
                self.network['id'],
                self.project_id,
                self.safe_client,
                use_dhcp=True))
        vm.block_until_boot()
        vm.block_until_dhcp_config_done()
        return vm

    def _create_network_subnet_and_vm(self):
        self.network = self.safe_client.create_network(self.project_id)

        self.subnet = self.safe_client.create_subnet(
            self.project_id, self.network['id'],
            cidr='10.0.0.0/24',
            gateway_ip='10.0.0.1',
            name='subnet-test',
            enable_dhcp=True)

        self.vm = self._spawn_vm()


class TestDhcpAgentNoHA(BaseDhcpAgentTest):

    number_of_hosts = 1
    agent_down_time = 60

    def test_dhcp_assignment(self):
        # First check if network was scheduled to one DHCP agent
        dhcp_agents = self.client.list_dhcp_agent_hosting_networks(
            self.network['id'])
        self.assertEqual(1, len(dhcp_agents['agents']))

        # And check if IP and gateway config is fine on FakeMachine
        self.vm.block_until_dhcp_config_done()

    def test_mtu_update(self):
        # The test case needs access to devices in nested namespaces. ip_lib
        # doesn't support it, and it's probably unsafe to touch the library for
        # testing matters.
        # TODO(jlibosva) revisit when ip_lib supports nested namespaces
        if self.environment.hosts[0].dhcp_agent.namespace is not None:
            self.skipTest("ip_lib doesn't support nested namespaces")

        self.vm.block_until_dhcp_config_done()

        namespace = dhcp_agent._get_namespace_name(
            self.network['id'],
            suffix=self.environment.hosts[0].dhcp_agent.get_namespace_suffix())
        self.assert_namespace_exists(namespace)

        ip = ip_lib.IPWrapper(namespace)
        devices = ip.get_devices()
        self.assertEqual(1, len(devices))

        dhcp_dev = devices[0]
        mtu = dhcp_dev.link.mtu
        self.assertEqual(1450, mtu)

        mtu -= 1
        self.safe_client.update_network(self.network['id'], mtu=mtu)
        common_utils.wait_until_true(lambda: dhcp_dev.link.mtu == mtu)


class TestDhcpAgentHA(BaseDhcpAgentTest):

    number_of_hosts = 2
    agent_down_time = 30

    def _wait_until_network_rescheduled(self, old_agent):
        def _agent_rescheduled():
            network_agents = self.client.list_dhcp_agent_hosting_networks(
                self.network['id'])['agents']
            if network_agents:
                return network_agents[0]['id'] != old_agent['id']
            return False

        common_utils.wait_until_true(_agent_rescheduled, timeout=120)

    def _kill_dhcp_agent(self, agent):
        for host in self.environment.hosts:
            hostname = host.dhcp_agent.get_agent_hostname()
            if hostname == agent['host']:
                host.dhcp_agent.kill()
                self._wait_until_agent_down(agent['id'])
                break

    def _add_network_to_new_agent(self):
        dhcp_agents = self.client.list_agents(
            agent_type=constants.AGENT_TYPE_DHCP)['agents']
        dhcp_agents_ids = [agent['id'] for agent in dhcp_agents]

        current_agents = self.client.list_dhcp_agent_hosting_networks(
            self.network['id'])['agents']
        current_agents_ids = [agent['id'] for agent in current_agents]

        new_agents_ids = list(set(dhcp_agents_ids) - set(current_agents_ids))
        if new_agents_ids:
            new_agent_id = random.choice(new_agents_ids)
            self.client.add_network_to_dhcp_agent(
                new_agent_id, {'network_id': self.network['id']})

    def test_reschedule_network_on_new_agent(self):
        network_dhcp_agents = self.client.list_dhcp_agent_hosting_networks(
            self.network['id'])['agents']
        self.assertEqual(1, len(network_dhcp_agents))

        self._kill_dhcp_agent(network_dhcp_agents[0])
        self._wait_until_network_rescheduled(network_dhcp_agents[0])

        # ensure that only one agent is handling DHCP for this network
        new_network_dhcp_agents = self.client.list_dhcp_agent_hosting_networks(
            self.network['id'])['agents']
        self.assertEqual(1, len(new_network_dhcp_agents))

        # check if new vm will get IP from new DHCP agent
        self._spawn_vm()

    def test_multiple_agents_for_network(self):
        network_dhcp_agents = self.client.list_dhcp_agent_hosting_networks(
            self.network['id'])['agents']
        self.assertEqual(1, len(network_dhcp_agents))

        self._add_network_to_new_agent()
        # ensure that two agents are handling DHCP for this network
        network_dhcp_agents = self.client.list_dhcp_agent_hosting_networks(
            self.network['id'])['agents']
        self.assertEqual(2, len(network_dhcp_agents))

        self._kill_dhcp_agent(network_dhcp_agents[0])

        # check if new vm will get IP from DHCP agent which is still alive
        self._spawn_vm()


class TestDhcpAgentHARaceCondition(BaseDhcpAgentTest):

    agent_down_time = 30
    number_of_hosts = 2
    boot_vm_for_test = False
    api_workers = 2
    dhcp_scheduler_class = ('neutron.tests.fullstack.schedulers.dhcp.'
                            'AlwaysTheOtherAgentScheduler')

    def setUp(self):
        super(TestDhcpAgentHARaceCondition, self).setUp()
        self._create_network_with_multiple_subnets()

    def _create_network_with_multiple_subnets(self):
        self.network = self.safe_client.create_network(self.project_id)

        funcs = []
        args = []
        for i in range(4):
            funcs.append(self.safe_client.create_subnet)
            args.append((
                self.project_id, self.network['id'], '10.0.%s.0/24' % i,
                '10.0.%s.1' % i, 'subnet-test-%s' % i, True
            ))
        self._simulate_concurrent_requests_process_and_raise(funcs, args)

    def test_dhcp_agent_ha_with_race_condition(self):
        # NOTE(ralonsoh): the concurrent creation in the same thread could
        # fail because the context and the session is the same for all DB
        # calls.
        network_dhcp_agents = self.client.list_dhcp_agent_hosting_networks(
            self.network['id'])['agents']
        self.assertEqual(1, len(network_dhcp_agents))


class TestSubnetDeleteRace(BaseDhcpAgentTest):
    agent_down_time = 30
    number_of_hosts = 2
    boot_vm_for_test = False

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(
                dhcp_agent=True, l2_agent_type=constants.AGENT_TYPE_OVS),
            environment.HostDescription(
                dhcp_agent=False,
                l2_agent_type=constants.AGENT_TYPE_LINUXBRIDGE)
        ]

        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type='vlan',
                mech_drivers='openvswitch,linuxbridge',
                l2_pop=False,
                arp_responder=False,
                agent_down_time=self.agent_down_time,
                service_plugins='router,segments'
            ),
            host_descriptions)

        # Note(lajoskatona): Here, call grandparent's (BaseFullStackTestCase)
        # setup(), to avoid BaseDhcpAgentTest mess up environment.
        super(BaseDhcpAgentTest, self).setUp(env)
        self.project_id = uuidutils.generate_uuid()
        if self.boot_vm_for_test:
            self._create_network_subnet_and_vm()

    def test_subnet_delete_race_condition(self):
        ovs_physnet = ''
        lb_physnet = ''

        agents = self.client.list_agents()
        for agent in agents['agents']:
            if agent['binary'] == 'neutron-openvswitch-agent':
                ovs_physnet = list(
                    agent['configurations']['bridge_mappings'].keys())[0]
            if agent['binary'] == 'neutron-linuxbridge-agent':
                lb_physnet = list(
                    agent['configurations']['interface_mappings'].keys())[0]

        self.network = self.safe_client.create_network(
            tenant_id=self.project_id, network_type='vlan',
            segmentation_id=103, physical_network=lb_physnet)

        self.segment2 = self.safe_client.create_segment(
            project_id=self.project_id, network=self.network['id'],
            network_type='vlan', name='segment_2', segmentation_id=103,
            physical_network=ovs_physnet)

        subnet = self.safe_client.create_subnet(
            self.project_id,
            self.network['id'],
            cidr='10.0.11.0/24',
            gateway_ip='10.0.11.1',
            name='subnet-test',
            enable_dhcp=True)

        self.vm = self._spawn_vm()

        dhcp_ports = self.safe_client.list_ports(**{
            'device_owner': 'network:dhcp',
            'network_id': self.network['id']
        })
        self.assertEqual(1, len(dhcp_ports))
        self.assertEqual('ACTIVE', dhcp_ports[0]['status'])

        self.vm.destroy(delete_port=True)

        dhcp_ports = self.safe_client.list_ports(**{
            'device_owner': 'network:dhcp',
            'network_id': self.network['id']
        })
        self.assertEqual(1, len(dhcp_ports))

        self.client.delete_subnet(subnet['id'])

        def _is_subnet_deleted():
            snets = self.safe_client.list_subnets()
            if len(snets) == 0:
                return True
            return False

        common_utils.wait_until_true(_is_subnet_deleted)
        # Note(lajoskatona): Here cleanup do its job and the cleanup
        # will fail if the segment or network deletion is inpossible
