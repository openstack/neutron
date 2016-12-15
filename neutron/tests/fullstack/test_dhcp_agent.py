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

from neutron_lib import constants
from oslo_utils import uuidutils

from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests


class TestDhcpAgent(base.BaseFullStackTestCase):

    scenarios = [
        (constants.AGENT_TYPE_OVS,
         {'l2_agent_type': constants.AGENT_TYPE_OVS}),
        (constants.AGENT_TYPE_LINUXBRIDGE,
         {'l2_agent_type': constants.AGENT_TYPE_LINUXBRIDGE})
    ]

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(
                dhcp_agent=True,
                l2_agent_type=self.l2_agent_type)]

        env = environment.Environment(
            environment.EnvironmentDescription(
                l2_pop=False,
                arp_responder=False),
            host_descriptions)

        super(TestDhcpAgent, self).setUp(env)
        self.project_id = uuidutils.generate_uuid()
        self._create_network_subnet_and_vm()

    def _create_network_subnet_and_vm(self):
        self.network = self.safe_client.create_network(self.project_id)

        self.subnet = self.safe_client.create_subnet(
            self.project_id, self.network['id'],
            cidr='10.0.0.0/24',
            gateway_ip='10.0.0.1',
            name='subnet-test',
            enable_dhcp=True)

        self.vm = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[0],
                self.network['id'],
                self.project_id,
                self.safe_client,
                use_dhcp=True))
        self.vm.block_until_boot()

    def test_dhcp_assignment(self):
        # First check if network was scheduled to one DHCP agent
        dhcp_agents = self.client.list_dhcp_agent_hosting_networks(
            self.network['id'])
        self.assertEqual(1, len(dhcp_agents['agents']))

        # And check if IP and gateway config is fine on FakeMachine
        self.vm.block_until_dhcp_config_done()
