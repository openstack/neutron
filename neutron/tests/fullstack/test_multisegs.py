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

from neutron.common import utils as common_utils
from neutron.tests import base as tests_base
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine
from neutron.tests.unit import testlib_api


load_tests = testlib_api.module_load_tests


class TestMultiSegs(base.BaseFullStackTestCase):
    scenarios = [
        ('Open vSwitch Agent', {'l2_agent_type': constants.AGENT_TYPE_OVS})]
    num_hosts = 1
    agent_down_time = 30
    network_type = "vlan"

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(
                dhcp_agent=True, l2_agent_type=constants.AGENT_TYPE_OVS),
        ]

        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type=self.network_type,
                mech_drivers='openvswitch',
                l2_pop=False,
                arp_responder=False,
                agent_down_time=self.agent_down_time,
                service_plugins='router,segments',
                api_workers=1,
            ),
            host_descriptions)

        super(TestMultiSegs, self).setUp(env)
        self.project_id = uuidutils.generate_uuid()

    def _spawn_vm(self, neutron_port=None):
        vm = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[0],
                self.network['id'],
                self.project_id,
                self.safe_client,
                neutron_port=neutron_port,
                use_dhcp=True))
        vm.block_until_boot()
        vm.block_until_dhcp_config_done()
        return vm

    @tests_base.unstable_test("bug 2007152")
    def test_multi_segs_network(self):
        ovs_physnet = None
        agents = self.client.list_agents()
        for agent in agents['agents']:
            if agent['binary'] == 'neutron-openvswitch-agent':
                ovs_physnet = list(
                    agent['configurations']['bridge_mappings'].keys())[0]

        self.network = self.safe_client.create_network(
            tenant_id=self.project_id,
            network_type=self.network_type,
            segmentation_id=1010,
            physical_network=ovs_physnet)

        self.segment1 = self.safe_client.client.list_segments()['segments'][0]
        self.segment2 = self.safe_client.create_segment(
            project_id=self.project_id,
            network=self.network['id'],
            network_type=self.network_type,
            name='segment2',
            segmentation_id=1011,
            physical_network=ovs_physnet)

        # Let's validate segments created on network
        net = self.safe_client.client.show_network(
            self.network['id'])['network']
        self.assertEqual(
            ovs_physnet, net['segments'][0]['provider:physical_network'])
        self.assertEqual(
            ovs_physnet, net['segments'][1]['provider:physical_network'])
        self.assertEqual(
            1010, net['segments'][0]['provider:segmentation_id'])
        self.assertEqual(
            1011, net['segments'][1]['provider:segmentation_id'])

        self.subnet1 = self.safe_client.create_subnet(
            self.project_id,
            self.network['id'],
            cidr='10.0.11.0/24',
            gateway_ip='10.0.11.1',
            name='subnet-test1',
            enable_dhcp=True,
            segment=self.segment1['id'])

        self.port1 = self.safe_client.create_port(
            network_id=self.network['id'],
            tenant_id=self.project_id,
            hostname=self.environment.hosts[0].hostname,
            fixed_ips=[{'subnet_id': self.subnet1['id']}])

        self.subnet2 = self.safe_client.create_subnet(
            self.project_id,
            self.network['id'],
            cidr='10.0.12.0/24',
            gateway_ip='10.0.12.1',
            name='subnet-test2',
            enable_dhcp=True,
            segment=self.segment2['id'])

        self.port2 = self.safe_client.create_port(
            network_id=self.network['id'],
            tenant_id=self.project_id,
            hostname=self.environment.hosts[0].hostname,
            fixed_ips=[{'subnet_id': self.subnet2['id']}])

        def _is_dhcp_ports_ready():
            dhcp_ports = self.safe_client.list_ports(**{
                'device_owner': 'network:dhcp',
                'network_id': self.network['id']})
            if len(dhcp_ports) != 2:
                return False
            if dhcp_ports[0]['status'] != 'ACTIVE':
                return False
            if dhcp_ports[1]['status'] != 'ACTIVE':
                return False
            return True
        common_utils.wait_until_true(_is_dhcp_ports_ready)

        self.vm1 = self._spawn_vm(neutron_port=self.port1)
        self.vm2 = self._spawn_vm(neutron_port=self.port2)
