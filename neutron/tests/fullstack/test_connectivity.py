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

from oslo_utils import uuidutils
import testscenarios

from neutron.common import constants
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine


load_tests = testscenarios.load_tests_apply_scenarios


class BaseConnectivitySameNetworkTest(base.BaseFullStackTestCase):

    def setUp(self):
        host_descriptions = [
            # There's value in enabling L3 agents registration when l2pop
            # is enabled, because l2pop code makes assumptions about the
            # agent types present on machines.
            environment.HostDescription(
                l3_agent=self.l2_pop,
                of_interface=self.of_interface,
                l2_agent_type=self.l2_agent_type) for _ in range(3)]
        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type=self.network_type,
                l2_pop=self.l2_pop),
            host_descriptions)
        super(BaseConnectivitySameNetworkTest, self).setUp(env)

    def _test_connectivity(self):
        tenant_uuid = uuidutils.generate_uuid()

        network = self.safe_client.create_network(tenant_uuid)
        self.safe_client.create_subnet(
            tenant_uuid, network['id'], '20.0.0.0/24')

        vms = [
            self.useFixture(
                machine.FakeFullstackMachine(
                    self.environment.hosts[i],
                    network['id'],
                    tenant_uuid,
                    self.safe_client))
            for i in range(3)]

        for vm in vms:
            vm.block_until_boot()

        vms[0].block_until_ping(vms[1].ip)
        vms[0].block_until_ping(vms[2].ip)
        vms[1].block_until_ping(vms[2].ip)


class TestOvsConnectivitySameNetwork(BaseConnectivitySameNetworkTest):

    l2_agent_type = constants.AGENT_TYPE_OVS
    network_scenarios = [
        ('VXLAN', {'network_type': 'vxlan',
                   'l2_pop': False}),
        ('GRE and l2pop', {'network_type': 'gre',
                           'l2_pop': True}),
        ('VLANs', {'network_type': 'vlan',
                   'l2_pop': False})]
    interface_scenarios = [
        ('Ofctl', {'of_interface': 'ovs-ofctl'}),
        ('Native', {'of_interface': 'native'})]
    scenarios = testscenarios.multiply_scenarios(
        network_scenarios, interface_scenarios)

    def test_connectivity(self):
        self._test_connectivity()


class TestLinuxBridgeConnectivitySameNetwork(BaseConnectivitySameNetworkTest):

    l2_agent_type = constants.AGENT_TYPE_LINUXBRIDGE
    scenarios = [
        ('VXLAN', {'network_type': 'vxlan',
                   'l2_pop': False}),
        ('VLANs', {'network_type': 'vlan',
                   'l2_pop': False}),
        ('VXLAN and l2pop', {'network_type': 'vxlan',
                             'l2_pop': True})
    ]
    of_interface = None

    def test_connectivity(self):
        self._test_connectivity()
