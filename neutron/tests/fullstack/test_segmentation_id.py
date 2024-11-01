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

from neutron.tests.common.agents import l2_extensions
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import config
from neutron.tests.fullstack.resources import environment
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests


class BaseSegmentationIdTest(base.BaseFullStackTestCase):

    network_type = "vlan"

    def setUp(self):
        host_descriptions = [
            environment.HostDescription(
                l2_agent_type=self.l2_agent_type, l3_agent=False
            ) for _ in range(self.num_hosts)]
        env = environment.Environment(
            environment.EnvironmentDescription(
                network_type=self.network_type),
            host_descriptions)

        super().setUp(env)
        self.project_id = uuidutils.generate_uuid()

    def _create_network(self):
        seg_id = 100
        network = self.safe_client.create_network(
            self.project_id, network_type=self.network_type,
            segmentation_id=seg_id,
            physical_network=config.PHYSICAL_NETWORK_NAME)
        self.assertEqual(seg_id, network['provider:segmentation_id'])

        # Ensure that segmentation_id is really set properly in DB
        network = self.safe_client.client.show_network(
            network['id'])['network']
        self.assertEqual(seg_id, network['provider:segmentation_id'])
        return network

    def _update_segmentation_id(self, network):
        new_seg_id = network['provider:segmentation_id'] + 1
        new_net_args = {'provider:segmentation_id': new_seg_id}
        network = self.safe_client.update_network(
            network['id'], **new_net_args)
        self.assertEqual(
            new_seg_id, network['provider:segmentation_id'])
        # Ensure that segmentation_id was really changed
        network = self.safe_client.client.show_network(
            network['id'])['network']
        self.assertEqual(new_seg_id, network['provider:segmentation_id'])
        return network


class TestSegmentationId(BaseSegmentationIdTest):

    scenarios = [
        ('Open vSwitch Agent', {'l2_agent_type': constants.AGENT_TYPE_OVS}),
    ]
    num_hosts = 1

    def test_change_segmentation_id(self):
        network = self._create_network()
        # Now change segmentation_id to some other value when there are no
        # ports created in network
        network = self._update_segmentation_id(network)

        self.safe_client.create_subnet(
            self.project_id, network['id'], '20.0.0.0/24')

        # Create some unbound and binding_failed ports
        # Unbound port
        self.safe_client.create_port(self.project_id, network['id'])
        # Port failed to bind
        self.safe_client.create_port(self.project_id, network['id'],
                                     "non-existing-host")

        # Test update segmentation_id to some othe value with unbound and
        # binding_failed ports created in the network
        network = self._update_segmentation_id(network)

        # Create bound port
        self.safe_client.create_port(self.project_id, network['id'],
                                     self.environment.hosts[0].hostname)

        # Test update segmentation_id to some othe value when bound ports are
        # created in the network
        self._update_segmentation_id(network)


class TestSegmentationIdConnectivity(BaseSegmentationIdTest):

    scenarios = [
        ('Open vSwitch Agent', {'l2_agent_type': constants.AGENT_TYPE_OVS})]

    num_hosts = 2

    def _ensure_vlan_id_set_in_flows(self, vlan_id):
        for host in self.environment.hosts:
            l2_extensions.wait_for_mod_vlan_id_applied(host.br_phys, vlan_id)

    def test_connectivity_after_segmentation_id_update(self):
        network = self._create_network()
        self.safe_client.create_subnet(
            self.project_id, network['id'],
            cidr='10.0.0.0/24',
            gateway_ip='10.0.0.1',
            name='subnet-test',
            enable_dhcp=False)

        vms = self._prepare_vms_in_net(self.project_id, network, False)
        self._ensure_vlan_id_set_in_flows(network['provider:segmentation_id'])
        vms.ping_all()

        network = self._update_segmentation_id(network)
        self._ensure_vlan_id_set_in_flows(network['provider:segmentation_id'])
        vms.ping_all()
