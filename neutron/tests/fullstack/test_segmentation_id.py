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
from neutronclient.common import exceptions
from oslo_utils import uuidutils

from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import config
from neutron.tests.fullstack.resources import environment
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests


class TestSegmentationId(base.BaseFullStackTestCase):

    scenarios = [
        ('Open vSwitch Agent', {'l2_agent_type': constants.AGENT_TYPE_OVS}),
        ('Linux Bridge Agent', {
            'l2_agent_type': constants.AGENT_TYPE_LINUXBRIDGE})]

    def setUp(self):
        hosts_description = [
            environment.HostDescription(
                l2_agent_type=self.l2_agent_type, l3_agent=False)]
        env = environment.Environment(
            environment.EnvironmentDescription(),
            hosts_description)

        super(TestSegmentationId, self).setUp(env)
        self.tenant_id = uuidutils.generate_uuid()

    def _create_network(self):
        seg_id = 100
        network = self.safe_client.create_network(
            self.tenant_id, network_type="vlan", segmentation_id=seg_id,
            physical_network=config.PHYSICAL_NETWORK_NAME)
        self.assertEqual(seg_id, network['provider:segmentation_id'])

        # Ensure that segmentation_id is really set properly in DB
        network = self.safe_client.client.show_network(
            network['id'])['network']
        self.assertEqual(seg_id, network['provider:segmentation_id'])
        return network

    def _update_segmentation_id(self, network):
        # Now change segmentation_id to some other value
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

    def test_change_segmentation_id_no_ports_in_network(self):
        network = self._create_network()
        self._update_segmentation_id(network)

    def test_change_segmentation_id_with_unbound_ports_in_network(self):
        network = self._create_network()

        self.safe_client.create_subnet(
            self.tenant_id, network['id'], '20.0.0.0/24')

        # Unbound port
        self.safe_client.create_port(self.tenant_id, network['id'])
        # Port failed to bind
        self.safe_client.create_port(self.tenant_id, network['id'],
                                     "non-exisiting-host")

        self._update_segmentation_id(network)

    def test_change_segmentation_id_with_bound_ports_in_network(self):
        network = self._create_network()

        self.safe_client.create_subnet(
            self.tenant_id, network['id'], '20.0.0.0/24')
        self.safe_client.create_port(self.tenant_id, network['id'],
                                     self.environment.hosts[0].hostname)

        if self.l2_agent_type == constants.AGENT_TYPE_LINUXBRIDGE:
            # Linuxbridge agent don't support update of segmentation_id for
            # the network so this should raise an exception
            self.assertRaises(exceptions.BadRequest,
                              self._update_segmentation_id, network)
        else:
            self._update_segmentation_id(network)
