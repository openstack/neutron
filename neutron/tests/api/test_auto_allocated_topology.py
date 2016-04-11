# Copyright 2016 IBM
# All Rights Reserved.
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

from oslo_config import cfg
from tempest import test

from neutron.tests.api import base


class TestAutoAllocatedTopology(base.BaseAdminNetworkTest):

    """
    NOTE: This test may eventually migrate to Tempest.

    Tests the Get-Me-A-Network operation in the Neutron API
    using the REST client for Neutron.
    """

    @classmethod
    @test.requires_ext(extension="auto-allocated-topology", service="network")
    def skip_checks(cls):
        super(TestAutoAllocatedTopology, cls).skip_checks()

    @classmethod
    def resource_setup(cls):
        super(TestAutoAllocatedTopology, cls).resource_setup()

        # The deployment must contain a default subnetpool
        body = cls.client.list_subnetpools(is_default=True)
        # The deployment may contain one or two default subnetpools:
        # one ipv4 pool, or one ipv6 pool, or one of each.
        # This run-time dependency should be revisited if the test is
        # moved over to tempest.
        cls.num_subnetpools = len(body['subnetpools'])
        if cls.num_subnetpools == 0:
            raise cls.skipException("No default subnetpool")

        # Ensure the public external network is the default external network
        public_net_id = cfg.CONF.network.public_network_id
        cls.admin_client.update_network(public_net_id, is_default=True)

    def _count_topology_resources(self):
        '''Count the resources whose names begin with 'auto_allocated_'.'''

        def _count(resources):
            return len([resource['id'] for resource in resources
                        if resource['name'].startswith('auto_allocated_')])

        networks = _count(self.client.list_networks()['networks'])
        subnets = _count(self.client.list_subnets()['subnets'])
        routers = _count(self.client.list_routers()['routers'])
        return networks, subnets, routers

    def _add_topology_cleanup(self, client):
        '''Add the auto-allocated resources to the cleanup lists.'''

        body = client.list_routers(name='auto_allocated_router')
        self.routers.extend(body['routers'])
        body = client.list_subnets(name='auto_allocated_subnet_v4')
        self.subnets.extend(body['subnets'])
        body = client.list_subnets(name='auto_allocated_subnet_v6')
        self.subnets.extend(body['subnets'])
        body = client.list_networks(name='auto_allocated_network')
        self.networks.extend(body['networks'])

    @test.attr(type='smoke')
    @test.idempotent_id('64bc0b02-cee4-11e5-9f3c-080027605a2b')
    def test_get_allocated_net_topology_as_tenant(self):
        resources_before = self._count_topology_resources()
        self.assertEqual((0, 0, 0), resources_before)

        body = self.client.get_auto_allocated_topology()
        topology = body['auto_allocated_topology']
        self.assertIsNotNone(topology)
        self._add_topology_cleanup(self.client)

        network_id1 = topology['id']
        self.assertIsNotNone(network_id1)
        resources_after1 = self._count_topology_resources()
        # One network, two subnets (v4 and v6) and one router
        self.assertEqual((1, self.num_subnetpools, 1), resources_after1)

        body = self.client.get_auto_allocated_topology()
        topology = body['auto_allocated_topology']
        network_id2 = topology['id']
        resources_after2 = self._count_topology_resources()
        # After the initial GET, the API should be idempotent
        self.assertEqual(network_id1, network_id2)
        self.assertEqual(resources_after1, resources_after2)
