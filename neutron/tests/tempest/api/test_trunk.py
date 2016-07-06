# Copyright 2016 Hewlett Packard Enterprise Development Company LP
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

from tempest.lib import exceptions as lib_exc
from tempest import test

from neutron.tests.tempest.api import base


class TrunkTestJSONBase(base.BaseAdminNetworkTest):

    def _create_trunk_with_network_and_parent(self, subports):
        network = self.create_network()
        parent_port = self.create_port(network)
        return self.client.create_trunk(parent_port['id'], subports)


class TrunkTestJSON(TrunkTestJSONBase):

    @classmethod
    @test.requires_ext(extension="trunk", service="network")
    def resource_setup(cls):
        super(TrunkTestJSON, cls).resource_setup()

    def tearDown(self):
        # NOTE(tidwellr) These tests create networks and ports, clean them up
        # after each test to avoid hitting quota limits
        self.resource_cleanup()
        super(TrunkTestJSON, self).tearDown()

    @test.idempotent_id('e1a6355c-4768-41f3-9bf8-0f1d192bd501')
    def test_create_trunk_empty_subports_list(self):
        trunk = self._create_trunk_with_network_and_parent([])
        observed_trunk = self.client.show_trunk(trunk['trunk']['id'])
        self.assertEqual(trunk, observed_trunk)

    @test.idempotent_id('382dfa39-ca03-4bd3-9a1c-91e36d2e3796')
    def test_create_trunk_subports_not_specified(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        observed_trunk = self.client.show_trunk(trunk['trunk']['id'])
        self.assertEqual(trunk, observed_trunk)

    @test.idempotent_id('7de46c22-e2b6-4959-ac5a-0e624632ab32')
    def test_create_show_delete_trunk(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        trunk_id = trunk['trunk']['id']
        parent_port_id = trunk['trunk']['port_id']
        res = self.client.show_trunk(trunk_id)
        self.assertEqual(trunk_id, res['trunk']['id'])
        self.assertEqual(parent_port_id, res['trunk']['port_id'])
        self.client.delete_trunk(trunk_id)
        self.assertRaises(lib_exc.NotFound, self.client.show_trunk, trunk_id)

    @test.idempotent_id('73365f73-bed6-42cd-960b-ec04e0c99d85')
    def test_list_trunks(self):
        trunk1 = self._create_trunk_with_network_and_parent(None)
        trunk2 = self._create_trunk_with_network_and_parent(None)
        expected_trunks = {trunk1['trunk']['id']: trunk1['trunk'],
                           trunk2['trunk']['id']: trunk2['trunk']}
        trunk_list = self.client.list_trunks()['trunks']
        matched_trunks = [x for x in trunk_list if x['id'] in expected_trunks]
        self.assertEqual(2, len(matched_trunks))
        for trunk in matched_trunks:
            self.assertEqual(expected_trunks[trunk['id']], trunk)

    @test.idempotent_id('bb5fcead-09b5-484a-bbe6-46d1e06d6cc0')
    def test_add_subport(self):
        trunk = self._create_trunk_with_network_and_parent([])
        network = self.create_network()
        port = self.create_port(network)
        subports = [{'port_id': port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]
        self.client.add_subports(trunk['trunk']['id'], subports)
        trunk = self.client.show_trunk(trunk['trunk']['id'])
        observed_subports = trunk['trunk']['sub_ports']
        self.assertEqual(1, len(observed_subports))
        created_subport = observed_subports[0]
        self.assertEqual(subports[0], created_subport)

    @test.idempotent_id('96eea398-a03c-4c3e-a99e-864392c2ca53')
    def test_remove_subport(self):
        subport_parent1 = self.create_port(self.create_network())
        subport_parent2 = self.create_port(self.create_network())
        subports = [{'port_id': subport_parent1['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2},
                    {'port_id': subport_parent2['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 4}]
        trunk = self._create_trunk_with_network_and_parent(subports)
        removed_subport = trunk['trunk']['sub_ports'][0]
        expected_subport = None

        for subport in subports:
            if subport['port_id'] != removed_subport['port_id']:
                expected_subport = subport
                break

        # Remove the subport and validate PUT response
        res = self.client.remove_subports(trunk['trunk']['id'],
                                          [removed_subport])
        self.assertEqual(1, len(res['sub_ports']))
        self.assertEqual(expected_subport, res['sub_ports'][0])

        # Validate the results of a subport list
        trunk = self.client.show_trunk(trunk['trunk']['id'])
        observed_subports = trunk['trunk']['sub_ports']
        self.assertEqual(1, len(observed_subports))
        self.assertEqual(expected_subport, observed_subports[0])

    @test.idempotent_id('bb5fcaad-09b5-484a-dde6-4cd1ea6d6ff0')
    def test_get_subports(self):
        network = self.create_network()
        port = self.create_port(network)
        subports = [{'port_id': port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]
        trunk = self._create_trunk_with_network_and_parent(subports)
        trunk = self.client.get_subports(trunk['trunk']['id'])
        observed_subports = trunk['sub_ports']
        self.assertEqual(1, len(observed_subports))
