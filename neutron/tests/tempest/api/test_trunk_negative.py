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

from oslo_utils import uuidutils
from tempest.common import utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc
import testtools

from neutron.tests.tempest.api import test_trunk


class TrunkTestJSON(test_trunk.TrunkTestJSONBase):

    @decorators.attr(type='negative')
    @decorators.idempotent_id('1b5cf87a-1d3a-4a94-ba64-647153d54f32')
    def test_create_trunk_nonexistent_port_id(self):
        self.assertRaises(lib_exc.NotFound, self.client.create_trunk,
                          uuidutils.generate_uuid(), [])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('980bca3b-b0be-45ac-8067-b401e445b796')
    def test_create_trunk_nonexistent_subport_port_id(self):
        network = self.create_network()
        parent_port = self.create_port(network)
        self.assertRaises(lib_exc.NotFound, self.client.create_trunk,
                          parent_port['id'],
                          [{'port_id': uuidutils.generate_uuid(),
                            'segmentation_type': 'vlan',
                            'segmentation_id': 2}])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('a5c5200a-72a0-43c5-a11a-52f808490344')
    def test_create_subport_nonexistent_port_id(self):
        trunk = self._create_trunk_with_network_and_parent([])
        self.assertRaises(lib_exc.NotFound, self.client.add_subports,
                          trunk['trunk']['id'],
                          [{'port_id': uuidutils.generate_uuid(),
                            'segmentation_type': 'vlan',
                            'segmentation_id': 2}])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('80deb6a9-da2a-48db-b7fd-bcef5b14edc1')
    def test_create_subport_nonexistent_trunk(self):
        network = self.create_network()
        parent_port = self.create_port(network)
        self.assertRaises(lib_exc.NotFound, self.client.add_subports,
                          uuidutils.generate_uuid(),
                          [{'port_id': parent_port['id'],
                            'segmentation_type': 'vlan',
                            'segmentation_id': 2}])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('7e0f99ab-fe37-408b-a889-9e44ef300084')
    def test_create_subport_missing_segmentation_id(self):
        trunk = self._create_trunk_with_network_and_parent([])
        subport_network = self.create_network()
        parent_port = self.create_port(subport_network)
        self.assertRaises(lib_exc.BadRequest, self.client.add_subports,
                          trunk['trunk']['id'],
                          [{'port_id': parent_port['id'],
                            'segmentation_type': 'vlan'}])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('a315d78b-2f43-4efa-89ae-166044c568aa')
    def test_create_trunk_with_subport_missing_segmentation_id(self):
        subport_network = self.create_network()
        parent_port = self.create_port(subport_network)
        self.assertRaises(lib_exc.BadRequest, self.client.create_trunk,
                          parent_port['id'],
                          [{'port_id': uuidutils.generate_uuid(),
                            'segmentation_type': 'vlan'}])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('33498618-f75a-4796-8ae6-93d4fd203fa4')
    def test_create_trunk_with_subport_missing_segmentation_type(self):
        subport_network = self.create_network()
        parent_port = self.create_port(subport_network)
        self.assertRaises(lib_exc.BadRequest, self.client.create_trunk,
                          parent_port['id'],
                          [{'port_id': uuidutils.generate_uuid(),
                            'segmentation_id': 3}])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('a717691c-4e07-4d81-a98d-6f1c18c5d183')
    def test_create_trunk_with_subport_missing_port_id(self):
        subport_network = self.create_network()
        parent_port = self.create_port(subport_network)
        self.assertRaises(lib_exc.BadRequest, self.client.create_trunk,
                          parent_port['id'],
                          [{'segmentation_type': 'vlan',
                            'segmentation_id': 3}])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('40aed9be-e976-47d0-dada-bde2c7e74e57')
    @utils.requires_ext(extension="provider", service="network")
    def test_create_subport_invalid_inherit_network_segmentation_type(self):
        if not self.is_type_driver_enabled('vxlan'):
            msg = "Vxlan type driver must be enabled for this test."
            raise self.skipException(msg)

        trunk = self._create_trunk_with_network_and_parent(
            subports=[], parent_network_type='vxlan')
        subport_network = self.create_network()
        parent_port = self.create_port(subport_network)
        self.assertRaises(lib_exc.BadRequest, self.client.add_subports,
                          trunk['trunk']['id'],
                          [{'port_id': parent_port['id'],
                            'segmentation_type': 'inherit',
                            'segmentation_id': -1}])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('40aed9be-e976-47d0-a555-bde2c7e74e57')
    def test_create_trunk_duplicate_subport_segmentation_ids(self):
        trunk = self._create_trunk_with_network_and_parent([])
        subport_network1 = self.create_network()
        subport_network2 = self.create_network()
        parent_port1 = self.create_port(subport_network1)
        parent_port2 = self.create_port(subport_network2)
        self.assertRaises(lib_exc.BadRequest, self.client.create_trunk,
                          trunk['trunk']['id'],
                          [{'port_id': parent_port1['id'],
                            'segmentation_id': 2,
                            'segmentation_type': 'vlan'},
                           {'port_id': parent_port2['id'],
                            'segmentation_id': 2,
                            'segmentation_type': 'vlan'}])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('6f132ccc-1380-42d8-9c44-50411612bd01')
    def test_add_subport_port_id_uses_trunk_port_id(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        self.assertRaises(lib_exc.Conflict, self.client.add_subports,
                          trunk['trunk']['id'],
                          [{'port_id': trunk['trunk']['port_id'],
                            'segmentation_type': 'vlan',
                            'segmentation_id': 2}])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('7f132ccc-1380-42d8-9c44-50411612bd01')
    def test_add_subport_port_id_disabled_trunk(self):
        trunk = self._create_trunk_with_network_and_parent(
            None, admin_state_up=False)
        self.assertRaises(lib_exc.Conflict,
            self.client.add_subports,
            trunk['trunk']['id'],
            [{'port_id': trunk['trunk']['port_id'],
              'segmentation_type': 'vlan',
              'segmentation_id': 2}])
        self.client.update_trunk(
            trunk['trunk']['id'], admin_state_up=True)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('8f132ccc-1380-42d8-9c44-50411612bd01')
    def test_remove_subport_port_id_disabled_trunk(self):
        trunk = self._create_trunk_with_network_and_parent(
            None, admin_state_up=False)
        self.assertRaises(lib_exc.Conflict,
            self.client.remove_subports,
            trunk['trunk']['id'],
            [{'port_id': trunk['trunk']['port_id'],
              'segmentation_type': 'vlan',
              'segmentation_id': 2}])
        self.client.update_trunk(
            trunk['trunk']['id'], admin_state_up=True)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('9f132ccc-1380-42d8-9c44-50411612bd01')
    def test_delete_trunk_disabled_trunk(self):
        trunk = self._create_trunk_with_network_and_parent(
            None, admin_state_up=False)
        self.assertRaises(lib_exc.Conflict,
            self.client.delete_trunk,
            trunk['trunk']['id'])
        self.client.update_trunk(
            trunk['trunk']['id'], admin_state_up=True)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('00cb40bb-1593-44c8-808c-72b47e64252f')
    def test_add_subport_duplicate_segmentation_details(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        network = self.create_network()
        parent_port1 = self.create_port(network)
        parent_port2 = self.create_port(network)
        self.client.add_subports(trunk['trunk']['id'],
                                 [{'port_id': parent_port1['id'],
                                   'segmentation_type': 'vlan',
                                   'segmentation_id': 2}])
        self.assertRaises(lib_exc.Conflict, self.client.add_subports,
                          trunk['trunk']['id'],
                          [{'port_id': parent_port2['id'],
                            'segmentation_type': 'vlan',
                            'segmentation_id': 2}])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('4eac8c25-83ee-4051-9620-34774f565730')
    def test_add_subport_passing_dict(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        self.assertRaises(lib_exc.BadRequest, self.client.add_subports,
                          trunk['trunk']['id'],
                          {'port_id': trunk['trunk']['port_id'],
                           'segmentation_type': 'vlan',
                           'segmentation_id': 2})

    @decorators.attr(type='negative')
    @decorators.idempotent_id('17ca7dd7-96a8-445a-941e-53c0c86c2fe2')
    def test_remove_subport_passing_dict(self):
        network = self.create_network()
        parent_port = self.create_port(network)
        subport_data = {'port_id': parent_port['id'],
                        'segmentation_type': 'vlan',
                        'segmentation_id': 2}
        trunk = self._create_trunk_with_network_and_parent([subport_data])
        self.assertRaises(lib_exc.BadRequest, self.client.remove_subports,
                          trunk['trunk']['id'], subport_data)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('aaca7dd7-96b8-445a-931e-63f0d86d2fe2')
    def test_remove_subport_not_found(self):
        network = self.create_network()
        parent_port = self.create_port(network)
        subport_data = {'port_id': parent_port['id'],
                        'segmentation_type': 'vlan',
                        'segmentation_id': 2}
        trunk = self._create_trunk_with_network_and_parent([])
        self.assertRaises(lib_exc.NotFound, self.client.remove_subports,
                          trunk['trunk']['id'], [subport_data])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('6c9c5126-4f61-11e6-8248-40a8f063c891')
    def test_delete_port_in_use_by_trunk(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        self.assertRaises(lib_exc.Conflict, self.client.delete_port,
                          trunk['trunk']['port_id'])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('343a03d0-4f7c-11e6-97fa-40a8f063c891')
    def test_delete_port_in_use_by_subport(self):
        network = self.create_network()
        port = self.create_port(network)
        subports = [{'port_id': port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]
        self._create_trunk_with_network_and_parent(subports)
        self.assertRaises(lib_exc.Conflict, self.client.delete_port,
                          port['id'])


class TrunkTestMtusJSON(test_trunk.TrunkTestMtusJSONBase):

    required_extensions = (
        ['net-mtu'] + test_trunk.TrunkTestMtusJSONBase.required_extensions)

    @decorators.attr(type='negative')
    @decorators.idempotent_id('228380ef-1b7a-495e-b759-5b1f08e3e858')
    def test_create_trunk_with_mtu_smaller_than_subport(self):
        subports = [{'port_id': self.larger_mtu_port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]

        with testtools.ExpectedException(lib_exc.Conflict):
            trunk = self.client.create_trunk(self.smaller_mtu_port['id'],
                                             subports)
            self.trunks.append(trunk['trunk'])

    @decorators.attr(type='negative')
    @decorators.idempotent_id('3b32bf77-8002-403e-ad01-6f4cf018daa5')
    def test_add_subport_with_mtu_greater_than_trunk(self):
        subports = [{'port_id': self.larger_mtu_port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]

        trunk = self.client.create_trunk(self.smaller_mtu_port['id'], None)
        self.trunks.append(trunk['trunk'])

        self.assertRaises(lib_exc.Conflict,
                          self.client.add_subports,
                          trunk['trunk']['id'], subports)
