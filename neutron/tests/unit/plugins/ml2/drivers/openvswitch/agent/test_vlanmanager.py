# Copyright 2016 Red Hat, Inc
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

import fixtures
import testtools

from neutron.plugins.ml2.drivers.openvswitch.agent import vlanmanager
from neutron.tests import base


class LocalVlanManagerFixture(fixtures.Fixture):
    def _setUp(self):
        super()._setUp()
        self.vlan_manager = vlanmanager.LocalVlanManager()
        self.addCleanup(self.restore_manager)
        # Remove _instance attribute from VlanManager in order to not obtain a
        # singleton
        del vlanmanager.LocalVlanManager._instance
        self.manager = vlanmanager.LocalVlanManager()

    def restore_manager(self):
        vlanmanager.LocalVlanManager._instance = self.vlan_manager


class TestLocalVLANMapping(base.BaseTestCase):
    def test___eq___equal(self):
        mapping1 = vlanmanager.LocalVLANMapping(1, 2, 3, 4, 5)
        mapping2 = vlanmanager.LocalVLANMapping(1, 2, 3, 4, 5)
        self.assertEqual(mapping1, mapping2)

    def test___eq___different(self):
        mapping1 = vlanmanager.LocalVLANMapping(1, 2, 3, 4, 5)
        mapping2 = vlanmanager.LocalVLANMapping(1, 2, 4, 4, 5)
        self.assertNotEqual(mapping1, mapping2)

    def test___eq___different_type(self):
        mapping = vlanmanager.LocalVLANMapping(1, 2, 3, 4, 5)
        self.assertNotEqual(mapping, "foo")


class TestLocalVlanManager(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.vlan_manager = self.useFixture(LocalVlanManagerFixture()).manager

    def test_is_singleton(self):
        self.vlan_manager.add(1, None, None, None, None)
        new_vlan_manager = vlanmanager.LocalVlanManager()
        self.assertIs(new_vlan_manager, self.vlan_manager)
        self.assertCountEqual(new_vlan_manager.mapping,
                              self.vlan_manager.mapping)

    def test_in_operator_on_key(self):
        self.vlan_manager.add(1, None, None, None, None)
        self.assertIn(1, self.vlan_manager)
        self.assertNotIn(2, self.vlan_manager)

    def test_iterator_returns_vlan_mappings(self):
        created_vlans = []
        for val in range(3):
            self.vlan_manager.add(val, val, val, val, val)
            created_vlans.append({val: self.vlan_manager.get(val, val)})

        self.assertCountEqual(created_vlans, list(self.vlan_manager))

    def test_get_net_and_segmentation_id_existing(self):
        port_id = 'port-id'
        vlan_data = (2, 3, 4, 5, {port_id: 'port'})
        net_id = 1
        self.vlan_manager.add(net_id, *vlan_data)
        obtained_net_id = (
            self.vlan_manager.get_net_and_segmentation_id(port_id))
        self.assertEqual((net_id, 5), obtained_net_id)

    def test_get_net_and_segmentation_id_non_existing_raises_exception(self):
        vlan_data = (1, 2, 3, 4, 5, {'port_id': 'port'})
        self.vlan_manager.add(*vlan_data)
        with testtools.ExpectedException(vlanmanager.VifIdNotFound):
            self.vlan_manager.get_net_and_segmentation_id('non-existing-port')

    def test_add_and_get(self):
        vlan_data = (2, 3, 4, 5, 6)
        expected_vlan_mapping = vlanmanager.LocalVLANMapping(*vlan_data)
        self.vlan_manager.add(1, *vlan_data)
        vlan_mapping = self.vlan_manager.get(1, 5)
        self.assertEqual(expected_vlan_mapping, vlan_mapping)

    def test_add_existing_raises_exception(self):
        vlan_data = (2, 3, 4, 5, 6)
        self.vlan_manager.add(1, *vlan_data)
        with testtools.ExpectedException(vlanmanager.MappingAlreadyExists):
            self.vlan_manager.add(1, *vlan_data)

    def test_get_non_existing_raises_keyerror(self):
        with testtools.ExpectedException(vlanmanager.MappingNotFound):
            self.vlan_manager.get(1, 5)

    def test_pop(self):
        vlan_data = (2, 3, 4, 5, 6)
        expected_vlan_mapping = vlanmanager.LocalVLANMapping(*vlan_data)
        self.vlan_manager.add(1, *vlan_data)
        vlan_mapping = self.vlan_manager.pop(1, 5)
        self.assertEqual(expected_vlan_mapping, vlan_mapping)
        self.assertFalse(self.vlan_manager.mapping)

    def test_pop_non_existing_raises_exception(self):
        with testtools.ExpectedException(vlanmanager.MappingNotFound):
            self.vlan_manager.pop(1, 5)

    def test_update_segmentation_id(self):
        self.vlan_manager.add('net_id', 'vlan_id', 'vlan', 'phys_net',
                              1001, None)
        self.assertEqual(1001, self.vlan_manager.get(
            'net_id', 1001).segmentation_id)
        self.vlan_manager.update_segmentation_id('net_id', 1002)
        self.assertEqual(1002, self.vlan_manager.get(
            'net_id', 1002).segmentation_id)

    def test_update_segmentation_id_not_found(self):
        with testtools.ExpectedException(vlanmanager.MappingNotFound):
            self.vlan_manager.update_segmentation_id(
                'net_id-notfound', 1002)

    def test_update_segmentation_id_not_uniq(self):
        self.vlan_manager.add('net_id-not-uniq', 'vlan_id', 'vlan', 'phys_net',
                              1001, None)
        self.vlan_manager.add('net_id-not-uniq', 'vlan_id', 'vlan', 'phys_net',
                              1002, None)
        with testtools.ExpectedException(vlanmanager.NotUniqMapping):
            self.vlan_manager.update_segmentation_id(
                'net_id-not-uniq', 1003)

    def test_add_with_tun_ofports(self):
        self.vlan_manager.add('net_id', 'vlan_id', 'vlan', 'phys_net',
                              1001, None, {2, 3})
        self.assertEqual({2, 3}, self.vlan_manager.get(
            'net_id', 1001).tun_ofports)

    def test_add_without_tun_ofports(self):
        self.vlan_manager.add('net_id', 'vlan_id', 'vlan', 'phys_net',
                              1001, None)
        self.assertEqual(set(), self.vlan_manager.get(
            'net_id', 1001).tun_ofports)
