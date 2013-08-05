# Copyright (c) 2013 OpenStack Foundation
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

import collections
import testtools

from neutron.plugins.ml2.drivers.cisco.nexus import exceptions
from neutron.plugins.ml2.drivers.cisco.nexus import nexus_db_v2
from neutron.tests.unit import testlib_api


class CiscoNexusDbTest(testlib_api.SqlTestCase):

    """Unit tests for Cisco mechanism driver's Nexus port binding database."""

    NpbObj = collections.namedtuple('NpbObj', 'port vlan switch instance')

    def _npb_test_obj(self, pnum, vnum, switch='10.9.8.7', instance=None):
        """Creates a Nexus port binding test object from a pair of numbers."""
        if pnum is 'router':
            port = pnum
        else:
            port = '1/%s' % pnum
        if instance is None:
            instance = 'instance_%s_%s' % (pnum, vnum)
        return self.NpbObj(port, vnum, switch, instance)

    def _assert_bindings_match(self, npb, npb_obj):
        """Asserts that a port binding matches a port binding test obj."""
        self.assertEqual(npb.port_id, npb_obj.port)
        self.assertEqual(npb.vlan_id, npb_obj.vlan)
        self.assertEqual(npb.switch_ip, npb_obj.switch)
        self.assertEqual(npb.instance_id, npb_obj.instance)

    def _add_binding_to_db(self, npb):
        """Adds a port binding to the Nexus database."""
        return nexus_db_v2.add_nexusport_binding(
            npb.port, npb.vlan, npb.switch, npb.instance)

    def _add_bindings_to_db(self, npbs):
        """Adds a list of port bindings to the Nexus database."""
        for npb in npbs:
            nexus_db_v2.add_nexusport_binding(
                npb.port, npb.vlan, npb.switch, npb.instance)

    def _remove_binding_from_db(self, npb):
        """Removes a port binding from the Nexus database."""
        return nexus_db_v2.remove_nexusport_binding(
            npb.port, npb.vlan, npb.switch, npb.instance)

    def _get_nexusport_binding(self, npb):
        """Gets a port binding based on port, vlan, switch, and instance."""
        return nexus_db_v2.get_nexusport_binding(
            npb.port, npb.vlan, npb.switch, npb.instance)

    def _get_nexusvlan_binding(self, npb):
        """Gets port bindings based on vlan and switch."""
        return nexus_db_v2.get_nexusvlan_binding(npb.vlan, npb.switch)

    def _get_nexusvm_binding(self, npb):
        """Gets port binding based on vlan and instance."""
        return nexus_db_v2.get_nexusvm_bindings(npb.vlan, npb.instance)[0]

    def _get_port_vlan_switch_binding(self, npb):
        """Gets port bindings based on port, vlan, and switch."""
        return nexus_db_v2.get_port_vlan_switch_binding(
            npb.port, npb.vlan, npb.switch)

    def _get_port_switch_bindings(self, npb):
        """Get port bindings based on port and switch."""
        return nexus_db_v2.get_port_switch_bindings(npb.port, npb.switch)

    def test_nexusportbinding_add_remove(self):
        """Tests add and removal of port bindings from the Nexus database."""
        npb11 = self._npb_test_obj(10, 100)
        npb = self._add_binding_to_db(npb11)
        self._assert_bindings_match(npb, npb11)
        npb = self._remove_binding_from_db(npb11)
        self.assertEqual(len(npb), 1)
        self._assert_bindings_match(npb[0], npb11)
        with testtools.ExpectedException(exceptions.NexusPortBindingNotFound):
            self._remove_binding_from_db(npb11)

    def test_nexusportbinding_get(self):
        """Tests get of specific port bindings from the database."""
        npb11 = self._npb_test_obj(10, 100)
        npb21 = self._npb_test_obj(20, 100)
        npb22 = self._npb_test_obj(20, 200)
        self._add_bindings_to_db([npb11, npb21, npb22])

        npb = self._get_nexusport_binding(npb11)
        self.assertEqual(len(npb), 1)
        self._assert_bindings_match(npb[0], npb11)
        npb = self._get_nexusport_binding(npb21)
        self.assertEqual(len(npb), 1)
        self._assert_bindings_match(npb[0], npb21)
        npb = self._get_nexusport_binding(npb22)
        self.assertEqual(len(npb), 1)
        self._assert_bindings_match(npb[0], npb22)

        with testtools.ExpectedException(exceptions.NexusPortBindingNotFound):
            nexus_db_v2.get_nexusport_binding(
                npb21.port, npb21.vlan, npb21.switch, "dummyInstance")

    def test_nexusvlanbinding_get(self):
        """Test get of port bindings based on vlan and switch."""
        npb11 = self._npb_test_obj(10, 100)
        npb21 = self._npb_test_obj(20, 100)
        npb22 = self._npb_test_obj(20, 200)
        self._add_bindings_to_db([npb11, npb21, npb22])

        npb_all_v100 = self._get_nexusvlan_binding(npb11)
        self.assertEqual(len(npb_all_v100), 2)
        npb_v200 = self._get_nexusvlan_binding(npb22)
        self.assertEqual(len(npb_v200), 1)
        self._assert_bindings_match(npb_v200[0], npb22)

        with testtools.ExpectedException(exceptions.NexusPortBindingNotFound):
            nexus_db_v2.get_nexusvlan_binding(npb21.vlan, "dummySwitch")

    def test_nexusvmbinding_get(self):
        """Test get of port bindings based on vlan and instance."""
        npb11 = self._npb_test_obj(10, 100)
        npb21 = self._npb_test_obj(20, 100)
        npb22 = self._npb_test_obj(20, 200)
        self._add_bindings_to_db([npb11, npb21, npb22])

        npb = self._get_nexusvm_binding(npb21)
        self._assert_bindings_match(npb, npb21)
        npb = self._get_nexusvm_binding(npb22)
        self._assert_bindings_match(npb, npb22)

        with testtools.ExpectedException(exceptions.NexusPortBindingNotFound):
            nexus_db_v2.get_nexusvm_bindings(npb21.vlan, "dummyInstance")[0]

    def test_nexusportvlanswitchbinding_get(self):
        """Tests get of port bindings based on port, vlan, and switch."""
        npb11 = self._npb_test_obj(10, 100)
        npb21 = self._npb_test_obj(20, 100)
        self._add_bindings_to_db([npb11, npb21])

        npb = self._get_port_vlan_switch_binding(npb11)
        self.assertEqual(len(npb), 1)
        self._assert_bindings_match(npb[0], npb11)

        with testtools.ExpectedException(exceptions.NexusPortBindingNotFound):
            nexus_db_v2.get_port_vlan_switch_binding(
                npb21.port, npb21.vlan, "dummySwitch")

    def test_nexusportswitchbinding_get(self):
        """Tests get of port bindings based on port and switch."""
        npb11 = self._npb_test_obj(10, 100)
        npb21 = self._npb_test_obj(20, 100, switch='2.2.2.2')
        npb22 = self._npb_test_obj(20, 200, switch='2.2.2.2')
        self._add_bindings_to_db([npb11, npb21, npb22])

        npb = self._get_port_switch_bindings(npb11)
        self.assertEqual(len(npb), 1)
        self._assert_bindings_match(npb[0], npb11)
        npb_all_p20 = self._get_port_switch_bindings(npb21)
        self.assertEqual(len(npb_all_p20), 2)

        npb = nexus_db_v2.get_port_switch_bindings(npb21.port, "dummySwitch")
        self.assertIsNone(npb)

    def test_nexusbinding_update(self):
        """Tests update of vlan IDs for port bindings."""
        npb11 = self._npb_test_obj(10, 100, switch='1.1.1.1', instance='test')
        npb21 = self._npb_test_obj(20, 100, switch='1.1.1.1', instance='test')
        self._add_bindings_to_db([npb11, npb21])

        npb_all_v100 = nexus_db_v2.get_nexusvlan_binding(100, '1.1.1.1')
        self.assertEqual(len(npb_all_v100), 2)

        npb22 = self._npb_test_obj(20, 200, switch='1.1.1.1', instance='test')
        npb = nexus_db_v2.update_nexusport_binding(npb21.port, 200)
        self._assert_bindings_match(npb, npb22)

        npb_all_v100 = nexus_db_v2.get_nexusvlan_binding(100, '1.1.1.1')
        self.assertEqual(len(npb_all_v100), 1)
        self._assert_bindings_match(npb_all_v100[0], npb11)

        npb = nexus_db_v2.update_nexusport_binding(npb21.port, 0)
        self.assertIsNone(npb)

        npb33 = self._npb_test_obj(30, 300, switch='1.1.1.1', instance='test')
        with testtools.ExpectedException(exceptions.NexusPortBindingNotFound):
            nexus_db_v2.update_nexusport_binding(npb33.port, 200)
