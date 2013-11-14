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
import mock
import testtools

from neutron.db import api as db
from neutron.plugins.cisco.common import cisco_exceptions as c_exc
from neutron.plugins.cisco.common import config
from neutron.plugins.cisco.db import nexus_db_v2 as nxdb
from neutron.plugins.cisco.nexus import cisco_nexus_plugin_v2
from neutron.tests import base


class CiscoNexusDbTest(base.BaseTestCase):

    """Unit tests for cisco.db.nexus_models_v2.NexusPortBinding model."""

    NpbObj = collections.namedtuple('NpbObj', 'port vlan switch instance')

    def setUp(self):
        super(CiscoNexusDbTest, self).setUp()
        db.configure_db()
        self.session = db.get_session()
        self.addCleanup(db.clear_db)

    def _npb_test_obj(self, pnum, vnum, switch=None, instance=None):
        """Create a Nexus port binding test object from a pair of numbers."""
        if pnum is 'router':
            port = pnum
        else:
            port = '1/%s' % str(pnum)
        vlan = str(vnum)
        if switch is None:
            switch = '10.9.8.7'
        if instance is None:
            instance = 'instance_%s_%s' % (str(pnum), str(vnum))
        return self.NpbObj(port, vlan, switch, instance)

    def _assert_equal(self, npb, npb_obj):
        self.assertEqual(npb.port_id, npb_obj.port)
        self.assertEqual(int(npb.vlan_id), int(npb_obj.vlan))
        self.assertEqual(npb.switch_ip, npb_obj.switch)
        self.assertEqual(npb.instance_id, npb_obj.instance)

    def _add_to_db(self, npbs):
        for npb in npbs:
            nxdb.add_nexusport_binding(
                npb.port, npb.vlan, npb.switch, npb.instance)

    def test_nexusportbinding_add_remove(self):
        npb11 = self._npb_test_obj(10, 100)
        npb = nxdb.add_nexusport_binding(
            npb11.port, npb11.vlan, npb11.switch, npb11.instance)
        self._assert_equal(npb, npb11)
        npb = nxdb.remove_nexusport_binding(
            npb11.port, npb11.vlan, npb11.switch, npb11.instance)
        self.assertEqual(len(npb), 1)
        self._assert_equal(npb[0], npb11)
        with testtools.ExpectedException(c_exc.NexusPortBindingNotFound):
            nxdb.remove_nexusport_binding(
                npb11.port, npb11.vlan, npb11.switch, npb11.instance)

    def test_nexusportbinding_get(self):
        npb11 = self._npb_test_obj(10, 100)
        npb21 = self._npb_test_obj(20, 100)
        npb22 = self._npb_test_obj(20, 200)
        self._add_to_db([npb11, npb21, npb22])

        npb = nxdb.get_nexusport_binding(
            npb11.port, npb11.vlan, npb11.switch, npb11.instance)
        self.assertEqual(len(npb), 1)
        self._assert_equal(npb[0], npb11)
        npb = nxdb.get_nexusport_binding(
            npb21.port, npb21.vlan, npb21.switch, npb21.instance)
        self.assertEqual(len(npb), 1)
        self._assert_equal(npb[0], npb21)
        npb = nxdb.get_nexusport_binding(
            npb22.port, npb22.vlan, npb22.switch, npb22.instance)
        self.assertEqual(len(npb), 1)
        self._assert_equal(npb[0], npb22)

        with testtools.ExpectedException(c_exc.NexusPortBindingNotFound):
            nxdb.get_nexusport_binding(
                npb21.port, npb21.vlan, npb21.switch, "dummyInstance")

    def test_nexusvlanbinding_get(self):
        npb11 = self._npb_test_obj(10, 100)
        npb21 = self._npb_test_obj(20, 100)
        npb22 = self._npb_test_obj(20, 200)
        self._add_to_db([npb11, npb21, npb22])

        npb_all_v100 = nxdb.get_nexusvlan_binding(npb11.vlan, npb11.switch)
        self.assertEqual(len(npb_all_v100), 2)
        npb_v200 = nxdb.get_nexusvlan_binding(npb22.vlan, npb22.switch)
        self.assertEqual(len(npb_v200), 1)
        self._assert_equal(npb_v200[0], npb22)

        with testtools.ExpectedException(c_exc.NexusPortBindingNotFound):
            nxdb.get_nexusvlan_binding(npb21.vlan, "dummySwitch")

    def test_nexusvmbinding_get(self):
        npb11 = self._npb_test_obj(10, 100)
        npb21 = self._npb_test_obj(20, 100)
        npb22 = self._npb_test_obj(20, 200)
        self._add_to_db([npb11, npb21, npb22])

        npb = nxdb.get_nexusvm_bindings(npb21.vlan, npb21.instance)[0]
        self._assert_equal(npb, npb21)
        npb = nxdb.get_nexusvm_bindings(npb22.vlan, npb22.instance)[0]
        self._assert_equal(npb, npb22)

        with testtools.ExpectedException(c_exc.NexusPortBindingNotFound):
            nxdb.get_nexusvm_bindings(npb21.vlan, "dummyInstance")

    def test_nexusportvlanswitchbinding_get(self):
        npb11 = self._npb_test_obj(10, 100)
        npb21 = self._npb_test_obj(20, 100)
        self._add_to_db([npb11, npb21])

        npb = nxdb.get_port_vlan_switch_binding(
            npb11.port, npb11.vlan, npb11.switch)
        self.assertEqual(len(npb), 1)
        self._assert_equal(npb[0], npb11)

        with testtools.ExpectedException(c_exc.NexusPortBindingNotFound):
            nxdb.get_port_vlan_switch_binding(
                npb21.port, npb21.vlan, "dummySwitch")

    def test_nexusportswitchbinding_get(self):
        npb11 = self._npb_test_obj(10, 100)
        npb21 = self._npb_test_obj(20, 100, switch='2.2.2.2')
        npb22 = self._npb_test_obj(20, 200, switch='2.2.2.2')
        self._add_to_db([npb11, npb21, npb22])

        npb = nxdb.get_port_switch_bindings(npb11.port, npb11.switch)
        self.assertEqual(len(npb), 1)
        self._assert_equal(npb[0], npb11)
        npb_all_p20 = nxdb.get_port_switch_bindings(npb21.port, npb21.switch)
        self.assertEqual(len(npb_all_p20), 2)

        npb = nxdb.get_port_switch_bindings(npb21.port, "dummySwitch")
        self.assertIsNone(npb)

    def test_nexussvibinding_get(self):
        npbr1 = self._npb_test_obj('router', 100)
        npb21 = self._npb_test_obj(20, 100)
        self._add_to_db([npbr1, npb21])

        npb_svi = nxdb.get_nexussvi_bindings()
        self.assertEqual(len(npb_svi), 1)
        self._assert_equal(npb_svi[0], npbr1)

        npbr2 = self._npb_test_obj('router', 200)
        self._add_to_db([npbr2])
        npb_svi = nxdb.get_nexussvi_bindings()
        self.assertEqual(len(npb_svi), 2)

    def test_nexussviswitch_find(self):
        """Test Nexus switch selection for SVI placement."""
        # Configure 2 Nexus switches
        nexus_switches = {
            ('1.1.1.1', 'username'): 'admin',
            ('1.1.1.1', 'password'): 'password1',
            ('1.1.1.1', 'host1'): '1/1',
            ('2.2.2.2', 'username'): 'admin',
            ('2.2.2.2', 'password'): 'password2',
            ('2.2.2.2', 'host2'): '1/1',
        }
        nexus_plugin = cisco_nexus_plugin_v2.NexusPlugin()
        nexus_plugin._client = mock.Mock()
        nexus_plugin._client.nexus_switches = nexus_switches

        # Set the Cisco config module's first configured device IP address
        # according to the preceding switch config
        with mock.patch.object(config, 'first_device_ip', new='1.1.1.1'):

            # Enable round-robin mode with no SVIs configured on any of the
            # Nexus switches (i.e. no entries in the SVI database). The
            # plugin should select the first switch in the configuration.
            config.CONF.set_override('svi_round_robin', True, 'CISCO')
            switch_ip = nexus_plugin._find_switch_for_svi()
            self.assertEqual(switch_ip, '1.1.1.1')

            # Keep round-robin mode enabled, and add entries to the SVI
            # database. The plugin should select the switch with the least
            # number of entries in the SVI database.
            vlan = 100
            npbr11 = self._npb_test_obj('router', vlan, switch='1.1.1.1',
                                        instance='instance11')
            npbr12 = self._npb_test_obj('router', vlan, switch='1.1.1.1',
                                        instance='instance12')
            npbr21 = self._npb_test_obj('router', vlan, switch='2.2.2.2',
                                        instance='instance21')
            self._add_to_db([npbr11, npbr12, npbr21])
            switch_ip = nexus_plugin._find_switch_for_svi()
            self.assertEqual(switch_ip, '2.2.2.2')

            # Disable round-robin mode. The plugin should select the
            # first switch in the configuration.
            config.CONF.clear_override('svi_round_robin', 'CISCO')
            switch_ip = nexus_plugin._find_switch_for_svi()
            self.assertEqual(switch_ip, '1.1.1.1')

    def test_nexusbinding_update(self):
        npb11 = self._npb_test_obj(10, 100, switch='1.1.1.1', instance='test')
        npb21 = self._npb_test_obj(20, 100, switch='1.1.1.1', instance='test')
        self._add_to_db([npb11, npb21])

        npb_all_v100 = nxdb.get_nexusvlan_binding(npb11.vlan, '1.1.1.1')
        self.assertEqual(len(npb_all_v100), 2)

        npb22 = self._npb_test_obj(20, 200, switch='1.1.1.1', instance='test')
        npb = nxdb.update_nexusport_binding(npb21.port, 200)
        self._assert_equal(npb, npb22)

        npb_all_v100 = nxdb.get_nexusvlan_binding(npb11.vlan, '1.1.1.1')
        self.assertEqual(len(npb_all_v100), 1)
        self._assert_equal(npb_all_v100[0], npb11)

        npb = nxdb.update_nexusport_binding(npb21.port, 0)
        self.assertIsNone(npb)

        npb33 = self._npb_test_obj(30, 300, switch='1.1.1.1', instance='test')
        with testtools.ExpectedException(c_exc.NexusPortBindingNotFound):
            nxdb.update_nexusport_binding(npb33.port, 200)
