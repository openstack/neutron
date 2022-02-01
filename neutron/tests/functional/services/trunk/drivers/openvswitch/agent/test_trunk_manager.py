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

from unittest import mock

from neutron_lib.utils import net
from oslo_log import log as logging
from oslo_utils import uuidutils
import testtools

from neutron.services.trunk.drivers.openvswitch.agent import trunk_manager
from neutron.services.trunk.drivers.openvswitch import utils
from neutron.tests.common import conn_testers
from neutron.tests.common import helpers
from neutron.tests.common import net_helpers
from neutron.tests.functional import base
from neutron.tests.functional import constants as test_constants

LOG = logging.getLogger(__name__)

VLAN_RANGE = set(range(1, test_constants.VLAN_COUNT - 1))


class FakeOVSDBException(Exception):
    pass


class TrunkParentPortTestCase(base.BaseSudoTestCase):
    def setUp(self):
        super(TrunkParentPortTestCase, self).setUp()
        trunk_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        port_mac = net.get_random_mac('fa:16:3e:00:00:00'.split(':'))
        self.trunk = trunk_manager.TrunkParentPort(trunk_id, port_id, port_mac)
        self.trunk.bridge = self.useFixture(
            net_helpers.OVSTrunkBridgeFixture(
                self.trunk.bridge.br_name)).bridge
        self.br_int = self.useFixture(net_helpers.OVSBridgeFixture()).bridge

    def test_plug(self):
        self.trunk.plug(self.br_int)
        self.assertIn(self.trunk.patch_port_trunk_name,
                      self.trunk.bridge.get_port_name_list())
        self.assertIn(self.trunk.patch_port_int_name,
                      self.br_int.get_port_name_list())

    def test_plug_failure_doesnt_create_ports(self):
        with mock.patch.object(
                self.trunk.bridge.ovsdb, 'db_set',
                side_effect=FakeOVSDBException):
            with testtools.ExpectedException(FakeOVSDBException):
                self.trunk.plug(self.br_int)
        self.assertNotIn(self.trunk.patch_port_trunk_name,
                         self.trunk.bridge.get_port_name_list())
        self.assertNotIn(self.trunk.patch_port_int_name,
                         self.br_int.get_port_name_list())

    def test_unplug(self):
        self.trunk.plug(self.br_int)
        self.trunk.unplug(self.br_int)
        self.assertFalse(
            self.trunk.bridge.bridge_exists(self.trunk.bridge.br_name))
        self.assertNotIn(self.trunk.patch_port_int_name,
                         self.br_int.get_port_name_list())

    def test_unplug_failure_doesnt_delete_bridge(self):
        self.trunk.plug(self.br_int)
        with mock.patch.object(
                self.trunk.bridge.ovsdb, 'del_port',
                side_effect=FakeOVSDBException):
            with testtools.ExpectedException(FakeOVSDBException):
                self.trunk.unplug(self.br_int)
        self.assertTrue(
            self.trunk.bridge.bridge_exists(self.trunk.bridge.br_name))
        self.assertIn(self.trunk.patch_port_trunk_name,
                      self.trunk.bridge.get_port_name_list())
        self.assertIn(self.trunk.patch_port_int_name,
                      self.br_int.get_port_name_list())


class SubPortTestCase(base.BaseSudoTestCase):
    def setUp(self):
        super(SubPortTestCase, self).setUp()
        trunk_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        port_mac = net.get_random_mac('fa:16:3e:00:00:00'.split(':'))
        trunk_bridge_name = utils.gen_trunk_br_name(trunk_id)
        trunk_bridge = self.useFixture(
            net_helpers.OVSTrunkBridgeFixture(trunk_bridge_name)).bridge
        segmentation_id = helpers.get_not_used_vlan(
            trunk_bridge, VLAN_RANGE)
        self.subport = trunk_manager.SubPort(
            trunk_id, port_id, port_mac, segmentation_id)
        self.subport.bridge = trunk_bridge
        self.br_int = self.useFixture(net_helpers.OVSBridgeFixture()).bridge

    def test_plug(self):
        self.subport.plug(self.br_int)
        self.assertIn(self.subport.patch_port_trunk_name,
                      self.subport.bridge.get_port_name_list())
        self.assertIn(self.subport.patch_port_int_name,
                      self.br_int.get_port_name_list())
        self.assertEqual(
            self.subport.segmentation_id,
            self.subport.bridge.db_get_val(
                'Port', self.subport.patch_port_trunk_name, 'tag'))

    def test_plug_failure_doesnt_create_ports(self):
        with mock.patch.object(
                self.subport.bridge.ovsdb, 'db_set',
                side_effect=FakeOVSDBException):
            with testtools.ExpectedException(FakeOVSDBException):
                self.subport.plug(self.br_int)
        self.assertNotIn(self.subport.patch_port_trunk_name,
                         self.subport.bridge.get_port_name_list())
        self.assertNotIn(self.subport.patch_port_int_name,
                         self.br_int.get_port_name_list())

    def test_unplug(self):
        self.subport.plug(self.br_int)
        self.subport.unplug(self.br_int)
        self.assertNotIn(self.subport.patch_port_trunk_name,
                         self.subport.bridge.get_port_name_list())
        self.assertNotIn(self.subport.patch_port_int_name,
                         self.br_int.get_port_name_list())

    def test_unplug_failure(self):
        self.subport.plug(self.br_int)
        with mock.patch.object(
                self.subport.bridge.ovsdb, 'del_port',
                side_effect=FakeOVSDBException):
            with testtools.ExpectedException(FakeOVSDBException):
                self.subport.unplug(self.br_int)
        self.assertIn(self.subport.patch_port_trunk_name,
                      self.subport.bridge.get_port_name_list())
        self.assertIn(self.subport.patch_port_int_name,
                      self.br_int.get_port_name_list())


class TrunkManagerTestCase(base.BaseSudoTestCase):
    net1_cidr = '192.178.0.1/24'
    net2_cidr = '192.168.0.1/24'

    def setUp(self):
        super(TrunkManagerTestCase, self).setUp()
        trunk_id = uuidutils.generate_uuid()
        self.tester = self.useFixture(
            conn_testers.OVSTrunkConnectionTester(
                self.net1_cidr, utils.gen_trunk_br_name(trunk_id)))
        self.trunk_manager = trunk_manager.TrunkManager(
            self.tester.bridge)
        self.trunk = trunk_manager.TrunkParentPort(
            trunk_id, uuidutils.generate_uuid())
        mock.patch('neutron.agent.common.ovs_lib.'
                   'OVSBridge._set_port_dead').start()

    def test_connectivity(self):
        """Test connectivity with trunk and sub ports.

        In this test we create a vm that has a trunk on net1 and a vm peer on
        the same network. We check connectivity between the peer and the vm.
        We create a sub port on net2 and a peer, check connectivity again.

        """
        vlan_net1 = helpers.get_not_used_vlan(self.tester.bridge, VLAN_RANGE)
        vlan_net2 = helpers.get_not_used_vlan(self.tester.bridge, VLAN_RANGE)
        trunk_mac = net.get_random_mac('fa:16:3e:00:00:00'.split(':'))
        sub_port_mac = net.get_random_mac('fa:16:3e:00:00:00'.split(':'))
        sub_port_segmentation_id = helpers.get_not_used_vlan(
            self.tester.bridge, VLAN_RANGE)
        LOG.debug("Using %(n1)d vlan tag as local vlan ID for net1 and %(n2)d "
                  "for local vlan ID for net2", {
                      'n1': vlan_net1, 'n2': vlan_net2})
        self.tester.set_peer_tag(vlan_net1)
        self.trunk_manager.create_trunk(self.trunk.trunk_id,
                                        self.trunk.port_id,
                                        trunk_mac)

        # tag the patch port, this should be done by the ovs agent but we mock
        # it for this test
        conn_testers.OVSBaseConnectionTester.set_tag(
            self.trunk.patch_port_int_name, self.tester.bridge, vlan_net1)

        self.tester.wait_for_connection(self.tester.INGRESS)
        self.tester.wait_for_connection(self.tester.EGRESS)

        self.tester.add_vlan_interface_and_peer(sub_port_segmentation_id,
                                                self.net2_cidr)
        conn_testers.OVSBaseConnectionTester.set_tag(
            self.tester._peer2.port.name, self.tester.bridge, vlan_net2)

        sub_port = trunk_manager.SubPort(self.trunk.trunk_id,
                                         uuidutils.generate_uuid(),
                                         sub_port_mac,
                                         sub_port_segmentation_id)

        self.trunk_manager.add_sub_port(sub_port.trunk_id,
                                        sub_port.port_id,
                                        sub_port.port_mac,
                                        sub_port.segmentation_id)
        # tag the patch port, this should be done by the ovs agent but we mock
        # it for this test
        conn_testers.OVSBaseConnectionTester.set_tag(
            sub_port.patch_port_int_name, self.tester.bridge, vlan_net2)

        self.tester.wait_for_sub_port_connectivity(self.tester.INGRESS)
        self.tester.wait_for_sub_port_connectivity(self.tester.EGRESS)

        self.trunk_manager.remove_sub_port(sub_port.trunk_id,
                                           sub_port.port_id)
        self.tester.wait_for_sub_port_no_connectivity(self.tester.INGRESS)
        self.tester.wait_for_sub_port_no_connectivity(self.tester.EGRESS)

        self.trunk_manager.remove_trunk(self.trunk.trunk_id,
                                        self.trunk.port_id)
        self.tester.wait_for_no_connection(self.tester.INGRESS)


class TrunkManagerDisposeTrunkTestCase(base.BaseSudoTestCase):

    def setUp(self):
        super(TrunkManagerDisposeTrunkTestCase, self).setUp()
        trunk_id = uuidutils.generate_uuid()
        self.trunk = trunk_manager.TrunkParentPort(
            trunk_id, uuidutils.generate_uuid())
        self.trunk.bridge = self.useFixture(
            net_helpers.OVSTrunkBridgeFixture(
                self.trunk.bridge.br_name)).bridge
        self.br_int = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        self.trunk_manager = trunk_manager.TrunkManager(
            self.br_int)

    def test_dispose_trunk(self):
        self.trunk.plug(self.br_int)
        self.trunk_manager.dispose_trunk(self.trunk.bridge)
        self.assertFalse(
            self.trunk.bridge.bridge_exists(self.trunk.bridge.br_name))
        self.assertNotIn(self.trunk.patch_port_int_name,
                         self.br_int.get_port_name_list())
