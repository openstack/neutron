# Copyright (c) 2015 Red Hat, Inc.
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
import uuid

from neutron.agent.common import ovs_lib
from neutron.agent.linux import ip_lib
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.linux import base


class OVSBridgeTestBase(base.BaseOVSLinuxTestCase):
    # TODO(twilson) So far, only ovsdb-related tests are written. It would be
    # good to also add the openflow-related functions
    def setUp(self):
        super(OVSBridgeTestBase, self).setUp()
        self.ovs = ovs_lib.BaseOVS()
        self.br = self.useFixture(net_helpers.OVSBridgeFixture()).bridge

    def create_ovs_port(self, *interface_attrs):
        # Convert ((a, b), (c, d)) to {a: b, c: d} and add 'type' by default
        attrs = collections.OrderedDict(interface_attrs)
        attrs.setdefault('type', 'internal')
        port_name = net_helpers.get_rand_port_name()
        return (port_name, self.br.add_port(port_name, *attrs.items()))

    def create_ovs_vif_port(self, iface_id=None, mac=None,
                            iface_field='iface-id'):
        if iface_id is None:
            iface_id = base.get_rand_name()
        if mac is None:
            mac = base.get_rand_name()
        attrs = ('external_ids', {iface_field: iface_id, 'attached-mac': mac})
        port_name, ofport = self.create_ovs_port(attrs)
        return ovs_lib.VifPort(port_name, ofport, iface_id, mac, self.br)


class OVSBridgeTestCase(OVSBridgeTestBase):

    def test_port_lifecycle(self):
        (port_name, ofport) = self.create_ovs_port(('type', 'internal'))
        # ofport should always be an integer string with value -1 or > 0.
        self.assertTrue(int(ofport))
        self.assertTrue(int(self.br.get_port_ofport(port_name)))
        self.assertTrue(self.br.port_exists(port_name))
        self.assertEqual(self.br.br_name,
                         self.br.get_bridge_for_iface(port_name))
        self.br.delete_port(port_name)
        self.assertFalse(self.br.port_exists(port_name))

    def test_duplicate_port_may_exist_false(self):
        port_name, ofport = self.create_ovs_port(('type', 'internal'))
        cmd = self.br.ovsdb.add_port(self.br.br_name,
                                     port_name, may_exist=False)
        self.assertRaises(RuntimeError, cmd.execute, check_error=True)

    def test_delete_port_if_exists_false(self):
        cmd = self.br.ovsdb.del_port('nonexistantport', if_exists=False)
        self.assertRaises(RuntimeError, cmd.execute, check_error=True)

    def test_replace_port(self):
        port_name = net_helpers.get_rand_port_name()
        self.br.replace_port(port_name, ('type', 'internal'))
        self.assertTrue(self.br.port_exists(port_name))
        self.assertEqual('internal',
                         self.br.db_get_val('Interface', port_name, 'type'))
        self.br.replace_port(port_name, ('type', 'internal'),
                             ('external_ids', {'test': 'test'}))
        self.assertTrue(self.br.port_exists(port_name))
        self.assertEqual('test', self.br.db_get_val('Interface', port_name,
                                                    'external_ids')['test'])

    def test_attribute_lifecycle(self):
        (port_name, ofport) = self.create_ovs_port()
        tag = 42
        self.ovs.set_db_attribute('Port', port_name, 'tag', tag)
        self.assertEqual(tag, self.ovs.db_get_val('Port', port_name, 'tag'))
        self.assertEqual(tag, self.br.get_port_tag_dict()[port_name])
        self.ovs.clear_db_attribute('Port', port_name, 'tag')
        self.assertEqual(self.ovs.db_get_val('Port', port_name, 'tag'), [])
        self.assertEqual(self.br.get_port_tag_dict()[port_name], [])

    def test_get_bridge_external_bridge_id(self):
        self.ovs.set_db_attribute('Bridge', self.br.br_name,
                                  'external_ids',
                                  {'bridge-id': self.br.br_name})
        self.assertEqual(
            self.br.br_name,
            self.ovs.get_bridge_external_bridge_id(self.br.br_name))

    def test_controller_lifecycle(self):
        controllers = {'tcp:127.0.0.1:6633', 'tcp:172.17.16.10:55'}
        self.br.set_controller(controllers)
        self.assertSetEqual(controllers, set(self.br.get_controller()))
        self.br.del_controller()
        self.assertEqual([], self.br.get_controller())

    def test_non_index_queries(self):
        controllers = ['tcp:127.0.0.1:6633']
        self.br.set_controller(controllers)
        cmd = self.br.ovsdb.db_set('Controller', self.br.br_name,
                                   ('connection_mode', 'out-of-band'))
        cmd.execute(check_error=True)
        self.assertEqual('out-of-band',
                         self.br.db_get_val('Controller', self.br.br_name,
                                            'connection_mode'))

    def test_set_fail_mode_secure(self):
        self.br.set_secure_mode()
        self._assert_br_fail_mode(ovs_lib.FAILMODE_SECURE)

    def test_set_fail_mode_standalone(self):
        self.br.set_standalone_mode()
        self._assert_br_fail_mode(ovs_lib.FAILMODE_STANDALONE)

    def _assert_br_fail_mode(self, fail_mode):
        self.assertEqual(
            self.br.db_get_val('Bridge', self.br.br_name, 'fail_mode'),
            fail_mode)

    def test_set_protocols(self):
        self.br.set_protocols('OpenFlow10')
        self.assertEqual(
            self.br.db_get_val('Bridge', self.br.br_name, 'protocols'),
            "OpenFlow10")

    def test_get_datapath_id(self):
        brdev = ip_lib.IPDevice(self.br.br_name)
        dpid = brdev.link.attributes['link/ether'].replace(':', '')
        self.br.set_db_attribute('Bridge',
                                 self.br.br_name, 'datapath_id', dpid)
        self.assertIn(dpid, self.br.get_datapath_id())

    def test_add_tunnel_port(self):
        attrs = {
            'remote_ip': '192.0.2.1',  # RFC 5737 TEST-NET-1
            'local_ip': '198.51.100.1',  # RFC 5737 TEST-NET-2
        }
        port_name = net_helpers.get_rand_port_name()
        self.br.add_tunnel_port(port_name, attrs['remote_ip'],
                                attrs['local_ip'])
        self.assertEqual(self.ovs.db_get_val('Interface', port_name, 'type'),
                         'gre')
        options = self.ovs.db_get_val('Interface', port_name, 'options')
        for attr, val in attrs.items():
            self.assertEqual(val, options[attr])

    def test_add_patch_port(self):
        local = net_helpers.get_rand_port_name()
        peer = 'remotepeer'
        self.br.add_patch_port(local, peer)
        self.assertEqual(self.ovs.db_get_val('Interface', local, 'type'),
                         'patch')
        options = self.ovs.db_get_val('Interface', local, 'options')
        self.assertEqual(peer, options['peer'])

    def test_get_port_name_list(self):
        # Note that ovs-vsctl's list-ports does not include the port created
        # with the same name as the bridge
        ports = {self.create_ovs_port()[0] for i in range(5)}
        self.assertSetEqual(ports, set(self.br.get_port_name_list()))

    def test_get_port_stats(self):
        # Nothing seems to use this function?
        (port_name, ofport) = self.create_ovs_port()
        stats = set(self.br.get_port_stats(port_name).keys())
        self.assertTrue(set(['rx_packets', 'tx_packets']).issubset(stats))

    def test_get_vif_ports(self):
        for i in range(2):
            self.create_ovs_port()
        vif_ports = [self.create_ovs_vif_port() for i in range(3)]
        ports = self.br.get_vif_ports()
        self.assertEqual(3, len(ports))
        self.assertTrue(all([isinstance(x, ovs_lib.VifPort) for x in ports]))
        self.assertEqual(sorted([x.port_name for x in vif_ports]),
                         sorted([x.port_name for x in ports]))

    def test_get_vif_port_set(self):
        for i in range(2):
            self.create_ovs_port()
        vif_ports = [self.create_ovs_vif_port() for i in range(2)]
        ports = self.br.get_vif_port_set()
        expected = set([x.vif_id for x in vif_ports])
        self.assertEqual(expected, ports)

    def test_get_port_tag_dict(self):
        # Simple case tested in port test_set_get_clear_db_val
        pass

    def test_get_vif_port_by_id(self):
        for i in range(2):
            self.create_ovs_port()
        vif_ports = [self.create_ovs_vif_port() for i in range(3)]
        for vif in vif_ports:
            self.assertEqual(self.br.get_vif_port_by_id(vif.vif_id).vif_id,
                             vif.vif_id)

    def test_delete_ports(self):
        # TODO(twilson) I intensely dislike the current delete_ports function
        # as the default behavior is really delete_vif_ports(), then it acts
        # more like a delete_ports() seems like it should if all_ports=True is
        # passed
        # Create 2 non-vif ports and 2 vif ports
        nonvifs = {self.create_ovs_port()[0] for i in range(2)}
        vifs = {self.create_ovs_vif_port().port_name for i in range(2)}
        self.assertSetEqual(nonvifs.union(vifs),
                            set(self.br.get_port_name_list()))
        self.br.delete_ports()
        self.assertSetEqual(nonvifs, set(self.br.get_port_name_list()))
        self.br.delete_ports(all_ports=True)
        self.assertEqual(len(self.br.get_port_name_list()), 0)

    def test_reset_bridge(self):
        self.create_ovs_port()
        self.br.reset_bridge()
        self.assertEqual(len(self.br.get_port_name_list()), 0)
        self._assert_br_fail_mode([])

    def test_reset_bridge_secure_mode(self):
        self.br.reset_bridge(secure_mode=True)
        self._assert_br_fail_mode(ovs_lib.FAILMODE_SECURE)

    def test_set_controller_connection_mode(self):
        controllers = ['tcp:192.0.2.0:6633']
        self._set_controllers_connection_mode(controllers)

    def test_set_multi_controllers_connection_mode(self):
        controllers = ['tcp:192.0.2.0:6633', 'tcp:192.0.2.1:55']
        self._set_controllers_connection_mode(controllers)

    def _set_controllers_connection_mode(self, controllers):
        self.br.set_controller(controllers)
        self.assertEqual(sorted(controllers), sorted(self.br.get_controller()))
        self.br.set_controllers_connection_mode('out-of-band')
        self._assert_controllers_connection_mode('out-of-band')
        self.br.del_controller()
        self.assertEqual([], self.br.get_controller())

    def _assert_controllers_connection_mode(self, connection_mode):
        controllers = self.br.db_get_val('Bridge', self.br.br_name,
                                         'controller')
        controllers = [controllers] if isinstance(
            controllers, uuid.UUID) else controllers
        for controller in controllers:
            self.assertEqual(connection_mode,
                             self.br.db_get_val('Controller',
                                                controller,
                                                'connection_mode'))


class OVSLibTestCase(base.BaseOVSLinuxTestCase):

    def setUp(self):
        super(OVSLibTestCase, self).setUp()
        self.ovs = ovs_lib.BaseOVS()

    def test_bridge_lifecycle_baseovs(self):
        name = base.get_rand_name(prefix=net_helpers.BR_PREFIX)
        self.addCleanup(self.ovs.delete_bridge, name)
        br = self.ovs.add_bridge(name)
        self.assertEqual(br.br_name, name)
        self.assertTrue(self.ovs.bridge_exists(name))
        self.ovs.delete_bridge(name)
        self.assertFalse(self.ovs.bridge_exists(name))

    def test_get_bridges(self):
        bridges = {
            self.useFixture(net_helpers.OVSBridgeFixture()).bridge.br_name
            for i in range(5)}
        self.assertTrue(set(self.ovs.get_bridges()).issuperset(bridges))

    def test_bridge_lifecycle_ovsbridge(self):
        name = base.get_rand_name(prefix=net_helpers.BR_PREFIX)
        br = ovs_lib.OVSBridge(name)
        self.assertEqual(br.br_name, name)
        # Make sure that instantiating an OVSBridge does not actually create
        self.assertFalse(self.ovs.bridge_exists(name))
        self.addCleanup(self.ovs.delete_bridge, name)
        br.create()
        self.assertTrue(self.ovs.bridge_exists(name))
        br.destroy()
        self.assertFalse(self.ovs.bridge_exists(name))
