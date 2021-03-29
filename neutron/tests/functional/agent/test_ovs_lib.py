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

import mock
from neutron_lib import constants as const
from oslo_config import cfg
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.agent.common import ovs_lib
from neutron.agent.linux import ip_lib
from neutron.common import utils
from neutron.plugins.ml2.drivers.openvswitch.agent.common import (
    constants as agent_const)
from neutron.tests.common.exclusive_resources import port
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
        port_name = utils.get_rand_device_name(net_helpers.PORT_PREFIX)
        return (port_name, self.br.add_port(port_name, *attrs.items()))

    def create_ovs_vif_port(self, iface_id=None, mac=None,
                            iface_field='iface-id'):
        if iface_id is None:
            iface_id = utils.get_rand_name()
        if mac is None:
            mac = utils.get_rand_name()
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
        port_name = utils.get_rand_device_name(net_helpers.PORT_PREFIX)
        self.br.replace_port(port_name, ('type', 'internal'))
        self.assertTrue(self.br.port_exists(port_name))
        self.assertEqual('internal',
                         self.br.db_get_val('Interface', port_name, 'type'))
        self.br.replace_port(port_name, ('type', 'internal'),
                             ('external_ids', {'test': 'test'}))
        self.assertTrue(self.br.port_exists(port_name))
        self.assertEqual('test', self.br.db_get_val('Interface', port_name,
                                                    'external_ids')['test'])
        self.assertEqual(agent_const.DEAD_VLAN_TAG,
                         self.br.db_get_val('Port', port_name, 'tag'))

    def test_attribute_lifecycle(self):
        (port_name, ofport) = self.create_ovs_port()
        tag = 42
        self.ovs.set_db_attribute('Port', port_name, 'tag', tag)
        self.assertEqual(tag, self.ovs.db_get_val('Port', port_name, 'tag'))
        self.assertEqual(tag, self.br.get_port_tag_dict()[port_name])
        self.ovs.clear_db_attribute('Port', port_name, 'tag')
        self.assertEqual([], self.ovs.db_get_val('Port', port_name, 'tag'))
        self.assertEqual([], self.br.get_port_tag_dict()[port_name])

    def test_attribute_map_handling(self):
        (pname, ofport) = self.create_ovs_port()
        expected = {'a': 'b'}
        self.ovs.set_db_attribute('Port', pname, 'other_config', expected)
        self.assertEqual(expected,
                         self.ovs.db_get_val('Port', pname, 'other_config'))
        other = {'c': 'd'}
        expected.update(other)
        self.ovs.set_db_attribute('Port', pname, 'other_config', other)
        self.assertEqual(expected,
                         self.ovs.db_get_val('Port', pname, 'other_config'))
        other = {'a': 'x'}
        expected.update(other)
        self.ovs.set_db_attribute('Port', pname, 'other_config', other)
        self.assertEqual(expected,
                         self.ovs.db_get_val('Port', pname, 'other_config'))

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

    def test_add_protocols_start_with_one(self):
        self.br.set_db_attribute('Bridge', self.br.br_name, 'protocols',
                                 ['OpenFlow10'],
                                 check_error=True)
        self.br.add_protocols('OpenFlow13')
        self.assertEqual(
            self.br.db_get_val('Bridge', self.br.br_name, 'protocols'),
            ['OpenFlow10', 'OpenFlow13'])

    def test_add_protocols_start_with_two_add_two(self):
        self.br.set_db_attribute('Bridge', self.br.br_name, 'protocols',
                                 ['OpenFlow10', 'OpenFlow12'],
                                 check_error=True)
        self.br.add_protocols('OpenFlow13', 'OpenFlow14')
        self.assertEqual(
            self.br.db_get_val('Bridge', self.br.br_name, 'protocols'),
            ['OpenFlow10', 'OpenFlow12', 'OpenFlow13', 'OpenFlow14'])

    def test_add_protocols_add_existing(self):
        self.br.set_db_attribute('Bridge', self.br.br_name, 'protocols',
                                 ['OpenFlow10', 'OpenFlow12', 'OpenFlow13'],
                                 check_error=True)
        self.br.add_protocols('OpenFlow13')
        self.assertEqual(
            self.br.db_get_val('Bridge', self.br.br_name, 'protocols'),
            ['OpenFlow10', 'OpenFlow12', 'OpenFlow13'])

    def _test_set_igmp_snooping_state(self, state):
        self.br.set_igmp_snooping_state(state)
        self.assertEqual(
            state,
            self.br.db_get_val(
                'Bridge', self.br.br_name, 'mcast_snooping_enable'))
        br_other_config = self.ovs.ovsdb.db_find(
            'Bridge', ('name', '=', self.br.br_name), columns=['other_config']
        ).execute()[0]['other_config']
        self.assertEqual(
            'false',
            br_other_config.get(
                'mcast-snooping-disable-flood-unregistered', '').lower())

    def test_set_igmp_snooping_enabled(self):
        self._test_set_igmp_snooping_state(True)

    def test_set_igmp_snooping_disabled(self):
        self._test_set_igmp_snooping_state(False)

    def test_get_datapath_id(self):
        brdev = ip_lib.IPDevice(self.br.br_name)
        dpid = brdev.link.attributes['link/ether'].replace(':', '')
        self.br.set_db_attribute('Bridge',
                                 self.br.br_name, 'datapath_id', dpid)
        self.assertIn(dpid, self.br.get_datapath_id())

    def _test_add_tunnel_port(self, attrs,
                              expected_tunnel_type=const.TYPE_GRE):
        port_name = utils.get_rand_device_name(net_helpers.PORT_PREFIX)
        self.br.add_tunnel_port(port_name, attrs['remote_ip'],
                                attrs['local_ip'])
        self.assertEqual(expected_tunnel_type,
                         self.ovs.db_get_val('Interface', port_name, 'type'))
        options = self.ovs.db_get_val('Interface', port_name, 'options')
        for attr, val in attrs.items():
            self.assertEqual(val, options[attr])

    def test_add_tunnel_port_ipv4(self):
        attrs = {
            'remote_ip': self.get_test_net_address(1),
            'local_ip': self.get_test_net_address(2),
        }
        self._test_add_tunnel_port(attrs)

    def test_add_tunnel_port_ipv6(self):
        attrs = {
            'remote_ip': '2001:db8:200::1',
            'local_ip': '2001:db8:100::1',
            'packet_type': 'legacy_l2',
        }
        self._test_add_tunnel_port(
            attrs, expected_tunnel_type=ovs_lib.TYPE_GRE_IP6)

    def test_add_tunnel_port_custom_port(self):
        port_name = utils.get_rand_device_name(net_helpers.PORT_PREFIX)
        self.br.add_tunnel_port(
            port_name,
            self.get_test_net_address(1),
            self.get_test_net_address(2),
            tunnel_type=const.TYPE_VXLAN,
            vxlan_udp_port=12345)
        options = self.ovs.db_get_val('Interface', port_name, 'options')
        self.assertEqual("12345", options['dst_port'])

    def test_add_tunnel_port_tos(self):
        attrs = {
            'remote_ip': self.get_test_net_address(1),
            'local_ip': self.get_test_net_address(2),
            'tos': 'inherit',
        }
        port_name = utils.get_rand_device_name(net_helpers.PORT_PREFIX)
        self.br.add_tunnel_port(port_name, attrs['remote_ip'],
                                attrs['local_ip'], tos=attrs['tos'])
        self.assertEqual('gre',
                         self.ovs.db_get_val('Interface', port_name, 'type'))
        options = self.ovs.db_get_val('Interface', port_name, 'options')
        for attr, val in attrs.items():
            self.assertEqual(val, options[attr])

    def test_add_patch_port(self):
        local = utils.get_rand_device_name(net_helpers.PORT_PREFIX)
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

    def test_get_iface_name_list(self):
        ifaces = {self.create_ovs_port()[0] for i in range(5)}
        self.assertSetEqual(ifaces, set(self.br.get_iface_name_list()))

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

    def test_get_vif_ports_with_bond(self):
        for i in range(2):
            self.create_ovs_port()
        vif_ports = [self.create_ovs_vif_port() for i in range(3)]
        # bond ports don't have records in the Interface table but they do in
        # the Port table
        orig = self.br.get_port_name_list
        new_port_name_list = lambda: orig() + ['bondport']
        mock.patch.object(self.br, 'get_port_name_list',
                          new=new_port_name_list).start()
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

    def test_get_vif_port_set_with_missing_port(self):
        self.create_ovs_port()
        vif_ports = [self.create_ovs_vif_port()]

        # return an extra port to make sure the db list ignores it
        orig = self.br.get_port_name_list
        new_port_name_list = lambda: orig() + ['anotherport']
        mock.patch.object(self.br, 'get_port_name_list',
                          new=new_port_name_list).start()
        ports = self.br.get_vif_port_set()
        expected = set([vif_ports[0].vif_id])
        self.assertEqual(expected, ports)

    def test_get_vif_port_set_on_empty_bridge_returns_empty_set(self):
        # Create a port on self.br
        self.create_ovs_vif_port()

        # Create another, empty bridge
        br_2 = self.useFixture(net_helpers.OVSBridgeFixture()).bridge

        # Assert that get_vif_port_set on an empty bridge returns an empty set,
        # and does not return the other bridge's ports.
        self.assertEqual(set(), br_2.get_vif_port_set())

    def test_get_ports_attributes(self):
        port_names = [self.create_ovs_port()[0], self.create_ovs_port()[0]]
        db_ports = self.br.get_ports_attributes('Interface', columns=['name'])
        db_ports_names = [p['name'] for p in db_ports]
        self.assertEqual(sorted(port_names), sorted(db_ports_names))

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

    def test_get_vifs_by_ids(self):
        for i in range(2):
            self.create_ovs_port()
        vif_ports = [self.create_ovs_vif_port() for i in range(3)]
        by_id = self.br.get_vifs_by_ids([v.vif_id for v in vif_ports])
        # convert to str for comparison of VifPorts
        by_id = {vid: str(vport) for vid, vport in by_id.items()}
        self.assertEqual({v.vif_id: str(v) for v in vif_ports}, by_id)

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

    def test_egress_bw_limit(self):
        port_name, _ = self.create_ovs_port()
        self.br.create_egress_bw_limit_for_port(port_name, 700, 70)
        max_rate, burst = self.br.get_egress_bw_limit_for_port(port_name)
        self.assertEqual(700, max_rate)
        self.assertEqual(70, burst)
        self.br.delete_egress_bw_limit_for_port(port_name)
        max_rate, burst = self.br.get_egress_bw_limit_for_port(port_name)
        self.assertIsNone(max_rate)
        self.assertIsNone(burst)

    def test_ingress_bw_limit(self):
        port_name, _ = self.create_ovs_port()
        self.br.update_ingress_bw_limit_for_port(port_name, 700, 70)
        max_rate, burst = self.br.get_ingress_bw_limit_for_port(port_name)
        self.assertEqual(700, max_rate)
        self.assertEqual(70, burst)

        self.br.update_ingress_bw_limit_for_port(port_name, 750, 100)
        max_rate, burst = self.br.get_ingress_bw_limit_for_port(port_name)
        self.assertEqual(750, max_rate)
        self.assertEqual(100, burst)

        self.br.delete_ingress_bw_limit_for_port(port_name)
        max_rate, burst = self.br.get_ingress_bw_limit_for_port(port_name)
        self.assertIsNone(max_rate)
        self.assertIsNone(burst)

    def test_ingress_bw_limit_dpdk_port(self):
        port_name, _ = self.create_ovs_port(
            ('type', agent_const.OVS_DPDK_VHOST_USER))
        self.br.update_ingress_bw_limit_for_port(port_name, 700, 70)
        max_rate, burst = self.br.get_ingress_bw_limit_for_dpdk_port(
            port_name)
        self.assertEqual(700, max_rate)
        self.assertEqual(70, burst)

        self.br.update_ingress_bw_limit_for_port(port_name, 750, 100)
        max_rate, burst = self.br.get_ingress_bw_limit_for_dpdk_port(
            port_name)
        self.assertEqual(750, max_rate)
        self.assertEqual(100, burst)

        self.br.delete_ingress_bw_limit_for_port(port_name)
        max_rate, burst = self.br.get_ingress_bw_limit_for_dpdk_port(
            port_name)
        self.assertIsNone(max_rate)
        self.assertIsNone(burst)

    def test_db_create_references(self):
        with self.ovs.ovsdb.transaction(check_error=True) as txn:
            queue = txn.add(self.ovs.ovsdb.db_create("Queue",
                                                     other_config={'a': '1'}))
            qos = txn.add(self.ovs.ovsdb.db_create("QoS", queues={0: queue}))
            txn.add(self.ovs.ovsdb.db_set("Port", self.br.br_name,
                                          ('qos', qos)))

        def cleanup():
            with self.ovs.ovsdb.transaction() as t:
                t.add(self.ovs.ovsdb.db_destroy("QoS", qos.result))
                t.add(self.ovs.ovsdb.db_destroy("Queue", queue.result))
                t.add(self.ovs.ovsdb.db_clear("Port", self.br.br_name, 'qos'))

        self.addCleanup(cleanup)
        val = self.ovs.ovsdb.db_get("Port", self.br.br_name, 'qos').execute()
        self.assertEqual(qos.result, val)

    def test_db_add_set(self):
        protocols = ["OpenFlow10", "OpenFlow11"]
        expected = self.br.initial_protocols.union(protocols)
        self.br.ovsdb.db_add("Bridge", self.br.br_name, "protocols",
                             *protocols).execute(check_error=True)
        self.assertItemsEqual(expected,
                              self.br.db_get_val('Bridge',
                                                 self.br.br_name, "protocols"))

    def test_db_add_map(self):
        key = "testdata"
        data = {key: "testvalue"}
        self.br.ovsdb.db_add("Bridge", self.br.br_name, "external_ids",
                             data).execute(check_error=True)
        self.assertEqual(data, self.br.db_get_val('Bridge', self.br.br_name,
                                                  'external_ids'))
        self.br.ovsdb.db_add("Bridge", self.br.br_name, "external_ids",
                             {key: "newdata"}).execute(check_error=True)
        self.assertEqual(data, self.br.db_get_val('Bridge', self.br.br_name,
                                                  'external_ids'))

    def test_db_add_map_multiple_one_dict(self):
        data = {"one": "1", "two": "2", "three": "3"}
        self.br.ovsdb.db_add("Bridge", self.br.br_name, "external_ids",
                             data).execute(check_error=True)
        self.assertEqual(data, self.br.db_get_val('Bridge', self.br.br_name,
                                                  'external_ids'))

    def test_db_add_map_multiple_dicts(self):
        data = ({"one": "1"}, {"two": "2"}, {"three": "3"})
        self.br.ovsdb.db_add("Bridge", self.br.br_name, "external_ids",
                             *data).execute(check_error=True)
        combined = {k: v for a in data for k, v in a.items()}
        self.assertEqual(combined, self.br.db_get_val('Bridge',
                                                      self.br.br_name,
                                                      'external_ids'))

    def test_db_add_ref(self):
        ovsdb = self.ovs.ovsdb
        brname = utils.get_rand_name(prefix=net_helpers.BR_PREFIX)
        br = ovs_lib.OVSBridge(brname)  # doesn't create
        self.addCleanup(br.destroy)
        with ovsdb.transaction(check_error=True) as txn:
            br = txn.add(ovsdb.db_create('Bridge', name=brname))
            txn.add(ovsdb.db_add('Open_vSwitch', '.', 'bridges', br))

        self.assertIn(brname, self.ovs.get_bridges())

    def test_db_add_to_new_object(self):
        ovsdb = self.ovs.ovsdb
        brname = utils.get_rand_name(prefix=net_helpers.BR_PREFIX)
        br = ovs_lib.OVSBridge(brname)  # doesn't create
        self.addCleanup(br.destroy)
        with ovsdb.transaction(check_error=True) as txn:
            txn.add(ovsdb.add_br(brname))
            txn.add(ovsdb.db_add('Bridge', brname, 'protocols', 'OpenFlow10'))

    def test_cascading_del_in_txn(self):
        ovsdb = self.ovs.ovsdb
        port_name, _ = self.create_ovs_port()

        def del_port_mod_iface():
            with ovsdb.transaction(check_error=True) as txn:
                txn.add(ovsdb.del_port(port_name, self.br.br_name,
                                       if_exists=False))
                txn.add(ovsdb.db_set('Interface', port_name,
                                     ('type', 'internal')))
        self.assertRaises((RuntimeError, idlutils.RowNotFound),
                          del_port_mod_iface)

    def test_delete_flows_all(self):
        self.br.add_flow(in_port=1, actions="output:2")
        self.br.delete_flows(cookie=ovs_lib.COOKIE_ANY)
        self.assertEqual([], self.br.dump_all_flows())

    def test_delete_flows_strict(self):
        self.br.delete_flows(cookie=ovs_lib.COOKIE_ANY)  # remove NORMAL action
        self.br.add_flow(in_port=1, actions="output:2")
        self.br.add_flow(in_port=1, priority=100, actions="output:3")
        self.assertEqual(2, len(self.br.dump_all_flows()))
        self.br.delete_flows(in_port=1, priority=100, strict=True)
        self.assertEqual(1, len(self.br.dump_all_flows()))


class OVSLibTestCase(base.BaseOVSLinuxTestCase):

    def setUp(self):
        super(OVSLibTestCase, self).setUp()
        self.ovs = ovs_lib.BaseOVS()

    def test_add_manager_appends(self):
        port1 = self.useFixture(port.ExclusivePort(const.PROTO_NAME_TCP,
            start=net_helpers.OVS_MANAGER_TEST_PORT_FIRST,
            end=net_helpers.OVS_MANAGER_TEST_PORT_LAST)).port
        port2 = self.useFixture(port.ExclusivePort(const.PROTO_NAME_TCP,
            start=net_helpers.OVS_MANAGER_TEST_PORT_FIRST,
            end=net_helpers.OVS_MANAGER_TEST_PORT_LAST)).port
        manager_list = ["ptcp:%s:127.0.0.1" % port1,
                        "ptcp:%s:127.0.0.1" % port2]
        # Verify that add_manager does not override the existing manager
        expected_manager_list = list()
        for conn_uri in manager_list:
            self.ovs.add_manager(conn_uri)
            self.addCleanup(self.ovs.remove_manager, conn_uri)
            self.assertIn(conn_uri, self.ovs.get_manager())
            expected_manager_list.append(conn_uri)

        # Verify that switch is configured with both the managers
        for manager_uri in expected_manager_list:
            self.assertIn(manager_uri, manager_list)

    def test_add_manager_lifecycle_baseovs(self):
        port1 = self.useFixture(port.ExclusivePort(const.PROTO_NAME_TCP,
            start=net_helpers.OVS_MANAGER_TEST_PORT_FIRST,
            end=net_helpers.OVS_MANAGER_TEST_PORT_LAST)).port
        conn_uri = "ptcp:%s:127.0.0.1" % port1
        self.addCleanup(self.ovs.remove_manager, conn_uri)
        self.ovs.add_manager(conn_uri)
        self.assertIn(conn_uri, self.ovs.get_manager())
        self.assertEqual(self.ovs.db_get_val('Manager', conn_uri,
                                             'inactivity_probe'),
                         self.ovs.ovsdb_timeout * 1000)
        self.ovs.remove_manager(conn_uri)
        self.assertNotIn(conn_uri, self.ovs.get_manager())

    def test_bridge_lifecycle_baseovs(self):
        name = utils.get_rand_name(prefix=net_helpers.BR_PREFIX)
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
        name = utils.get_rand_name(prefix=net_helpers.BR_PREFIX)
        mac_table_size = 12345
        cfg.CONF.set_override(
            'bridge_mac_table_size', mac_table_size, group='OVS')
        br = ovs_lib.OVSBridge(name)
        self.assertEqual(br.br_name, name)
        # Make sure that instantiating an OVSBridge does not actually create
        self.assertFalse(self.ovs.bridge_exists(name))
        self.addCleanup(self.ovs.delete_bridge, name)
        br.create()
        self.assertTrue(self.ovs.bridge_exists(name))
        br_other_config = self.ovs.ovsdb.db_find(
            'Bridge', ('name', '=', name), columns=['other_config']
        ).execute()[0]['other_config']
        self.assertEqual(str(mac_table_size),
                         br_other_config['mac-table-size'])
        br.destroy()
        self.assertFalse(self.ovs.bridge_exists(name))

    def test_db_find_column_type_list(self):
        """Fixate output for vsctl/native ovsdb_interface.

        Makes sure that db_find search queries give the same result for both
        implementations.
        """
        bridge_name = utils.get_rand_name(prefix=net_helpers.BR_PREFIX)
        self.addCleanup(self.ovs.delete_bridge, bridge_name)
        br = self.ovs.add_bridge(bridge_name)
        port_name = utils.get_rand_name(prefix=net_helpers.PORT_PREFIX)
        br.add_port(port_name)
        self.ovs.set_db_attribute('Port', port_name, 'tag', 42)

        # wrap list/find in transaction so we get a single isolated snapshot
        with self.ovs.ovsdb.transaction(check_error=True) as txn:
            tags = txn.add(self.ovs.ovsdb.db_list('Port', columns=['tag']))
            len_0_list = txn.add(self.ovs.ovsdb.db_find(
                    'Port', ('tag', '!=', []), columns=['tag']))
            single_value = txn.add(self.ovs.ovsdb.db_find(
                    'Port', ('tag', '=', 42), columns=['tag']))

        # Make sure that there is data to query.
        # It should be, but let's be a little paranoid here as otherwise
        # the test has no sense
        tags_present = [t for t in tags.result if t['tag'] != []]
        self.assertTrue(tags_present)
        tags_42 = [t for t in tags_present if t['tag'] == 42]
        self.assertEqual(tags_42, single_value.result)
        self.assertItemsEqual(len_0_list.result, tags_present)
