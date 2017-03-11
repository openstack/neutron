#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
from oslo_utils import uuidutils

from neutron.objects import trunk
from neutron.services.trunk.drivers.linuxbridge.agent import trunk_plumber
from neutron.tests import base


class PlumberTestCase(base.BaseTestCase):
    def setUp(self):
        self.plumber = trunk_plumber.Plumber()
        self.get_tap_device_name = mock.patch.object(
            self.plumber, '_get_tap_device_name',
            return_value='devname').start()
        self.trunk = trunk.Trunk()
        self.trunk.port_id = uuidutils.generate_uuid()
        self.trunk.sub_ports = []
        self.device_exists = mock.patch.object(trunk_plumber.ip_lib,
                                               'device_exists').start()
        self.device_exists.return_value = True
        ipwrap = mock.patch.object(trunk_plumber.ip_lib, 'IPWrapper').start()
        ipwrap.return_value.netns.execute.return_value = IP_LINK_OUTPUT
        super(PlumberTestCase, self).setUp()

    def test_trunk_on_host(self):
        self.assertTrue(self.plumber.trunk_on_host(self.trunk))
        self.device_exists.return_value = False
        self.assertFalse(self.plumber.trunk_on_host(self.trunk))

    def test_ensure_trunk_subports(self):
        trunk_vals = set([('dev2', 23), ('dev3', 44), ('dev4', 45)])
        existing_vals = set([('dev1', 21), ('dev2', 23), ('dev3', 45)])
        mock.patch.object(self.plumber, '_get_subport_devs_and_vlans',
                          return_value=trunk_vals).start()
        mock.patch.object(self.plumber, '_get_vlan_children',
                          return_value=existing_vals).start()
        delete = mock.patch.object(self.plumber, '_safe_delete_device').start()
        create = mock.patch.object(self.plumber, '_create_vlan_subint').start()
        self.plumber.ensure_trunk_subports(self.trunk)
        # dev1 is gone and dev3 changed vlans
        delete.assert_has_calls([mock.call('dev3'), mock.call('dev1')],
                                any_order=True)
        create.assert_has_calls([mock.call('devname', 'dev4', 45),
                                 mock.call('devname', 'dev3', 44)],
                                any_order=True)

    def test_delete_trunk_subports(self):
        existing_vals = set([('dev1', 21), ('dev2', 23), ('dev3', 45)])
        mock.patch.object(self.plumber, '_get_vlan_children',
                          return_value=existing_vals).start()
        delete = mock.patch.object(self.plumber, '_safe_delete_device').start()
        self.plumber.delete_trunk_subports(self.trunk)
        delete.assert_has_calls([mock.call('dev3'), mock.call('dev2'),
                                 mock.call('dev1')],
                                any_order=True)

    def test__get_vlan_children(self):
        expected = [('tap47198374-5a', 777),
                    ('tap47198374-5b', 2),
                    ('tap47198374-5c', 3)]
        self.assertEqual(set(expected),
                         self.plumber._get_vlan_children('tap34786ac-28'))
        expected = [('tap39df7d39-c5', 99),
                    ('tap39df7d44-b2', 904),
                    ('tap11113d44-3f', 777)]
        self.assertEqual(set(expected),
                         self.plumber._get_vlan_children('tapa962cfc7-9d'))
        # vlan sub-interface and non-trunk shouldn't have children
        self.assertEqual(set(),
                         self.plumber._get_vlan_children('tap47198374-5c'))
        self.assertEqual(set(),
                         self.plumber._get_vlan_children('br-int'))

    def test__iter_output_by_interface(self):
        iterator = trunk_plumber._iter_output_by_interface(IP_LINK_OUTPUT)
        names = [i.devname for i in iterator]
        expected = ['lo', 'eth0', 'bond0', 'ovs-system', 'br-ex',
                    'testb9cfb5d7', 'br-int', 'br-tun', 'tapa962cfc7-9d',
                    'tap39df7d39-c5', 'tap39df7d44-b2', 'tap11113d44-3f',
                    'tap34786ac-28', 'tap47198374-5a', 'tap47198374-5b',
                    'tap47198374-5c']
        self.assertEqual(expected, names)

IP_LINK_OUTPUT = """
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFA
    link/ether 00:0c:29:10:68:04 brd ff:ff:ff:ff:ff:ff promiscuity 0
3: bond0: <BROADCAST,MULTICAST,MASTER> mtu 1500 qdisc noop state DOWN mode DEFAULT grou
    link/ether 5e:dc:86:6f:b7:19 brd ff:ff:ff:ff:ff:ff promiscuity 0
    bond
4: ovs-system: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group
    link/ether 5a:95:a1:b9:42:25 brd ff:ff:ff:ff:ff:ff promiscuity 1
5: br-ex: <BROADCAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT gro
    link/ether be:cc:4f:f7:28:48 brd ff:ff:ff:ff:ff:ff promiscuity 1
6: testb9cfb5d7: <BROADCAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFA
    link/ether 82:90:49:84:32:47 brd ff:ff:ff:ff:ff:ff promiscuity 1
7: br-int: <BROADCAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT gr
    link/ether 5a:5e:7d:02:7c:4d brd ff:ff:ff:ff:ff:ff promiscuity 1
8: br-tun: <BROADCAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN mode DEFAULT gr
    link/ether 76:d8:a5:16:d7:4a brd ff:ff:ff:ff:ff:ff promiscuity 1
10: tapa962cfc7-9d: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT g
    link/ether 9a:31:1d:cc:b3:86 brd ff:ff:ff:ff:ff:ff promiscuity 0
    tun
11: tap39df7d39-c5@tapa962cfc7-9d: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop sta
    link/ether 9a:31:1d:cc:b3:86 brd ff:ff:ff:ff:ff:ff promiscuity 0
    vlan protocol 802.1Q id 99 <REORDER_HDR>
12: tap39df7d44-b2@tapa962cfc7-9d: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop sta
    link/ether 9a:31:1d:cc:b3:86 brd ff:ff:ff:ff:ff:ff promiscuity 0
    vlan protocol 802.1Q id 904 <REORDER_HDR>
13: tap11113d44-3f@tapa962cfc7-9d: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop sta
    link/ether 9a:31:1d:cc:b3:86 brd ff:ff:ff:ff:ff:ff promiscuity 0
    vlan protocol 802.1Q id 777 <REORDER_HDR>
14: tap34786ac-28: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT gr
    link/ether f6:07:9f:11:4c:dc brd ff:ff:ff:ff:ff:ff promiscuity 0
    tun
15: tap47198374-5a@tap34786ac-28: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop stat
    link/ether f6:07:9f:11:4c:dc brd ff:ff:ff:ff:ff:ff promiscuity 0
    vlan protocol 802.1Q id 777 <REORDER_HDR>
16: tap47198374-5b@tap34786ac-28: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop stat
    link/ether f6:07:9f:11:4c:dc brd ff:ff:ff:ff:ff:ff promiscuity 0
    vlan protocol 802.1Q id 2 <REORDER_HDR>
17: tap47198374-5c@tap34786ac-28: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop stat
    link/ether f6:07:9f:11:4c:dc brd ff:ff:ff:ff:ff:ff promiscuity 0
    vlan protocol 802.1Q id 3 <REORDER_HDR>
"""  # noqa
