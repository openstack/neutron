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

from unittest import mock

from oslo_utils import uuidutils

from neutron.agent.linux import ip_lib
from neutron.objects import trunk
from neutron.services.trunk.drivers.linuxbridge.agent import trunk_plumber
from neutron.tests import base


IP_LINK_OUTPUT = [
    {'index': 1, 'name': 'lo'},
    {'index': 2, 'name': 'eth0'},
    {'index': 3, 'name': 'bond0'},
    {'index': 4, 'name': 'ovs-system'},
    {'index': 5, 'name': 'br-ex'},
    {'index': 6, 'name': 'testb9cfb5d7'},
    {'index': 7, 'name': 'br-int'},
    {'index': 8, 'name': 'br-tun'},
    {'index': 10, 'name': 'tapa962cfc7-9d'},
    {'index': 11, 'name': 'tap39df7d39-c5', 'kind': 'vlan',
     'parent_name': 'tapa962cfc7-9d', 'vlan_id': 99},
    {'index': 12, 'name': 'tap39df7d44-b2', 'kind': 'vlan',
     'parent_name': 'tapa962cfc7-9d', 'vlan_id': 904},
    {'index': 13, 'name': 'tap11113d44-3f', 'kind': 'vlan',
     'parent_name': 'tapa962cfc7-9d', 'vlan_id': 777},
    {'index': 14, 'name': 'tap34786ac-28'},
    {'index': 15, 'name': 'tap47198374-5a', 'kind': 'vlan',
     'parent_name': 'tap34786ac-28', 'vlan_id': 777},
    {'index': 16, 'name': 'tap47198374-5b', 'kind': 'vlan',
     'parent_name': 'tap34786ac-28', 'vlan_id': 2},
    {'index': 17, 'name': 'tap47198374-5c', 'kind': 'vlan',
     'parent_name': 'tap34786ac-28', 'vlan_id': 3}
]


class PlumberTestCase(base.BaseTestCase):
    def setUp(self):
        self.plumber = trunk_plumber.Plumber()
        self.get_tap_device_name = mock.patch.object(
            self.plumber, '_get_tap_device_name',
            return_value='devname').start()
        self.trunk = trunk.Trunk()
        self.trunk.port_id = uuidutils.generate_uuid()
        self.trunk.sub_ports = []
        self.device_exists = mock.patch.object(ip_lib, 'device_exists').start()
        self.device_exists.return_value = True
        self.mock_get_devices = mock.patch.object(ip_lib,
                                                  'get_devices_info').start()
        # ipwrap.return_value.netns.execute.return_value = IP_LINK_OUTPUT
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
        self.mock_get_devices.return_value = IP_LINK_OUTPUT
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
