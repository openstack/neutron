# Copyright 2022 Red Hat, Inc.
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

# TODO(haleyb) remove when pyroute >=0.9.1 required
try:
    from pyroute2.netlink import core as nlcore
except ImportError:
    from pyroute2.netlink import nlsocket as nlcore

from neutron.agent.linux import devlink
from neutron.privileged.agent import linux as priv_linux
from neutron.privileged.agent.linux import devlink as priv_devlink
from neutron.tests import base


GET_PORT_LIST = (
    {'cmd': 3,
     'version': 1,
     'reserved': 0,
     'attrs': [
         ('DEVLINK_ATTR_BUS_NAME', 'pci'),
         ('DEVLINK_ATTR_DEV_NAME', '0000:04:00.0'),
         ('DEVLINK_ATTR_PORT_INDEX', 65535),
         ('DEVLINK_ATTR_PORT_TYPE', 2),
         ('DEVLINK_ATTR_PORT_NETDEV_IFINDEX', 6),
         ('DEVLINK_ATTR_PORT_NETDEV_NAME', 'enp4s0f0np0'),
         ('DEVLINK_ATTR_PORT_SPLITTABLE', 0),
         ('DEVLINK_ATTR_PORT_FLAVOUR', 0),
         ('DEVLINK_ATTR_PORT_NUMBER', 0)
     ],
     'header': {
         'length': 112,
         'type': 20,
         'flags': 2,
         'sequence_number': 258,
         'pid': 448943,
         'error': None,
         'target': 'localhost',
         'stats': nlcore.Stats(qsize=0, delta=0, delay=0)
     },
     'event': 'DEVLINK_CMD_NEW'},
    {'cmd': 3,
     'version': 1,
     'reserved': 0,
     'attrs': [
         ('DEVLINK_ATTR_BUS_NAME', 'pci'),
         ('DEVLINK_ATTR_DEV_NAME', '0000:04:00.0'),
         ('DEVLINK_ATTR_PORT_INDEX', 1),
         ('DEVLINK_ATTR_PORT_TYPE', 2),
         ('DEVLINK_ATTR_PORT_NETDEV_IFINDEX', 14),
         ('DEVLINK_ATTR_PORT_NETDEV_NAME', 'enp4s0f0np0_0'),
         ('DEVLINK_ATTR_PORT_SPLITTABLE', 0),
         ('DEVLINK_ATTR_PORT_FLAVOUR', 4),
         ('UNKNOWN', {'header': {'length': 8, 'type': 150}}),
         ('DEVLINK_ATTR_PORT_PCI_PF_NUMBER', 0),
         ('DEVLINK_ATTR_PORT_PCI_VF_NUMBER', 0),
         ('UNKNOWN', {'header': {'length': 5, 'type': 149}}),
         ('DEVLINK_ATTR_PORT_FUNCTION', {
             'attrs': [('DEVLINK_ATTR_BUS_NAME', '')]
         })
     ],
     'header': {
         'length': 156,
         'type': 20,
         'flags': 2,
         'sequence_number': 258,
         'pid': 448943,
         'error': None,
         'target': 'localhost',
         'stats': nlcore.Stats(qsize=0, delta=0, delay=0)
     },
     'event': 'DEVLINK_CMD_NEW'},
    {'cmd': 3,
     'version': 1,
     'reserved': 0,
     'attrs': [
         ('DEVLINK_ATTR_BUS_NAME', 'pci'),
         ('DEVLINK_ATTR_DEV_NAME', '0000:04:00.0'),
         ('DEVLINK_ATTR_PORT_INDEX', 2),
         ('DEVLINK_ATTR_PORT_TYPE', 2),
         ('DEVLINK_ATTR_PORT_NETDEV_IFINDEX', 15),
         ('DEVLINK_ATTR_PORT_NETDEV_NAME', 'enp4s0f0np0_1'),
         ('DEVLINK_ATTR_PORT_SPLITTABLE', 0),
         ('DEVLINK_ATTR_PORT_FLAVOUR', 4),
         ('UNKNOWN', {'header': {'length': 8, 'type': 150}}),
         ('DEVLINK_ATTR_PORT_PCI_PF_NUMBER', 0),
         ('DEVLINK_ATTR_PORT_PCI_VF_NUMBER', 1),
         ('UNKNOWN', {'header': {'length': 5, 'type': 149}}),
         ('DEVLINK_ATTR_PORT_FUNCTION', {
             'attrs': [('DEVLINK_ATTR_BUS_NAME', '')]
         })
     ],
     'header': {
         'length': 156,
         'type': 20,
         'flags': 2,
         'sequence_number': 258,
         'pid': 448943,
         'error': None,
         'target': 'localhost',
         'stats': nlcore.Stats(qsize=0, delta=0, delay=0)
     },
     'event': 'DEVLINK_CMD_NEW'}
)


class TestDevlink(base.BaseTestCase):

    @mock.patch.object(priv_devlink, 'get_port_list')
    def test_get_port(self, mock_get_port_list):
        mock_get_port_list.return_value = priv_linux.make_serializable(
            GET_PORT_LIST)
        expected_port1 = {'pf_pci': '0000:04:00.0', 'pf_num': 0,
                          'pf_name': 'enp4s0f0np0', 'vf_num': 0,
                          'vf_name': 'enp4s0f0np0_0'}
        expected_port2 = {'pf_pci': '0000:04:00.0', 'pf_num': 0,
                          'pf_name': 'enp4s0f0np0', 'vf_num': 1,
                          'vf_name': 'enp4s0f0np0_1'}
        port1 = devlink.get_port('enp4s0f0np0_0')
        port2 = devlink.get_port('enp4s0f0np0_1')
        port3 = devlink.get_port('enp4s0f0np0_not_present')
        self.assertEqual(expected_port1, port1)
        self.assertEqual(expected_port2, port2)
        self.assertIsNone(port3)
