# Copyright (c) 2015 Thales Services SAS
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

import random

import netaddr
from neutron_lib import constants
from oslo_utils import uuidutils
import testscenarios

from neutron.agent.linux import bridge_lib
from neutron.agent.linux import ip_lib
from neutron.privileged.agent.linux import ip_lib as priv_ip_lib
from neutron.tests.functional import base


MAC_ALL_NODES_ADDRESS = '33:33:00:00:00:01'


class FdbInterfaceTestCase(testscenarios.WithScenarios, base.BaseSudoTestCase):

    MAC1 = 'ca:fe:ca:fe:ca:fe'
    MAC2 = 'ca:fe:ca:fe:ca:01'

    scenarios = [
        ('namespace', {'namespace': 'ns_' + uuidutils.generate_uuid()}),
        ('no_namespace', {'namespace': None})
    ]

    def setUp(self):
        super().setUp()
        _uuid = uuidutils.generate_uuid()
        self.device = ('int_' + _uuid)[:constants.DEVICE_NAME_MAX_LEN]
        self.device_vxlan = ('vxlan_' + _uuid)[:constants.DEVICE_NAME_MAX_LEN]
        self.ip = '10.220.0.1/24'
        self.ip_vxlan = '10.221.0.1/24'
        if self.namespace:
            priv_ip_lib.create_netns(self.namespace)
        else:
            self._cleanup()
        self.addCleanup(self._cleanup)
        vni = random.randint(1, 2**24 - 1)
        ip_wrapper = ip_lib.IPWrapper(self.namespace)
        ip_wrapper.add_dummy(self.device)
        ip_wrapper.add_vxlan(self.device_vxlan, vni, self.device)
        ip_device = ip_lib.IPDevice(self.device, self.namespace)
        ip_device.link.set_up()
        ip_device.addr.add(self.ip)
        ip_device_vxlan = ip_lib.IPDevice(self.device_vxlan, self.namespace)
        ip_device_vxlan.link.set_up()
        ip_device_vxlan.addr.add(self.ip_vxlan)

    def _cleanup(self):
        if self.namespace:
            priv_ip_lib.remove_netns(self.namespace)
        else:
            for device in (self.device_vxlan, self.device):
                try:
                    priv_ip_lib.delete_interface(device, None)
                except priv_ip_lib.NetworkInterfaceNotFound:
                    pass

    def _assert_mac(self, mac_address, device, present=True):
        msg = ('MAC address %(mac_address)s %(present)s in the FDB table for '
               'the device %(device)s in namespace %(namespace)s' %
               {'mac_address': mac_address, 'device': device,
                'namespace': self.namespace,
                'present': 'not present' if present else 'present'})

        for _device, fdbs in bridge_lib.FdbInterface.show(
                dev=device, namespace=self.namespace).items():
            self.assertEqual(device, _device)
            macs = [fdb['mac'] for fdb in fdbs]
            if ((mac_address in macs and not present) or
                    (mac_address not in macs and present)):
                self.fail(msg)

    def _assert_ip(self, mac_address, ip_address, device):
        msg = ('Destination IP address %(ip_address)s not present in the FDB '
               'table for the MAC address %(mac_address)s and device '
               '%(device)s in namespace %(namespace)s' %
               {'mac_address': mac_address, 'device': device,
                'namespace': self.namespace, 'ip_address': ip_address})

        for _device, fdbs in bridge_lib.FdbInterface.show(
                dev=device, namespace=self.namespace).items():
            self.assertEqual(device, _device)
            for _ in (fdb for fdb in fdbs if fdb['mac'] == mac_address and
                      fdb['dst_ip'] == ip_address):
                return
            self.fail(msg)

    def test_add_delete(self):
        self._assert_mac(self.MAC1, self.device, present=False)
        bridge_lib.FdbInterface.add(self.MAC1, self.device,
                                    namespace=self.namespace)
        self._assert_mac(self.MAC1, self.device)
        bridge_lib.FdbInterface.delete(self.MAC1, self.device,
                                       namespace=self.namespace)
        self._assert_mac(self.MAC1, self.device, present=False)

        try:
            # This should not raise for a non-existent entry
            bridge_lib.FdbInterface.delete(self.MAC1, self.device,
                                           namespace=self.namespace)
        except Exception:
            self.fail('Delete FDB entry threw unexpected exception')

    def test_add_delete_dst(self):
        self._assert_mac(self.MAC1, self.device_vxlan, present=False)
        bridge_lib.FdbInterface.add(
            self.MAC1, self.device_vxlan, namespace=self.namespace,
            dst_ip=str(netaddr.IPNetwork(self.ip).ip))
        self._assert_ip(self.MAC1, str(netaddr.IPNetwork(self.ip).ip),
                        self.device_vxlan)
        bridge_lib.FdbInterface.delete(
            self.MAC1, self.device_vxlan, namespace=self.namespace,
            dst_ip=str(netaddr.IPNetwork(self.ip).ip))
        self._assert_mac(self.MAC1, self.device_vxlan, present=False)

    def test_append(self):
        self._assert_mac(self.MAC1, self.device, present=False)
        bridge_lib.FdbInterface.append(self.MAC1, self.device,
                                       namespace=self.namespace)
        self._assert_mac(self.MAC1, self.device)

    def test_append_dst(self):
        self._assert_mac(self.MAC1, self.device_vxlan)
        bridge_lib.FdbInterface.append(
            self.MAC1, self.device_vxlan, namespace=self.namespace,
            dst_ip=str(netaddr.IPNetwork(self.ip).ip))
        self._assert_ip(self.MAC1, str(netaddr.IPNetwork(self.ip).ip),
                        self.device_vxlan)

    def test_replace(self):
        self._assert_mac(self.MAC1, self.device, present=False)
        bridge_lib.FdbInterface.add(
            self.MAC1, self.device_vxlan, namespace=self.namespace,
            dst_ip=str(netaddr.IPNetwork(self.ip).ip))
        self._assert_ip(self.MAC1, str(netaddr.IPNetwork(self.ip).ip),
                        self.device_vxlan)
        bridge_lib.FdbInterface.replace(
            self.MAC1, self.device_vxlan, namespace=self.namespace,
            dst_ip='1.1.1.1')
        self._assert_ip(self.MAC1, '1.1.1.1', self.device_vxlan)

    def test_show(self):
        ip_str = str(netaddr.IPNetwork(self.ip).ip)
        bridge_lib.FdbInterface.add(
            self.MAC1, self.device_vxlan, namespace=self.namespace,
            dst_ip=ip_str)
        rules = bridge_lib.FdbInterface.show(dev=self.device_vxlan,
                                             namespace=self.namespace)
        self.assertEqual(1, len(rules))
        self.assertEqual(1, len(rules[self.device_vxlan]))
        self.assertEqual(self.MAC1, rules[self.device_vxlan][0]['mac'])
        self.assertEqual(ip_str, rules[self.device_vxlan][0]['dst_ip'])

        _uuid = uuidutils.generate_uuid()
        bridge_name = ('br_' + _uuid)[:constants.DEVICE_NAME_MAX_LEN]
        priv_ip_lib.create_interface(bridge_name, self.namespace, 'bridge')
        bridge = bridge_lib.BridgeDevice(bridge_name, namespace=self.namespace)
        bridge.addif(self.device)
        rules = bridge_lib.FdbInterface.show(dev=bridge_name,
                                             namespace=self.namespace)
        self.assertEqual(1, len(rules))
        self._assert_mac(MAC_ALL_NODES_ADDRESS, bridge_name)

        rules = bridge_lib.FdbInterface.show(dev=self.device,
                                             namespace=self.namespace)
        mac_address = ip_lib.IPDevice(self.device, self.namespace).link.address
        for rule in (rule for rule in rules[self.device] if
                     rule['mac'] == mac_address):
            self.assertEqual(bridge_name, rule['master'])
            self.assertIn(rule['vlan'], (1, None))
