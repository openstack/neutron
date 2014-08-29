# Copyright (c) 2014 Red Hat, Inc.
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

from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.openstack.common import uuidutils
from neutron.tests.functional.agent.linux import base

ICMP_BLOCK_RULE = '-p icmp -j DROP'
SRC_VETH_NAME = 'source'
DEST_VETH_NAME = 'destination'


class IpBase(base.BaseLinuxTestCase):
    SRC_ADDRESS = '192.168.0.1'
    DST_ADDRESS = '192.168.0.2'

    @staticmethod
    def _set_ip_up(device, cidr, broadcast='192.168.0.255', ip_version=4):
        device.addr.add(ip_version=ip_version, cidr=cidr, broadcast=broadcast)
        device.link.set_up()

    @staticmethod
    def _ping_destination(src_namespace, dest_address, attempts=3):
        src_namespace.netns.execute(['ping', '-c', attempts, dest_address])

    def _create_namespace(self):
        ip_cmd = ip_lib.IPWrapper(self.root_helper)
        name = "func-%s" % uuidutils.generate_uuid()
        namespace = ip_cmd.ensure_namespace(name)
        self.addCleanup(namespace.netns.delete, namespace.namespace)

        return namespace

    def _prepare_veth_pairs(self):
        src_ns = self._create_namespace()
        dst_ns = self._create_namespace()
        src_veth, dst_veth = src_ns.add_veth(SRC_VETH_NAME,
                                             DEST_VETH_NAME,
                                             dst_ns.namespace)
        self._set_ip_up(src_veth, '%s/24' % self.SRC_ADDRESS)
        self._set_ip_up(dst_veth, '%s/24' % self.DST_ADDRESS)

        return src_ns, dst_ns


class IptablesManagerTestCase(IpBase):
    def setUp(self):
        super(IptablesManagerTestCase, self).setUp()
        self.check_sudo_enabled()
        self.src_ns, self.dst_ns = self._prepare_veth_pairs()
        self.iptables = iptables_manager.IptablesManager(
            root_helper=self.root_helper,
            namespace=self.dst_ns.namespace)

    def test_icmp(self):
        self._ping_destination(self.src_ns, self.DST_ADDRESS)
        self.iptables.ipv4['filter'].add_rule('INPUT', ICMP_BLOCK_RULE)
        self.iptables.apply()
        self.assertRaises(RuntimeError, self._ping_destination, self.src_ns,
                          self.DST_ADDRESS)
        self.iptables.ipv4['filter'].remove_rule('INPUT', ICMP_BLOCK_RULE)
        self.iptables.apply()
        self._ping_destination(self.src_ns, self.DST_ADDRESS)
