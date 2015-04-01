# Copyright 2014 Cisco Systems, Inc.
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

import testscenarios

from neutron.tests import base as tests_base
from neutron.tests.common import net_helpers
from neutron.tests.functional import base as functional_base


MARK_VALUE = '0x1'
MARK_MASK = '0xffffffff'
ICMP_MARK_RULE = ('-j MARK --set-xmark %(value)s/%(mask)s'
                  % {'value': MARK_VALUE, 'mask': MARK_MASK})
MARKED_BLOCK_RULE = '-m mark --mark %s -j DROP' % MARK_VALUE
ICMP_BLOCK_RULE = '-p icmp -j DROP'


#TODO(jschwarz): Move these two functions to neutron/tests/common/
get_rand_name = tests_base.get_rand_name


class BaseLinuxTestCase(functional_base.BaseSudoTestCase):

    def _create_namespace(self, prefix=net_helpers.NS_PREFIX):
        return self.useFixture(net_helpers.NamespaceFixture(prefix)).ip_wrapper

    def create_veth(self):
        return self.useFixture(net_helpers.VethFixture()).ports


# Regarding MRO, it goes BaseOVSLinuxTestCase, WithScenarios,
# BaseLinuxTestCase, ..., UnitTest, object. setUp is not dfined in
# WithScenarios, so it will correctly be found in BaseLinuxTestCase.
class BaseOVSLinuxTestCase(testscenarios.WithScenarios, BaseLinuxTestCase):
    scenarios = [
        ('vsctl', dict(ovsdb_interface='vsctl')),
        ('native', dict(ovsdb_interface='native')),
    ]

    def setUp(self):
        super(BaseOVSLinuxTestCase, self).setUp()
        self.config(group='OVS', ovsdb_interface=self.ovsdb_interface)


class BaseIPVethTestCase(BaseLinuxTestCase):
    SRC_ADDRESS = '192.168.0.1'
    DST_ADDRESS = '192.168.0.2'

    @staticmethod
    def _set_ip_up(device, cidr):
        device.addr.add(cidr)
        device.link.set_up()

    def prepare_veth_pairs(self):

        src_addr = self.SRC_ADDRESS
        dst_addr = self.DST_ADDRESS

        src_veth, dst_veth = self.create_veth()
        src_ns = self._create_namespace()
        dst_ns = self._create_namespace()
        src_ns.add_device_to_namespace(src_veth)
        dst_ns.add_device_to_namespace(dst_veth)

        self._set_ip_up(src_veth, '%s/24' % src_addr)
        self._set_ip_up(dst_veth, '%s/24' % dst_addr)

        return src_ns, dst_ns
