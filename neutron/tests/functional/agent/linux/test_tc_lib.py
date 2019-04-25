# Copyright (c) 2016 OVH SAS
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

import netaddr
from oslo_utils import uuidutils

from neutron.agent.linux import ip_lib
from neutron.agent.linux import tc_lib
from neutron.privileged.agent.linux import ip_lib as priv_ip_lib
from neutron.tests.common import net_helpers
from neutron.tests.functional import base as functional_base

TEST_HZ_VALUE = 250
LATENCY = 50
BW_LIMIT = 1024
BURST = 512

BASE_DEV_NAME = "test_tap"


class TcLibTestCase(functional_base.BaseSudoTestCase):

    def create_device(self, name):
        """Create a tuntap with the specified name.

        The device is cleaned up at the end of the test.
        """

        ip = ip_lib.IPWrapper()
        tap_device = ip.add_tuntap(name)
        self.addCleanup(tap_device.link.delete)
        tap_device.link.set_up()

    def test_filters_bandwidth_limit(self):
        device_name = "%s_filters" % BASE_DEV_NAME
        self.create_device(device_name)
        tc = tc_lib.TcCommand(device_name, TEST_HZ_VALUE)

        tc.set_filters_bw_limit(BW_LIMIT, BURST)
        bw_limit, burst = tc.get_filters_bw_limits()
        self.assertEqual(BW_LIMIT, bw_limit)
        self.assertEqual(BURST, burst)

        new_bw_limit = BW_LIMIT + 500
        new_burst = BURST + 50

        tc.update_filters_bw_limit(new_bw_limit, new_burst)
        bw_limit, burst = tc.get_filters_bw_limits()
        self.assertEqual(new_bw_limit, bw_limit)
        self.assertEqual(new_burst, burst)

        tc.delete_filters_bw_limit()
        bw_limit, burst = tc.get_filters_bw_limits()
        self.assertIsNone(bw_limit)
        self.assertIsNone(burst)

    def test_tbf_bandwidth_limit(self):
        device_name = "%s_tbf" % BASE_DEV_NAME
        self.create_device(device_name)
        tc = tc_lib.TcCommand(device_name, TEST_HZ_VALUE)

        tc.set_tbf_bw_limit(BW_LIMIT, BURST, LATENCY)
        bw_limit, burst = tc.get_tbf_bw_limits()
        self.assertEqual(BW_LIMIT, bw_limit)
        self.assertEqual(BURST, burst)

        new_bw_limit = BW_LIMIT + 500
        new_burst = BURST + 50

        tc.set_tbf_bw_limit(new_bw_limit, new_burst, LATENCY)
        bw_limit, burst = tc.get_tbf_bw_limits()
        self.assertEqual(new_bw_limit, bw_limit)
        self.assertEqual(new_burst, burst)

        tc.delete_tbf_bw_limit()
        bw_limit, burst = tc.get_tbf_bw_limits()
        self.assertIsNone(bw_limit)
        self.assertIsNone(burst)


class TcPolicyClassTestCase(functional_base.BaseSudoTestCase):

    def _remove_ns(self, namespace):
        priv_ip_lib.remove_netns(namespace)

    def _create_two_namespaces(self):
        self.ns = ['ns1_' + uuidutils.generate_uuid(),
                   'ns2_' + uuidutils.generate_uuid()]
        self.device = ['int1', 'int2']
        self.mac = []
        self.ip = ['10.100.0.1/24', '10.100.0.2/24']
        list(map(priv_ip_lib.create_netns, self.ns))
        ip_wrapper = ip_lib.IPWrapper(self.ns[0])
        ip_wrapper.add_veth(self.device[0], self.device[1], self.ns[1])
        for i in range(2):
            self.addCleanup(self._remove_ns, self.ns[i])
            ip_device = ip_lib.IPDevice(self.device[i], self.ns[i])
            self.mac.append(ip_device.link.address)
            ip_device.link.set_up()
            ip_device.addr.add(self.ip[i])

    def test_list_tc_policy_class_retrieve_statistics(self):
        statistics = {'bytes', 'packets', 'drop', 'overlimits', 'bps', 'pps',
                      'qlen', 'backlog'}
        self._create_two_namespaces()
        tc_lib.add_tc_qdisc(self.device[0], 'htb', parent='root', handle='1:',
                            namespace=self.ns[0])
        tc_lib.add_tc_policy_class(self.device[0], '1:', '1:10',
                                   max_kbps=1000, burst_kb=900, min_kbps=500,
                                   namespace=self.ns[0])
        tc_lib.add_tc_filter_match_mac(self.device[0], '1:', '1:10',
                                       self.mac[1], namespace=self.ns[0])
        tc_classes = tc_lib.list_tc_policy_class(self.device[0],
                                                 namespace=self.ns[0])
        self.assertEqual(1, len(tc_classes))
        self.assertEqual(statistics, set(tc_classes[0]['stats']))

        bytes = tc_classes[0]['stats']['bytes']
        packets = tc_classes[0]['stats']['packets']
        net_helpers.assert_ping(self.ns[1], netaddr.IPNetwork(self.ip[0]).ip,
                                count=1)
        tc_classes = tc_lib.list_tc_policy_class(self.device[0],
                                                 namespace=self.ns[0])
        self.assertGreater(tc_classes[0]['stats']['bytes'], bytes)
        self.assertGreater(tc_classes[0]['stats']['packets'], packets)
