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

import random
from unittest import mock

import netaddr
from neutron_lib.services.qos import constants as qos_consts
from oslo_utils import uuidutils

from neutron.agent.linux import bridge_lib
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

    def test_add_tc_policy_class_check_min_kbps_values(self):
        def warning_args(rate, min_rate):
            return ('TC HTB class policy rate %(rate)s (bytes/second) is '
                    'lower than the minimum accepted %(min_rate)s '
                    '(bytes/second), for device %(device)s, qdisc '
                    '%(qdisc)s and classid %(classid)s',
                    {'rate': rate, 'min_rate': min_rate, 'classid': '1:10',
                     'device': self.device[0], 'qdisc': '1:'})

        self._create_two_namespaces()
        tc_lib.add_tc_qdisc(self.device[0], 'htb', parent='root', handle='1:',
                            namespace=self.ns[0])

        with mock.patch.object(tc_lib, 'LOG') as mock_log:
            # rate > min_rate: OK
            tc_lib.add_tc_policy_class(self.device[0], '1:', '1:10',
                                       max_kbps=2000, burst_kb=1000,
                                       min_kbps=4, namespace=self.ns[0])
            mock_log.warning.assert_not_called()

            # rate < min_rate: min_rate = 466 with burst = 128000
            tc_lib.add_tc_policy_class(self.device[0], '1:', '1:10',
                                       max_kbps=2000, burst_kb=1000,
                                       min_kbps=3, namespace=self.ns[0])
            mock_log.warning.assert_called_once_with(
                *warning_args(3 * 125, tc_lib._calc_min_rate(1000 * 125)))

            # rate < min_rate: min_rate = 455 with burst = 0.8 ceil = 256000
            mock_log.reset_mock()
            tc_lib.add_tc_policy_class(self.device[0], '1:', '1:10',
                                       max_kbps=2000, burst_kb=None,
                                       min_kbps=5, namespace=self.ns[0])
            min_rate = tc_lib._calc_min_rate(qos_consts.DEFAULT_BURST_RATE *
                                             2000 * 125)
            mock_log.warning.assert_called_once_with(
                *warning_args(5 * 125, min_rate))


class TcFiltersTestCase(functional_base.BaseSudoTestCase):

    def _remove_ns(self, namespace):
        priv_ip_lib.remove_netns(namespace)

    def _create_two_namespaces_connected_using_vxlan(self):
        """Create two namespaces connected with a veth pair and VXLAN

        ---------------------------------    ----------------------------------
        (ns1)                           |    |                            (ns2)
        int1: 10.0.100.1/24 <-----------|----|------------> int2: 10.0.100.2/24
          |                             |    |                              |
          |> int1_vxlan1: 10.0.200.1/24 |    |  int1_vxlan2: 10.0.200.2/24 <|
        ---------------------------------    ----------------------------------
        """
        self.vxlan_id = 100
        self.ns = ['ns1_' + uuidutils.generate_uuid(),
                   'ns2_' + uuidutils.generate_uuid()]
        self.device = ['int1', 'int2']
        self.device_vxlan = ['int_vxlan1', 'int_vxlan2']
        self.mac_vxlan = []
        self.ip = ['10.100.0.1/24', '10.100.0.2/24']
        self.ip_vxlan = ['10.200.0.1/24', '10.200.0.2/24']
        for i in range(len(self.ns)):
            priv_ip_lib.create_netns(self.ns[i])
            self.addCleanup(self._remove_ns, self.ns[i])
            ip_wrapper = ip_lib.IPWrapper(self.ns[i])
            if i == 0:
                ip_wrapper.add_veth(self.device[0], self.device[1], self.ns[1])
            ip_wrapper.add_vxlan(self.device_vxlan[i], self.vxlan_id,
                                 dev=self.device[i])
            ip_device = ip_lib.IPDevice(self.device[i], self.ns[i])
            ip_device.link.set_up()
            ip_device.addr.add(self.ip[i])
            ip_device_vxlan = ip_lib.IPDevice(self.device_vxlan[i], self.ns[i])
            self.mac_vxlan.append(ip_device_vxlan.link.address)
            ip_device_vxlan.link.set_up()
            ip_device_vxlan.addr.add(self.ip_vxlan[i])

        bridge_lib.FdbInterface.append(
            '00:00:00:00:00:00', self.device_vxlan[0], namespace=self.ns[0],
            ip_dst=str(netaddr.IPNetwork(self.ip[1]).ip))
        bridge_lib.FdbInterface.append(
            '00:00:00:00:00:00', self.device_vxlan[1], namespace=self.ns[1],
            ip_dst=str(netaddr.IPNetwork(self.ip[0]).ip))

    def test_add_tc_filter_vxlan(self):
        # The traffic control is applied on the veth pair device of the first
        # namespace (self.ns[0]). The traffic created from the VXLAN interface
        # when replying to the ping (sent from the other namespace), is
        # encapsulated in a VXLAN frame and goes through the veth pair
        # interface.
        self._create_two_namespaces_connected_using_vxlan()

        tc_lib.add_tc_qdisc(self.device[0], 'htb', parent='root', handle='1:',
                            namespace=self.ns[0])
        classes = tc_lib.list_tc_policy_class(self.device[0],
                                              namespace=self.ns[0])
        self.assertEqual(0, len(classes))

        class_ids = []
        for i in range(1, 10):
            class_id = '1:%s' % i
            class_ids.append(class_id)
            tc_lib.add_tc_policy_class(
                self.device[0], '1:', class_id, namespace=self.ns[0],
                min_kbps=1000, max_kbps=2000, burst_kb=1600)

        # Add a filter for a randomly chosen created class, in the first
        # namespace veth pair device, with the VXLAN MAC address. The traffic
        # from the VXLAN device must go through this chosen class.
        chosen_class_id = random.choice(class_ids)
        tc_lib.add_tc_filter_vxlan(
            self.device[0], '1:', chosen_class_id, self.mac_vxlan[0],
            self.vxlan_id, namespace=self.ns[0])

        tc_classes = tc_lib.list_tc_policy_class(self.device[0],
                                              namespace=self.ns[0])
        for tc_class in (c for c in tc_classes if
                         c['classid'] == chosen_class_id):
            bytes = tc_class['stats']['bytes']
            packets = tc_class['stats']['packets']
            break
        else:
            self.fail('TC class %(class_id)s is not present in the device '
                      '%(device)s' % {'class_id': chosen_class_id,
                                      'device': self.device[0]})

        net_helpers.assert_ping(
            self.ns[1], netaddr.IPNetwork(self.ip_vxlan[0]).ip, count=1)
        tc_classes = tc_lib.list_tc_policy_class(self.device[0],
                                                 namespace=self.ns[0])
        for tc_class in tc_classes:
            if tc_class['classid'] == chosen_class_id:
                self.assertGreater(tc_class['stats']['bytes'], bytes)
                self.assertGreater(tc_class['stats']['packets'], packets)
            else:
                self.assertEqual(0, tc_class['stats']['bytes'])
                self.assertEqual(0, tc_class['stats']['packets'])
