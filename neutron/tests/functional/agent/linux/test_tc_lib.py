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

from neutron.agent.linux import ip_lib
from neutron.agent.linux import tc_lib
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
