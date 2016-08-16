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

BW_LIMIT = 100
BURST = 50
BW_MIN = 25
DIRECTION_EGRESS = 'egress'


class TcLibTestCase(functional_base.BaseSudoTestCase):

    def create_device(self, name):
        """Create a tuntap with the specified name.

        The device is cleaned up at the end of the test.
        """

        ip = ip_lib.IPWrapper()
        tap_device = ip.add_tuntap(name)
        self.addCleanup(tap_device.link.delete)
        tap_device.link.set_up()

    def test_bandwidth_limit(self):
        device_name = "tap_testmax"
        self.create_device(device_name)
        tc = tc_lib.TcCommand(device_name)

        tc.set_bw(BW_LIMIT, BURST, None, DIRECTION_EGRESS)
        bw_limit, burst, _ = tc.get_limits(DIRECTION_EGRESS)
        self.assertEqual(BW_LIMIT, bw_limit)
        self.assertEqual(BURST, burst)

        new_bw_limit = BW_LIMIT + 100
        new_burst = BURST + 50

        tc.set_bw(new_bw_limit, new_burst, None, DIRECTION_EGRESS)
        bw_limit, burst, _ = tc.get_limits(DIRECTION_EGRESS)
        self.assertEqual(new_bw_limit, bw_limit)
        self.assertEqual(new_burst, burst)

        tc.delete_bw(DIRECTION_EGRESS)
        bw_limit, burst, _ = tc.get_limits(DIRECTION_EGRESS)
        self.assertIsNone(bw_limit)
        self.assertIsNone(burst)

    def test_minimum_bandwidth(self):
        device_name = "tap_testmin"
        self.create_device(device_name)
        tc = tc_lib.TcCommand(device_name)

        tc.set_bw(None, None, BW_MIN, DIRECTION_EGRESS)
        _, _, bw_min = tc.get_limits(DIRECTION_EGRESS)
        self.assertEqual(BW_MIN, bw_min)

        new_bw_min = BW_MIN + 50

        tc.set_bw(None, None, new_bw_min, DIRECTION_EGRESS)
        _, _, bw_min = tc.get_limits(DIRECTION_EGRESS)
        self.assertEqual(new_bw_min, bw_min)

        tc.delete_bw(DIRECTION_EGRESS)
        _, _, bw_min = tc.get_limits(DIRECTION_EGRESS)
        self.assertIsNone(bw_min)
