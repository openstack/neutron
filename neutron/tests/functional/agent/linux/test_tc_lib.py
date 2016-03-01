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

from oslo_log import log as logging

from neutron.agent.linux import ip_lib
from neutron.agent.linux import tc_lib
from neutron.tests.functional import base as functional_base

LOG = logging.getLogger(__name__)

TEST_HZ_VALUE = 250
LATENCY = 50
BW_LIMIT = 1024
BURST = 512

DEV_NAME = "test_tap"
MAC_ADDRESS = "fa:16:3e:01:01:01"


class TcLibTestCase(functional_base.BaseSudoTestCase):

    def setUp(self):
        super(TcLibTestCase, self).setUp()
        self.create_device()
        self.tc = tc_lib.TcCommand(DEV_NAME, TEST_HZ_VALUE)

    def create_device(self):
        """Create a tuntap with the specified attributes.

        The device is cleaned up at the end of the test.
        """

        ip = ip_lib.IPWrapper()
        tap_device = ip.add_tuntap(DEV_NAME)
        self.addCleanup(tap_device.link.delete)
        tap_device.link.set_address(MAC_ADDRESS)
        tap_device.link.set_up()

    def test_bandwidth_limit(self):
        self.tc.set_bw_limit(BW_LIMIT, BURST, LATENCY)
        bw_limit, burst = self.tc.get_bw_limits()
        self.assertEqual(BW_LIMIT, bw_limit)
        self.assertEqual(BURST, burst)

        new_bw_limit = BW_LIMIT + 500
        new_burst = BURST + 50

        self.tc.update_bw_limit(new_bw_limit, new_burst, LATENCY)
        bw_limit, burst = self.tc.get_bw_limits()
        self.assertEqual(new_bw_limit, bw_limit)
        self.assertEqual(new_burst, burst)

        self.tc.delete_bw_limit()
        bw_limit, burst = self.tc.get_bw_limits()
        self.assertIsNone(bw_limit)
        self.assertIsNone(burst)
