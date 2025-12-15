# Copyright 2025 Red Hat, Inc.
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

from neutron.services.bgp import helpers
from neutron.tests import base


class GetMacAddressFromLrpNameTestCase(base.BaseTestCase):
    def test_get_mac_address_from_lrp_name_unique(self):
        num_macs = 1000
        macs = set()
        for i in range(num_macs):
            lrp_name = f'test-lrp-{i}'
            mac = helpers.get_mac_address_from_lrp_name(lrp_name)
            try:
                netaddr.EUI(mac, version=48)
            except netaddr.AddrFormatError as e:
                self.fail(f"Invalid MAC address generated: {mac}, error: {e}")
            macs.add(mac)

        self.assertEqual(num_macs, len(macs))

    def test_get_mac_address_from_lrp_name_consistent(self):
        lrp_name = 'test-lrp-1'
        mac1 = helpers.get_mac_address_from_lrp_name(lrp_name)
        mac2 = helpers.get_mac_address_from_lrp_name(lrp_name)
        self.assertEqual(mac1, mac2)
