# Copyright 2014 NEC Corporation.  All rights reserved.
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

from neutron.plugins.nec.common import utils
from neutron.tests import base


class NecUtilsTest(base.BaseTestCase):

    def test_cmp_dpid(self):
        self.assertTrue(utils.cmp_dpid('0xabcd', '0xabcd'))
        self.assertTrue(utils.cmp_dpid('abcd', '0xabcd'))
        self.assertTrue(utils.cmp_dpid('0x000000000000abcd', '0xabcd'))
        self.assertTrue(utils.cmp_dpid('0x000000000000abcd', '0x00abcd'))
        self.assertFalse(utils.cmp_dpid('0x000000000000abcd', '0xabc0'))
        self.assertFalse(utils.cmp_dpid('0x000000000000abcd', '0x00abc0'))

    def test_cmp_dpid_with_exception(self):
        self.assertFalse(utils.cmp_dpid('0xabcx', '0xabcx'))
        self.assertFalse(utils.cmp_dpid(None, None))
