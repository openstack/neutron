# Copyright (c) 2013 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
Test vlans alloc/dealloc.
"""

from neutron import context as n_context
from neutron.plugins.brocade import vlanbm as vlan_bitmap
from neutron.tests.unit import testlib_api


class TestVlanBitmap(testlib_api.SqlTestCase):
    """exercise Vlan bitmap ."""

    def setUp(self):
        super(TestVlanBitmap, self).setUp()
        self.context = n_context.get_admin_context()

    def test_vlan(self):
        """test vlan allocation/de-alloc."""

        self.vbm_ = vlan_bitmap.VlanBitmap(self.context)
        vlan_id = self.vbm_.get_next_vlan(None)

        # First vlan is always 2
        self.assertEqual(vlan_id, 2)

        # next vlan is always 3
        vlan_id = self.vbm_.get_next_vlan(None)
        self.assertEqual(vlan_id, 3)

        # get a specific vlan i.e. 4
        vlan_id = self.vbm_.get_next_vlan(4)
        self.assertEqual(vlan_id, 4)

        # get a specific vlan i.e. 5
        vlan_id = self.vbm_.get_next_vlan(5)
        self.assertEqual(vlan_id, 5)

        # Skip 6

        # get a specific vlan i.e. 7
        vlan_id = self.vbm_.get_next_vlan(7)
        self.assertEqual(vlan_id, 7)

        # get a specific vlan i.e. 1900
        vlan_id = self.vbm_.get_next_vlan(1900)
        self.assertEqual(vlan_id, 1900)

        # Release 4 and get next again
        self.vbm_.release_vlan(4)
        vlan_id = self.vbm_.get_next_vlan(None)
        self.assertEqual(vlan_id, 4)
