# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Nicira Networks, Inc.
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

import unittest
from ovs_quantum_plugin import VlanMap


class VlanMapTest(unittest.TestCase):

    def setUp(self):
        self.vmap = VlanMap()

    def tearDown(self):
        pass

    def testAddVlan(self):
        vlan_id = self.vmap.acquire("foobar")
        self.assertTrue(vlan_id == 2)

    def testReleaseVlan(self):
        vlan_id = self.vmap.acquire("foobar")
        self.vmap.release("foobar")
        self.assertTrue(self.vmap.get(vlan_id) is None)

    def testAddRelease4kVlans(self):
        vlan_id = None
        for id in range(2, 4000):
            vlan_id = self.vmap.acquire(id)
            self.assertTrue(vlan_id == id)
        for id in range(2, 4000):
            self.vmap.release(id)
            self.assertTrue(self.vmap.get(id) is None)
