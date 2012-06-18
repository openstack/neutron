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

from quantum.plugins.openvswitch.ovs_quantum_plugin import (
    NoFreeVLANException,
    VlanMap,
)


class VlanMapTest(unittest.TestCase):

    def setUp(self):
        self.vmap = VlanMap()

    def tearDown(self):
        pass

    def testAddVlan(self):
        vlan_id = self.vmap.acquire("foobar")
        self.assertTrue(vlan_id >= self.vmap.vlan_min)
        self.assertTrue(vlan_id <= self.vmap.vlan_max)

    def testReleaseVlan(self):
        vlan_id = self.vmap.acquire("foobar")
        self.vmap.release("foobar")

    def testAddRelease4kVlans(self):
        vlan_id = None
        num_vlans = self.vmap.vlan_max - self.vmap.vlan_min
        for id in xrange(num_vlans):
            vlan_id = self.vmap.acquire("net-%s" % id)
            self.assertTrue(vlan_id >= self.vmap.vlan_min)
            self.assertTrue(vlan_id <= self.vmap.vlan_max)
        for id in xrange(num_vlans):
            self.vmap.release("net-%s" % id)

    def testAlreadyUsed(self):
        existing_vlan = 2
        self.vmap.already_used(existing_vlan, "net1")
        try:
            # this value is high enough that we will exhaust
            # all VLANs.  We want to make sure 'existing_vlan'
            # is never reallocated.
            num_vlans = self.vmap.vlan_max - self.vmap.vlan_min + 1
            for x in xrange(num_vlans):
                vlan_id = self.vmap.acquire("net-%x" % x)
                self.assertTrue(vlan_id != existing_vlan)

            self.fail("Did not run out of VLANs as expected")
        except NoFreeVLANException:
            pass  # Expected exit
