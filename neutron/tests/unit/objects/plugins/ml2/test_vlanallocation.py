# Copyright (c) 2016 Intel Corporation.
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

from neutron.objects.plugins.ml2 import vlanallocation
from neutron.tests.unit.objects.plugins.ml2 import test_base as ml2_test_base
from neutron.tests.unit.objects import test_base
from neutron.tests.unit import testlib_api


class VlanAllocationIfaceObjTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = vlanallocation.VlanAllocation


class VlanAllocationDbObjTestCase(
        test_base.BaseDbObjectTestCase, testlib_api.SqlTestCase,
        ml2_test_base.SegmentAllocationDbObjTestCase):

    _test_class = vlanallocation.VlanAllocation

    def test_delete_physical_networks_keeps_allocated(self):
        for vlan_id, allocated in ((100, False), (101, True)):
            vlanallocation.VlanAllocation(
                self.context, physical_network='physnet1', vlan_id=vlan_id,
                allocated=allocated).create()
        vlanallocation.VlanAllocation(
            self.context, physical_network='physnet2', vlan_id=100,
            allocated=False).create()

        vlanallocation.VlanAllocation.delete_physical_networks(
            self.context, ['physnet1'])

        remaining = {(alloc.physical_network, alloc.vlan_id)
                     for alloc in vlanallocation.VlanAllocation.get_objects(
                         self.context)}
        # the unallocated physnet1 register is gone, the allocated one is
        # kept, and other physical networks are untouched
        self.assertEqual({('physnet1', 101), ('physnet2', 100)}, remaining)
