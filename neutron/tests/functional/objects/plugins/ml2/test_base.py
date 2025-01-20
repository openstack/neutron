# Copyright 2021 Red Hat, Inc.
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

import itertools

from neutron_lib import context

from neutron.tests.unit import testlib_api


class SegmentAllocation(testlib_api.SqlTestCase,
                        testlib_api.MySQLTestCaseMixin):

    PHYSNETS = ('phys1', 'phys2')
    NUM_SEGIDS = 10
    segment_allocation_class = None

    def setUp(self):
        if not self.segment_allocation_class:
            self.skipTest('No allocation class defined')
        super().setUp()
        self.context = context.Context(user_id='usier_id',
                                       project_id='tenant_id')
        self.segid_field = (
            self.segment_allocation_class.get_segmentation_id().name)
        self.is_vlan = ('physical_network' in
                        self.segment_allocation_class.db_model.primary_keys())
        pk_columns = self.segment_allocation_class.db_model.__table__.\
            primary_key.columns
        self.primary_keys = {col.name for col in pk_columns}
        self.segments = None

    def _create_segments(self, num_segids, physnets, allocated=False):

        if self.is_vlan:
            self.segments = list(itertools.product(physnets,
                                                   range(1, num_segids + 1)))
            kwargs_list = [
                {'physical_network': physnet,
                 self.segid_field: segid,
                 'allocated': allocated} for physnet, segid in self.segments]
        else:
            self.segments = list(range(1, num_segids + 1))
            kwargs_list = [{self.segid_field: segid,
                            'allocated': allocated} for segid in self.segments]

        for kwargs in kwargs_list:
            self.segment_allocation_class(self.context, **kwargs).create()

        self.assertTrue(
            len(kwargs_list),
            len(self.segment_allocation_class.get_objects(self.context)))

    def test_get_random_unallocated_segment_and_allocate(self):
        m_get = self.segment_allocation_class.get_random_unallocated_segment
        m_alloc = self.segment_allocation_class.allocate
        self._create_segments(self.NUM_SEGIDS, self.PHYSNETS)
        for _ in range(len(self.segments)):
            unalloc = m_get(self.context)
            segment = {k: unalloc[k] for k in self.primary_keys}
            m_alloc(self.context, **segment)
            if self.is_vlan:
                self.segments.remove((unalloc['physical_network'],
                                      unalloc.segmentation_id))
            else:
                self.segments.remove(unalloc.segmentation_id)

        self.assertEqual(0, len(self.segments))
        self.assertIsNone(m_get(self.context))
