# Copyright (c) 2019 Intel Corporation.
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
import random
from unittest import mock

from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from neutron_lib.utils import helpers
from oslo_utils import uuidutils

from neutron.objects import network as net_obj
from neutron.objects import network_segment_range
from neutron.objects.plugins.ml2 import base as ml2_base
from neutron.objects.plugins.ml2 import vlanallocation as vlan_alloc_obj
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api

TEST_TENANT_ID = '46f70361-ba71-4bd0-9769-3573fd227c4b'
TEST_PHYSICAL_NETWORK = 'phys_net'
NUM_ALLOCATIONS = 3


class NetworkSegmentRangeIfaceObjectTestCase(
      obj_test_base.BaseObjectIfaceTestCase):

    _test_class = network_segment_range.NetworkSegmentRange

    def setUp(self):
        self._mock_get_available_allocation = mock.patch.object(
            network_segment_range.NetworkSegmentRange,
            '_get_available_allocation',
            return_value=[])
        self.mock_get_available_allocation = (
            self._mock_get_available_allocation.start())
        self._mock_get_used_allocation_mapping = mock.patch.object(
            network_segment_range.NetworkSegmentRange,
            '_get_used_allocation_mapping',
            return_value={})
        self.mock_get_used_allocation_mapping = (
            self._mock_get_used_allocation_mapping.start())
        super(NetworkSegmentRangeIfaceObjectTestCase, self).setUp()
        # `project_id` and `physical_network` attributes in
        # network_segment_range are nullable, depending on the value of
        # `shared` and `network_type` respectively.
        # Hack to always populate test project_id and physical_network
        # fields in network segment range Iface object testing so that related
        # tests like `test_create_updates_from_db_object` and
        # `test_update_updates_from_db_object` can have those fields.
        # Alternatives can be skipping those tests when executing
        # NetworkSegmentRangeIfaceObjectTestCase, or making base test case
        # adjustments.
        self.update_obj_fields({'project_id': TEST_TENANT_ID,
                                'physical_network': TEST_PHYSICAL_NETWORK})
        self.extra_fields_not_in_dict = ['tenant_id']


class NetworkSegmentRangeDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                          testlib_api.SqlTestCase):

    _test_class = network_segment_range.NetworkSegmentRange

    def _create_allocation(self, allocation_class, segmentation_id=None,
                           physical_network=None, allocated=False):
        attr = self.get_random_object_fields(allocation_class)
        attr['allocated'] = allocated
        allocation_class.update_primary_keys(
            attr, segmentation_id=segmentation_id,
            physical_network=physical_network or 'foo')
        allocation = allocation_class(self.context, **attr)
        allocation.create()
        return allocation

    def _create_test_network(self, name=None, network_id=None):
        name = "test-network-%s" % helpers.get_random_string(4)
        network_id = (uuidutils.generate_uuid() if network_id is None
                      else network_id)
        _network = net_obj.Network(self.context, name=name, id=network_id,
                                   project_id=uuidutils.generate_uuid())
        _network.create()
        return _network

    def _create_segment(self, segmentation_id=None, network_id=None,
                        physical_network=None, network_type=None):
        attr = self.get_random_object_fields(net_obj.NetworkSegment)
        attr.update({
            'network_id': network_id or self._create_test_network_id(),
            'network_type': network_type or constants.TYPE_VLAN,
            'physical_network': physical_network or 'foo',
            'segmentation_id': segmentation_id or random.randint(
                constants.MIN_VLAN_TAG, constants.MAX_VLAN_TAG)})
        _segment = net_obj.NetworkSegment(self.context, **attr)
        _segment.create()
        return _segment

    def _create_network_segment_range(
            self, minimum, maximum, network_type=None, physical_network=None,
            project_id=None, default=False, shared=False):
        kwargs = self.get_random_db_fields()
        kwargs.update({'network_type': network_type or constants.TYPE_VLAN,
                       'physical_network': physical_network or 'foo',
                       'minimum': minimum,
                       'maximum': maximum,
                       'default': default,
                       'shared': shared,
                       'project_id': project_id})
        db_obj = self._test_class.db_model(**kwargs)
        obj_fields = self._test_class.modify_fields_from_db(db_obj)
        obj = self._test_class(self.context, **obj_fields)
        return obj

    def test__get_available_allocation(self):
        range_minimum = 100
        range_maximum = 120
        to_alloc = range(range_minimum, range_maximum - 5)
        not_to_alloc = range(range_maximum - 5, range_maximum + 1)
        for vlan_id in to_alloc:
            self._create_allocation(vlan_alloc_obj.VlanAllocation,
                                    segmentation_id=vlan_id, allocated=True,
                                    physical_network='foo')
        for vlan_id in not_to_alloc:
            self._create_allocation(vlan_alloc_obj.VlanAllocation,
                                    segmentation_id=vlan_id, allocated=False,
                                    physical_network='foo')
        obj = self._create_network_segment_range(range_minimum, range_maximum)
        available_alloc = self._test_class._get_available_allocation(obj)
        self.assertItemsEqual(not_to_alloc, available_alloc)

    def test__get_used_allocation_mapping(self):
        alloc_mapping = {}
        for _ in range(5):
            network = self._create_test_network()
            segment = self._create_segment(network_id=network.id)
            alloc_mapping.update({segment.segmentation_id: network.project_id})

        obj = self._create_network_segment_range(
            minimum=min(list(alloc_mapping.keys())),
            maximum=max(list(alloc_mapping.keys())))
        ret_alloc_mapping = self._test_class._get_used_allocation_mapping(obj)
        self.assertDictEqual(alloc_mapping, ret_alloc_mapping)

    def _define_network_segment_range(self, shared=False,
                                      remove_project_id=False):
        attrs = self.get_random_object_fields(obj_cls=self._test_class)
        obj = self._test_class(self.context, **attrs)
        obj.shared = shared
        obj.project_id = None if remove_project_id else obj.project_id
        return obj

    def test_create_not_shared_with_project_id(self):
        obj = self._define_network_segment_range()
        obj.create()

    def test_create_not_shared_without_project_id(self):
        obj = self._define_network_segment_range(remove_project_id=True)
        self.assertRaises(n_exc.ObjectActionError, obj.create)

    def test_update_not_shared_with_project_id(self):
        obj = self._define_network_segment_range(shared=True)
        obj.create()
        obj.shared = False
        obj.update()

    def test_update_not_shared_without_project_id(self):
        obj = self._define_network_segment_range(shared=True,
                                                 remove_project_id=True)
        obj.create()
        obj.shared = False
        self.assertRaises(n_exc.ObjectActionError, obj.update)

    def _create_vlan_environment_with_multiple_phynet(
            self, physical_networks, project_id):
        for phynet_name, vlan_range in physical_networks.items():
            self._create_network_segment_range(
                    vlan_range[0], vlan_range[1],
                    network_type=constants.TYPE_VLAN,
                    project_id=project_id,
                    physical_network=phynet_name,
                    default=True, shared=True).create()

            for segmentation_id in range(2, 4):
                self._create_allocation(
                    vlan_alloc_obj.VlanAllocation,
                    segmentation_id=segmentation_id,
                    physical_network=phynet_name)

    def _create_environment(self, default_range=True):
        self.projects = [uuidutils.generate_uuid() for _ in range(3)]
        self.segment_ranges = {
            'default': [100, 120], self.projects[0]: [90, 105],
            self.projects[1]: [109, 114], self.projects[2]: [117, 130]}
        self.seg_min = self.segment_ranges['default'][0]
        self.seg_max = self.segment_ranges['default'][1]

        for subclass in ml2_base.SegmentAllocation.__subclasses__():
            # Build segment ranges: default one and project specific ones.
            for name, ranges in self.segment_ranges.items():
                default = True if name == 'default' else False
                project = name if not default else None
                if default and not default_range:
                    continue

                self._create_network_segment_range(
                    ranges[0], ranges[1], network_type=subclass.network_type,
                    project_id=project, default=default,
                    shared=default).create()

            # Build allocations (non allocated).
            for segmentation_id in range(self.seg_min, self.seg_max + 1):
                self._create_allocation(subclass,
                                        segmentation_id=segmentation_id)

    def _create_shared_ranges(self):
        self.shared_ranges = {0: [100, 105], 1: [110, 115]}
        self.shared_ids = set(itertools.chain.from_iterable(
            list(range(r[0], r[1] + 1)) for r in self.shared_ranges.values()))
        for shared_range, subclass in itertools.product(
                self.shared_ranges.values(),
                ml2_base.SegmentAllocation.__subclasses__()):
            self._create_network_segment_range(
                shared_range[0], shared_range[1],
                network_type=subclass.network_type, default=False,
                shared=True).create()

    def _default_range_set(self, project_id=None):
        range_set = set(range(self.segment_ranges['default'][0],
                              self.segment_ranges['default'][1] + 1))
        for p_id, ranges in ((p, r) for (p, r) in self.segment_ranges.items()
                             if p not in [project_id, 'default']):
            pranges = self.segment_ranges.get(p_id, [0, 0])
            prange_set = set(range(pranges[0], pranges[1] + 1))
            range_set.difference_update(prange_set)
        return range_set

    def _allocate_random_allocations(self, allocations, subclass,
                                     num_of_allocations=None):
        pk_cols = subclass.db_model.__table__.primary_key.columns
        primary_keys = [col.name for col in pk_cols]
        allocated = []
        for allocation in random.sample(
                allocations, k=(num_of_allocations or NUM_ALLOCATIONS)):
            segment = dict((k, allocation[k]) for k in primary_keys)
            allocated.append(segment)
            self.assertEqual(1, subclass.allocate(self.context, **segment))
        return allocated

    def test_get_segments_for_project(self):
        self._create_environment()
        for project_id, subclass in itertools.product(
                self.projects, ml2_base.SegmentAllocation.__subclasses__()):
            allocations = network_segment_range.NetworkSegmentRange. \
                get_segments_for_project(
                    self.context, subclass.db_model, subclass.network_type,
                    subclass.get_segmentation_id(), project_id=project_id)
            project_min = max(self.seg_min, self.segment_ranges[project_id][0])
            project_max = min(self.seg_max, self.segment_ranges[project_id][1])
            project_segment_ids = list(range(project_min, project_max + 1))
            self.assertEqual(len(allocations), len(project_segment_ids))
            for allocation in allocations:
                self.assertFalse(allocation.allocated)
                self.assertIn(allocation.segmentation_id, project_segment_ids)

            # Allocate random segments inside the project range.
            self._allocate_random_allocations(allocations, subclass)
            allocations = network_segment_range.NetworkSegmentRange. \
                get_segments_for_project(
                    self.context, subclass.db_model, subclass.network_type,
                    subclass.get_segmentation_id(), project_id=project_id)
            self.assertEqual(len(allocations),
                             len(project_segment_ids) - NUM_ALLOCATIONS)

    def test_get_segments_shared(self):
        self._create_environment()
        self.projects.append(None)
        for project_id, subclass in itertools.product(
                self.projects, ml2_base.SegmentAllocation.__subclasses__()):
            filters = {'project_id': project_id,
                       'physical_network': 'foo'}
            allocations = network_segment_range.NetworkSegmentRange. \
                get_segments_shared(
                    self.context, subclass.db_model, subclass.network_type,
                    subclass.get_segmentation_id(), **filters)

            prange = self._default_range_set(project_id)
            self.assertEqual(len(prange), len(allocations))

            # Allocate random segments inside the project shared range.
            allocated = self._allocate_random_allocations(allocations,
                                                          subclass)
            allocations = network_segment_range.NetworkSegmentRange. \
                get_segments_shared(
                    self.context, subclass.db_model, subclass.network_type,
                    subclass.get_segmentation_id(), **filters)
            self.assertEqual(len(allocations), len(prange) - NUM_ALLOCATIONS)

            # Deallocate the allocated segments because can be allocated in
            # a segmentation ID not belonging to any project.
            for alloc in allocated:
                self.assertEqual(1, subclass.deallocate(self.context, **alloc))

    def test_get_segments_shared_without_physical_network_for_vlan(self):
        phynet1_vlan_range = [2, 3]
        phynet1_vlan_size = phynet1_vlan_range[1] - phynet1_vlan_range[0] + 1
        phynet2_vlan_range = [8, 9]
        phynet2_vlan_size = phynet2_vlan_range[1] - phynet2_vlan_range[0] + 1
        phynets = {'phynet1': phynet1_vlan_range,
                   'phynet2': phynet2_vlan_range}
        project_id = uuidutils.generate_uuid()
        self._create_vlan_environment_with_multiple_phynet(
            phynets, project_id)
        all_vlan_size = phynet1_vlan_size + phynet2_vlan_size
        filters = {'project_id': project_id}

        # First allocation, the phynet1's vlan id will be exhausted.
        allocations = network_segment_range.NetworkSegmentRange. \
            get_segments_shared(
                self.context, vlan_alloc_obj.VlanAllocation.db_model,
                constants.TYPE_VLAN,
                vlan_alloc_obj.VlanAllocation.get_segmentation_id(),
                **filters)
        self.assertEqual(all_vlan_size, len(allocations))
        alloc_phynet = []
        for alloc in allocations:
            alloc_phynet.append(alloc.physical_network)
        alloc_phynet = set(alloc_phynet)
        self.assertEqual(2, len(alloc_phynet))
        allocated = self._allocate_random_allocations(
            allocations, vlan_alloc_obj.VlanAllocation)
        remain_vlan_size = all_vlan_size - len(allocated)

        # Second allocation, all vlan id will be exhausted.
        allocations = network_segment_range.NetworkSegmentRange. \
            get_segments_shared(
                self.context, vlan_alloc_obj.VlanAllocation.db_model,
                constants.TYPE_VLAN,
                vlan_alloc_obj.VlanAllocation.get_segmentation_id(),
                **filters)
        self.assertEqual(len(allocations), all_vlan_size - NUM_ALLOCATIONS)
        self._allocate_random_allocations(allocations,
                                          vlan_alloc_obj.VlanAllocation,
                                          remain_vlan_size)
        alloc_phynet = []
        for alloc in allocations:
            alloc_phynet.append(alloc.physical_network)
        alloc_phynet = set(alloc_phynet)
        self.assertEqual(1, len(alloc_phynet))

        # Last allocation, we can't get any vlan segment.
        allocations = network_segment_range.NetworkSegmentRange. \
            get_segments_shared(
                self.context, vlan_alloc_obj.VlanAllocation.db_model,
                constants.TYPE_VLAN,
                vlan_alloc_obj.VlanAllocation.get_segmentation_id(),
                **filters)
        self.assertEqual(0, len(allocations))

    def test_get_segments_shared_no_shared_ranges(self):
        self._create_environment(default_range=False)
        for project_id, subclass in itertools.product(
                self.projects, ml2_base.SegmentAllocation.__subclasses__()):
            filters = {'project_id': project_id,
                       'physical_network': 'foo'}
            allocations = network_segment_range.NetworkSegmentRange. \
                get_segments_shared(
                    self.context, subclass.db_model, subclass.network_type,
                    subclass.get_segmentation_id(), **filters)

            self.assertEqual([], allocations)

    def test_get_segments_shared_no_default_range_two_shared_ranges(self):
        self._create_environment(default_range=False)
        self.projects.append(None)
        self._create_shared_ranges()
        for project_id, subclass in itertools.product(
                self.projects, ml2_base.SegmentAllocation.__subclasses__()):

            filters = {'project_id': project_id,
                       'physical_network': 'foo'}
            allocations = network_segment_range.NetworkSegmentRange. \
                get_segments_shared(
                    self.context, subclass.db_model, subclass.network_type,
                    subclass.get_segmentation_id(), **filters)

            prange = self._default_range_set(project_id)
            available_ids = prange & self.shared_ids
            self.assertEqual(len(available_ids), len(allocations))
            for alloc in allocations:
                self.assertIn(alloc.segmentation_id, available_ids)
