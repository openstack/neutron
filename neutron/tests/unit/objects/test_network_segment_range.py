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

import random

import mock
from neutron_lib import constants
from neutron_lib.utils import helpers
from oslo_utils import uuidutils

from neutron.objects import network as net_obj
from neutron.objects import network_segment_range
from neutron.objects.plugins.ml2 import vlanallocation as vlan_alloc_obj
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api

TEST_TENANT_ID = '46f70361-ba71-4bd0-9769-3573fd227c4b'
TEST_PHYSICAL_NETWORK = 'phys_net'


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
        # tests like `test_extra_fields`, `test_create_updates_from_db_object`,
        # `test_update_updates_from_db_object` can have those fields.
        # Alternatives can be skipping those tests when executing
        # NetworkSegmentRangeIfaceObjectTestCase, or making base test case
        # adjustments.
        self.update_obj_fields({'project_id': TEST_TENANT_ID,
                                'physical_network': TEST_PHYSICAL_NETWORK})


class NetworkSegmentRangeDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                          testlib_api.SqlTestCase):

    _test_class = network_segment_range.NetworkSegmentRange

    def _create_test_vlan_allocation(self, vlan_id=None, allocated=False):
        attr = self.get_random_object_fields(vlan_alloc_obj.VlanAllocation)
        attr.update({
            'vlan_id': vlan_id or random.randint(
                constants.MIN_VLAN_TAG, constants.MAX_VLAN_TAG),
            'physical_network': 'foo',
            'allocated': allocated})
        _vlan_allocation = vlan_alloc_obj.VlanAllocation(self.context, **attr)
        _vlan_allocation.create()
        return _vlan_allocation

    def _create_test_network(self, name=None, network_id=None):
        name = "test-network-%s" % helpers.get_random_string(4)
        network_id = (uuidutils.generate_uuid() if network_id is None
                      else network_id)
        _network = net_obj.Network(self.context, name=name, id=network_id,
                                   project_id=uuidutils.generate_uuid())
        _network.create()
        return _network

    def _create_test_vlan_segment(self, segmentation_id=None, network_id=None):
        attr = self.get_random_object_fields(net_obj.NetworkSegment)
        attr.update({
            'network_id': network_id or self._create_test_network_id(),
            'network_type': constants.TYPE_VLAN,
            'physical_network': 'foo',
            'segmentation_id': segmentation_id or random.randint(
                constants.MIN_VLAN_TAG, constants.MAX_VLAN_TAG)})
        _segment = net_obj.NetworkSegment(self.context, **attr)
        _segment.create()
        return _segment

    def _create_test_vlan_network_segment_range_obj(self, minimum, maximum):
        kwargs = self.get_random_db_fields()
        kwargs.update({'network_type': constants.TYPE_VLAN,
                       'physical_network': 'foo',
                       'minimum': minimum,
                       'maximum': maximum})
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
            self._create_test_vlan_allocation(vlan_id=vlan_id, allocated=True)
        for vlan_id in not_to_alloc:
            self._create_test_vlan_allocation(vlan_id=vlan_id, allocated=False)
        obj = self._create_test_vlan_network_segment_range_obj(range_minimum,
                                                               range_maximum)
        available_alloc = self._test_class._get_available_allocation(obj)
        self.assertItemsEqual(not_to_alloc, available_alloc)

    def test__get_used_allocation_mapping(self):
        alloc_mapping = {}
        for _ in range(5):
            network = self._create_test_network()
            segment = self._create_test_vlan_segment(network_id=network.id)
            alloc_mapping.update({segment.segmentation_id: network.project_id})

        obj = self._create_test_vlan_network_segment_range_obj(
            minimum=min(list(alloc_mapping.keys())),
            maximum=max(list(alloc_mapping.keys())))
        ret_alloc_mapping = self._test_class._get_used_allocation_mapping(obj)
        self.assertDictEqual(alloc_mapping, ret_alloc_mapping)
