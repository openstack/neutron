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
from unittest import mock

from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from neutron_lib.objects import exceptions as obj_exc
from neutron_lib.utils import helpers
from oslo_utils import timeutils
from oslo_utils import uuidutils

from neutron.common import utils as n_utils
from neutron.objects import network as net_obj
from neutron.objects import network_segment_range
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api

TEST_PROJECT_ID = '46f70361-ba71-4bd0-9769-3573fd227c4b'
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
        super().setUp()
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
        self.update_obj_fields({'project_id': TEST_PROJECT_ID,
                                'physical_network': TEST_PHYSICAL_NETWORK})
        self.extra_fields_not_in_dict = ['tenant_id']


class NetworkSegmentRangeDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                          testlib_api.SqlTestCase):

    _test_class = network_segment_range.NetworkSegmentRange

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
            'network_id': network_id or self._create_test_network().id,
            'network_type': network_type or constants.TYPE_VLAN,
            'physical_network': physical_network or 'foo',
            'segmentation_id': segmentation_id or random.randint(
                constants.MIN_VLAN_TAG, constants.MAX_VLAN_TAG)})
        _segment = net_obj.NetworkSegment(self.context, **attr)
        _segment.create()
        return _segment

    def _create_network_segment_range(
            self, minimum, maximum, network_type=None, physical_network=None,
            project_id=None, default=False, shared=False, start_time=None):
        kwargs = self.get_random_db_fields()
        created_at = (n_utils.ts_to_datetime(start_time) if start_time else
                      timeutils.utcnow())
        kwargs.update({'network_type': network_type or constants.TYPE_VLAN,
                       'physical_network': physical_network or 'foo',
                       'minimum': minimum,
                       'maximum': maximum,
                       'default': default,
                       'shared': shared,
                       'project_id': project_id,
                       'created_at': created_at,
                       })
        db_obj = self._test_class.db_model(**kwargs)
        obj_fields = self._test_class.modify_fields_from_db(db_obj)
        obj = self._test_class(self.context, **obj_fields)
        return obj

    def test__get_available_allocation(self):
        range_minimum = 100
        range_maximum = 120
        used_ids = range(range_minimum, range_maximum - 5)
        free_ids = range(range_maximum - 5, range_maximum + 1)
        for vlan_id in used_ids:
            self._create_segment(segmentation_id=vlan_id,
                                 physical_network='foo')
        obj = self._create_network_segment_range(range_minimum, range_maximum)
        available_alloc = self._test_class._get_available_allocation(obj)
        self.assertCountEqual(free_ids, available_alloc)

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

    def test_delete_expired_default_network_segment_ranges(self):
        start_time = n_utils.datetime_to_ts(timeutils.utcnow())
        num_ranges = 5
        for network_type in network_segment_range.SEGMENT_RANGE_TYPES:
            for idx in range(num_ranges):
                try:
                    obj = self._create_network_segment_range(
                        1, 10, network_type=network_type, default=True,
                        shared=True, start_time=start_time - idx)
                    obj.create()
                except obj_exc.NeutronDbObjectDuplicateEntry:
                    pass
            ranges = network_segment_range.NetworkSegmentRange.get_objects(
                self.context, default=True, shared=True,
                network_type=network_type)
            # No duplicated entry in DB at all
            self.assertEqual(1, len(ranges))

    def test_new_default(self):
        start_time = n_utils.datetime_to_ts(timeutils.utcnow())
        for network_type in network_segment_range.SEGMENT_RANGE_TYPES:
            physical_network = ('foo' if network_type == constants.TYPE_VLAN
                                else '')
            ranges = network_segment_range.NetworkSegmentRange.get_objects(
                self.context, network_type=network_type)
            self.assertEqual(0, len(ranges))

            # The method "new_default" is idempotent, call it twice.
            for _ in range(2):
                network_segment_range.NetworkSegmentRange.new_default(
                    self.context, network_type, physical_network,
                    1, 10, start_time)
                ranges = network_segment_range.NetworkSegmentRange.get_objects(
                    self.context, network_type=network_type)
                self.assertEqual(1, len(ranges))
