# Copyright (c) 2016 Intel Corporation.  All rights reserved.
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

import datetime

from neutron_lib.db import api as db_api
from oslo_utils import uuidutils

from neutron.objects import quota
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api


class ResourceDeltaObjectIfaceTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = quota.ResourceDelta


class ResourceDeltaDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                    testlib_api.SqlTestCase):

    _test_class = quota.ResourceDelta

    def setUp(self):
        super(ResourceDeltaDbObjectTestCase, self).setUp()
        for obj in self.obj_fields:
            self._create_test_reservation(res_id=obj['reservation_id'])

    def _create_test_reservation(self, res_id):
        self._reservation = quota.Reservation(self.context, id=res_id)
        self._reservation.create()


class ReservationObjectIfaceTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = quota.Reservation


class ReservationDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                  testlib_api.SqlTestCase):

    _test_class = quota.Reservation

    def _create_test_reservation(self, res=None, exp=None):
        res_id = uuidutils.generate_uuid()
        reservation = self._test_class(self.context,
            id=res_id, resource=res, expiration=exp)
        reservation.create()
        return reservation

    def test_delete_expired(self):
        dt = datetime.datetime.utcnow()
        resources = {'goals': 2, 'assists': 1}
        exp_date1 = datetime.datetime(2016, 3, 31, 14, 30)
        exp_date2 = datetime.datetime(2015, 3, 31, 14, 30)
        with db_api.CONTEXT_WRITER.using(self.context):
            res1 = self._create_test_reservation(resources, exp_date1)
            res2 = self._create_test_reservation(resources, exp_date2)
        with db_api.CONTEXT_WRITER.using(self.context):
            self.assertEqual(2, self._test_class.delete_expired(
                self.context, dt, None))
        with db_api.CONTEXT_READER.using(self.context):
            objs = self._test_class.get_objects(self.context,
                id=[res1.id, res2.id])
        self.assertEqual([], objs)

    def test_reservation_synthetic_field(self):
        res = self._create_test_reservation()
        resource = 'test-res'
        res_delta = quota.ResourceDelta(self.context,
            resource=resource, reservation_id=res.id, amount='10')
        res_delta.create()
        obj = self._test_class.get_object(self.context, id=res.id)
        self.assertEqual(res_delta, obj.resource_deltas[0])
        res_delta.delete()
        obj.update()
        # NOTE(manjeets) update on reservation should reflect
        # changes on synthetic field when it is deleted.
        obj = self._test_class.get_object(self.context, id=res.id)
        self.assertEqual([], obj.resource_deltas)


class QuotaObjectIfaceTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = quota.Quota


class QuotaDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                            testlib_api.SqlTestCase):

    _test_class = quota.Quota


class QuotaUsageObjectIfaceTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = quota.QuotaUsage


class QuotaUsageDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                                 testlib_api.SqlTestCase):

    _test_class = quota.QuotaUsage

    def _test_get_object_dirty_protected(self, obj, dirty=True):
        obj.create()
        obj.dirty = dirty
        obj.update()
        new = self._test_class.get_object_dirty_protected(
            self.context,
            **obj._get_composite_keys())
        self.assertEqual(obj, new)
        self.assertEqual(dirty, new.dirty)

    def test_get_object_dirty_protected(self):
        obj = self._make_object(self.obj_fields[0])
        obj1 = self._make_object(self.obj_fields[1])
        self._test_get_object_dirty_protected(obj, dirty=False)
        self._test_get_object_dirty_protected(obj1)
