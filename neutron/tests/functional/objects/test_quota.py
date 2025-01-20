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

import datetime

from neutron_lib import context
from neutron_lib.db import api as db_api
from oslo_utils import timeutils
from oslo_utils import uuidutils

from neutron.objects import quota
from neutron.tests.unit import testlib_api


class TestReservationSql(testlib_api.SqlTestCase,
                         testlib_api.MySQLTestCaseMixin):
    def setUp(self):
        super().setUp()
        self.context = context.Context(user_id=None, project_id=None,
                                       is_admin=True, overwrite=False)

    def _create_test_reservation(self, exp):
        res_id = uuidutils.generate_uuid()
        project_id = uuidutils.generate_uuid()
        reservation = quota.Reservation(
            self.context, id=res_id, expiration=exp, project_id=project_id)
        reservation.create()
        return reservation

    def _get_reservation(self, _id):
        return quota.Reservation.get_object(self.context, id=_id)

    def _create_resource_delta(self, resource, reservation_id, amount):
        resource_delta = quota.ResourceDelta(
            self.context, resource=resource, reservation_id=reservation_id,
            amount=amount)
        resource_delta.create()
        return resource_delta

    def test_get_total_reservations_map(self):
        resources = ['port']
        a_long_time_ago = datetime.datetime(1978, 9, 4)
        res = self._create_test_reservation(a_long_time_ago)
        res_delta = self._create_resource_delta('port', res.id, 100)
        res = self._get_reservation(res.id)
        self.assertEqual(1, len(res.resource_deltas))
        self.assertEqual(res_delta, res.resource_deltas[0])
        with db_api.CONTEXT_READER.using(self.context):
            res_map = quota.Reservation.get_total_reservations_map(
                self.context, timeutils.utcnow(),
                res.project_id, resources, True)
        self.assertEqual({'port': 100}, res_map)
        self.assertIsInstance(res_map['port'], int)
