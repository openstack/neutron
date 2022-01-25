# Copyright (c) 2021 Red Hat, Inc.
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

import itertools

from neutron_lib.db import api as db_api

from neutron.db.quota import api as quota_api
from neutron.db.quota import driver_nolock
from neutron.objects import quota as quota_obj
from neutron.tests.unit.db.quota import test_driver


class TestDbQuotaDriverNoLock(test_driver.TestDbQuotaDriver):

    def setUp(self):
        super(TestDbQuotaDriverNoLock, self).setUp()
        self.quota_driver = driver_nolock.DbQuotaNoLockDriver()

    @staticmethod
    def _cleanup_timeout(previous_value):
        quota_api.RESERVATION_EXPIRATION_TIMEOUT = previous_value

    def test__remove_expired_reservations(self):
        for project, resource in itertools.product(self.projects,
                                                   self.resources):
            deltas = {resource: 1}
            with db_api.CONTEXT_WRITER.using(self.context):
                quota_api.create_reservation(self.context, project, deltas)

        # Initial check: the reservations are correctly created.
        for project in self.projects:
            for res in quota_obj.Reservation.get_objects(self.context,
                                                         project_id=project):
                self.assertEqual(1, len(res.resource_deltas))
                delta = res.resource_deltas[0]
                self.assertEqual(1, delta.amount)
                self.assertIn(delta.resource, self.resources)

        # Delete the expired reservations and check.
        # NOTE(ralonsoh): the timeout is set to -121 to force the deletion
        # of all created reservations, including those ones created in this
        # test. The value of 121 overcomes the 120 seconds of default
        # expiration time a reservation has.
        timeout = quota_api.RESERVATION_EXPIRATION_TIMEOUT
        quota_api.RESERVATION_EXPIRATION_TIMEOUT = -(timeout + 1)
        self.addCleanup(self._cleanup_timeout, timeout)
        self.quota_driver._remove_expired_reservations()
        res = quota_obj.Reservation.get_objects(self.context)
        self.assertEqual([], res)
