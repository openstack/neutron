# Copyright (c) 2015 OpenStack Foundation.  All rights reserved.
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
from unittest import mock

from neutron_lib import context
from neutron_lib.plugins import constants as const
from neutron_lib.plugins import directory
from oslo_config import cfg

from neutron.db.quota import api as quota_api
from neutron import policy  # noqa
from neutron.tests.unit.db.quota import test_driver
from neutron.tests.unit import testlib_api


DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class TestQuotaDbApi(testlib_api.SqlTestCaseLight):

    def _set_context(self):
        self.project_id = 'Higuain'
        self.context = context.Context('Gonzalo', self.project_id,
                                       is_admin=False, is_advsvc=False)

    def _create_reservation(self, resource_deltas,
                            project_id=None, expiration=None):
        project_id = project_id or self.project_id
        return quota_api.create_reservation(
            self.context, project_id, resource_deltas, expiration)

    def _create_quota_usage(self, resource, used, project_id=None):
        project_id = project_id or self.project_id
        return quota_api.set_quota_usage(context.get_admin_context(),
            resource, project_id, in_use=used)

    def _verify_quota_usage(self, usage_info,
                            expected_resource=None,
                            expected_used=None,
                            expected_dirty=None):
        self.assertEqual(self.project_id, usage_info.project_id)
        if expected_resource:
            self.assertEqual(expected_resource, usage_info.resource)
        if expected_dirty is not None:
            self.assertEqual(expected_dirty, usage_info.dirty)
        if expected_used is not None:
            self.assertEqual(expected_used, usage_info.used)

    def setUp(self):
        super(TestQuotaDbApi, self).setUp()
        self._set_context()
        self.plugin = test_driver.FakePlugin()
        directory.add_plugin(const.CORE, self.plugin)
        cfg.CONF.set_override("core_plugin", DB_PLUGIN_KLASS)

    def test_create_quota_usage(self):
        usage_info = self._create_quota_usage('goals', 26)
        self._verify_quota_usage(usage_info,
                                 expected_resource='goals',
                                 expected_used=26)

    def test_update_quota_usage(self):
        self._create_quota_usage('goals', 26)
        # Higuain scores a double
        usage_info_1 = quota_api.set_quota_usage(
            self.context, 'goals', self.project_id,
            in_use=28)
        self._verify_quota_usage(usage_info_1,
                                 expected_used=28)
        usage_info_2 = quota_api.set_quota_usage(
            self.context, 'goals', self.project_id,
            in_use=24)
        self._verify_quota_usage(usage_info_2,
                                 expected_used=24)

    def test_update_quota_usage_with_deltas(self):
        self._create_quota_usage('goals', 26)
        # Higuain scores a double
        usage_info_1 = quota_api.set_quota_usage(
            self.context, 'goals', self.project_id,
            in_use=2, delta=True)
        self._verify_quota_usage(usage_info_1,
                                 expected_used=28)

    def test_set_resources_quota_usage_dirty_one_resource_only(self):
        self._create_quota_usage('goals', 26)
        # Higuain needs a shower after the match
        self.assertEqual(1, quota_api.set_resources_quota_usage_dirty(
            self.context, 'goals', self.project_id))
        usage_info = quota_api.get_quota_usage_by_resource_and_project(
            self.context, 'goals', self.project_id)
        self._verify_quota_usage(usage_info,
                                 expected_dirty=True)
        # Higuain is clean now
        self.assertEqual(1, quota_api.set_resources_quota_usage_dirty(
            self.context, 'goals', self.project_id, dirty=False))
        usage_info = quota_api.get_quota_usage_by_resource_and_project(
            self.context, 'goals', self.project_id)
        self._verify_quota_usage(usage_info,
                                 expected_dirty=False)

    def test_set_dirty_non_existing_quota_usage(self):
        self.assertEqual(0, quota_api.set_resources_quota_usage_dirty(
            self.context, 'meh', self.project_id))
        self.assertEqual(0, quota_api.set_resources_quota_usage_dirty(
            self.context, ['meh1', 'meh2'], self.project_id))

    def test_set_resources_quota_usage_dirty(self):
        self._create_quota_usage('goals', 26)
        self._create_quota_usage('assists', 11)
        self._create_quota_usage('bookings', 3)
        self.assertEqual(2, quota_api.set_resources_quota_usage_dirty(
            self.context, ['goals', 'bookings'], self.project_id))
        usage_info_goals = quota_api.get_quota_usage_by_resource_and_project(
            self.context, 'goals', self.project_id)
        usage_info_assists = quota_api.get_quota_usage_by_resource_and_project(
            self.context, 'assists', self.project_id)
        usage_info_bookings = (
            quota_api.get_quota_usage_by_resource_and_project(
                self.context, 'bookings', self.project_id))
        self._verify_quota_usage(usage_info_goals, expected_dirty=True)
        self._verify_quota_usage(usage_info_assists, expected_dirty=False)
        self._verify_quota_usage(usage_info_bookings, expected_dirty=True)

    def test_set_resources_quota_usage_dirty_with_empty_list(self):
        self._create_quota_usage('goals', 26)
        self._create_quota_usage('assists', 11)
        self._create_quota_usage('bookings', 3)
        # Expect all the resources for the project to be set dirty
        self.assertEqual(3, quota_api.set_resources_quota_usage_dirty(
            self.context, [], self.project_id))
        usage_info_goals = quota_api.get_quota_usage_by_resource_and_project(
            self.context, 'goals', self.project_id)
        usage_info_assists = quota_api.get_quota_usage_by_resource_and_project(
            self.context, 'assists', self.project_id)
        usage_info_bookings = (
            quota_api.get_quota_usage_by_resource_and_project(
                self.context, 'bookings', self.project_id))
        self._verify_quota_usage(usage_info_goals, expected_dirty=True)
        self._verify_quota_usage(usage_info_assists, expected_dirty=True)
        self._verify_quota_usage(usage_info_bookings, expected_dirty=True)

        # Higuain is clean now
        self.assertEqual(1, quota_api.set_resources_quota_usage_dirty(
            self.context, 'goals', self.project_id, dirty=False))
        usage_info = quota_api.get_quota_usage_by_resource_and_project(
            self.context, 'goals', self.project_id)
        self._verify_quota_usage(usage_info,
                                 expected_dirty=False)

    def _test_set_all_quota_usage_dirty(self, expected):
        self._create_quota_usage('goals', 26)
        self._create_quota_usage('goals', 12, project_id='Callejon')
        self.assertEqual(expected, quota_api.set_all_quota_usage_dirty(
            self.context, 'goals'))

    def test_set_all_quota_usage_dirty(self):
        # All goal scorers need a shower after the match, but since this is not
        # admin context we can clean only one
        self._test_set_all_quota_usage_dirty(expected=1)

    def test_get_quota_usage_by_project(self):
        self._create_quota_usage('goals', 26)
        self._create_quota_usage('assists', 11)
        # Create a resource for a different project
        self._create_quota_usage('mehs', 99, project_id='buffon')
        usage_infos = quota_api.get_quota_usage_by_project_id(
            self.context, self.project_id)

        self.assertEqual(2, len(usage_infos))
        resources = [info.resource for info in usage_infos]
        self.assertIn('goals', resources)
        self.assertIn('assists', resources)

    def test_get_quota_usage_by_resource(self):
        self._create_quota_usage('goals', 26)
        self._create_quota_usage('assists', 11)
        self._create_quota_usage('goals', 12, project_id='Callejon')
        usage_infos = quota_api.get_quota_usage_by_resource(
            self.context, 'goals')
        # Only 1 result expected in project context
        self.assertEqual(1, len(usage_infos))
        self._verify_quota_usage(usage_infos[0],
                                 expected_resource='goals',
                                 expected_used=26)

    def test_get_quota_usage_by_project_and_resource(self):
        self._create_quota_usage('goals', 26)
        usage_info = quota_api.get_quota_usage_by_resource_and_project(
            self.context, 'goals', self.project_id)
        self._verify_quota_usage(usage_info,
                                 expected_resource='goals',
                                 expected_used=26)

    def test_get_non_existing_quota_usage_returns_none(self):
        self.assertIsNone(quota_api.get_quota_usage_by_resource_and_project(
            self.context, 'goals', self.project_id))

    def _verify_reserved_resources(self, expected, actual):
        for (resource, delta) in actual.items():
            self.assertIn(resource, expected)
            self.assertEqual(delta, expected[resource])
            del expected[resource]
        self.assertFalse(expected)

    def test_create_reservation(self):
        resources = {'goals': 2, 'assists': 1}
        resv = self._create_reservation(resources)
        self.assertEqual(self.project_id, resv.project_id)
        self._verify_reserved_resources(resources, resv.deltas)

    def test_create_reservation_with_expiration(self):
        resources = {'goals': 2, 'assists': 1}
        exp_date = datetime.datetime(2016, 3, 31, 14, 30)
        resv = self._create_reservation(resources, expiration=exp_date)
        self.assertEqual(self.project_id, resv.project_id)
        self.assertEqual(exp_date, resv.expiration)
        self._verify_reserved_resources(resources, resv.deltas)

    def test_remove_non_existent_reservation(self):
        self.assertIsNone(quota_api.remove_reservation(self.context, 'meh'))

    def _get_reservations_for_resource_helper(self):
        # create three reservation, 1 expired
        resources_1 = {'goals': 2, 'assists': 1}
        resources_2 = {'goals': 3, 'bookings': 1}
        resources_3 = {'bookings': 2, 'assists': 2}
        exp_date_1 = datetime.datetime(2016, 3, 31, 14, 30)
        exp_date_2 = datetime.datetime(2015, 3, 31, 14, 30)
        self._create_reservation(resources_1, expiration=exp_date_1)
        self._create_reservation(resources_2, expiration=exp_date_1)
        self._create_reservation(resources_3, expiration=exp_date_2)

    def test_get_reservations_for_resources(self):
        with mock.patch('neutron.db.quota.api.utcnow') as mock_utcnow:
            self._get_reservations_for_resource_helper()
            mock_utcnow.return_value = datetime.datetime(
                2015, 5, 20, 0, 0)
            deltas = quota_api.get_reservations_for_resources(
                self.context, self.project_id,
                ['goals', 'assists', 'bookings'])
            self.assertIn('goals', deltas)
            self.assertEqual(5, deltas['goals'])
            self.assertIn('assists', deltas)
            self.assertEqual(1, deltas['assists'])
            self.assertIn('bookings', deltas)
            self.assertEqual(1, deltas['bookings'])
            self.assertEqual(3, len(deltas))

    def test_get_expired_reservations_for_resources(self):
        with mock.patch('neutron.db.quota.api.utcnow') as mock_utcnow:
            mock_utcnow.return_value = datetime.datetime(
                2015, 5, 20, 0, 0)
            self._get_reservations_for_resource_helper()
            deltas = quota_api.get_reservations_for_resources(
                self.context, self.project_id,
                ['goals', 'assists', 'bookings'],
                expired=True)
            self.assertIn('assists', deltas)
            self.assertEqual(2, deltas['assists'])
            self.assertIn('bookings', deltas)
            self.assertEqual(2, deltas['bookings'])
            self.assertEqual(2, len(deltas))

    def test_get_reservation_for_resources_with_empty_list(self):
        self.assertIsNone(quota_api.get_reservations_for_resources(
            self.context, self.project_id, []))

    def test_remove_expired_reservations(self):
        with mock.patch('neutron.db.quota.api.utcnow') as mock_utcnow:
            mock_utcnow.return_value = datetime.datetime(
                2015, 5, 20, 0, 0)
            resources = {'goals': 2, 'assists': 1}
            exp_date_1 = datetime.datetime(2016, 3, 31, 14, 30)
            resv_1 = self._create_reservation(resources, expiration=exp_date_1)
            exp_date_2 = datetime.datetime(2015, 3, 31, 14, 30)
            resv_2 = self._create_reservation(resources, expiration=exp_date_2)
            self.assertEqual(1, quota_api.remove_expired_reservations(
                self.context, self.project_id))
            self.assertIsNone(quota_api.get_reservation(
                self.context, resv_2.reservation_id))
            self.assertIsNotNone(quota_api.get_reservation(
                self.context, resv_1.reservation_id))

    def test_remove_expired_reservations_no_project(self):
        with mock.patch('neutron.db.quota.api.utcnow') as mock_utcnow:
            mock_utcnow.return_value = datetime.datetime(
                2015, 5, 20, 0, 0)
            resources = {'goals': 2, 'assists': 1}
            exp_date_1 = datetime.datetime(2014, 3, 31, 14, 30)
            resv_1 = self._create_reservation(resources, expiration=exp_date_1)
            exp_date_2 = datetime.datetime(2015, 3, 31, 14, 30)
            resv_2 = self._create_reservation(resources,
                                              expiration=exp_date_2,
                                              project_id='Callejon')
            self.assertEqual(2, quota_api.remove_expired_reservations(
                context.get_admin_context()))
            self.assertIsNone(quota_api.get_reservation(
                self.context, resv_2.reservation_id))
            self.assertIsNone(quota_api.get_reservation(
                self.context, resv_1.reservation_id))


class TestQuotaDbApiAdminContext(TestQuotaDbApi):

    def _set_context(self):
        self.project_id = 'Higuain'
        self.context = context.Context('Gonzalo', self.project_id,
                                       is_admin=True, is_advsvc=True)

    def test_get_quota_usage_by_resource(self):
        self._create_quota_usage('goals', 26)
        self._create_quota_usage('assists', 11)
        self._create_quota_usage('goals', 12, project_id='Callejon')
        usage_infos = quota_api.get_quota_usage_by_resource(
            self.context, 'goals')
        # 2 results expected in admin context
        self.assertEqual(2, len(usage_infos))
        for usage_info in usage_infos:
            self.assertEqual('goals', usage_info.resource)

    def test_set_all_quota_usage_dirty(self):
        # All goal scorers need a shower after the match, and with admin
        # context we should be able to clean all of them
        self._test_set_all_quota_usage_dirty(expected=2)
