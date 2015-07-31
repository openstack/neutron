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

from neutron import context
from neutron.db.quota import api as quota_api
from neutron.tests.unit import testlib_api


class TestQuotaDbApi(testlib_api.SqlTestCaseLight):

    def _set_context(self):
        self.tenant_id = 'Higuain'
        self.context = context.Context('Gonzalo', self.tenant_id,
                                       is_admin=False, is_advsvc=False)

    def _create_quota_usage(self, resource, used, reserved, tenant_id=None):
        tenant_id = tenant_id or self.tenant_id
        return quota_api.set_quota_usage(
            self.context, resource, tenant_id,
            in_use=used, reserved=reserved)

    def _verify_quota_usage(self, usage_info,
                            expected_resource=None,
                            expected_used=None,
                            expected_reserved=None,
                            expected_dirty=None):
        self.assertEqual(self.tenant_id, usage_info.tenant_id)
        if expected_resource:
            self.assertEqual(expected_resource, usage_info.resource)
        if expected_dirty is not None:
                self.assertEqual(expected_dirty, usage_info.dirty)
        if expected_used is not None:
            self.assertEqual(expected_used, usage_info.used)
        if expected_reserved is not None:
            self.assertEqual(expected_reserved, usage_info.reserved)
        if expected_used is not None and expected_reserved is not None:
            self.assertEqual(expected_used + expected_reserved,
                             usage_info.total)

    def setUp(self):
        super(TestQuotaDbApi, self).setUp()
        self._set_context()

    def test_create_quota_usage(self):
        usage_info = self._create_quota_usage('goals', 26, 10)
        self._verify_quota_usage(usage_info,
                                 expected_resource='goals',
                                 expected_used=26,
                                 expected_reserved=10)

    def test_update_quota_usage(self):
        self._create_quota_usage('goals', 26, 10)
        # Higuain scores a double
        usage_info_1 = quota_api.set_quota_usage(
            self.context, 'goals', self.tenant_id,
            in_use=28)
        self._verify_quota_usage(usage_info_1,
                                 expected_used=28,
                                 expected_reserved=10)
        usage_info_2 = quota_api.set_quota_usage(
            self.context, 'goals', self.tenant_id,
            reserved=8)
        self._verify_quota_usage(usage_info_2,
                                 expected_used=28,
                                 expected_reserved=8)

    def test_update_quota_usage_with_deltas(self):
        self._create_quota_usage('goals', 26, 10)
        # Higuain scores a double
        usage_info_1 = quota_api.set_quota_usage(
            self.context, 'goals', self.tenant_id,
            in_use=2, delta=True)
        self._verify_quota_usage(usage_info_1,
                                 expected_used=28,
                                 expected_reserved=10)
        usage_info_2 = quota_api.set_quota_usage(
            self.context, 'goals', self.tenant_id,
            reserved=-2, delta=True)
        self._verify_quota_usage(usage_info_2,
                                 expected_used=28,
                                 expected_reserved=8)

    def test_set_quota_usage_dirty(self):
        self._create_quota_usage('goals', 26, 10)
        # Higuain needs a shower after the match
        self.assertEqual(1, quota_api.set_quota_usage_dirty(
            self.context, 'goals', self.tenant_id))
        usage_info = quota_api.get_quota_usage_by_resource_and_tenant(
            self.context, 'goals', self.tenant_id)
        self._verify_quota_usage(usage_info,
                                 expected_dirty=True)
        # Higuain is clean now
        self.assertEqual(1, quota_api.set_quota_usage_dirty(
            self.context, 'goals', self.tenant_id, dirty=False))
        usage_info = quota_api.get_quota_usage_by_resource_and_tenant(
            self.context, 'goals', self.tenant_id)
        self._verify_quota_usage(usage_info,
                                 expected_dirty=False)

    def test_set_dirty_non_existing_quota_usage(self):
        self.assertEqual(0, quota_api.set_quota_usage_dirty(
            self.context, 'meh', self.tenant_id))

    def test_set_resources_quota_usage_dirty(self):
        self._create_quota_usage('goals', 26, 10)
        self._create_quota_usage('assists', 11, 5)
        self._create_quota_usage('bookings', 3, 1)
        self.assertEqual(2, quota_api.set_resources_quota_usage_dirty(
            self.context, ['goals', 'bookings'], self.tenant_id))
        usage_info_goals = quota_api.get_quota_usage_by_resource_and_tenant(
            self.context, 'goals', self.tenant_id)
        usage_info_assists = quota_api.get_quota_usage_by_resource_and_tenant(
            self.context, 'assists', self.tenant_id)
        usage_info_bookings = quota_api.get_quota_usage_by_resource_and_tenant(
            self.context, 'bookings', self.tenant_id)
        self._verify_quota_usage(usage_info_goals, expected_dirty=True)
        self._verify_quota_usage(usage_info_assists, expected_dirty=False)
        self._verify_quota_usage(usage_info_bookings, expected_dirty=True)

    def test_set_resources_quota_usage_dirty_with_empty_list(self):
        self._create_quota_usage('goals', 26, 10)
        self._create_quota_usage('assists', 11, 5)
        self._create_quota_usage('bookings', 3, 1)
        # Expect all the resources for the tenant to be set dirty
        self.assertEqual(3, quota_api.set_resources_quota_usage_dirty(
            self.context, [], self.tenant_id))
        usage_info_goals = quota_api.get_quota_usage_by_resource_and_tenant(
            self.context, 'goals', self.tenant_id)
        usage_info_assists = quota_api.get_quota_usage_by_resource_and_tenant(
            self.context, 'assists', self.tenant_id)
        usage_info_bookings = quota_api.get_quota_usage_by_resource_and_tenant(
            self.context, 'bookings', self.tenant_id)
        self._verify_quota_usage(usage_info_goals, expected_dirty=True)
        self._verify_quota_usage(usage_info_assists, expected_dirty=True)
        self._verify_quota_usage(usage_info_bookings, expected_dirty=True)

        # Higuain is clean now
        self.assertEqual(1, quota_api.set_quota_usage_dirty(
            self.context, 'goals', self.tenant_id, dirty=False))
        usage_info = quota_api.get_quota_usage_by_resource_and_tenant(
            self.context, 'goals', self.tenant_id)
        self._verify_quota_usage(usage_info,
                                 expected_dirty=False)

    def _test_set_all_quota_usage_dirty(self, expected):
        self._create_quota_usage('goals', 26, 10)
        self._create_quota_usage('goals', 12, 6, tenant_id='Callejon')
        self.assertEqual(expected, quota_api.set_all_quota_usage_dirty(
            self.context, 'goals'))

    def test_set_all_quota_usage_dirty(self):
        # All goal scorers need a shower after the match, but since this is not
        # admin context we can clean only one
        self._test_set_all_quota_usage_dirty(expected=1)

    def test_get_quota_usage_by_tenant(self):
        self._create_quota_usage('goals', 26, 10)
        self._create_quota_usage('assists', 11, 5)
        # Create a resource for a different tenant
        self._create_quota_usage('mehs', 99, 99, tenant_id='buffon')
        usage_infos = quota_api.get_quota_usage_by_tenant_id(
            self.context, self.tenant_id)

        self.assertEqual(2, len(usage_infos))
        resources = [info.resource for info in usage_infos]
        self.assertIn('goals', resources)
        self.assertIn('assists', resources)

    def test_get_quota_usage_by_resource(self):
        self._create_quota_usage('goals', 26, 10)
        self._create_quota_usage('assists', 11, 5)
        self._create_quota_usage('goals', 12, 6, tenant_id='Callejon')
        usage_infos = quota_api.get_quota_usage_by_resource(
            self.context, 'goals')
        # Only 1 result expected in tenant context
        self.assertEqual(1, len(usage_infos))
        self._verify_quota_usage(usage_infos[0],
                                 expected_resource='goals',
                                 expected_used=26,
                                 expected_reserved=10)

    def test_get_quota_usage_by_tenant_and_resource(self):
        self._create_quota_usage('goals', 26, 10)
        usage_info = quota_api.get_quota_usage_by_resource_and_tenant(
            self.context, 'goals', self.tenant_id)
        self._verify_quota_usage(usage_info,
                                 expected_resource='goals',
                                 expected_used=26,
                                 expected_reserved=10)

    def test_get_non_existing_quota_usage_returns_none(self):
        self.assertIsNone(quota_api.get_quota_usage_by_resource_and_tenant(
            self.context, 'goals', self.tenant_id))


class TestQuotaDbApiAdminContext(TestQuotaDbApi):

    def _set_context(self):
        self.tenant_id = 'Higuain'
        self.context = context.Context('Gonzalo', self.tenant_id,
                                       is_admin=True, is_advsvc=True,
                                       load_admin_roles=False)

    def test_get_quota_usage_by_resource(self):
        self._create_quota_usage('goals', 26, 10)
        self._create_quota_usage('assists', 11, 5)
        self._create_quota_usage('goals', 12, 6, tenant_id='Callejon')
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
