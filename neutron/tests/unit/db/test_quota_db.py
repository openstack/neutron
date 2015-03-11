# Copyright (c) 2014 OpenStack Foundation.
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

from neutron.common import exceptions
from neutron import context
from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.db import quota_db
from neutron.tests.unit import testlib_api


class FakePlugin(base_plugin.NeutronDbPluginV2, quota_db.DbQuotaDriver):
    """A fake plugin class containing all DB methods."""


class TestResource(object):
    """Describe a test resource for quota checking."""

    def __init__(self, name, default):
        self.name = name
        self.quota = default

    @property
    def default(self):
        return self.quota

PROJECT = 'prj_test'
RESOURCE = 'res_test'


class TestDbQuotaDriver(testlib_api.SqlTestCase):
    def setUp(self):
        super(TestDbQuotaDriver, self).setUp()
        self.plugin = FakePlugin()
        self.context = context.get_admin_context()

    def test_create_quota_limit(self):
        defaults = {RESOURCE: TestResource(RESOURCE, 4)}

        self.plugin.update_quota_limit(self.context, PROJECT, RESOURCE, 2)
        quotas = self.plugin.get_tenant_quotas(self.context, defaults, PROJECT)
        self.assertEqual(2, quotas[RESOURCE])

    def test_update_quota_limit(self):
        defaults = {RESOURCE: TestResource(RESOURCE, 4)}

        self.plugin.update_quota_limit(self.context, PROJECT, RESOURCE, 2)
        self.plugin.update_quota_limit(self.context, PROJECT, RESOURCE, 3)
        quotas = self.plugin.get_tenant_quotas(self.context, defaults, PROJECT)
        self.assertEqual(3, quotas[RESOURCE])

    def test_delete_tenant_quota_restores_default_limit(self):
        defaults = {RESOURCE: TestResource(RESOURCE, 4)}

        self.plugin.update_quota_limit(self.context, PROJECT, RESOURCE, 2)
        self.plugin.delete_tenant_quota(self.context, PROJECT)
        quotas = self.plugin.get_tenant_quotas(self.context, defaults, PROJECT)
        self.assertEqual(4, quotas[RESOURCE])

    def test_get_all_quotas(self):
        project_1 = 'prj_test_1'
        project_2 = 'prj_test_2'
        resource_1 = 'res_test_1'
        resource_2 = 'res_test_2'

        resources = {resource_1: TestResource(resource_1, 3),
                     resource_2: TestResource(resource_2, 5)}

        self.plugin.update_quota_limit(self.context, project_1, resource_1, 7)
        self.plugin.update_quota_limit(self.context, project_2, resource_2, 9)
        quotas = self.plugin.get_all_quotas(self.context, resources)

        # Expect two tenants' quotas
        self.assertEqual(2, len(quotas))
        # But not quotas for the same tenant twice
        self.assertNotEqual(quotas[0]['tenant_id'], quotas[1]['tenant_id'])

        # Check the expected limits. The quotas can be in any order.
        for quota in quotas:
            self.assertEqual(3, len(quota))
            project = quota['tenant_id']
            self.assertIn(project, (project_1, project_2))
            if project == project_1:
                expected_limit_r1 = 7
                expected_limit_r2 = 5
            if project == project_2:
                expected_limit_r1 = 3
                expected_limit_r2 = 9
            self.assertEqual(expected_limit_r1, quota[resource_1])
            self.assertEqual(expected_limit_r2, quota[resource_2])

    def test_limit_check(self):
        resources = {RESOURCE: TestResource(RESOURCE, 2)}
        values = {RESOURCE: 1}

        self.plugin.update_quota_limit(self.context, PROJECT, RESOURCE, 2)
        self.plugin.limit_check(self.context, PROJECT, resources, values)

    def test_limit_check_over_quota(self):
        resources = {RESOURCE: TestResource(RESOURCE, 2)}
        values = {RESOURCE: 3}

        self.plugin.update_quota_limit(self.context, PROJECT, RESOURCE, 2)

        self.assertRaises(exceptions.OverQuota, self.plugin.limit_check,
                          context.get_admin_context(), PROJECT, resources,
                          values)

    def test_limit_check_equals_to_quota(self):
        resources = {RESOURCE: TestResource(RESOURCE, 2)}
        values = {RESOURCE: 2}

        self.plugin.update_quota_limit(self.context, PROJECT, RESOURCE, 2)
        self.plugin.limit_check(self.context, PROJECT, resources, values)

    def test_limit_check_value_lower_than_zero(self):
        resources = {RESOURCE: TestResource(RESOURCE, 2)}
        values = {RESOURCE: -1}

        self.plugin.update_quota_limit(self.context, PROJECT, RESOURCE, 2)
        self.assertRaises(exceptions.InvalidQuotaValue,
                          self.plugin.limit_check, context.get_admin_context(),
                          PROJECT, resources, values)
