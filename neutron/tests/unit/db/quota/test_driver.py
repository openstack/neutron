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

from neutron_lib import context
from neutron_lib import exceptions as lib_exc

from neutron.common import exceptions
from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.db.quota import api as quota_api
from neutron.db.quota import driver
from neutron.objects import quota as quota_obj
from neutron.quota import resource
from neutron.tests import base
from neutron.tests.unit import quota as test_quota
from neutron.tests.unit import testlib_api

DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


def _count_resource(context, resource, tenant_id):
    """A fake counting function to determine current used counts"""
    if resource[-1] == 's':
        resource = resource[:-1]
    result = quota_obj.QuotaUsage.get_object_dirty_protected(
        context, resource=resource)
    return 0 if not result else result.in_use


class FakePlugin(base_plugin.NeutronDbPluginV2, driver.DbQuotaDriver):
    """A fake plugin class containing all DB methods."""


class TestResource(object):
    """Describe a test resource for quota checking."""

    def __init__(self, name, default, fake_count=0):
        self.name = name
        self.quota = default
        self.fake_count = fake_count

    @property
    def default(self):
        return self.quota

    def count(self, *args, **kwargs):
        return self.fake_count


class TestTrackedResource(resource.TrackedResource):
    """Describes a test tracked resource for detailed quota checking"""
    def __init__(self, name, model_class, flag=None,
                 plural_name=None):
        super(TestTrackedResource, self).__init__(
            name, model_class, flag=flag, plural_name=None)

    @property
    def default(self):
        return self.flag


class TestCountableResource(resource.CountableResource):
    """Describes a test countable resource for detailed quota checking"""
    def __init__(self, name, count, flag=-1, plural_name=None):
        super(TestCountableResource, self).__init__(
            name, count, flag=flag, plural_name=None)

    @property
    def default(self):
        return self.flag

PROJECT = 'prj_test'
RESOURCE = 'res_test'
ALT_RESOURCE = 'res_test_meh'


class TestDbQuotaDriver(testlib_api.SqlTestCase,
                        base.BaseTestCase):
    def setUp(self):
        super(TestDbQuotaDriver, self).setUp()
        self.plugin = FakePlugin()
        self.context = context.get_admin_context()
        self.setup_coreplugin(core_plugin=DB_PLUGIN_KLASS)

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

    def test_get_default_quotas(self):
        defaults = {RESOURCE: TestResource(RESOURCE, 4)}
        user_ctx = context.Context(user_id=PROJECT, tenant_id=PROJECT)
        self.plugin.update_quota_limit(self.context, PROJECT, RESOURCE, 2)
        quotas = self.plugin.get_default_quotas(user_ctx, defaults, PROJECT)
        self.assertEqual(4, quotas[RESOURCE])

    def test_get_tenant_quotas(self):
        user_ctx = context.Context(user_id=PROJECT, tenant_id=PROJECT)
        self.plugin.update_quota_limit(self.context, PROJECT, RESOURCE, 2)
        quotas = self.plugin.get_tenant_quotas(user_ctx, {}, PROJECT)
        self.assertEqual(2, quotas[RESOURCE])

    def test_get_tenant_quotas_different_tenant(self):
        user_ctx = context.Context(user_id=PROJECT,
                                   tenant_id='another_project')
        self.plugin.update_quota_limit(self.context, PROJECT, RESOURCE, 2)
        # It is appropriate to use assertFalse here as the expected return
        # value is an empty dict (the defaults passed in the statement below
        # after the request context)
        self.assertFalse(self.plugin.get_tenant_quotas(user_ctx, {}, PROJECT))

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

        self.assertRaises(lib_exc.OverQuota, self.plugin.limit_check,
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

    def _test_make_reservation_success(self, quota_driver,
                                       resource_name, deltas):
        resources = {resource_name: TestResource(resource_name, 2)}
        self.plugin.update_quota_limit(self.context, PROJECT, resource_name, 2)
        reservation = quota_driver.make_reservation(
            self.context,
            self.context.tenant_id,
            resources,
            deltas,
            self.plugin)
        self.assertIn(resource_name, reservation.deltas)
        self.assertEqual(deltas[resource_name],
                         reservation.deltas[resource_name])
        self.assertEqual(self.context.tenant_id,
                         reservation.tenant_id)

    def test_make_reservation_single_resource(self):
        quota_driver = driver.DbQuotaDriver()
        self._test_make_reservation_success(
            quota_driver, RESOURCE, {RESOURCE: 1})

    def test_make_reservation_fill_quota(self):
        quota_driver = driver.DbQuotaDriver()
        self._test_make_reservation_success(
            quota_driver, RESOURCE, {RESOURCE: 2})

    def test_make_reservation_multiple_resources(self):
        quota_driver = driver.DbQuotaDriver()
        resources = {RESOURCE: TestResource(RESOURCE, 2),
                     ALT_RESOURCE: TestResource(ALT_RESOURCE, 2)}
        deltas = {RESOURCE: 1, ALT_RESOURCE: 2}
        self.plugin.update_quota_limit(self.context, PROJECT, RESOURCE, 2)
        self.plugin.update_quota_limit(self.context, PROJECT, ALT_RESOURCE, 2)
        reservation = quota_driver.make_reservation(
            self.context,
            self.context.tenant_id,
            resources,
            deltas,
            self.plugin)
        self.assertIn(RESOURCE, reservation.deltas)
        self.assertIn(ALT_RESOURCE, reservation.deltas)
        self.assertEqual(1, reservation.deltas[RESOURCE])
        self.assertEqual(2, reservation.deltas[ALT_RESOURCE])
        self.assertEqual(self.context.tenant_id,
                         reservation.tenant_id)

    def test_make_reservation_over_quota_fails(self):
        quota_driver = driver.DbQuotaDriver()
        resources = {RESOURCE: TestResource(RESOURCE, 2,
                                            fake_count=2)}
        deltas = {RESOURCE: 1}
        self.plugin.update_quota_limit(self.context, PROJECT, RESOURCE, 2)
        self.assertRaises(lib_exc.OverQuota,
                          quota_driver.make_reservation,
                          self.context,
                          self.context.tenant_id,
                          resources,
                          deltas,
                          self.plugin)

    def test_get_detailed_tenant_quotas_resource(self):
        res = {RESOURCE: TestTrackedResource(RESOURCE, test_quota.MehModel)}

        self.plugin.update_quota_limit(self.context, PROJECT, RESOURCE, 6)
        quota_driver = driver.DbQuotaDriver()
        quota_driver.make_reservation(self.context, PROJECT, res,
                                      {RESOURCE: 1}, self.plugin)
        quota_api.set_quota_usage(self.context, RESOURCE, PROJECT, 2)
        detailed_quota = self.plugin.get_detailed_tenant_quotas(self.context,
                                                                res, PROJECT)
        self.assertEqual(6, detailed_quota[RESOURCE]['limit'])
        self.assertEqual(2, detailed_quota[RESOURCE]['used'])
        self.assertEqual(1, detailed_quota[RESOURCE]['reserved'])

    def test_get_detailed_tenant_quotas_multiple_resource(self):
        project_1 = 'prj_test_1'
        resource_1 = 'res_test_1'
        resource_2 = 'res_test_2'
        resources = {resource_1:
                     TestTrackedResource(resource_1, test_quota.MehModel),
                     resource_2:
                     TestCountableResource(resource_2, _count_resource)}

        self.plugin.update_quota_limit(self.context, project_1, resource_1, 6)
        self.plugin.update_quota_limit(self.context, project_1, resource_2, 9)
        quota_driver = driver.DbQuotaDriver()
        quota_driver.make_reservation(self.context, project_1,
                                      resources,
                                      {resource_1: 1, resource_2: 7},
                                      self.plugin)

        quota_api.set_quota_usage(self.context, resource_1, project_1, 2)
        quota_api.set_quota_usage(self.context, resource_2, project_1, 3)
        detailed_quota = self.plugin.get_detailed_tenant_quotas(self.context,
                                                                resources,
                                                                project_1)

        self.assertEqual(6, detailed_quota[resource_1]['limit'])
        self.assertEqual(1, detailed_quota[resource_1]['reserved'])
        self.assertEqual(2, detailed_quota[resource_1]['used'])

        self.assertEqual(9, detailed_quota[resource_2]['limit'])
        self.assertEqual(7, detailed_quota[resource_2]['reserved'])
        self.assertEqual(3, detailed_quota[resource_2]['used'])
