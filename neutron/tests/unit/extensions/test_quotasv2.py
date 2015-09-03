# Copyright 2012 OpenStack Foundation.
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

import sys

import mock
from oslo_config import cfg
import testtools
from webob import exc
import webtest

from neutron.api import extensions
from neutron.api.v2 import router
from neutron.common import config
from neutron.common import constants
from neutron.common import exceptions
from neutron import context
from neutron.db.quota import driver
from neutron import quota
from neutron.quota import resource_registry
from neutron.tests import base
from neutron.tests import tools
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit import testlib_api

TARGET_PLUGIN = 'neutron.plugins.ml2.plugin.Ml2Plugin'

_get_path = test_base._get_path


class QuotaExtensionTestCase(testlib_api.WebTestCase):

    def setUp(self):
        super(QuotaExtensionTestCase, self).setUp()
        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None

        self.useFixture(tools.AttributeMapMemento())

        # Create the default configurations
        self.config_parse()

        # Update the plugin and extensions path
        self.setup_coreplugin(TARGET_PLUGIN)
        cfg.CONF.set_override(
            'quota_items',
            ['network', 'subnet', 'port', 'extra1'],
            group='QUOTAS')
        quota.QUOTAS = quota.QuotaEngine()
        quota.register_resources_from_config()
        self._plugin_patcher = mock.patch(TARGET_PLUGIN, autospec=True)
        self.plugin = self._plugin_patcher.start()
        self.plugin.return_value.supported_extension_aliases = ['quotas']
        # QUOTAS will register the items in conf when starting
        # extra1 here is added later, so have to do it manually
        resource_registry.register_resource_by_name('extra1')
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        app = config.load_paste_app('extensions_test_app')
        ext_middleware = extensions.ExtensionMiddleware(app, ext_mgr=ext_mgr)
        self.api = webtest.TestApp(ext_middleware)
        # Initialize the router for the core API in order to ensure core quota
        # resources are registered
        router.APIRouter()

    def tearDown(self):
        self.api = None
        self.plugin = None
        super(QuotaExtensionTestCase, self).tearDown()

    def _test_quota_default_values(self, expected_values):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env)
        quota = self.deserialize(res)
        for resource, expected_value in expected_values.items():
            self.assertEqual(expected_value,
                             quota['quota'][resource])


class QuotaExtensionDbTestCase(QuotaExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        cfg.CONF.set_override(
            'quota_driver',
            'neutron.db.quota.driver.DbQuotaDriver',
            group='QUOTAS')
        super(QuotaExtensionDbTestCase, self).setUp()

    def test_quotas_loaded_right(self):
        res = self.api.get(_get_path('quotas', fmt=self.fmt))
        quota = self.deserialize(res)
        self.assertEqual([], quota['quotas'])
        self.assertEqual(200, res.status_int)

    def test_quotas_default_values(self):
        self._test_quota_default_values(
            {'network': 10,
             'subnet': 10,
             'port': 50,
             'extra1': -1})

    def test_quotas_negative_default_value(self):
        cfg.CONF.set_override(
            'quota_port', -666, group='QUOTAS')
        cfg.CONF.set_override(
            'quota_network', -10, group='QUOTAS')
        cfg.CONF.set_override(
            'quota_subnet', -50, group='QUOTAS')
        self._test_quota_default_values(
            {'network': -1,
             'subnet': -1,
             'port': -1,
             'extra1': -1})

    def test_show_quotas_with_admin(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id + '2',
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual(10, quota['quota']['network'])
        self.assertEqual(10, quota['quota']['subnet'])
        self.assertEqual(50, quota['quota']['port'])

    def test_show_quotas_without_admin_forbidden_returns_403(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id + '2',
                                                  is_admin=False)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env, expect_errors=True)
        self.assertEqual(403, res.status_int)

    def test_show_quotas_with_owner_tenant(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=False)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual(10, quota['quota']['network'])
        self.assertEqual(10, quota['quota']['subnet'])
        self.assertEqual(50, quota['quota']['port'])

    def test_list_quotas_with_admin(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas', fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual([], quota['quotas'])

    def test_list_quotas_without_admin_forbidden_returns_403(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=False)}
        res = self.api.get(_get_path('quotas', fmt=self.fmt),
                           extra_environ=env, expect_errors=True)
        self.assertEqual(403, res.status_int)

    def test_update_quotas_without_admin_forbidden_returns_403(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=False)}
        quotas = {'quota': {'network': 100}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=True)
        self.assertEqual(403, res.status_int)

    def test_update_quotas_with_non_integer_returns_400(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': 'abc'}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=True)
        self.assertEqual(400, res.status_int)

    def test_update_quotas_with_negative_integer_returns_400(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': -2}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=True)
        self.assertEqual(400, res.status_int)

    def test_update_quotas_with_out_of_range_integer_returns_400(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': constants.DB_INTEGER_MAX_VALUE + 1}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=True)
        self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_update_quotas_to_unlimited(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': -1}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=False)
        self.assertEqual(200, res.status_int)

    def test_update_quotas_exceeding_current_limit(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': 120}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=False)
        self.assertEqual(200, res.status_int)

    def test_update_quotas_with_non_support_resource_returns_400(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        quotas = {'quota': {'abc': 100}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=True)
        self.assertEqual(400, res.status_int)

    def test_update_quotas_with_admin(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id + '2',
                                                  is_admin=True)}
        quotas = {'quota': {'network': 100}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env)
        self.assertEqual(200, res.status_int)
        env2 = {'neutron.context': context.Context('', tenant_id)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env2)
        quota = self.deserialize(res)
        self.assertEqual(100, quota['quota']['network'])
        self.assertEqual(10, quota['quota']['subnet'])
        self.assertEqual(50, quota['quota']['port'])

    def test_update_attributes(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id + '2',
                                                  is_admin=True)}
        quotas = {'quota': {'extra1': 100}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env)
        self.assertEqual(200, res.status_int)
        env2 = {'neutron.context': context.Context('', tenant_id)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env2)
        quota = self.deserialize(res)
        self.assertEqual(100, quota['quota']['extra1'])

    def test_delete_quotas_with_admin(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id + '2',
                                                  is_admin=True)}
        res = self.api.delete(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                              extra_environ=env)
        self.assertEqual(204, res.status_int)

    def test_delete_quotas_without_admin_forbidden_returns_403(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=False)}
        res = self.api.delete(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                              extra_environ=env, expect_errors=True)
        self.assertEqual(403, res.status_int)

    def test_quotas_loaded_bad_returns_404(self):
        try:
            res = self.api.get(_get_path('quotas'), expect_errors=True)
            self.assertEqual(404, res.status_int)
        except Exception:
            pass

    def test_quotas_limit_check(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': 5}}
        res = self.api.put(_get_path('quotas', id=tenant_id,
                                     fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota.QUOTAS.limit_check(context.Context('', tenant_id),
                                 tenant_id,
                                 network=4)

    def test_quotas_limit_check_with_invalid_quota_value(self):
        tenant_id = 'tenant_id1'
        with testtools.ExpectedException(exceptions.InvalidQuotaValue):
            quota.QUOTAS.limit_check(context.Context('', tenant_id),
                                     tenant_id,
                                     network=-2)

    def test_quotas_limit_check_with_not_registered_resource_fails(self):
        tenant_id = 'tenant_id1'
        self.assertRaises(exceptions.QuotaResourceUnknown,
                          quota.QUOTAS.limit_check,
                          context.get_admin_context(),
                          tenant_id,
                          foobar=1)

    def test_quotas_get_tenant_from_request_context(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas/tenant', fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual(quota['tenant']['tenant_id'], tenant_id)

    def test_quotas_get_tenant_from_empty_request_context_returns_400(self):
        env = {'neutron.context': context.Context('', '',
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas/tenant', fmt=self.fmt),
                           extra_environ=env, expect_errors=True)
        self.assertEqual(400, res.status_int)

    def test_make_reservation_resource_unknown_raises(self):
        tenant_id = 'tenant_id1'
        self.assertRaises(exceptions.QuotaResourceUnknown,
                          quota.QUOTAS.make_reservation,
                          context.get_admin_context(load_admin_roles=False),
                          tenant_id,
                          {'foobar': 1},
                          plugin=None)

    def test_make_reservation_negative_delta_raises(self):
        tenant_id = 'tenant_id1'
        self.assertRaises(exceptions.InvalidQuotaValue,
                          quota.QUOTAS.make_reservation,
                          context.get_admin_context(load_admin_roles=False),
                          tenant_id,
                          {'network': -1},
                          plugin=None)


class QuotaExtensionCfgTestCase(QuotaExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        cfg.CONF.set_override(
            'quota_driver',
            'neutron.quota.ConfDriver',
            group='QUOTAS')
        super(QuotaExtensionCfgTestCase, self).setUp()

    def test_quotas_default_values(self):
        self._test_quota_default_values(
            {'network': 10,
             'subnet': 10,
             'port': 50,
             'extra1': -1})

    def test_quotas_negative_default_value(self):
        cfg.CONF.set_override(
            'quota_port', -666, group='QUOTAS')
        self._test_quota_default_values(
            {'network': 10,
             'subnet': 10,
             'port': -1,
             'extra1': -1})

    def test_show_quotas_with_admin(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id + '2',
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)

    def test_show_quotas_without_admin_forbidden(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id + '2',
                                                  is_admin=False)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env, expect_errors=True)
        self.assertEqual(403, res.status_int)

    def test_update_quotas_forbidden(self):
        tenant_id = 'tenant_id1'
        quotas = {'quota': {'network': 100}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas),
                           expect_errors=True)
        self.assertEqual(403, res.status_int)

    def test_delete_quotas_forbidden(self):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=False)}
        res = self.api.delete(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                              extra_environ=env, expect_errors=True)
        self.assertEqual(403, res.status_int)


class TestDbQuotaDriver(base.BaseTestCase):
    """Test for neutron.db.quota.driver.DbQuotaDriver."""

    def test_get_tenant_quotas_arg(self):
        """Call neutron.db.quota.driver.DbQuotaDriver._get_quotas."""

        quota_driver = driver.DbQuotaDriver()
        ctx = context.Context('', 'bar')

        foo_quotas = {'network': 5}
        default_quotas = {'network': 10}
        target_tenant = 'foo'

        with mock.patch.object(driver.DbQuotaDriver,
                               'get_tenant_quotas',
                               return_value=foo_quotas) as get_tenant_quotas:

            quotas = quota_driver._get_quotas(ctx,
                                              target_tenant,
                                              default_quotas)

            self.assertEqual(quotas, foo_quotas)
            get_tenant_quotas.assert_called_once_with(ctx,
                                                      default_quotas,
                                                      target_tenant)


class TestQuotaDriverLoad(base.BaseTestCase):
    def setUp(self):
        super(TestQuotaDriverLoad, self).setUp()
        # Make sure QuotaEngine is reinitialized in each test.
        quota.QUOTAS._driver = None

    def _test_quota_driver(self, cfg_driver, loaded_driver,
                           with_quota_db_module=True):
        cfg.CONF.set_override('quota_driver', cfg_driver, group='QUOTAS')
        with mock.patch.dict(sys.modules, {}):
            if (not with_quota_db_module and
                    'neutron.db.quota.driver' in sys.modules):
                del sys.modules['neutron.db.quota.driver']
            driver = quota.QUOTAS.get_driver()
            self.assertEqual(loaded_driver, driver.__class__.__name__)

    def test_quota_db_driver_with_quotas_table(self):
        self._test_quota_driver('neutron.db.quota.driver.DbQuotaDriver',
                                'DbQuotaDriver', True)

    def test_quota_db_driver_fallback_conf_driver(self):
        self._test_quota_driver('neutron.db.quota.driver.DbQuotaDriver',
                                'ConfDriver', False)

    def test_quota_conf_driver(self):
        self._test_quota_driver('neutron.quota.ConfDriver',
                                'ConfDriver', True)
