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
from unittest import mock

from neutron_lib import context
from neutron_lib.db import constants
from neutron_lib import exceptions
from neutron_lib import fixture
from oslo_config import cfg
import testtools
from webob import exc
import webtest

from neutron.api import extensions
from neutron.api.v2 import router
from neutron.common import config
from neutron.conf import quota as qconf
from neutron.db.quota import driver
from neutron.db.quota import driver_nolock
from neutron.db.quota import driver_null
from neutron import quota
from neutron.quota import resource_registry
from neutron.tests import base
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit import testlib_api

DEFAULT_QUOTAS_ACTION = 'default'
TARGET_PLUGIN = 'neutron.plugins.ml2.plugin.Ml2Plugin'

_get_path = test_base._get_path


class QuotaExtensionTestCase(testlib_api.WebTestCase):

    def setUp(self):
        super(QuotaExtensionTestCase, self).setUp()
        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None

        self.useFixture(fixture.APIDefinitionFixture())

        # Create the default configurations
        self.config_parse()

        # Update the plugin and extensions path
        self.setup_coreplugin('ml2')
        quota.QUOTAS = quota.QuotaEngine()
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

    def _test_quota_default_values(self, expected_values):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id)}
        res = self.api.get(_get_path('quotas', id=project_id, fmt=self.fmt),
                           extra_environ=env)
        quota = self.deserialize(res)
        for resource, expected_value in expected_values.items():
            self.assertEqual(expected_value,
                             quota['quota'][resource])


class QuotaExtensionDbTestCase(QuotaExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        cfg.CONF.set_override(
            'quota_driver', qconf.QUOTA_DB_DRIVER, group='QUOTAS')
        super(QuotaExtensionDbTestCase, self).setUp()

    def test_quotas_loaded_right(self):
        res = self.api.get(_get_path('quotas', fmt=self.fmt))
        quota = self.deserialize(res)
        self.assertEqual([], quota['quotas'])
        self.assertEqual(200, res.status_int)

    def test_quotas_default_values(self):
        self._test_quota_default_values(
            {'network': qconf.DEFAULT_QUOTA_NETWORK,
             'subnet': qconf.DEFAULT_QUOTA_SUBNET,
             'port': qconf.DEFAULT_QUOTA_PORT,
             'extra1': qconf.DEFAULT_QUOTA})

    def test_quotas_negative_default_value(self):
        cfg.CONF.set_override(
            'quota_port', -666, group='QUOTAS')
        cfg.CONF.set_override(
            'quota_network', -10, group='QUOTAS')
        cfg.CONF.set_override(
            'quota_subnet', -50, group='QUOTAS')
        self._test_quota_default_values(
            {'network': qconf.DEFAULT_QUOTA,
             'subnet': qconf.DEFAULT_QUOTA,
             'port': qconf.DEFAULT_QUOTA,
             'extra1': qconf.DEFAULT_QUOTA})

    def test_show_default_quotas_with_admin(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id + '2',
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas', id=project_id,
                                     action=DEFAULT_QUOTAS_ACTION,
                                     fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual(
            qconf.DEFAULT_QUOTA_NETWORK, quota['quota']['network'])
        self.assertEqual(
            qconf.DEFAULT_QUOTA_SUBNET, quota['quota']['subnet'])
        self.assertEqual(
            qconf.DEFAULT_QUOTA_PORT, quota['quota']['port'])

    def test_show_default_quotas_with_owner_project(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=False)}
        res = self.api.get(_get_path('quotas', id=project_id,
                                     action=DEFAULT_QUOTAS_ACTION,
                                     fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual(
            qconf.DEFAULT_QUOTA_NETWORK, quota['quota']['network'])
        self.assertEqual(
            qconf.DEFAULT_QUOTA_SUBNET, quota['quota']['subnet'])
        self.assertEqual(
            qconf.DEFAULT_QUOTA_PORT, quota['quota']['port'])

    def test_show_default_quotas_without_admin_forbidden_returns_403(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id + '2',
                                                  is_admin=False)}
        res = self.api.get(_get_path('quotas', id=project_id,
                                     action=DEFAULT_QUOTAS_ACTION,
                                     fmt=self.fmt),
                           extra_environ=env, expect_errors=True)
        self.assertEqual(403, res.status_int)

    def test_show_quotas_with_admin(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id + '2',
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas', id=project_id, fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual(
            qconf.DEFAULT_QUOTA_NETWORK, quota['quota']['network'])
        self.assertEqual(
            qconf.DEFAULT_QUOTA_SUBNET, quota['quota']['subnet'])
        self.assertEqual(
            qconf.DEFAULT_QUOTA_PORT, quota['quota']['port'])

    def test_show_quotas_without_admin_forbidden_returns_403(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id + '2',
                                                  is_admin=False)}
        res = self.api.get(_get_path('quotas', id=project_id, fmt=self.fmt),
                           extra_environ=env, expect_errors=True)
        self.assertEqual(403, res.status_int)

    def test_show_quotas_with_owner_project(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=False)}
        res = self.api.get(_get_path('quotas', id=project_id, fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual(
            qconf.DEFAULT_QUOTA_NETWORK, quota['quota']['network'])
        self.assertEqual(
            qconf.DEFAULT_QUOTA_SUBNET, quota['quota']['subnet'])
        self.assertEqual(
            qconf.DEFAULT_QUOTA_PORT, quota['quota']['port'])

    def test_list_quotas_with_admin(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas', fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual([], quota['quotas'])

    def test_list_quotas_without_admin_forbidden_returns_403(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=False)}
        res = self.api.get(_get_path('quotas', fmt=self.fmt),
                           extra_environ=env, expect_errors=True)
        self.assertEqual(403, res.status_int)

    def test_update_quotas_without_admin_forbidden_returns_403(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=False)}
        quotas = {'quota': {'network': 100}}
        res = self.api.put(_get_path('quotas', id=project_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=True)
        self.assertEqual(403, res.status_int)

    def test_update_quotas_with_non_integer_returns_400(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': 'abc'}}
        res = self.api.put(_get_path('quotas', id=project_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=True)
        self.assertEqual(400, res.status_int)

    def test_update_quotas_with_negative_integer_returns_400(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': -2}}
        res = self.api.put(_get_path('quotas', id=project_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=True)
        self.assertEqual(400, res.status_int)

    def test_update_quotas_with_out_of_range_integer_returns_400(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': constants.DB_INTEGER_MAX_VALUE + 1}}
        res = self.api.put(_get_path('quotas', id=project_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=True)
        self.assertEqual(exc.HTTPBadRequest.code, res.status_int)

    def test_update_quotas_to_unlimited(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': -1}}
        res = self.api.put(_get_path('quotas', id=project_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=False)
        self.assertEqual(200, res.status_int)

    def test_update_quotas_exceeding_current_limit(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': 120}}
        res = self.api.put(_get_path('quotas', id=project_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=False)
        self.assertEqual(200, res.status_int)

    def test_update_quotas_with_non_support_resource_returns_400(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=True)}
        quotas = {'quota': {'abc': 100}}
        res = self.api.put(_get_path('quotas', id=project_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=True)
        self.assertEqual(400, res.status_int)

    def test_update_quotas_with_admin(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id + '2',
                                                  is_admin=True)}
        quotas = {'quota': {'network': 100}}
        res = self.api.put(_get_path('quotas', id=project_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env)
        self.assertEqual(200, res.status_int)
        env2 = {'neutron.context': context.Context('', project_id)}
        res = self.api.get(_get_path('quotas', id=project_id, fmt=self.fmt),
                           extra_environ=env2)
        quota = self.deserialize(res)
        self.assertEqual(100, quota['quota']['network'])
        self.assertEqual(qconf.DEFAULT_QUOTA_SUBNET, quota['quota']['subnet'])
        self.assertEqual(qconf.DEFAULT_QUOTA_PORT, quota['quota']['port'])

    def test_update_attributes(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id + '2',
                                                  is_admin=True)}
        quotas = {'quota': {'extra1': 100}}
        res = self.api.put(_get_path('quotas', id=project_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env)
        self.assertEqual(200, res.status_int)
        env2 = {'neutron.context': context.Context('', project_id)}
        res = self.api.get(_get_path('quotas', id=project_id, fmt=self.fmt),
                           extra_environ=env2)
        quota = self.deserialize(res)
        self.assertEqual(100, quota['quota']['extra1'])

    @mock.patch.object(driver_nolock.DbQuotaNoLockDriver, 'get_resource_usage')
    def test_update_quotas_check_limit(self, mock_get_resource_usage):
        tenant_id = 'tenant_id1'
        env = {'neutron.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': 100, 'check_limit': False}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=False)
        self.assertEqual(200, res.status_int)

        quotas = {'quota': {'network': 50, 'check_limit': True}}
        mock_get_resource_usage.return_value = 51
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=True)
        self.assertEqual(400, res.status_int)

    def test_delete_quotas_with_admin(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id + '2',
                                                  is_admin=True)}
        # Create a quota to ensure we have something to delete
        quotas = {'quota': {'network': 100}}
        self.api.put(_get_path('quotas', id=project_id, fmt=self.fmt),
                     self.serialize(quotas), extra_environ=env)
        res = self.api.delete(_get_path('quotas', id=project_id, fmt=self.fmt),
                              extra_environ=env)
        self.assertEqual(204, res.status_int)

    def test_delete_quotas_without_admin_forbidden_returns_403(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=False)}
        res = self.api.delete(_get_path('quotas', id=project_id, fmt=self.fmt),
                              extra_environ=env, expect_errors=True)
        self.assertEqual(403, res.status_int)

    def test_delete_quota_with_unknown_project_returns_404(self):
        project_id = 'idnotexist'
        env = {'neutron.context': context.Context('', project_id + '2',
                                                  is_admin=True)}
        res = self.api.delete(_get_path('quotas', id=project_id, fmt=self.fmt),
                              extra_environ=env, expect_errors=True)
        self.assertEqual(exc.HTTPNotFound.code, res.status_int)

    def test_quotas_loaded_bad_returns_404(self):
        try:
            res = self.api.get(_get_path('quotas'), expect_errors=True)
            self.assertEqual(404, res.status_int)
        except Exception:
            pass

    def test_quotas_limit_check(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': 5}}
        res = self.api.put(_get_path('quotas', id=project_id,
                                     fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota.QUOTAS.limit_check(context.Context('', project_id),
                                 project_id,
                                 network=4)

    def test_quotas_limit_check_with_invalid_quota_value(self):
        project_id = 'project_id1'
        with testtools.ExpectedException(exceptions.InvalidQuotaValue):
            quota.QUOTAS.limit_check(context.Context('', project_id),
                                     project_id,
                                     network=-2)

    def test_quotas_limit_check_with_not_registered_resource_fails(self):
        project_id = 'project_id1'
        self.assertRaises(exceptions.QuotaResourceUnknown,
                          quota.QUOTAS.limit_check,
                          context.get_admin_context(),
                          project_id,
                          foobar=1)

    def test_quotas_get_project_from_request_context(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=True)}
        # NOTE(ralonsoh): the Quota API keeps "tenant" and "project" methods
        # for compatibility. "tenant" is already deprecated and will be
        # removed.
        for key in ('project', 'tenant'):
            res = self.api.get(_get_path('quotas/' + key, fmt=self.fmt),
                               extra_environ=env)
            self.assertEqual(200, res.status_int)
            quota = self.deserialize(res)
            self.assertEqual(quota[key][key + '_id'], project_id)

    def test_quotas_get_project_from_empty_request_context_returns_400(self):
        env = {'neutron.context': context.Context('', '',
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas/tenant', fmt=self.fmt),
                           extra_environ=env, expect_errors=True)
        self.assertEqual(400, res.status_int)

    def test_make_reservation_resource_unknown_raises(self):
        project_id = 'project_id1'
        self.assertRaises(exceptions.QuotaResourceUnknown,
                          quota.QUOTAS.make_reservation,
                          context.get_admin_context(),
                          project_id,
                          {'foobar': 1},
                          plugin=None)

    def test_make_reservation_negative_delta_raises(self):
        project_id = 'project_id1'
        self.assertRaises(exceptions.InvalidQuotaValue,
                          quota.QUOTAS.make_reservation,
                          context.get_admin_context(),
                          project_id,
                          {'network': -1},
                          plugin=None)


class QuotaExtensionCfgTestCase(QuotaExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        cfg.CONF.set_override(
            'quota_driver', qconf.QUOTA_DB_DRIVER, group='QUOTAS')
        super(QuotaExtensionCfgTestCase, self).setUp()

    def test_quotas_default_values(self):
        self._test_quota_default_values(
            {'network': qconf.DEFAULT_QUOTA_NETWORK,
             'subnet': qconf.DEFAULT_QUOTA_SUBNET,
             'port': qconf.DEFAULT_QUOTA_PORT,
             'extra1': qconf.DEFAULT_QUOTA})

    def test_quotas_negative_default_value(self):
        cfg.CONF.set_override(
            'quota_port', -666, group='QUOTAS')
        self._test_quota_default_values(
            {'network': qconf.DEFAULT_QUOTA_NETWORK,
             'subnet': qconf.DEFAULT_QUOTA_SUBNET,
             'port': qconf.DEFAULT_QUOTA,
             'extra1': qconf.DEFAULT_QUOTA})

    def test_show_quotas_with_admin(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id + '2',
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas', id=project_id, fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)

    def test_show_quotas_without_admin_forbidden(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id + '2',
                                                  is_admin=False)}
        res = self.api.get(_get_path('quotas', id=project_id, fmt=self.fmt),
                           extra_environ=env, expect_errors=True)
        self.assertEqual(403, res.status_int)

    def test_update_quotas_forbidden(self):
        project_id = 'project_id1'
        quotas = {'quota': {'network': 100}}
        res = self.api.put(_get_path('quotas', id=project_id, fmt=self.fmt),
                           self.serialize(quotas),
                           expect_errors=True)
        self.assertEqual(200, res.status_int)

    def test_delete_quotas_forbidden(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=False)}
        res = self.api.delete(_get_path('quotas', id=project_id, fmt=self.fmt),
                              extra_environ=env, expect_errors=True)
        self.assertEqual(403, res.status_int)


class TestDbQuotaDriver(base.BaseTestCase):
    """Test for neutron.db.quota.driver.DbQuotaDriver."""

    def test_get_project_quotas_arg(self):
        """Call neutron.db.quota.driver.DbQuotaDriver._get_quotas."""

        quota_driver = driver.DbQuotaDriver()
        ctx = context.Context('', 'bar')

        foo_quotas = {'network': 5}
        default_quotas = {'network': 10}
        target_project = 'foo'

        with mock.patch.object(driver.DbQuotaDriver,
                               'get_project_quotas',
                               return_value=foo_quotas) as get_project_quotas:

            quotas = quota_driver._get_quotas(ctx,
                                              target_project,
                                              default_quotas)

            self.assertEqual(quotas, foo_quotas)
            get_project_quotas.assert_called_once_with(ctx,
                                                      default_quotas,
                                                      target_project)


class TestQuotaDriverLoad(base.BaseTestCase):

    MODULE_CLASS = [
        (qconf.QUOTA_DB_DRIVER_LEGACY, driver.DbQuotaDriver),
        (qconf.QUOTA_DB_DRIVER_NO_LOCK, driver_nolock.DbQuotaNoLockDriver),
        (qconf.QUOTA_DB_DRIVER_NULL, driver_null.DbQuotaDriverNull),
    ]

    def _test_quota_driver(self, module, cfg_driver, loaded_driver):
        quota.QUOTAS._driver = None
        cfg.CONF.set_override('quota_driver', cfg_driver, group='QUOTAS')
        with mock.patch.dict(sys.modules, {}):
            if module in sys.modules:
                del sys.modules[quota.QUOTA_DB_MODULE]
            driver = quota.QUOTAS.get_driver()
            self.assertEqual(loaded_driver, driver.__class__.__name__)

    def test_quota_driver_load(self):
        for module, klass in self.MODULE_CLASS:
            self._test_quota_driver(
                module,
                '.'.join([klass.__module__, klass.__name__]),
                klass.__name__)
