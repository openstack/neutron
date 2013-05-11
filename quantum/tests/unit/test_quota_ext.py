import mock
from oslo.config import cfg
import testtools
import webtest

from quantum.api import extensions
from quantum.api.v2 import attributes
from quantum.common import config
from quantum.common import exceptions
from quantum import context
from quantum.db import api as db
from quantum import manager
from quantum.plugins.linuxbridge.db import l2network_db_v2
from quantum import quota
from quantum.tests.unit import test_api_v2
from quantum.tests.unit import test_extensions
from quantum.tests.unit import testlib_api

TARGET_PLUGIN = ('quantum.plugins.linuxbridge.lb_quantum_plugin'
                 '.LinuxBridgePluginV2')

_get_path = test_api_v2._get_path


class QuotaExtensionTestCase(testlib_api.WebTestCase):

    def setUp(self):
        super(QuotaExtensionTestCase, self).setUp()
        db._ENGINE = None
        db._MAKER = None
        # Ensure 'stale' patched copies of the plugin are never returned
        manager.QuantumManager._instance = None

        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None

        # Save the global RESOURCE_ATTRIBUTE_MAP
        self.saved_attr_map = {}
        for resource, attrs in attributes.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self.saved_attr_map[resource] = attrs.copy()

        # Create the default configurations
        args = ['--config-file', test_extensions.etcdir('quantum.conf.test')]
        config.parse(args=args)

        # Update the plugin and extensions path
        cfg.CONF.set_override('core_plugin', TARGET_PLUGIN)
        cfg.CONF.set_override(
            'quota_items',
            ['network', 'subnet', 'port', 'extra1'],
            group='QUOTAS')
        quota.QUOTAS = quota.QuotaEngine()
        quota.register_resources_from_config()
        self._plugin_patcher = mock.patch(TARGET_PLUGIN, autospec=True)
        self.plugin = self._plugin_patcher.start()
        self.plugin.return_value.supported_extension_aliases = ['quotas']
        # QUOTAS will regester the items in conf when starting
        # extra1 here is added later, so have to do it manually
        quota.QUOTAS.register_resource_by_name('extra1')
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        l2network_db_v2.initialize()
        app = config.load_paste_app('extensions_test_app')
        ext_middleware = extensions.ExtensionMiddleware(app, ext_mgr=ext_mgr)
        self.api = webtest.TestApp(ext_middleware)

    def tearDown(self):
        self._plugin_patcher.stop()
        self.api = None
        self.plugin = None
        db._ENGINE = None
        db._MAKER = None
        cfg.CONF.reset()

        # Restore the global RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP = self.saved_attr_map
        super(QuotaExtensionTestCase, self).tearDown()


class QuotaExtensionDbTestCase(QuotaExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        cfg.CONF.set_override(
            'quota_driver',
            'quantum.db.quota_db.DbQuotaDriver',
            group='QUOTAS')
        super(QuotaExtensionDbTestCase, self).setUp()

    def test_quotas_loaded_right(self):
        res = self.api.get(_get_path('quotas', fmt=self.fmt))
        quota = self.deserialize(res)
        self.assertEqual([], quota['quotas'])
        self.assertEqual(200, res.status_int)

    def test_quotas_default_values(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env)
        quota = self.deserialize(res)
        self.assertEqual(10, quota['quota']['network'])
        self.assertEqual(10, quota['quota']['subnet'])
        self.assertEqual(50, quota['quota']['port'])
        self.assertEqual(-1, quota['quota']['extra1'])

    def test_show_quotas_with_admin(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id + '2',
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
        env = {'quantum.context': context.Context('', tenant_id + '2',
                                                  is_admin=False)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env, expect_errors=True)
        self.assertEqual(403, res.status_int)

    def test_show_quotas_with_owner_tenant(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id,
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
        env = {'quantum.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas', fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual([], quota['quotas'])

    def test_list_quotas_without_admin_forbidden_returns_403(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id,
                                                  is_admin=False)}
        res = self.api.get(_get_path('quotas', fmt=self.fmt),
                           extra_environ=env, expect_errors=True)
        self.assertEqual(403, res.status_int)

    def test_update_quotas_without_admin_forbidden_returns_403(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id,
                                                  is_admin=False)}
        quotas = {'quota': {'network': 100}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=True)
        self.assertEqual(403, res.status_int)

    def test_update_quotas_with_non_integer_returns_400(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': 'abc'}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=True)
        self.assertEqual(400, res.status_int)

    def test_update_quotas_with_negative_integer_returns_400(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': -2}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=True)
        self.assertEqual(400, res.status_int)

    def test_update_quotas_to_unlimited(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': -1}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=False)
        self.assertEqual(200, res.status_int)

    def test_update_quotas_exceeding_current_limit(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        quotas = {'quota': {'network': 120}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=False)
        self.assertEqual(200, res.status_int)

    def test_update_quotas_with_non_support_resource_returns_400(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        quotas = {'quota': {'abc': 100}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env,
                           expect_errors=True)
        self.assertEqual(400, res.status_int)

    def test_update_quotas_with_admin(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id + '2',
                                                  is_admin=True)}
        quotas = {'quota': {'network': 100}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env)
        self.assertEqual(200, res.status_int)
        env2 = {'quantum.context': context.Context('', tenant_id)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env2)
        quota = self.deserialize(res)
        self.assertEqual(100, quota['quota']['network'])
        self.assertEqual(10, quota['quota']['subnet'])
        self.assertEqual(50, quota['quota']['port'])

    def test_update_attributes(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id + '2',
                                                  is_admin=True)}
        quotas = {'quota': {'extra1': 100}}
        res = self.api.put(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           self.serialize(quotas), extra_environ=env)
        self.assertEqual(200, res.status_int)
        env2 = {'quantum.context': context.Context('', tenant_id)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env2)
        quota = self.deserialize(res)
        self.assertEqual(100, quota['quota']['extra1'])

    def test_delete_quotas_with_admin(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id + '2',
                                                  is_admin=True)}
        res = self.api.delete(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                              extra_environ=env)
        self.assertEqual(204, res.status_int)

    def test_delete_quotas_without_admin_forbidden_returns_403(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id,
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
        env = {'quantum.context': context.Context('', tenant_id,
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

    def test_quotas_get_tenant_from_request_context(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id,
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas/tenant', fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual(quota['tenant']['tenant_id'], tenant_id)

    def test_quotas_get_tenant_from_empty_request_context_returns_400(self):
        env = {'quantum.context': context.Context('', '',
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas/tenant', fmt=self.fmt),
                           extra_environ=env, expect_errors=True)
        self.assertEqual(400, res.status_int)


class QuotaExtensionDbTestCaseXML(QuotaExtensionDbTestCase):
    fmt = 'xml'


class QuotaExtensionCfgTestCase(QuotaExtensionTestCase):
    fmt = 'json'

    def test_quotas_default_values(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env)
        quota = self.deserialize(res)
        self.assertEqual(10, quota['quota']['network'])
        self.assertEqual(10, quota['quota']['subnet'])
        self.assertEqual(50, quota['quota']['port'])
        self.assertEqual(-1, quota['quota']['extra1'])

    def test_show_quotas_with_admin(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id + '2',
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)

    def test_show_quotas_without_admin_forbidden(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id + '2',
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
        env = {'quantum.context': context.Context('', tenant_id,
                                                  is_admin=False)}
        res = self.api.delete(_get_path('quotas', id=tenant_id, fmt=self.fmt),
                              extra_environ=env, expect_errors=True)
        self.assertEqual(403, res.status_int)


class QuotaExtensionCfgTestCaseXML(QuotaExtensionCfgTestCase):
    fmt = 'xml'
