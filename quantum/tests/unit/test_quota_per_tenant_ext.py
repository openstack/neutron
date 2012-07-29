import unittest
import webtest

import mock

from quantum.api.v2 import attributes
from quantum.common import config
from quantum import context
from quantum.db import api as db
from quantum.extensions import extensions
from quantum import manager
from quantum.openstack.common import cfg
from quantum.plugins.linuxbridge.db import l2network_db_v2
from quantum import quota
from quantum.tests.unit import test_api_v2
from quantum.tests.unit import test_extensions


TARGET_PLUGIN = ('quantum.plugins.linuxbridge.lb_quantum_plugin'
                 '.LinuxBridgePluginV2')


_get_path = test_api_v2._get_path


class QuotaExtensionTestCase(unittest.TestCase):

    def setUp(self):
        if getattr(self, 'testflag', 1) == 1:
            self._setUp1()
        else:
            self._setUp2()

    def _setUp1(self):
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
            'quota_driver',
            'quantum.extensions._quotav2_driver.DbQuotaDriver',
            group='QUOTAS')
        cfg.CONF.set_override(
            'quota_items',
            ['network', 'subnet', 'port', 'extra1'],
            group='QUOTAS')

        self._plugin_patcher = mock.patch(TARGET_PLUGIN, autospec=True)
        self.plugin = self._plugin_patcher.start()
        # QUOTAS will regester the items in conf when starting
        # extra1 here is added later, so have to do it manually
        quota.QUOTAS.register_resource_by_name('extra1')
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        l2network_db_v2.initialize()
        app = config.load_paste_app('extensions_test_app')
        ext_middleware = extensions.ExtensionMiddleware(app, ext_mgr=ext_mgr)
        self.api = webtest.TestApp(ext_middleware)

    def _setUp2(self):
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
        self._plugin_patcher = mock.patch(TARGET_PLUGIN, autospec=True)
        self.plugin = self._plugin_patcher.start()
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

    def test_quotas_loaded_right(self):
        res = self.api.get(_get_path('quotas'))
        self.assertEquals(200, res.status_int)

    def test_quotas_defaul_values(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id)}
        res = self.api.get(_get_path('quotas', id=tenant_id),
                           extra_environ=env)
        self.assertEquals(10, res.json['quota']['network'])
        self.assertEquals(10, res.json['quota']['subnet'])
        self.assertEquals(50, res.json['quota']['port'])
        self.assertEquals(-1, res.json['quota']['extra1'])

    def test_show_quotas_with_admin(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id + '2',
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas', id=tenant_id),
                           extra_environ=env)
        self.assertEquals(200, res.status_int)

    def test_show_quotas_without_admin_forbidden(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id + '2',
                                                  is_admin=False)}
        res = self.api.get(_get_path('quotas', id=tenant_id),
                           extra_environ=env, expect_errors=True)
        self.assertEquals(403, res.status_int)

    def test_update_quotas_without_admin_forbidden(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id,
                                                  is_admin=False)}
        quotas = {'quota': {'network': 100}}
        res = self.api.put_json(_get_path('quotas', id=tenant_id,
                                          fmt='json'),
                                quotas, extra_environ=env,
                                expect_errors=True)
        self.assertEquals(403, res.status_int)

    def test_update_quotas_with_admin(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id + '2',
                                                  is_admin=True)}
        quotas = {'quota': {'network': 100}}
        res = self.api.put_json(_get_path('quotas', id=tenant_id, fmt='json'),
                                quotas, extra_environ=env)
        self.assertEquals(200, res.status_int)
        env2 = {'quantum.context': context.Context('', tenant_id)}
        res = self.api.get(_get_path('quotas', id=tenant_id),
                           extra_environ=env2).json
        self.assertEquals(100, res['quota']['network'])

    def test_delete_quotas_with_admin(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id + '2',
                                                  is_admin=True)}
        res = self.api.delete(_get_path('quotas', id=tenant_id, fmt='json'),
                              extra_environ=env)
        self.assertEquals(204, res.status_int)

    def test_delete_quotas_without_admin_forbidden(self):
        tenant_id = 'tenant_id1'
        env = {'quantum.context': context.Context('', tenant_id,
                                                  is_admin=False)}
        res = self.api.delete(_get_path('quotas', id=tenant_id, fmt='json'),
                              extra_environ=env, expect_errors=True)
        self.assertEquals(403, res.status_int)

    def test_quotas_loaded_bad(self):
        self.testflag = 2
        try:
            res = self.api.get(_get_path('quotas'), expect_errors=True)
            self.assertEquals(404, res.status_int)
        except Exception:
            pass
        self.testflag = 1
