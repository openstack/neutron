# Copyright 2017 Intel Corporation.
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

from unittest import mock

from neutron_lib import context
from neutron_lib import fixture
from oslo_config import cfg
import webtest

from neutron.api import extensions
from neutron.api.v2 import router
from neutron.common import config
from neutron.conf import quota as qconf
from neutron import quota
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit import testlib_api

DEFAULT_QUOTAS_ACTION = 'details'
TARGET_PLUGIN = 'neutron.plugins.ml2.plugin.Ml2Plugin'

_get_path = test_base._get_path


class DetailQuotaExtensionTestCase(testlib_api.WebTestCase):

    def setUp(self):
        super().setUp()
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
        self.plugin.return_value.supported_extension_aliases = \
            ['quotas', 'quota_details']
        # QUOTAS will register the items in conf when starting
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        app = config.load_paste_app('extensions_test_app')
        ext_middleware = extensions.ExtensionMiddleware(app, ext_mgr=ext_mgr)
        self.api = webtest.TestApp(ext_middleware)
        # Initialize the router for the core API in order to ensure core quota
        # resources are registered
        router.APIRouter()


class DetailQuotaExtensionDbTestCase(DetailQuotaExtensionTestCase):
    fmt = 'json'

    def test_show_detail_quotas(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id)}
        res = self.api.get(_get_path('quotas', id=project_id,
                                     fmt=self.fmt,
                                     endpoint=DEFAULT_QUOTAS_ACTION),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual(0, quota['quota']['network']['reserved'])
        self.assertEqual(0, quota['quota']['subnet']['reserved'])
        self.assertEqual(0, quota['quota']['port']['reserved'])
        self.assertEqual(0, quota['quota']['network']['used'])
        self.assertEqual(0, quota['quota']['subnet']['used'])
        self.assertEqual(0, quota['quota']['port']['used'])
        self.assertEqual(qconf.DEFAULT_QUOTA_NETWORK,
                         quota['quota']['network']['limit'])
        self.assertEqual(qconf.DEFAULT_QUOTA_SUBNET,
                         quota['quota']['subnet']['limit'])
        self.assertEqual(qconf.DEFAULT_QUOTA_PORT,
                         quota['quota']['port']['limit'])

    def test_detail_quotas_negative_limit_value(self):
        cfg.CONF.set_override(
            'quota_port', -666, group='QUOTAS')
        cfg.CONF.set_override(
            'quota_network', -10, group='QUOTAS')
        cfg.CONF.set_override(
            'quota_subnet', -50, group='QUOTAS')
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id,
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas', id=project_id,
                                     fmt=self.fmt,
                                     endpoint=DEFAULT_QUOTAS_ACTION),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual(0, quota['quota']['network']['reserved'])
        self.assertEqual(0, quota['quota']['subnet']['reserved'])
        self.assertEqual(0, quota['quota']['port']['reserved'])
        self.assertEqual(0, quota['quota']['network']['used'])
        self.assertEqual(0, quota['quota']['subnet']['used'])
        self.assertEqual(0, quota['quota']['port']['used'])
        self.assertEqual(qconf.DEFAULT_QUOTA,
                         quota['quota']['network']['limit'])
        self.assertEqual(qconf.DEFAULT_QUOTA,
                         quota['quota']['subnet']['limit'])
        self.assertEqual(qconf.DEFAULT_QUOTA,
                         quota['quota']['port']['limit'])

    def test_show_detail_quotas_with_admin(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id + '2',
                                                  is_admin=True)}
        res = self.api.get(_get_path('quotas', id=project_id,
                                     fmt=self.fmt,
                                     endpoint=DEFAULT_QUOTAS_ACTION),
                           extra_environ=env)
        self.assertEqual(200, res.status_int)
        quota = self.deserialize(res)
        self.assertEqual(0, quota['quota']['network']['reserved'])
        self.assertEqual(0, quota['quota']['subnet']['reserved'])
        self.assertEqual(0, quota['quota']['port']['reserved'])
        self.assertEqual(0, quota['quota']['network']['used'])
        self.assertEqual(0, quota['quota']['subnet']['used'])
        self.assertEqual(0, quota['quota']['port']['used'])
        self.assertEqual(qconf.DEFAULT_QUOTA_NETWORK,
                         quota['quota']['network']['limit'])
        self.assertEqual(qconf.DEFAULT_QUOTA_SUBNET,
                         quota['quota']['subnet']['limit'])
        self.assertEqual(qconf.DEFAULT_QUOTA_PORT,
                         quota['quota']['port']['limit'])

    def test_detail_quotas_without_admin_forbidden_returns_403(self):
        project_id = 'project_id1'
        env = {'neutron.context': context.Context('', project_id + '2',
                                                  is_admin=False)}
        res = self.api.get(_get_path('quotas', id=project_id,
                                     fmt=self.fmt,
                                     endpoint=DEFAULT_QUOTAS_ACTION),
                           extra_environ=env, expect_errors=True)
        self.assertEqual(403, res.status_int)
