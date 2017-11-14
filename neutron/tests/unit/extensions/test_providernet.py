# Copyright 2013 VMware
# All rights reserved.
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

import mock
from neutron_lib.api.definitions import provider_net
from neutron_lib import context
from neutron_lib import fixture
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import uuidutils
from webob import exc as web_exc
import webtest

from neutron.api import extensions
from neutron.api.v2 import router
from neutron.extensions import providernet as pnet
from neutron import quota
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit import testlib_api


class ProviderExtensionManager(object):

    def get_resources(self):
        return []

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []

    def get_extended_resources(self, version):
        return pnet.Providernet().get_extended_resources(version)


class ProvidernetExtensionTestCase(testlib_api.WebTestCase):
    fmt = 'json'

    def setUp(self):
        super(ProvidernetExtensionTestCase, self).setUp()

        plugin = 'neutron.neutron_plugin_base_v2.NeutronPluginBaseV2'

        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None

        self.useFixture(fixture.APIDefinitionFixture())

        # Update the plugin and extensions path
        self.setup_coreplugin(plugin, load_plugins=False)
        self._plugin_patcher = mock.patch(plugin, autospec=True)
        self.plugin = self._plugin_patcher.start()
        # Ensure Quota checks never fail because of mock
        instance = self.plugin.return_value
        instance.get_networks_count.return_value = 1
        # Register mock plugin and enable the 'provider' extension
        instance.supported_extension_aliases = ["provider"]
        directory.add_plugin(constants.CORE, instance)
        ext_mgr = ProviderExtensionManager()
        self.ext_mdw = test_extensions.setup_extensions_middleware(ext_mgr)
        self.addCleanup(self._plugin_patcher.stop)
        self.api = webtest.TestApp(router.APIRouter())

        quota.QUOTAS._driver = None
        cfg.CONF.set_override('quota_driver', 'neutron.quota.ConfDriver',
                              group='QUOTAS')

    def _prepare_net_data(self):
        return {'name': 'net1',
                provider_net.NETWORK_TYPE: 'sometype',
                provider_net.PHYSICAL_NETWORK: 'physnet',
                provider_net.SEGMENTATION_ID: 666}

    def _put_network_with_provider_attrs(self, ctx, expect_errors=False):
        data = self._prepare_net_data()
        env = {'neutron.context': ctx}
        instance = self.plugin.return_value
        instance.get_network.return_value = {'tenant_id': ctx.tenant_id,
                                             'shared': False}
        net_id = uuidutils.generate_uuid()
        res = self.api.put(test_base._get_path('networks',
                                               id=net_id,
                                               fmt=self.fmt),
                           self.serialize({'network': data}),
                           extra_environ=env,
                           expect_errors=expect_errors)
        return res, data, net_id

    def _post_network_with_provider_attrs(self, ctx, expect_errors=False):
        data = self._prepare_net_data()
        env = {'neutron.context': ctx}
        res = self.api.post(test_base._get_path('networks', fmt=self.fmt),
                            self.serialize({'network': data}),
                            content_type='application/' + self.fmt,
                            extra_environ=env,
                            expect_errors=expect_errors)
        return res, data

    def _post_network_with_bad_provider_attrs(self, ctx, bad_data,
                                              expect_errors=False):
        data = self._prepare_net_data()
        data.update(bad_data)
        env = {'neutron.context': ctx}
        res = self.api.post(test_base._get_path('networks', fmt=self.fmt),
                            self.serialize({'network': data}),
                            content_type='application/' + self.fmt,
                            extra_environ=env,
                            expect_errors=expect_errors)
        return res, data

    def test_network_create_with_provider_attrs(self):
        ctx = context.get_admin_context()
        tenant_id = 'an_admin'
        ctx.tenant_id = tenant_id
        res, data = self._post_network_with_provider_attrs(ctx)
        instance = self.plugin.return_value
        exp_input = {'network': data}
        exp_input['network'].update({'admin_state_up': True,
                                     'tenant_id': tenant_id,
                                     'project_id': tenant_id,
                                     'shared': False})
        instance.create_network.assert_called_with(mock.ANY,
                                                   network=exp_input)
        self.assertEqual(web_exc.HTTPCreated.code, res.status_int)

    def test_network_create_with_bad_provider_attrs_400(self):
        ctx = context.get_admin_context()
        ctx.tenant_id = 'an_admin'
        bad_data = {provider_net.SEGMENTATION_ID: "abc"}
        res, _1 = self._post_network_with_bad_provider_attrs(ctx, bad_data,
                                                             True)
        self.assertEqual(web_exc.HTTPBadRequest.code, res.status_int)

    def test_network_update_with_provider_attrs(self):
        ctx = context.get_admin_context()
        ctx.tenant_id = 'an_admin'
        res, data, net_id = self._put_network_with_provider_attrs(ctx)
        instance = self.plugin.return_value
        exp_input = {'network': data}
        instance.update_network.assert_called_with(mock.ANY,
                                                   net_id,
                                                   network=exp_input)
        self.assertEqual(web_exc.HTTPOk.code, res.status_int)

    def test_network_create_with_provider_attrs_noadmin_returns_403(self):
        tenant_id = 'no_admin'
        ctx = context.Context('', tenant_id, is_admin=False)
        res, _1 = self._post_network_with_provider_attrs(ctx, True)
        self.assertEqual(web_exc.HTTPForbidden.code, res.status_int)

    def test_network_update_with_provider_attrs_noadmin_returns_403(self):
        tenant_id = 'no_admin'
        ctx = context.Context('', tenant_id, is_admin=False)
        res, _1, _2 = self._put_network_with_provider_attrs(ctx, True)
        self.assertEqual(web_exc.HTTPForbidden.code, res.status_int)
