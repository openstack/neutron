# Copyright 2014 Intel Corporation.
# Copyright 2014 Isaku Yamahata <isaku.yamahata at intel com>
#                               <isaku.yamahata at gmail com>
# All Rights Reserved.
#
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

from neutron_lib import fixture
from oslo_config import cfg
from oslo_utils import uuidutils
from webob import exc
import webtest

from neutron.api import extensions
from neutron.conf import quota as quota_conf
from neutron import manager
from neutron import quota
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit import testlib_api


CORE_PLUGIN = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class ExtensionTestCase(testlib_api.WebTestCase):

    def setup_extension(self, plugin, service_type,
                        extension_class,
                        resource_prefix, plural_mappings=None,
                        translate_resource_name=False,
                        allow_pagination=False, allow_sorting=False,
                        supported_extension_aliases=None,
                        use_quota=False):

        self._resource_prefix = resource_prefix
        self._plural_mappings = plural_mappings or {}
        self._translate_resource_name = translate_resource_name

        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None

        self.useFixture(fixture.APIDefinitionFixture())

        # Create the default configurations
        self.config_parse()

        core_plugin = CORE_PLUGIN if service_type else plugin
        self.setup_coreplugin(core_plugin, load_plugins=False)
        if service_type:
            cfg.CONF.set_override('service_plugins', [plugin])

        self._plugin_patcher = mock.patch(plugin, autospec=True)
        self.plugin = self._plugin_patcher.start()
        instance = self.plugin.return_value
        if service_type:
            instance.get_plugin_type.return_value = service_type
        manager.init()

        if supported_extension_aliases is not None:
            instance.supported_extension_aliases = supported_extension_aliases
        if allow_pagination:
            # instance.__native_pagination_support = True
            native_pagination_attr_name = ("_%s__native_pagination_support"
                                           % instance.__class__.__name__)
            setattr(instance, native_pagination_attr_name, True)
        if allow_sorting:
            # instance.__native_sorting_support = True
            native_sorting_attr_name = ("_%s__native_sorting_support"
                                        % instance.__class__.__name__)
            setattr(instance, native_sorting_attr_name, True)
        if use_quota:
            quota.QUOTAS._driver = None
            cfg.CONF.set_override('quota_driver', quota_conf.QUOTA_DB_DRIVER,
                                  group='QUOTAS')
        setattr(instance, 'path_prefix', resource_prefix)

        class ExtensionTestExtensionManager(object):
            def get_resources(self):
                return extension_class.get_resources()

            def get_actions(self):
                return []

            def get_request_extensions(self):
                return []

        ext_mgr = ExtensionTestExtensionManager()
        self.ext_mdw = test_extensions.setup_extensions_middleware(ext_mgr)
        self.api = webtest.TestApp(self.ext_mdw)

    def _test_entity_delete(self, entity):
        """Does the entity deletion based on naming convention."""
        entity_id = uuidutils.generate_uuid()
        path = self._resource_prefix + '/' if self._resource_prefix else ''
        path += self._plural_mappings.get(entity, entity + 's')
        if self._translate_resource_name:
            path = path.replace('_', '-')
        res = self.api.delete(
            test_base._get_path(path, id=entity_id, fmt=self.fmt))
        delete_entity = getattr(self.plugin.return_value, "delete_" + entity)
        delete_entity.assert_called_with(mock.ANY, entity_id)
        self.assertEqual(exc.HTTPNoContent.code, res.status_int)
