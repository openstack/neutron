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

import uuid

import mock
from oslo_config import cfg
from webob import exc
import webtest

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron import quota
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit import testlib_api


class ExtensionTestCase(testlib_api.WebTestCase):
    def _resotre_attr_map(self):
        attributes.RESOURCE_ATTRIBUTE_MAP = self._saved_attr_map

    def _setUpExtension(self, plugin, service_type,
                        resource_attribute_map, extension_class,
                        resource_prefix, plural_mappings=None,
                        translate_resource_name=False,
                        allow_pagination=False, allow_sorting=False,
                        supported_extension_aliases=None,
                        use_quota=False,
                        ):

        self._resource_prefix = resource_prefix
        self._plural_mappings = plural_mappings or {}
        self._translate_resource_name = translate_resource_name

        # Ensure existing ExtensionManager is not used
        extensions.PluginAwareExtensionManager._instance = None

        # Save the global RESOURCE_ATTRIBUTE_MAP
        self._saved_attr_map = attributes.RESOURCE_ATTRIBUTE_MAP.copy()
        # Restore the global RESOURCE_ATTRIBUTE_MAP
        self.addCleanup(self._resotre_attr_map)

        # Create the default configurations
        self.config_parse()

        #just stubbing core plugin with plugin
        self.setup_coreplugin(plugin)
        cfg.CONF.set_override('core_plugin', plugin)
        if service_type:
            cfg.CONF.set_override('service_plugins', [plugin])

        self._plugin_patcher = mock.patch(plugin, autospec=True)
        self.plugin = self._plugin_patcher.start()
        instance = self.plugin.return_value
        if service_type:
            instance.get_plugin_type.return_value = service_type
        if supported_extension_aliases is not None:
            instance.supported_extension_aliases = supported_extension_aliases
        if allow_pagination:
            cfg.CONF.set_override('allow_pagination', True)
            # instance.__native_pagination_support = True
            native_pagination_attr_name = ("_%s__native_pagination_support"
                                           % instance.__class__.__name__)
            setattr(instance, native_pagination_attr_name, True)
        if allow_sorting:
            cfg.CONF.set_override('allow_sorting', True)
            # instance.__native_sorting_support = True
            native_sorting_attr_name = ("_%s__native_sorting_support"
                                        % instance.__class__.__name__)
            setattr(instance, native_sorting_attr_name, True)
        if use_quota:
            quota.QUOTAS._driver = None
            cfg.CONF.set_override('quota_driver', 'neutron.quota.ConfDriver',
                                  group='QUOTAS')

        class ExtensionTestExtensionManager(object):
            def get_resources(self):
                # Add the resources to the global attribute map
                # This is done here as the setup process won't
                # initialize the main API router which extends
                # the global attribute map
                attributes.RESOURCE_ATTRIBUTE_MAP.update(
                    resource_attribute_map)
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
        entity_id = str(uuid.uuid4())
        path = self._resource_prefix + '/' if self._resource_prefix else ''
        path += self._plural_mappings.get(entity, entity + 's')
        if self._translate_resource_name:
            path = path.replace('_', '-')
        res = self.api.delete(
            test_base._get_path(path, id=entity_id, fmt=self.fmt))
        delete_entity = getattr(self.plugin.return_value, "delete_" + entity)
        delete_entity.assert_called_with(mock.ANY, entity_id)
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)
