# Copyright (c) 2015 Mirantis, Inc.
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

from pecan import abort
from pecan import hooks

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import router

from neutron import manager


class ResourceIdentifierHook(hooks.PecanHook):

    priority = 95

    def before(self, state):
        # TODO(kevinbenton): find a better way to look this up. maybe something
        # in the pecan internals somewhere?
        state.request.resource_type = None
        try:
            url_type = state.request.path.split('/')[2].rsplit('.', 1)[0]
        except IndexError:
            return
        if url_type == 'extensions':
            return
        for plural, single in attributes.PLURALS.items():
            if plural == url_type:
                state.request.resource_type = single
                state.request.plugin = self._plugin_for_resource(single)
                return
        abort(404, detail='Resource: %s' % url_type)

    def _plugin_for_resource(self, resource):
        # NOTE(kevinbenton): memoizing the responses to this had no useful
        # performance improvement so I avoided it to keep complexity and
        # risks of memory leaks low.
        if resource in router.RESOURCES:
            # this is a core resource, return the core plugin
            return manager.NeutronManager.get_plugin()
        try:
            ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
            # find the plugin that supports this extension
            # TODO(kevinbenton): fix this. it incorrectly assumes the alias
            # matches the resource. need to walk extensions and build map
            for plugin in ext_mgr.plugins.values():
                if (hasattr(plugin, 'supported_extension_aliases') and
                        resource in plugin.supported_extension_aliases):
                    return plugin
        except KeyError:
            pass
        abort(404, detail='Resource: %s' % resource)
