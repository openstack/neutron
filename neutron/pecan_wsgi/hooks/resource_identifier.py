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
        # TODO(salv-orlando): try and leverage _lookup to this aim. Also remove
        # the "special" code path for "actions"
        state.request.resource_type = None
        try:
            # TODO(blogan): remove this dirty hack and do a better solution
            # needs to work with /v2.0, /v2.0/ports, and /v2.0/ports.json
            uri = state.request.path
            if not uri.endswith('.json'):
                uri += '.json'
            # Remove the format suffix if any
            uri = uri.rsplit('.', 1)[0].split('/')[2:]
            if not uri:
                # there's nothing to process in the URI
                return
        except IndexError:
            return
        resource_type = uri[0]
        if resource_type == 'extensions':
            return
        for plural, single in attributes.PLURALS.items():
            if plural == resource_type:
                state.request.resource_type = single
                state.request.plugin = self._plugin_for_resource(single)
                state.request.member_action = self._parse_action(
                    single, plural, uri[1:])
                return
        abort(404, detail='Resource: %s' % resource_type)

    def _parse_action(self, resource, collection, remainder):
        # NOTE(salv-orlando): This check is revolting and makes me
        # puke, but avoids silly failures when dealing with API actions
        # such as "add_router_interface".
        if len(remainder) > 1:
            action = remainder[1]
        else:
            return
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        resource_exts = ext_mgr.get_resources()
        for ext in resource_exts:
            if (ext.collection == collection and
                action in ext.member_actions):
                return action
        # Action or resource extension not found
        if action:
            abort(404, detail="Action %(action)s for resource "
                              "%(resource)s undefined" %
                              {'action': action,
                               'resource': resource})

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
