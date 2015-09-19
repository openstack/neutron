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


class MemberActionHook(hooks.PecanHook):

    priority = 95

    def before(self, state):
        # TODO(salv-orlando): This hook must go. Handling actions like this is
        # shameful
        resource = state.request.context.get('resource')
        if not resource:
            return
        try:
            # Remove the format suffix if any
            uri = state.request.path.rsplit('.', 1)[0].split('/')[2:]
            if not uri:
                # there's nothing to process in the URI
                return
        except IndexError:
            return
        collection = None
        for (collection, res) in attributes.PLURALS.items():
            if res == resource:
                break
        else:
            return
        state.request.member_action = self._parse_action(
            resource, collection, uri[1:])

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
            if (ext.collection == collection and action in ext.member_actions):
                return action
        # Action or resource extension not found
        if action:
            abort(404, detail="Action %(action)s for resource "
                              "%(resource)s undefined" %
                              {'action': action,
                               'resource': resource})
