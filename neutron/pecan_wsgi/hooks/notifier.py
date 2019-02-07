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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import rpc as n_rpc
from oslo_log import log
from pecan import hooks

from neutron.pecan_wsgi import constants as pecan_constants
from neutron.pecan_wsgi.hooks import utils

LOG = log.getLogger(__name__)


class NotifierHook(hooks.PecanHook):
    priority = 135

    @property
    def _notifier(self):
        if not hasattr(self, '_notifier_inst'):
            self._notifier_inst = n_rpc.get_notifier('network')
        return self._notifier_inst

    def before(self, state):
        if state.request.method not in ('POST', 'PUT', 'DELETE'):
            return
        resource = state.request.context.get('resource')
        if not resource:
            return
        if utils.is_member_action(utils.get_controller(state)):
            return
        action = pecan_constants.ACTION_MAP.get(state.request.method)
        event = '%s.%s.start' % (resource, action)
        if action in ('create', 'update'):
            # notifier just gets plain old body without any treatment other
            # than the population of the object ID being operated on
            try:
                payload = state.request.json.copy()
                if not payload:
                    return
            except ValueError:
                return
            if action == 'update':
                payload['id'] = state.request.context.get('resource_id')
        elif action == 'delete':
            resource_id = state.request.context.get('resource_id')
            payload = {resource + '_id': resource_id}
        self._notifier.info(state.request.context.get('neutron_context'),
                            event, payload)

    def after(self, state):
        resource_name = state.request.context.get('resource')
        collection_name = state.request.context.get('collection')
        neutron_context = state.request.context.get('neutron_context')
        action = pecan_constants.ACTION_MAP.get(state.request.method)
        if not action or action not in ('create', 'update', 'delete'):
            return
        if utils.is_member_action(utils.get_controller(state)):
            return
        if not resource_name:
            LOG.debug("Skipping NotifierHook processing as there was no "
                      "resource associated with the request")
            return
        if state.response.status_int > 300:
            LOG.debug("No notification will be sent due to unsuccessful "
                      "status code: %s", state.response.status_int)
            return

        original = {}
        if (action in ('delete', 'update') and
                state.request.context.get('original_resources', [])):
            # We only need the original resource for updates and deletes
            original = state.request.context.get('original_resources')[0]
        if action == 'delete':
            # The object has been deleted, so we must notify the agent with the
            # data of the original object as the payload, but we do not need
            # to pass it in as the original
            result = {resource_name: original}
            original = {}
        else:
            if not state.response.body:
                result = {}
            else:
                result = state.response.json

        notifier_method = '%s.%s.end' % (resource_name, action)
        notifier_action = utils.get_controller(state).plugin_handlers[action]
        registry.publish(resource_name, events.BEFORE_RESPONSE, self,
                         payload=events.APIEventPayload(
                             neutron_context, notifier_method, notifier_action,
                             request_body=state.request.body,
                             states=(original, result,),
                             collection_name=collection_name))

        if action == 'delete':
            resource_id = state.request.context.get('resource_id')
            result[resource_name + '_id'] = resource_id

        self._notifier.info(neutron_context, notifier_method, result)
