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

from neutron_lib import constants
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from pecan import hooks

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.common import rpc as n_rpc
from neutron import manager
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

    def _nova_notify(self, action, resource, *args):
        action_resource = '%s_%s' % (action, resource)
        if not hasattr(self, '_nova_notifier'):
            # this is scoped to avoid a dependency on nova client when nova
            # notifications aren't enabled
            from neutron.notifiers import nova
            self._nova_notifier = nova.Notifier()
        self._nova_notifier.send_network_change(action_resource, *args)

    def _notify_dhcp_agent(self, context, resource_name, action, resources):
        plugin = manager.NeutronManager.get_plugin_for_resource(resource_name)
        notifier_method = '%s.%s.end' % (resource_name, action)
        # use plugin's dhcp notifier, if this is already instantiated
        agent_notifiers = getattr(plugin, 'agent_notifiers', {})
        dhcp_agent_notifier = (
            agent_notifiers.get(constants.AGENT_TYPE_DHCP) or
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        )
        # The DHCP Agent does not accept bulk notifications
        for resource in resources:
            item = {resource_name: resource}
            LOG.debug("Sending DHCP agent notification for: %s", item)
            dhcp_agent_notifier.notify(context, item, notifier_method)

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
            payload = state.request.json.copy()
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
        if not resource_name:
            LOG.debug("Skipping NotifierHook processing as there was no "
                      "resource associated with the request")
            return
        action = pecan_constants.ACTION_MAP.get(state.request.method)
        if not action or action == 'get':
            LOG.debug("No notification will be sent for action: %s", action)
            return
        if utils.is_member_action(utils.get_controller(state)):
            return
        if state.response.status_int > 300:
            LOG.debug("No notification will be sent due to unsuccessful "
                      "status code: %s", state.response.status_int)
            return

        if action == 'delete':
            # The object has been deleted, so we must notify the agent with the
            # data of the original object
            data = {collection_name:
                    state.request.context.get('original_resources', [])}
        else:
            try:
                data = jsonutils.loads(state.response.body)
            except ValueError:
                if not state.response.body:
                    data = {}
        resources = []
        if data:
            if resource_name in data:
                resources = [data[resource_name]]
            elif collection_name in data:
                # This was a bulk request
                resources = data[collection_name]
        # Send a notification only if a resource can be identified in the
        # response. This means that for operations such as add_router_interface
        # no notification will be sent
        if cfg.CONF.dhcp_agent_notification and data:
            self._notify_dhcp_agent(
                neutron_context, resource_name,
                action, resources)
        if cfg.CONF.notify_nova_on_port_data_changes:
            orig = {}
            if action == 'update':
                orig = state.request.context.get('original_resources')[0]
            elif action == 'delete':
                # NOTE(kevinbenton): the nova notifier is a bit strange because
                # it expects the original to be in the last argument on a
                # delete rather than in the 'original_obj' position
                resources = (
                    state.request.context.get('original_resources') or [])
            for resource in resources:
                self._nova_notify(action, resource_name, orig,
                                  {resource_name: resource})

        event = '%s.%s.end' % (resource_name, action)
        if action == 'delete':
            resource_id = state.request.context.get('resource_id')
            payload = {resource_name + '_id': resource_id}
        elif action in ('create', 'update'):
            if not resources:
                # create/update did not complete so no notification
                return
            if len(resources) > 1:
                payload = {collection_name: resources}
            else:
                payload = {resource_name: resources[0]}
        else:
            return
        self._notifier.info(neutron_context, event, payload)
