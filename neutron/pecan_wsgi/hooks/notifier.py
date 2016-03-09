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

from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from pecan import hooks

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.common import constants
from neutron import manager
from neutron.pecan_wsgi import constants as pecan_constants

LOG = log.getLogger(__name__)


class NotifierHook(hooks.PecanHook):
    priority = 135

    # TODO(kevinbenton): implement ceilo notifier

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

    def after(self, state):
        # if the after hook is executed the request completed successfully and
        # therefore notifications must be sent
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
