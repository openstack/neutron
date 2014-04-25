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

from neutron.plugins.grouppolicy import group_policy_driver_api as api


class GroupPolicyContext(object):
    """GroupPolicy context base class."""
    def __init__(self, plugin, plugin_context):
        self._plugin = plugin
        self._plugin_context = plugin_context


class EndpointContext(GroupPolicyContext, api.EndpointContext):

    def __init__(self, plugin, plugin_context, endpoint,
                 original_endpoint=None):
        super(EndpointContext, self).__init__(plugin, plugin_context)
        self._endpoint = endpoint
        self._original_endpoint = original_endpoint

    @property
    def current(self):
        return self._endpoint

    @property
    def original(self):
        return self._original_endpoint


class EndpointGroupContext(GroupPolicyContext, api.EndpointGroupContext):

    def __init__(self, plugin, plugin_context, endpoint_group,
                 original_endpoint_group=None):
        super(EndpointGroupContext, self).__init__(plugin, plugin_context)
        self._endpoint_group = endpoint_group
        self._original_endpoint_group = original_endpoint_group

    @property
    def current(self):
        return self._endpoint_group

    @property
    def original(self):
        return self._original_endpoint_group


class BridgeDomainContext(GroupPolicyContext, api.BridgeDomainContext):

    def __init__(self, plugin, plugin_context, bridge_domain,
                 original_bridge_domain=None):
        super(BridgeDomainContext, self).__init__(plugin, plugin_context)
        self._bridge_domain = bridge_domain
        self._original_bridge_domain = original_bridge_domain

    @property
    def current(self):
        return self._bridge_domain

    @property
    def original(self):
        return self._original_bridge_domain


class RoutingDomainContext(GroupPolicyContext, api.RoutingDomainContext):

    def __init__(self, plugin, plugin_context, routing_domain,
                 original_routing_domain=None):
        super(RoutingDomainContext, self).__init__(plugin, plugin_context)
        self._routing_domain = routing_domain
        self._original_routing_domain = original_routing_domain

    @property
    def current(self):
        return self._routing_domain

    @property
    def original(self):
        return self._original_routing_domain
