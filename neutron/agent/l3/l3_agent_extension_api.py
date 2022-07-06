# Copyright 2016 Comcast
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

from neutron.agent.linux import ip_lib


class L3AgentExtensionAPI(object):
    '''Implements the Agent API for the L3 agent.

    Extensions can gain access to this API by overriding the consume_api
    method which has been added to the AgentCoreResourceExtension class.

    The purpose of this API is to give L3 agent extensions access to the
    agent's RouterInfo object.
    '''

    def __init__(self, router_info, router_factory):
        self._router_info = router_info
        self._router_factory = router_factory

    def _local_namespaces(self):
        local_ns_list = ip_lib.list_network_namespaces()
        return set(local_ns_list)

    def get_router_hosting_port(self, port_id):
        """Given a port_id, look up the router associated with that port in
        local namespace. Returns a RouterInfo object (or None if the router
        is not found).
        """
        if port_id:
            local_namespaces = self._local_namespaces()
            for router_info in self._router_info.values():
                if router_info.ns_name in local_namespaces:
                    for port in router_info.internal_ports:
                        if port['id'] == port_id:
                            return router_info

    def get_routers_in_project(self, project_id):
        """Given a project_id, return a list of routers that are all in
        the given project.  Returns empty list if the project_id provided
        doesn't evaluate to True.
        """
        if project_id:
            return [ri for ri in self._router_info.values()
                    if ri.router['project_id'] == project_id]
        else:
            return []

    def is_router_in_namespace(self, router_id):
        """Given a router_id, make sure that the router is in a local
        namespace.
        """
        local_namespaces = self._local_namespaces()
        ri = self._router_info.get(router_id)
        return ri and ri.ns_name in local_namespaces

    def get_router_info(self, router_id):
        """Return RouterInfo for the given router id."""
        return self._router_info.get(router_id)

    def register_router(self, features, router_cls):
        """Register router class with the given features. This is for the
        plugin to override with their own ``router_info`` class.
        """
        self._router_factory.register(features, router_cls)
