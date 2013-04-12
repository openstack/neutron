# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2013 OpenStack Foundation.
# All rights reserved.
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

from abc import abstractmethod

from quantum.api import extensions
from quantum.api.v2 import base
from quantum.api.v2 import resource
from quantum.common import constants
from quantum.common import exceptions
from quantum.extensions import agent
from quantum import manager
from quantum import policy
from quantum import wsgi

DHCP_NET = 'dhcp-network'
DHCP_NETS = DHCP_NET + 's'
DHCP_AGENT = 'dhcp-agent'
DHCP_AGENTS = DHCP_AGENT + 's'
L3_ROUTER = 'l3-router'
L3_ROUTERS = L3_ROUTER + 's'
L3_AGENT = 'l3-agent'
L3_AGENTS = L3_AGENT + 's'


class NetworkSchedulerController(wsgi.Controller):
    def index(self, request, **kwargs):
        plugin = manager.QuantumManager.get_plugin()
        policy.enforce(request.context,
                       "get_%s" % DHCP_NETS,
                       {},
                       plugin=plugin)
        return plugin.list_networks_on_dhcp_agent(
            request.context, kwargs['agent_id'])

    def create(self, request, body, **kwargs):
        plugin = manager.QuantumManager.get_plugin()
        policy.enforce(request.context,
                       "create_%s" % DHCP_NET,
                       {},
                       plugin=plugin)
        return plugin.add_network_to_dhcp_agent(
            request.context, kwargs['agent_id'], body['network_id'])

    def delete(self, request, id, **kwargs):
        plugin = manager.QuantumManager.get_plugin()
        policy.enforce(request.context,
                       "delete_%s" % DHCP_NET,
                       {},
                       plugin=plugin)
        return plugin.remove_network_from_dhcp_agent(
            request.context, kwargs['agent_id'], id)


class RouterSchedulerController(wsgi.Controller):
    def index(self, request, **kwargs):
        plugin = manager.QuantumManager.get_plugin()
        policy.enforce(request.context,
                       "get_%s" % L3_ROUTERS,
                       {},
                       plugin=plugin)
        return plugin.list_routers_on_l3_agent(
            request.context, kwargs['agent_id'])

    def create(self, request, body, **kwargs):
        plugin = manager.QuantumManager.get_plugin()
        policy.enforce(request.context,
                       "create_%s" % L3_ROUTER,
                       {},
                       plugin=plugin)
        return plugin.add_router_to_l3_agent(
            request.context,
            kwargs['agent_id'],
            body['router_id'])

    def delete(self, request, id, **kwargs):
        plugin = manager.QuantumManager.get_plugin()
        policy.enforce(request.context,
                       "delete_%s" % L3_ROUTER,
                       {},
                       plugin=plugin)
        return plugin.remove_router_from_l3_agent(
            request.context, kwargs['agent_id'], id)


class DhcpAgentsHostingNetworkController(wsgi.Controller):
    def index(self, request, **kwargs):
        plugin = manager.QuantumManager.get_plugin()
        policy.enforce(request.context,
                       "get_%s" % DHCP_AGENTS,
                       {},
                       plugin=plugin)
        return plugin.list_dhcp_agents_hosting_network(
            request.context, kwargs['network_id'])


class L3AgentsHostingRouterController(wsgi.Controller):
    def index(self, request, **kwargs):
        plugin = manager.QuantumManager.get_plugin()
        policy.enforce(request.context,
                       "get_%s" % L3_AGENTS,
                       {},
                       plugin=plugin)
        return plugin.list_l3_agents_hosting_router(
            request.context, kwargs['router_id'])


class Agentscheduler(extensions.ExtensionDescriptor):
    """Extension class supporting agent scheduler.
    """

    @classmethod
    def get_name(cls):
        return "Agent Schedulers"

    @classmethod
    def get_alias(cls):
        return constants.AGENT_SCHEDULER_EXT_ALIAS

    @classmethod
    def get_description(cls):
        return "Schedule resources among agents"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/agent_scheduler/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2013-02-03T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        parent = dict(member_name="agent",
                      collection_name="agents")
        controller = resource.Resource(NetworkSchedulerController(),
                                       base.FAULT_MAP)
        exts.append(extensions.ResourceExtension(
            DHCP_NETS, controller, parent))

        controller = resource.Resource(RouterSchedulerController(),
                                       base.FAULT_MAP)
        exts.append(extensions.ResourceExtension(
            L3_ROUTERS, controller, parent))

        parent = dict(member_name="network",
                      collection_name="networks")

        controller = resource.Resource(DhcpAgentsHostingNetworkController(),
                                       base.FAULT_MAP)
        exts.append(extensions.ResourceExtension(
            DHCP_AGENTS, controller, parent))

        parent = dict(member_name="router",
                      collection_name="routers")

        controller = resource.Resource(L3AgentsHostingRouterController(),
                                       base.FAULT_MAP)
        exts.append(extensions.ResourceExtension(
            L3_AGENTS, controller, parent))
        return exts

    def get_extended_resources(self, version):
        return {}


class InvalidDHCPAgent(agent.AgentNotFound):
    message = _("Agent %(id)s is not a valid DHCP Agent or has been disabled")


class NetworkHostedByDHCPAgent(exceptions.Conflict):
    message = _("The network %(network_id)s has been already hosted"
                " by the DHCP Agent %(agent_id)s.")


class NetworkNotHostedByDhcpAgent(exceptions.Conflict):
    message = _("The network %(network_id)s is not hosted"
                " by the DHCP agent %(agent_id)s.")


class InvalidL3Agent(agent.AgentNotFound):
    message = _("Agent %(id)s is not a L3 Agent or has been disabled")


class RouterHostedByL3Agent(exceptions.Conflict):
    message = _("The router %(router_id)s has been already hosted"
                " by the L3 Agent %(agent_id)s.")


class RouterSchedulingFailed(exceptions.Conflict):
    message = _("Failed scheduling router %(router_id)s to"
                " the L3 Agent %(agent_id)s.")


class RouterNotHostedByL3Agent(exceptions.Conflict):
    message = _("The router %(router_id)s is not hosted"
                " by L3 agent %(agent_id)s.")


class AgentSchedulerPluginBase(object):
    """REST API to operate the agent scheduler.

    All of method must be in an admin context.
    """

    @abstractmethod
    def add_network_to_dhcp_agent(self, context, id, network_id):
        pass

    @abstractmethod
    def remove_network_from_dhcp_agent(self, context, id, network_id):
        pass

    @abstractmethod
    def list_networks_on_dhcp_agent(self, context, id):
        pass

    @abstractmethod
    def list_dhcp_agents_hosting_network(self, context, network_id):
        pass

    @abstractmethod
    def add_router_to_l3_agent(self, context, id, router_id):
        pass

    @abstractmethod
    def remove_router_from_l3_agent(self, context, id, router_id):
        pass

    @abstractmethod
    def list_routers_on_l3_agent(self, context, id):
        pass

    @abstractmethod
    def list_l3_agents_hosting_router(self, context, router_id):
        pass
