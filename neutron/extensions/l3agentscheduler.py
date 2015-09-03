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

import abc

from oslo_log import log as logging
import webob.exc

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.api.v2 import resource
from neutron.common import constants
from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron.extensions import agent
from neutron.i18n import _LE
from neutron import manager
from neutron.plugins.common import constants as service_constants
from neutron import policy
from neutron import wsgi


LOG = logging.getLogger(__name__)


L3_ROUTER = 'l3-router'
L3_ROUTERS = L3_ROUTER + 's'
L3_AGENT = 'l3-agent'
L3_AGENTS = L3_AGENT + 's'


class RouterSchedulerController(wsgi.Controller):
    def get_plugin(self):
        plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        if not plugin:
            LOG.error(_LE('No plugin for L3 routing registered to handle '
                          'router scheduling'))
            msg = _('The resource could not be found.')
            raise webob.exc.HTTPNotFound(msg)
        return plugin

    def index(self, request, **kwargs):
        plugin = self.get_plugin()
        policy.enforce(request.context,
                       "get_%s" % L3_ROUTERS,
                       {})
        return plugin.list_routers_on_l3_agent(
            request.context, kwargs['agent_id'])

    def create(self, request, body, **kwargs):
        plugin = self.get_plugin()
        policy.enforce(request.context,
                       "create_%s" % L3_ROUTER,
                       {})
        agent_id = kwargs['agent_id']
        router_id = body['router_id']
        result = plugin.add_router_to_l3_agent(request.context, agent_id,
                                               router_id)
        notify(request.context, 'l3_agent.router.add', router_id, agent_id)
        return result

    def delete(self, request, id, **kwargs):
        plugin = self.get_plugin()
        policy.enforce(request.context,
                       "delete_%s" % L3_ROUTER,
                       {})
        agent_id = kwargs['agent_id']
        result = plugin.remove_router_from_l3_agent(request.context, agent_id,
                                                    id)
        notify(request.context, 'l3_agent.router.remove', id, agent_id)
        return result


class L3AgentsHostingRouterController(wsgi.Controller):
    def get_plugin(self):
        plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        if not plugin:
            LOG.error(_LE('No plugin for L3 routing registered to handle '
                          'router scheduling'))
            msg = _('The resource could not be found.')
            raise webob.exc.HTTPNotFound(msg)
        return plugin

    def index(self, request, **kwargs):
        plugin = self.get_plugin()
        policy.enforce(request.context,
                       "get_%s" % L3_AGENTS,
                       {})
        return plugin.list_l3_agents_hosting_router(
            request.context, kwargs['router_id'])


class L3agentscheduler(extensions.ExtensionDescriptor):
    """Extension class supporting l3 agent scheduler.
    """

    @classmethod
    def get_name(cls):
        return "L3 Agent Scheduler"

    @classmethod
    def get_alias(cls):
        return constants.L3_AGENT_SCHEDULER_EXT_ALIAS

    @classmethod
    def get_description(cls):
        return "Schedule routers among l3 agents"

    @classmethod
    def get_updated(cls):
        return "2013-02-07T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        parent = dict(member_name="agent",
                      collection_name="agents")

        controller = resource.Resource(RouterSchedulerController(),
                                       base.FAULT_MAP)
        exts.append(extensions.ResourceExtension(
            L3_ROUTERS, controller, parent))

        parent = dict(member_name="router",
                      collection_name="routers")

        controller = resource.Resource(L3AgentsHostingRouterController(),
                                       base.FAULT_MAP)
        exts.append(extensions.ResourceExtension(
            L3_AGENTS, controller, parent))
        return exts

    def get_extended_resources(self, version):
        return {}


class InvalidL3Agent(agent.AgentNotFound):
    message = _("Agent %(id)s is not a L3 Agent or has been disabled")


class RouterHostedByL3Agent(exceptions.Conflict):
    message = _("The router %(router_id)s has been already hosted"
                " by the L3 Agent %(agent_id)s.")


class RouterSchedulingFailed(exceptions.Conflict):
    message = _("Failed scheduling router %(router_id)s to"
                " the L3 Agent %(agent_id)s.")


class RouterReschedulingFailed(exceptions.Conflict):
    message = _("Failed rescheduling router %(router_id)s: "
                "no eligible l3 agent found.")


class RouterL3AgentMismatch(exceptions.Conflict):
    message = _("Cannot host %(router_type)s router %(router_id)s "
                "on %(agent_mode)s L3 agent %(agent_id)s.")


class DVRL3CannotAssignToDvrAgent(exceptions.Conflict):
    message = _("Not allowed to manually assign a %(router_type)s "
                "router %(router_id)s from an existing DVR node "
                "to another L3 agent %(agent_id)s.")


class L3AgentSchedulerPluginBase(object):
    """REST API to operate the l3 agent scheduler.

    All of method must be in an admin context.
    """

    @abc.abstractmethod
    def add_router_to_l3_agent(self, context, id, router_id):
        pass

    @abc.abstractmethod
    def remove_router_from_l3_agent(self, context, id, router_id):
        pass

    @abc.abstractmethod
    def list_routers_on_l3_agent(self, context, id):
        pass

    @abc.abstractmethod
    def list_l3_agents_hosting_router(self, context, router_id):
        pass


def notify(context, action, router_id, agent_id):
    info = {'id': agent_id, 'router_id': router_id}
    notifier = n_rpc.get_notifier('router')
    notifier.info(context, action, {'agent': info})
