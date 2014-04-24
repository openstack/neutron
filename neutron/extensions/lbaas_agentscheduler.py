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

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.api.v2 import resource
from neutron.common import constants
from neutron.extensions import agent
from neutron.extensions import loadbalancer
from neutron import manager
from neutron.plugins.common import constants as plugin_const
from neutron import policy
from neutron import wsgi

LOADBALANCER_POOL = 'loadbalancer-pool'
LOADBALANCER_POOLS = LOADBALANCER_POOL + 's'
LOADBALANCER_AGENT = 'loadbalancer-agent'


class PoolSchedulerController(wsgi.Controller):
    def index(self, request, **kwargs):
        lbaas_plugin = manager.NeutronManager.get_service_plugins().get(
            plugin_const.LOADBALANCER)
        if not lbaas_plugin:
            return {'pools': []}

        policy.enforce(request.context,
                       "get_%s" % LOADBALANCER_POOLS,
                       {},
                       plugin=lbaas_plugin)
        return lbaas_plugin.list_pools_on_lbaas_agent(
            request.context, kwargs['agent_id'])


class LbaasAgentHostingPoolController(wsgi.Controller):
    def index(self, request, **kwargs):
        lbaas_plugin = manager.NeutronManager.get_service_plugins().get(
            plugin_const.LOADBALANCER)
        if not lbaas_plugin:
            return

        policy.enforce(request.context,
                       "get_%s" % LOADBALANCER_AGENT,
                       {},
                       plugin=lbaas_plugin)
        return lbaas_plugin.get_lbaas_agent_hosting_pool(
            request.context, kwargs['pool_id'])


class Lbaas_agentscheduler(extensions.ExtensionDescriptor):
    """Extension class supporting LBaaS agent scheduler.
    """

    @classmethod
    def get_name(cls):
        return "Loadbalancer Agent Scheduler"

    @classmethod
    def get_alias(cls):
        return constants.LBAAS_AGENT_SCHEDULER_EXT_ALIAS

    @classmethod
    def get_description(cls):
        return "Schedule pools among lbaas agents"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/lbaas_agent_scheduler/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2013-02-07T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        parent = dict(member_name="agent",
                      collection_name="agents")

        controller = resource.Resource(PoolSchedulerController(),
                                       base.FAULT_MAP)
        exts.append(extensions.ResourceExtension(
            LOADBALANCER_POOLS, controller, parent))

        parent = dict(member_name="pool",
                      collection_name="pools")

        controller = resource.Resource(LbaasAgentHostingPoolController(),
                                       base.FAULT_MAP)
        exts.append(extensions.ResourceExtension(
            LOADBALANCER_AGENT, controller, parent,
            path_prefix=plugin_const.
            COMMON_PREFIXES[plugin_const.LOADBALANCER]))
        return exts

    def get_extended_resources(self, version):
        return {}


class NoEligibleLbaasAgent(loadbalancer.NoEligibleBackend):
    message = _("No eligible loadbalancer agent found "
                "for pool %(pool_id)s.")


class NoActiveLbaasAgent(agent.AgentNotFound):
    message = _("No active loadbalancer agent found "
                "for pool %(pool_id)s.")


class LbaasAgentSchedulerPluginBase(object):
    """REST API to operate the lbaas agent scheduler.

    All of method must be in an admin context.
    """

    @abc.abstractmethod
    def list_pools_on_lbaas_agent(self, context, id):
        pass

    @abc.abstractmethod
    def get_lbaas_agent_hosting_pool(self, context, pool_id):
        pass
