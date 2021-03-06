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

from neutron_lib.api.definitions import agent as agent_apidef
from neutron_lib.api.definitions import dhcpagentscheduler as apidef
from neutron_lib.api.definitions import network as net_apidef
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import faults
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log as logging

from neutron.api import extensions
from neutron.api.v2 import resource
from neutron import policy
from neutron import wsgi

LOG = logging.getLogger(__name__)


class NetworkSchedulerController(wsgi.Controller):
    def index(self, request, **kwargs):
        plugin = directory.get_plugin()
        policy.enforce(request.context,
                       "get_%s" % apidef.DHCP_NETS,
                       {})
        return plugin.list_networks_on_dhcp_agent(
            request.context, kwargs['agent_id'])

    def create(self, request, body, **kwargs):
        plugin = directory.get_plugin()
        policy.enforce(request.context,
                       "create_%s" % apidef.DHCP_NET,
                       {})
        agent_id = kwargs['agent_id']
        network_id = body['network_id']
        result = plugin.add_network_to_dhcp_agent(request.context, agent_id,
                                                  network_id)
        notify(request.context, 'dhcp_agent.network.add', network_id, agent_id)
        return result

    def delete(self, request, id, **kwargs):
        plugin = directory.get_plugin()
        policy.enforce(request.context,
                       "delete_%s" % apidef.DHCP_NET,
                       {})
        agent_id = kwargs['agent_id']
        result = plugin.remove_network_from_dhcp_agent(request.context,
                                                       agent_id, id)
        notify(request.context, 'dhcp_agent.network.remove', id, agent_id)
        return result


class DhcpAgentsHostingNetworkController(wsgi.Controller):
    def index(self, request, **kwargs):
        plugin = directory.get_plugin()
        policy.enforce(request.context,
                       "get_%s" % apidef.DHCP_AGENTS,
                       {})
        return plugin.list_dhcp_agents_hosting_network(
            request.context, kwargs['network_id'])


class Dhcpagentscheduler(api_extensions.APIExtensionDescriptor):
    """Extension class supporting dhcp agent scheduler.
    """

    api_definition = apidef

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        parent = dict(member_name=agent_apidef.RESOURCE_NAME,
                      collection_name=agent_apidef.COLLECTION_NAME)
        controller = resource.Resource(NetworkSchedulerController(),
                                       faults.FAULT_MAP)
        exts.append(extensions.ResourceExtension(
            apidef.DHCP_NETS, controller, parent))

        parent = dict(member_name=net_apidef.RESOURCE_NAME,
                      collection_name=net_apidef.COLLECTION_NAME)

        controller = resource.Resource(DhcpAgentsHostingNetworkController(),
                                       faults.FAULT_MAP)
        exts.append(extensions.ResourceExtension(
            apidef.DHCP_AGENTS, controller, parent))
        return exts


class DhcpAgentSchedulerPluginBase(object, metaclass=abc.ABCMeta):
    """REST API to operate the DHCP agent scheduler.

    All of method must be in an admin context.
    """

    @abc.abstractmethod
    def add_network_to_dhcp_agent(self, context, id, network_id):
        pass

    @abc.abstractmethod
    def remove_network_from_dhcp_agent(self, context, id, network_id):
        pass

    @abc.abstractmethod
    def list_networks_on_dhcp_agent(self, context, id):
        pass

    @abc.abstractmethod
    def list_dhcp_agents_hosting_network(self, context, network_id):
        pass


def notify(context, action, network_id, agent_id):
    info = {'id': agent_id, 'network_id': network_id}
    notifier = n_rpc.get_notifier('network')
    notifier.info(context, action, {'agent': info})


def disable_extension_by_config(aliases):
    if not cfg.CONF.enable_traditional_dhcp:
        if 'dhcp_agent_scheduler' in aliases:
            aliases.remove('dhcp_agent_scheduler')
        LOG.info('Disabled dhcp_agent_scheduler extension.')
