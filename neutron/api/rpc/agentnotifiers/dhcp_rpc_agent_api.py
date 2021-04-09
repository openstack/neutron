# Copyright (c) 2013 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import random

from neutron_lib.agent import topics
from neutron_lib.api import extensions
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from neutron.common import utils as common_utils

# Priorities - lower value is higher priority
PRIORITY_NETWORK_CREATE = 0
PRIORITY_NETWORK_UPDATE = 1
PRIORITY_NETWORK_DELETE = 2
PRIORITY_SUBNET_UPDATE = 3
PRIORITY_SUBNET_DELETE = 4
# In order to improve port dhcp provisioning when nova concurrently create
# multiple vms, I classify the port_create_end message to two levels, the
# high-level message only cast to one agent, the low-level message cast to all
# other agent. In this way, When there are a large number of ports that need to
# be processed, we can dispatch the high priority message of port to different
# agent, so that the processed port will not block other port's processing in
# other dhcp agents.
PRIORITY_PORT_CREATE_HIGH = 5
PRIORITY_PORT_CREATE_LOW = 6
PRIORITY_PORT_UPDATE = 6
PRIORITY_PORT_DELETE = 6

METHOD_PRIORITY_MAP = {
    'network_create_end': PRIORITY_NETWORK_CREATE,
    'network_update_end': PRIORITY_NETWORK_UPDATE,
    'network_delete_end': PRIORITY_NETWORK_DELETE,
    'subnet_create_end': PRIORITY_SUBNET_UPDATE,
    'subnet_update_end': PRIORITY_SUBNET_UPDATE,
    'subnet_delete_end': PRIORITY_SUBNET_DELETE,
    'port_create_end': PRIORITY_PORT_CREATE_LOW,
    'port_update_end': PRIORITY_PORT_UPDATE,
    'port_delete_end': PRIORITY_PORT_DELETE
}


LOG = logging.getLogger(__name__)


class DhcpAgentNotifyAPI(object):
    """API for plugin to notify DHCP agent.

    This class implements the client side of an rpc interface.  The server side
    is neutron.agent.dhcp.agent.DhcpAgent.  For more information about changing
    rpc interfaces, please see doc/source/contributor/internals/rpc_api.rst.
    """
    # It seems dhcp agent does not support bulk operation
    VALID_RESOURCES = ['network', 'subnet', 'port']
    VALID_METHOD_NAMES = ['network.create.end',
                          'network.update.end',
                          'network.delete.end',
                          'subnet.create.end',
                          'subnet.update.end',
                          'subnet.delete.end',
                          'port.create.end',
                          'port.update.end',
                          'port.delete.end']

    def __init__(self, topic=topics.DHCP_AGENT, plugin=None):
        self._unsubscribed_resources = []
        self._plugin = plugin
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)
        # register callbacks for router interface changes
        registry.subscribe(self._after_router_interface_created,
                           resources.ROUTER_INTERFACE, events.AFTER_CREATE)
        registry.subscribe(self._after_router_interface_deleted,
                           resources.ROUTER_INTERFACE, events.AFTER_DELETE)
        # register callbacks for events pertaining resources affecting DHCP
        callback_resources = (
            resources.NETWORK,
            resources.NETWORKS,
            resources.PORT,
            resources.PORTS,
            resources.SUBNET,
            resources.SUBNETS,
        )
        if not cfg.CONF.dhcp_agent_notification:
            return
        for resource in callback_resources:
            registry.subscribe(self._send_dhcp_notification,
                               resource, events.BEFORE_RESPONSE)
        self.uses_native_notifications = {}
        for resource in (resources.NETWORK, resources.PORT, resources.SUBNET):
            self.uses_native_notifications[resource] = {'create': False,
                                                        'update': False,
                                                        'delete': False}
            registry.subscribe(self._native_event_send_dhcp_notification,
                               resource, events.AFTER_CREATE)
            registry.subscribe(self._native_event_send_dhcp_notification,
                               resource, events.AFTER_UPDATE)
            registry.subscribe(self._native_event_send_dhcp_notification,
                               resource, events.AFTER_DELETE)

    @property
    def plugin(self):
        if self._plugin is None:
            self._plugin = directory.get_plugin()
        return self._plugin

    def _schedule_network(self, context, network, existing_agents):
        """Schedule the network to new agents

        :return: all agents associated with the network
        """
        new_agents = self.plugin.schedule_network(context, network) or []
        if new_agents:
            for agent in new_agents:
                self._cast_message(
                    context, 'network_create_end',
                    {'network': {'id': network['id']},
                     'priority': PRIORITY_NETWORK_CREATE}, agent['host'])
        elif not existing_agents:
            LOG.warning('Unable to schedule network %s: no agents '
                        'available; will retry on subsequent port '
                        'and subnet creation events.',
                        network['id'])
        return new_agents + existing_agents

    def _get_enabled_agents(
            self, context, network_id, network, agents, method, payload):
        """Get the list of agents who can provide services."""
        if not agents:
            return []
        enabled_agents = agents
        if not cfg.CONF.enable_services_on_agents_with_admin_state_down:
            enabled_agents = [x for x in agents if x.admin_state_up]
        active_agents = [x for x in agents if x.is_active]
        len_enabled_agents = len(enabled_agents)
        len_active_agents = len(active_agents)
        if len_active_agents < len_enabled_agents:
            LOG.warning("Only %(active)d of %(total)d DHCP agents "
                        "associated with network '%(net_id)s' "
                        "are marked as active, so notifications "
                        "may be sent to inactive agents.",
                        {'active': len_active_agents,
                         'total': len_enabled_agents,
                         'net_id': network_id})
        if not enabled_agents:
            num_ports = self.plugin.get_ports_count(
                context, {'network_id': [network_id]})
            if not network:
                admin_ctx = (context if context.is_admin else
                             common_utils.get_elevated_context(context))
                network = self.plugin.get_network(admin_ctx, network_id)
            notification_required = (
                num_ports > 0 and len(network['subnets']) >= 1)
            if notification_required:
                LOG.error("Will not send event %(method)s for network "
                          "%(net_id)s: no agent available. Payload: "
                          "%(payload)s",
                          {'method': method,
                           'net_id': network_id,
                           'payload': payload})
        return enabled_agents

    def _is_reserved_dhcp_port(self, port):
        return port.get('device_id') == constants.DEVICE_ID_RESERVED_DHCP_PORT

    def _notify_agents(
            self, context, method, payload, network_id, network=None):
        """Notify all the agents that are hosting the network."""
        payload['priority'] = METHOD_PRIORITY_MAP.get(method)
        # fanout is required as we do not know who is "listening"
        no_agents = not extensions.is_extension_supported(
            self.plugin, constants.DHCP_AGENT_SCHEDULER_EXT_ALIAS)
        fanout_required = method == 'network_delete_end' or no_agents

        # we do nothing on network creation because we want to give the
        # admin the chance to associate an agent to the network manually
        cast_required = method != 'network_create_end'

        if fanout_required:
            self._fanout_message(context, method, payload)
        elif cast_required:
            candidate_hosts = None
            if 'subnet' in payload and payload['subnet'].get('segment_id'):
                # if segment_id exists then the segment service plugin
                # must be loaded
                segment_plugin = directory.get_plugin('segments')
                segment = segment_plugin.get_segment(
                    context, payload['subnet']['segment_id'])
                candidate_hosts = segment['hosts']

            agents = self.plugin.get_dhcp_agents_hosting_networks(
                context, [network_id], hosts=candidate_hosts)
            # schedule the network first, if needed
            schedule_required = (
                method == 'subnet_create_end' or
                method == 'port_create_end' and
                not self._is_reserved_dhcp_port(payload['port']))
            if schedule_required:
                admin_ctx = (context if context.is_admin else
                             common_utils.get_elevated_context(context))
                network = network or self.plugin.get_network(
                    admin_ctx, network_id)
                if candidate_hosts:
                    network['candidate_hosts'] = candidate_hosts
                agents = self._schedule_network(admin_ctx, network, agents)
            if not agents:
                LOG.debug("Network %s is not hosted by any dhcp agent",
                          network_id)
                return
            enabled_agents = self._get_enabled_agents(
                context, network_id, network, agents, method, payload)

            if method == 'port_create_end' and enabled_agents:
                high_agent = enabled_agents.pop(
                    random.randint(0, len(enabled_agents) - 1))
                self._notify_high_priority_agent(
                    context, copy.deepcopy(payload), high_agent)
            for agent in enabled_agents:
                self._cast_message(
                    context, method, payload, agent.host, agent.topic)

    def _notify_high_priority_agent(self, context, payload, agent):
        payload['priority'] = PRIORITY_PORT_CREATE_HIGH
        self._cast_message(context, "port_create_end",
                           payload, agent.host, agent.topic)

    def _cast_message(self, context, method, payload, host,
                      topic=topics.DHCP_AGENT):
        """Cast the payload to the dhcp agent running on the host."""
        cctxt = self.client.prepare(topic=topic, server=host)
        cctxt.cast(context, method, payload=payload)

    def _fanout_message(self, context, method, payload):
        """Fanout the payload to all dhcp agents."""
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, method, payload=payload)

    def network_removed_from_agent(self, context, network_id, host):
        self._cast_message(context, 'network_delete_end',
                           {'network_id': network_id,
                            'priority': PRIORITY_NETWORK_DELETE}, host)

    def network_added_to_agent(self, context, network_id, host):
        self._cast_message(context, 'network_create_end',
                           {'network': {'id': network_id},
                            'priority': PRIORITY_NETWORK_CREATE}, host)

    def agent_updated(self, context, admin_state_up, host):
        self._cast_message(context, 'agent_updated',
                           {'admin_state_up': admin_state_up}, host)

    def _after_router_interface_created(self, resource, event, trigger,
                                        **kwargs):
        self._notify_agents(kwargs['context'], 'port_create_end',
                            {'port': kwargs['port']},
                            kwargs['port']['network_id'])

    def _after_router_interface_deleted(self, resource, event, trigger,
                                        **kwargs):
        self._notify_agents(kwargs['context'], 'port_delete_end',
                            {'port_id': kwargs['port']['id'],
                             'fixed_ips': kwargs['port']['fixed_ips']},
                            kwargs['port']['network_id'])

    def _native_event_send_dhcp_notification(self, resource, event, trigger,
                                             context, **kwargs):
        action = event.replace('after_', '')
        # we unsubscribe the _send_dhcp_notification method now that we know
        # the loaded core plugin emits native resource events
        if resource not in self._unsubscribed_resources:
            self.uses_native_notifications[resource][action] = True
            if all(self.uses_native_notifications[resource].values()):
                # only unsubscribe the API level listener if we are
                # receiving all event types for this resource
                self._unsubscribed_resources.append(resource)
                registry.unsubscribe_by_resource(self._send_dhcp_notification,
                                                 resource)
        method_name = '.'.join((resource, action, 'end'))
        payload = kwargs[resource]
        data = {resource: payload}
        if resource == resources.PORT:
            if self._only_status_changed(kwargs.get('original_port'),
                                         kwargs.get('port')):
                # don't waste time updating the DHCP agent for status updates
                return
        self.notify(context, data, method_name)

    def _only_status_changed(self, orig, new):
        # a status change will manifest as a bumped revision number, a new
        # updated_at timestamp, and a new status. If that's all that changed,
        # return True, else False
        if not orig or not new:
            return False
        if set(orig.keys()) != set(new.keys()):
            return False
        for k in orig.keys():
            if k in ('status', 'updated_at', 'revision_number'):
                continue
            if orig[k] != new[k]:
                return False
        return True

    def _send_dhcp_notification(self, resource, event, trigger, payload=None):
        action = payload.action.split('_')[0]
        if (resource in self.uses_native_notifications and
                self.uses_native_notifications[resource][action]):
            return
        data = payload.latest_state
        if payload.collection_name and payload.collection_name in data:
            for body in data[payload.collection_name]:
                item = {resource: body}
                self.notify(payload.context, item, payload.method_name)
        else:
            self.notify(payload.context, data, payload.method_name)

    def notify(self, context, data, method_name):
        # data is {'key' : 'value'} with only one key
        if method_name not in self.VALID_METHOD_NAMES:
            return
        obj_type = list(data.keys())[0]
        if obj_type not in self.VALID_RESOURCES:
            return
        obj_value = data[obj_type]
        network_id = None
        if obj_type == 'network' and 'id' in obj_value:
            network_id = obj_value['id']
        elif obj_type in ['port', 'subnet'] and 'network_id' in obj_value:
            network_id = obj_value['network_id']
        if not network_id:
            return
        method_name = method_name.replace(".", "_")
        if method_name.endswith("_delete_end"):
            if 'id' in obj_value:
                payload = {obj_type + '_id': obj_value['id']}
                if obj_type != 'network':
                    payload['network_id'] = network_id
                if obj_type == 'port':
                    payload['fixed_ips'] = obj_value['fixed_ips']
                self._notify_agents(context, method_name, payload, network_id,
                                    obj_value.get('network'))
        else:
            self._notify_agents(context, method_name, data, network_id,
                                obj_value.get('network'))
