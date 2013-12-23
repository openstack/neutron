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

from neutron.common import constants
from neutron.common import topics
from neutron.common import utils
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.openstack.common.rpc import proxy


LOG = logging.getLogger(__name__)


class DhcpAgentNotifyAPI(proxy.RpcProxy):
    """API for plugin to notify DHCP agent."""
    BASE_RPC_API_VERSION = '1.0'
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

    def __init__(self, topic=topics.DHCP_AGENT):
        super(DhcpAgentNotifyAPI, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)

    def _get_enabled_dhcp_agents(self, context, network_id):
        """Return enabled dhcp agents associated with the given network."""
        plugin = manager.NeutronManager.get_plugin()
        agents = plugin.get_dhcp_agents_hosting_networks(context, [network_id])
        return [x for x in agents if x.admin_state_up]

    def _notification_host(self, context, method, payload, host):
        """Notify the agent on host."""
        self.cast(
            context, self.make_msg(method,
                                   payload=payload),
            topic='%s.%s' % (topics.DHCP_AGENT, host))

    def _notification(self, context, method, payload, network_id):
        """Notify all the agents that are hosting the network."""
        plugin = manager.NeutronManager.get_plugin()
        if (method != 'network_delete_end' and utils.is_extension_supported(
                plugin, constants.DHCP_AGENT_SCHEDULER_EXT_ALIAS)):
            if method == 'port_create_end':
                # we don't schedule when we create network
                # because we want to give admin a chance to
                # schedule network manually by API
                adminContext = (context if context.is_admin else
                                context.elevated())
                network = plugin.get_network(adminContext, network_id)
                chosen_agents = plugin.schedule_network(adminContext, network)
                if chosen_agents:
                    for agent in chosen_agents:
                        self._notification_host(
                            context, 'network_create_end',
                            {'network': {'id': network_id}},
                            agent['host'])
            agents = self._get_enabled_dhcp_agents(context, network_id)
            if not agents:
                LOG.error(_("No DHCP agents are associated with network "
                            "'%(net_id)s'. Unable to send notification "
                            "for '%(method)s' with payload: %(payload)s"),
                          {
                              'net_id': network_id,
                              'method': method,
                              'payload': payload,
                          })
                return
            active_agents = [x for x in agents if x.is_active]
            if active_agents != agents:
                LOG.warning(_("Only %(active)d of %(total)d DHCP agents "
                              "associated with network '%(net_id)s' are "
                              "marked as active, so notifications may "
                              "be sent to inactive agents."),
                            {
                                'active': len(active_agents),
                                'total': len(agents),
                                'net_id': network_id,
                            })
            for agent in agents:
                self.cast(
                    context, self.make_msg(method,
                                           payload=payload),
                    topic='%s.%s' % (agent.topic, agent.host))
        else:
            # besides the non-agentscheduler plugin,
            # There is no way to query who is hosting the network
            # when the network is deleted, so we need to fanout
            self._notification_fanout(context, method, payload)

    def _notification_fanout(self, context, method, payload):
        """Fanout the payload to all dhcp agents."""
        self.fanout_cast(
            context, self.make_msg(method,
                                   payload=payload),
            topic=topics.DHCP_AGENT)

    def network_removed_from_agent(self, context, network_id, host):
        self._notification_host(context, 'network_delete_end',
                                {'network_id': network_id}, host)

    def network_added_to_agent(self, context, network_id, host):
        self._notification_host(context, 'network_create_end',
                                {'network': {'id': network_id}}, host)

    def agent_updated(self, context, admin_state_up, host):
        self._notification_host(context, 'agent_updated',
                                {'admin_state_up': admin_state_up},
                                host)

    def notify(self, context, data, methodname):
        # data is {'key' : 'value'} with only one key
        if methodname not in self.VALID_METHOD_NAMES:
            return
        obj_type = data.keys()[0]
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
        methodname = methodname.replace(".", "_")
        if methodname.endswith("_delete_end"):
            if 'id' in obj_value:
                self._notification(context, methodname,
                                   {obj_type + '_id': obj_value['id']},
                                   network_id)
        else:
            self._notification(context, methodname, data, network_id)
