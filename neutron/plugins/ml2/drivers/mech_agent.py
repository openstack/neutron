# Copyright (c) 2013 OpenStack Foundation
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

import abc

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib.plugins.ml2 import api
from oslo_log import log
import six

from neutron.db import provisioning_blocks

LOG = log.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class AgentMechanismDriverBase(api.MechanismDriver):
    """Base class for drivers that attach to networks using an L2 agent.

    The AgentMechanismDriverBase provides common code for mechanism
    drivers that integrate the ml2 plugin with L2 agents. Port binding
    with this driver requires the driver's associated agent to be
    running on the port's host, and that agent to have connectivity to
    at least one segment of the port's network.

    MechanismDrivers using this base class must pass the agent type to
    __init__(), and must implement try_to_bind_segment_for_agent().
    """

    def __init__(self, agent_type,
                 supported_vnic_types=[portbindings.VNIC_NORMAL]):
        """Initialize base class for specific L2 agent type.

        :param agent_type: Constant identifying agent type in agents_db
        :param supported_vnic_types: The binding:vnic_type values we can bind
        """
        self.agent_type = agent_type
        self.supported_vnic_types = supported_vnic_types

    def initialize(self):
        pass

    def create_port_precommit(self, context):
        self._insert_provisioning_block(context)

    def update_port_precommit(self, context):
        if context.host == context.original_host:
            return
        self._insert_provisioning_block(context)

    def _insert_provisioning_block(self, context):
        # we insert a status barrier to prevent the port from transitioning
        # to active until the agent reports back that the wiring is done
        port = context.current
        if not context.host or port['status'] == const.PORT_STATUS_ACTIVE:
            # no point in putting in a block if the status is already ACTIVE
            return
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        if vnic_type not in self.supported_vnic_types:
            # we check the VNIC type because there could be multiple agents
            # on a single host with different VNIC types
            return
        if context.host_agents(self.agent_type):
            provisioning_blocks.add_provisioning_component(
                context._plugin_context, port['id'], resources.PORT,
                provisioning_blocks.L2_AGENT_ENTITY)

    def bind_port(self, context):
        LOG.debug("Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        if vnic_type not in self.supported_vnic_types:
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return
        agents = context.host_agents(self.agent_type)
        if not agents:
            LOG.debug("Port %(pid)s on network %(network)s not bound, "
                      "no agent of type %(at)s registered on host %(host)s",
                      {'pid': context.current['id'],
                       'at': self.agent_type,
                       'network': context.network.current['id'],
                       'host': context.host})
        for agent in agents:
            LOG.debug("Checking agent: %s", agent)
            if agent['alive']:
                for segment in context.segments_to_bind:
                    if self.try_to_bind_segment_for_agent(context, segment,
                                                          agent):
                        LOG.debug("Bound using segment: %s", segment)
                        return
            else:
                LOG.warning("Refusing to bind port %(pid)s to dead agent: "
                            "%(agent)s",
                            {'pid': context.current['id'], 'agent': agent})

    @abc.abstractmethod
    def try_to_bind_segment_for_agent(self, context, segment, agent):
        """Try to bind with segment for agent.

        :param context: PortContext instance describing the port
        :param segment: segment dictionary describing segment to bind
        :param agent: agents_db entry describing agent to bind
        :returns: True iff segment has been bound for agent

        Called outside any transaction during bind_port() so that
        derived MechanismDrivers can use agent_db data along with
        built-in knowledge of the corresponding agent's capabilities
        to attempt to bind to the specified network segment for the
        agent.

        If the segment can be bound for the agent, this function must
        call context.set_binding() with appropriate values and then
        return True. Otherwise, it must return False.
        """


@six.add_metaclass(abc.ABCMeta)
class SimpleAgentMechanismDriverBase(AgentMechanismDriverBase):
    """Base class for simple drivers using an L2 agent.

    The SimpleAgentMechanismDriverBase provides common code for
    mechanism drivers that integrate the ml2 plugin with L2 agents,
    where the binding:vif_type and binding:vif_details values are the
    same for all bindings. Port binding with this driver requires the
    driver's associated agent to be running on the port's host, and
    that agent to have connectivity to at least one segment of the
    port's network.

    MechanismDrivers using this base class must pass the agent type
    and the values for binding:vif_type and binding:vif_details to
    __init__(), and must implement check_segment_for_agent().
    """

    def __init__(self, agent_type, vif_type, vif_details,
                 supported_vnic_types=[portbindings.VNIC_NORMAL]):
        """Initialize base class for specific L2 agent type.

        :param agent_type: Constant identifying agent type in agents_db
        :param vif_type: Value for binding:vif_type when bound
        :param vif_details: Dictionary with details for VIF driver when bound
        :param supported_vnic_types: The binding:vnic_type values we can bind
        """
        super(SimpleAgentMechanismDriverBase, self).__init__(
            agent_type, supported_vnic_types)
        self.vif_type = vif_type
        self.vif_details = vif_details

    def try_to_bind_segment_for_agent(self, context, segment, agent):
        if self.check_segment_for_agent(segment, agent):
            context.set_binding(segment[api.ID],
                                self.get_vif_type(context, agent, segment),
                                self.get_vif_details(context, agent, segment))
            return True
        else:
            return False

    def get_vif_details(self, context, agent, segment):
        return self.vif_details

    def get_vif_type(self, context, agent, segment):
        """Return the vif type appropriate for the agent and segment."""
        return self.vif_type

    @abc.abstractmethod
    def get_allowed_network_types(self, agent=None):
        """Return the agent's or driver's allowed network types.

        For example: return ('flat', ...). You can also refer to the
        configuration the given agent exposes.
        """
        pass

    @abc.abstractmethod
    def get_mappings(self, agent):
        """Return the agent's bridge or interface mappings.

        For example: agent['configurations'].get('bridge_mappings', {}).
        """
        pass

    def physnet_in_mappings(self, physnet, mappings):
        """Is the physical network part of the given mappings?"""
        return physnet in mappings

    def filter_hosts_with_segment_access(
            self, context, segments, candidate_hosts, agent_getter):

        hosts = set()
        filters = {'host': candidate_hosts, 'agent_type': [self.agent_type]}
        for agent in agent_getter(context, filters=filters):
            if any(self.check_segment_for_agent(s, agent) for s in segments):
                hosts.add(agent['host'])

        return hosts

    def check_segment_for_agent(self, segment, agent):
        """Check if segment can be bound for agent.

        :param segment: segment dictionary describing segment to bind
        :param agent: agents_db entry describing agent to bind
        :returns: True iff segment can be bound for agent

        Called outside any transaction during bind_port so that derived
        MechanismDrivers can use agent_db data along with built-in
        knowledge of the corresponding agent's capabilities to
        determine whether or not the specified network segment can be
        bound for the agent.
        """

        mappings = self.get_mappings(agent)
        allowed_network_types = self.get_allowed_network_types(agent)

        LOG.debug("Checking segment: %(segment)s "
                  "for mappings: %(mappings)s "
                  "with network types: %(network_types)s",
                  {'segment': segment, 'mappings': mappings,
                   'network_types': allowed_network_types})

        network_type = segment[api.NETWORK_TYPE]
        if network_type not in allowed_network_types:
            LOG.debug(
                'Network %(network_id)s with segment %(id)s is type '
                'of %(network_type)s but agent %(agent)s or mechanism driver '
                'only support %(allowed_network_types)s.',
                {'network_id': segment['network_id'],
                 'id': segment['id'],
                 'network_type': network_type,
                 'agent': agent['host'],
                 'allowed_network_types': allowed_network_types})
            return False

        if network_type in [const.TYPE_FLAT, const.TYPE_VLAN]:
            physnet = segment[api.PHYSICAL_NETWORK]
            if not self.physnet_in_mappings(physnet, mappings):
                LOG.debug(
                    'Network %(network_id)s with segment %(id)s is connected '
                    'to physical network %(physnet)s, but agent %(agent)s '
                    'reported physical networks %(mappings)s. '
                    'The physical network must be configured on the '
                    'agent if binding is to succeed.',
                    {'network_id': segment['network_id'],
                     'id': segment['id'],
                     'physnet': physnet,
                     'agent': agent['host'],
                     'mappings': mappings})
                return False

        return True
