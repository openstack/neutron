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
import six

from oslo_log import log

from neutron.extensions import portbindings
from neutron.i18n import _LW
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2 import driver_api as api

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
        for agent in context.host_agents(self.agent_type):
            LOG.debug("Checking agent: %s", agent)
            if agent['alive']:
                for segment in context.segments_to_bind:
                    if self.try_to_bind_segment_for_agent(context, segment,
                                                          agent):
                        LOG.debug("Bound using segment: %s", segment)
                        return
            else:
                LOG.warning(_LW("Refusing to bind port %(pid)s to dead agent: "
                                "%(agent)s"),
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
                                self.vif_type,
                                self.vif_details)
            return True
        else:
            return False

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
                'Network %(network_id)s is of type %(network_type)s '
                'but agent %(agent)s or mechanism driver only '
                'support %(allowed_network_types)s.',
                {'network_id': segment['id'],
                 'network_type': network_type,
                 'agent': agent['host'],
                 'allowed_network_types': allowed_network_types})
            return False

        if network_type in [p_constants.TYPE_FLAT, p_constants.TYPE_VLAN]:
            physnet = segment[api.PHYSICAL_NETWORK]
            if not self.physnet_in_mappings(physnet, mappings):
                LOG.debug(
                    'Network %(network_id)s is connected to physical '
                    'network %(physnet)s, but agent %(agent)s reported '
                    'physical networks %(mappings)s. '
                    'The physical network must be configured on the '
                    'agent if binding is to succeed.',
                    {'network_id': segment['id'],
                     'physnet': physnet,
                     'agent': agent['host'],
                     'mappings': mappings})
                return False

        return True
