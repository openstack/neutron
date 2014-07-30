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

from neutron.extensions import portbindings
from neutron.openstack.common import log
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
        LOG.debug(_("Attempting to bind port %(port)s on "
                    "network %(network)s"),
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        if vnic_type not in self.supported_vnic_types:
            LOG.debug(_("Refusing to bind due to unsupported vnic_type: %s"),
                      vnic_type)
            return
        for agent in context.host_agents(self.agent_type):
            LOG.debug(_("Checking agent: %s"), agent)
            if agent['alive']:
                for segment in context.network.network_segments:
                    if self.try_to_bind_segment_for_agent(context, segment,
                                                          agent):
                        LOG.debug(_("Bound using segment: %s"), segment)
                        return
            else:
                LOG.warning(_("Attempting to bind with dead agent: %s"),
                            agent)

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
