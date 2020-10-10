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
import uuid

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib.placement import utils as place_utils
from neutron_lib.plugins.ml2 import api
from oslo_log import log

from neutron._i18n import _
from neutron.db import provisioning_blocks

LOG = log.getLogger(__name__)


class AgentMechanismDriverBase(api.MechanismDriver, metaclass=abc.ABCMeta):
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
        super(AgentMechanismDriverBase, self).__init__()
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
                if (vnic_type == portbindings.VNIC_SMARTNIC and not
                        agent['configurations'].get('baremetal_smartnic')):
                    LOG.debug('Agent on host %s can not bind SmartNIC '
                              'port %s', agent['host'], context.current['id'])
                    continue
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

    def prohibit_list_supported_vnic_types(self, vnic_types, prohibit_list):
        """Validate the prohibit_list and prohibit the supported_vnic_types

        :param vnic_types: The supported_vnic_types list
        :param prohibit_list: The prohibit_list as in vnic_type_prohibit_list
        :return The prohibited vnic_types
        """
        if not prohibit_list:
            return vnic_types

        # Not valid values in the prohibit_list:
        if not all(bl in vnic_types for bl in prohibit_list):
            raise ValueError(_("Not all of the items from "
                               "vnic_type_prohibit_list "
                               "are valid vnic_types for %(agent)s mechanism "
                               "driver. The valid values are: "
                               "%(valid_vnics)s.") %
                             {'agent': self.agent_type,
                              'valid_vnics': vnic_types})

        supported_vnic_types = [vnic_t for vnic_t in vnic_types if
                                vnic_t not in prohibit_list]

        # Nothing left in the supported vnict types list:
        if len(supported_vnic_types) < 1:
            raise ValueError(_("All possible vnic_types were prohibited for "
                               "%s mechanism driver!") % self.agent_type)
        return supported_vnic_types

    def _possible_agents_for_port(self, context):
        agent_filters = {
            'host': [context.current['binding:host_id']],
            'agent_type': [self.agent_type],
            'admin_state_up': [True],
            # By not filtering for 'alive' we may report being responsible
            # and still not being able to handle the binding. But that case
            # will be properly logged and handled very soon. That is when
            # trying to bind with a dead agent.
        }
        return context._plugin.get_agents(
            context._plugin_context,
            filters=agent_filters,
        )

    def responsible_for_ports_allocation(self, context):
        """Report if an agent is responsible for a resource provider.

        :param context: PortContext instance describing the port
        :returns: True for responsible, False for not responsible

        An agent based mechanism driver is reponsible for a resource provider
        if an agent of it is responsible for that resource provider. An agent
        reports responsibility by including the resource provider in the
        configurations field of the agent heartbeat.
        """
        uuid_ns = self.resource_provider_uuid5_namespace
        if uuid_ns is None:
            return False
        if 'allocation' not in context.current['binding:profile']:
            return False

        rp = uuid.UUID(context.current['binding:profile']['allocation'])
        host_agents = self._possible_agents_for_port(context)

        reported = {}
        for agent in host_agents:
            if 'resource_provider_bandwidths' in agent['configurations']:
                for device in agent['configurations'][
                        'resource_provider_bandwidths'].keys():
                    device_rp_uuid = place_utils.device_resource_provider_uuid(
                        namespace=uuid_ns,
                        host=agent['host'],
                        device=device)
                    if device_rp_uuid == rp:
                        reported[agent['id']] = agent

        if len(reported) == 1:
            agent = list(reported.values())[0]
            LOG.debug("Agent %(agent)s of type %(agent_type)s reports to be "
                      "responsible for resource provider %(rsc_provider)s",
                      {'agent': agent['id'],
                       'agent_type': agent['agent_type'],
                       'rsc_provider': rp})
            return True
        elif len(reported) > 1:
            LOG.error("Agent misconfiguration, multiple agents on the same "
                      "host %(host)s reports being responsible for resource "
                      "provider %(rsc_provider)s: %(agents)s",
                      {'host': context.current['binding:host_id'],
                       'rsc_provider': rp,
                       'agents': reported.keys()})
            return False
        else:
            # not responsible, must be somebody else
            return False


class SimpleAgentMechanismDriverBase(AgentMechanismDriverBase,
                                     metaclass=abc.ABCMeta):
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
        self.vif_details = {portbindings.VIF_DETAILS_CONNECTIVITY:
                            portbindings.CONNECTIVITY_LEGACY}
        self.vif_details.update(vif_details)

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

    def get_supported_vif_type(self, agent):
        """Return supported vif type appropriate for the agent."""
        return self.vif_type

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
