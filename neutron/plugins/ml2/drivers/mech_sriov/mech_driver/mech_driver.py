# Copyright 2014 Mellanox Technologies, Ltd
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

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib.plugins.ml2 import api
from oslo_log import log

from neutron.plugins.ml2.drivers import mech_agent
from neutron.plugins.ml2.drivers.mech_sriov.mech_driver \
    import exceptions as exc
from neutron.services.qos.drivers.sriov import driver as sriov_qos_driver


LOG = log.getLogger(__name__)
FLAT_VLAN = 0


class SriovNicSwitchMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Mechanism Driver for SR-IOV capable NIC based switching.

    The SriovNicSwitchMechanismDriver integrates the ml2 plugin with the
    sriovNicSwitch L2 agent depending on configuration option.
    Port binding with this driver may require the sriovNicSwitch agent
    to be running on the port's host, and that agent to have connectivity
    to at least one segment of the port's network.
    L2 agent is not essential for port binding; port binding is handled by
    VIF Driver via libvirt domain XML.
    L2 Agent presents in  order to manage port update events.
    """

    def __init__(self,
                 agent_type=constants.AGENT_TYPE_NIC_SWITCH,
                 vif_details={portbindings.CAP_PORT_FILTER: False},
                 supported_vnic_types=[portbindings.VNIC_DIRECT,
                                       portbindings.VNIC_MACVTAP,
                                       portbindings.VNIC_DIRECT_PHYSICAL]):
        """Initialize base class for SriovNicSwitch L2 agent type.

        :param agent_type: Constant identifying agent type in agents_db
        :param vif_details: Dictionary with details for VIF driver when bound
        :param supported_vnic_types: The binding:vnic_type values we can bind
        """
        self.agent_type = agent_type
        self.supported_vnic_types = supported_vnic_types
        # NOTE(ndipanov): PF passthrough requires a different vif type
        self.vnic_type_for_vif_type = (
            {vtype: portbindings.VIF_TYPE_HOSTDEV_PHY
                if vtype == portbindings.VNIC_DIRECT_PHYSICAL
                else portbindings.VIF_TYPE_HW_VEB
             for vtype in self.supported_vnic_types})
        self.vif_details = vif_details
        sriov_qos_driver.register()

    def get_allowed_network_types(self, agent):
        return (constants.TYPE_FLAT, constants.TYPE_VLAN)

    def get_mappings(self, agent):
        return agent['configurations'].get('device_mappings', {})

    def bind_port(self, context):
        LOG.debug("Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        profile = context.current.get(portbindings.PROFILE)
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        capabilities = []
        if profile:
            capabilities = profile.get('capabilities', [])
        if (vnic_type == portbindings.VNIC_DIRECT and
            'switchdev' in capabilities):
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s "
                      "with switchdev capability", portbindings.VNIC_DIRECT)
            return
        if vnic_type not in self.supported_vnic_types:
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return

        if vnic_type == portbindings.VNIC_DIRECT_PHYSICAL:
            # Physical functions don't support things like QoS properties,
            # spoof checking, etc. so we might as well side-step the agent
            # for now. The agent also doesn't currently recognize non-VF
            # PCI devices so we won't get port status change updates
            # either. This should be changed in the future so physical
            # functions can use device mapping checks and the plugin can
            # get port status updates.
            for segment in context.segments_to_bind:
                if self.try_to_bind_segment_for_agent(context, segment,
                                                      agent=None):
                    break
            return

        for agent in context.host_agents(self.agent_type):
            LOG.debug("Checking agent: %s", agent)
            if agent['alive']:
                for segment in context.segments_to_bind:
                    if self.try_to_bind_segment_for_agent(context, segment,
                                                          agent):
                        return
            else:
                LOG.warning("Attempting to bind with dead agent: %s", agent)

    def try_to_bind_segment_for_agent(self, context, segment, agent):
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_DIRECT)
        vif_type = self.vnic_type_for_vif_type.get(
            vnic_type, portbindings.VIF_TYPE_HW_VEB)

        if not self.check_segment_for_agent(segment, agent):
            return False
        port_status = (constants.PORT_STATUS_ACTIVE if agent is None
                       else constants.PORT_STATUS_DOWN)
        context.set_binding(segment[api.ID],
                            vif_type,
                            self._get_vif_details(segment),
                            port_status)
        LOG.debug("Bound using segment: %s", segment)
        return True

    def check_segment_for_agent(self, segment, agent=None):
        """Check if segment can be bound.

        :param segment: segment dictionary describing segment to bind
        :param agent: agents_db entry describing agent to bind or None
        :returns: True if segment can be bound for agent
        """
        network_type = segment[api.NETWORK_TYPE]
        if network_type in self.get_allowed_network_types(agent):
            if agent:
                mappings = self.get_mappings(agent)
                LOG.debug("Checking segment: %(segment)s "
                          "for mappings: %(mappings)s ",
                          {'segment': segment, 'mappings': mappings})
                return segment[api.PHYSICAL_NETWORK] in mappings
            return True
        return False

    def check_vlan_transparency(self, context):
        """SR-IOV driver vlan transparency support."""
        return True

    def _get_vif_details(self, segment):
        network_type = segment[api.NETWORK_TYPE]
        if network_type == constants.TYPE_FLAT:
            vlan_id = FLAT_VLAN
        elif network_type == constants.TYPE_VLAN:
            vlan_id = segment[api.SEGMENTATION_ID]
        else:
            raise exc.SriovUnsupportedNetworkType(net_type=network_type)
        vif_details = self.vif_details.copy()
        vif_details[portbindings.VIF_DETAILS_VLAN] = str(vlan_id)
        return vif_details
