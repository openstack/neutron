# Copyright (c) 2016 IBM Corp.
#
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

from neutron_lib import constants
from oslo_log import log

from neutron.extensions import portbindings
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.macvtap import macvtap_common
from neutron.plugins.ml2.drivers import mech_agent

LOG = log.getLogger(__name__)

MACVTAP_MODE_BRIDGE = 'bridge'


class MacvtapMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using Macvtap L2 agent.

    The MacvtapMechanismDriver integrates the ml2 plugin with the
    macvtap L2 agent. Port binding with this driver requires the
    macvtap agent to be running on the port's host, and that agent
    to have connectivity to at least one segment of the port's
    network.
    """

    def __init__(self):
        super(MacvtapMechanismDriver, self).__init__(
            constants.AGENT_TYPE_MACVTAP,
            portbindings.VIF_TYPE_MACVTAP,
            {portbindings.CAP_PORT_FILTER: False})

    def get_allowed_network_types(self, agent):
        return [p_constants.TYPE_FLAT, p_constants.TYPE_VLAN]

    def get_mappings(self, agent):
        return agent['configurations'].get('interface_mappings', {})

    def check_vlan_transparency(self, context):
        """Macvtap driver vlan transparency support."""
        return False

    def try_to_bind_segment_for_agent(self, context, segment, agent):
        if self.check_segment_for_agent(segment, agent):
            vif_details_segment = self.vif_details
            mappings = self.get_mappings(agent)
            interface = mappings[segment['physical_network']]
            network_type = segment[api.NETWORK_TYPE]

            if network_type == p_constants.TYPE_VLAN:
                vlan_id = segment[api.SEGMENTATION_ID]
                macvtap_src = macvtap_common.get_vlan_device_name(interface,
                                                                  vlan_id)
                vif_details_segment['vlan'] = vlan_id
            else:
                macvtap_src = interface

            vif_details_segment['physical_interface'] = interface
            vif_details_segment['macvtap_source'] = macvtap_src
            vif_details_segment['macvtap_mode'] = MACVTAP_MODE_BRIDGE
            LOG.debug("Macvtap vif_details added to context binding: %s",
                      vif_details_segment)
            context.set_binding(segment[api.ID], self.vif_type,
                                vif_details_segment)
            return True
        return False
