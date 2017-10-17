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

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib.plugins.ml2 import api
from oslo_log import log

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
        return [constants.TYPE_FLAT, constants.TYPE_VLAN]

    def get_mappings(self, agent):
        return agent['configurations'].get('interface_mappings', {})

    def check_vlan_transparency(self, context):
        """Macvtap driver vlan transparency support."""
        return False

    def _is_live_migration(self, context):
        # We cannot just check if
        # context.original['host_id'] != context.current['host_id']
        # This condition is also true, if nova does a reschedule of a
        # instance when something went wrong during spawn. In this case,
        # context.original['host_id'] is set to the failed host.
        # The only safe way to detect a migration is to look into the binding
        # profiles 'migrating_to' attribute, which is set by Nova since patch
        # https://review.openstack.org/#/c/275073/.
        if not context.original:
            # new port
            return False
        port_profile = context.original.get(portbindings.PROFILE)
        if port_profile and port_profile.get('migrating_to', None):
            LOG.debug("Live migration with profile %s detected.", port_profile)
            return True
        else:
            return False

    def try_to_bind_segment_for_agent(self, context, segment, agent):
        if self.check_segment_for_agent(segment, agent):
            vif_details_segment = self.vif_details
            mappings = self.get_mappings(agent)
            interface = mappings[segment['physical_network']]
            network_type = segment[api.NETWORK_TYPE]

            if network_type == constants.TYPE_VLAN:
                vlan_id = segment[api.SEGMENTATION_ID]
                macvtap_src = macvtap_common.get_vlan_device_name(interface,
                                                                  vlan_id)
                vif_details_segment['vlan'] = vlan_id
            else:
                macvtap_src = interface

            if self._is_live_migration(context):
                # We can use the original port here, as during live migration
                # portbinding is done after the migration happened. Nova will
                # not do a reschedule of the instance migration if binding
                # fails, but just set the instance into error state.
                # Due to that we can  be sure that the original port is the
                # migration source port.
                orig_vif_details = context.original[portbindings.VIF_DETAILS]
                orig_source = orig_vif_details[
                    portbindings.VIF_DETAILS_MACVTAP_SOURCE]
                if orig_source != macvtap_src:
                    source_host = context.original[portbindings.HOST_ID]
                    target_host = agent['host']
                    LOG.error("Vif binding denied by mechanism driver. "
                              "MacVTap source device '%(target_dev)s' on "
                              "the migration target '%(target_host)s'is "
                              "not equal to device '%(source_dev)s' on "
                              "the migration source '%(source_host)s. "
                              "Make sure that the "
                              "interface mapping of macvtap "
                              "agent on both hosts is equal "
                              "for the physical network '%(physnet)s'!",
                              {'source_dev': orig_source,
                               'target_dev': macvtap_src,
                               'target_host': target_host,
                               'source_host': source_host,
                               'physnet': segment['physical_network']})
                    return False

            vif_details_segment['physical_interface'] = interface
            vif_details_segment['macvtap_source'] = macvtap_src
            vif_details_segment['macvtap_mode'] = MACVTAP_MODE_BRIDGE
            LOG.debug("Macvtap vif_details added to context binding: %s",
                      vif_details_segment)
            context.set_binding(segment[api.ID], self.vif_type,
                                vif_details_segment)
            return True
        return False
