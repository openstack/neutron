# Copyright 2025 Red Hat, Inc.
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

from oslo_log import log

from neutron.agent.ovn.extensions.bgp import bridge
from neutron.agent.ovn.extensions.bgp import events
from neutron.agent.ovn.extensions import extension_manager as ovn_ext_mgr

LOG = log.getLogger(__name__)


class BGPAgentExtension(ovn_ext_mgr.OVNAgentExtension):
    def __init__(self):
        super().__init__()
        # A map of bridge names to the bridge object
        # Example: {
        #     'br-eth1': BGPChassisBridge('br-eth1'),
        #     'br-eth2': BGPChassisBridge('br-eth2'),
        # }
        self.bgp_bridges = {}

    @property
    def name(self):
        return "BGP agent extension"

    @property
    def ovs_idl_events(self):
        return [
            events.CreateLocalOVSEvent,
            events.NewBgpBridgeEvent,
        ]

    @property
    def nb_idl_tables(self):
        return []

    @property
    def nb_idl_events(self):
        return []

    @property
    def sb_idl_tables(self):
        return [
            'Port_Binding',
        ]

    @property
    def sb_idl_events(self):
        return [
            events.PortBindingLrpMacEvent,
        ]

    def create_bgp_bridge(self, bridge_name):
        bgp_bridge = bridge.BGPChassisBridge(self, bridge_name)
        self.bgp_bridges[bridge_name] = bgp_bridge
        return bgp_bridge

    def watch_port_created_event(self, bgp_bridge, port_type):
        # Check the port doesn't exist on the bridge
        ports_ofports = bgp_bridge.ovs_bridge.get_iface_ofports_by_type(
            port_type)

        if not ports_ofports:
            LOG.debug("Waiting for a %s port creation on bridge %s",
                      port_type, bgp_bridge.name)
            event_handler = self.agent_api.ovs_idl.idl.notify_handler
            event = events.BGPBridgePortCreatedEvent(
                self.agent_api, bgp_bridge.name, port_type)
            event_handler.watch_event(event)

            # Check the port again in case it was created in the meantime
            ports_ofports = (
                bgp_bridge.ovs_bridge.get_iface_ofports_by_type(port_type))

            # FIXME(jlibosva): Check if there could be a race condition here
            #                  where we receive the event, it configures the
            #                  flows but then we still check here and configure
            #                  the flows again.
            if ports_ofports:
                LOG.debug(
                    "The %s port was created in the meantime on bridge %s "
                    "with ofport %d, removing the onetime event from the "
                    "queue.", bgp_bridge.name, ports_ofports[0])
                event_handler.unwatch_event(event)
                if bgp_bridge.check_requirements_for_flows_met():
                    bgp_bridge.configure_flows()
        else:
            LOG.debug("The BGP bridge %s already has a %s port with ofport"
                      " %d", bgp_bridge.name, port_type, ports_ofports[0])
            if bgp_bridge.check_requirements_for_flows_met():
                bgp_bridge.configure_flows()
