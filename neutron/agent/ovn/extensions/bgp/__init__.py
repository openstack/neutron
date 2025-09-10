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

from neutron.agent.ovn.agent import ovsdb
from neutron.agent.ovn.extensions.bgp import events
from neutron.agent.ovn.extensions import extension_manager as ovn_ext_mgr

LOG = log.getLogger(__name__)


class BGPAgentExtension(ovn_ext_mgr.OVNAgentExtension):
    @property
    def name(self):
        return "BGP agent extension"

    @property
    def ovs_idl_events(self):
        return [
            events.CreateLocalOVSEvent,
        ]

    @property
    def nb_idl_tables(self):
        return []

    @property
    def nb_idl_events(self):
        return []

    @property
    def sb_idl_tables(self):
        return []

    @property
    def sb_idl_events(self):
        return []

    def configure_bgp_bridge_mappings(
            self, bgp_peer_bridges, ovn_bridge_mappings):
        for bgp_bridge_name in bgp_peer_bridges:
            bgp_bridge_mapping = f'{bgp_bridge_name}:{bgp_bridge_name}'
            if bgp_bridge_mapping not in ovn_bridge_mappings:
                ovn_bridge_mappings.append(bgp_bridge_mapping)
        LOG.debug("Setting OVN bridge mappings: %s", ovn_bridge_mappings)
        ovsdb.set_ovn_bridge_mapping(
            self.agent_api.ovs_idl, ovn_bridge_mappings)
