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
from ovsdbapp.backend.ovs_idl import event as row_event

from neutron._i18n import _
from neutron.services.bgp import constants

LOG = log.getLogger(__name__)


def _get_bgp_peer_bridges(row):
    try:
        return row.external_ids[constants.AGENT_BGP_PEER_BRIDGES].split(',')
    except KeyError:
        LOG.warning("Chassis %s does not have BGP configuration but the "
                    "BGP extension is enabled", row.name)
        return []


class BGPAgentEvent(row_event.RowEvent):
    """Base class for BGP agent events."""

    def __init__(self, agent_api):
        self.agent_api = agent_api
        super().__init__(self.EVENTS, self.TABLE, None)

    @property
    def bgp_agent(self):
        if not hasattr(self, '_bgp_agent'):
            try:
                self._bgp_agent = self.agent_api[constants.AGENT_BGP_EXT_NAME]
            except KeyError:
                raise RuntimeError(_("BGP agent is not configured"))
        return self._bgp_agent


class LocalOVSEvent(BGPAgentEvent):
    """Base class for local OVS events."""
    TABLE = 'Open_vSwitch'


class CreateLocalOVSEvent(LocalOVSEvent):
    EVENTS = (LocalOVSEvent.ROW_CREATE,)

    def match_fn(self, event, row, old):
        if constants.AGENT_BGP_PEER_BRIDGES not in row.external_ids:
            LOG.warning("Chassis %s does not have BGP configuration but the "
                        "BGP extension is enabled", self.agent_api.chassis)
            return False
        return True

    def run(self, event, row, old):
        bgp_peer_bridges = _get_bgp_peer_bridges(row)
        ovn_bridge_mappings = row.external_ids.get(
            'ovn-bridge-mappings')
        if ovn_bridge_mappings:
            ovn_bridge_mappings = ovn_bridge_mappings.split(',')
        else:
            ovn_bridge_mappings = []
        self.bgp_agent.configure_bgp_bridge_mappings(
            bgp_peer_bridges, ovn_bridge_mappings)
