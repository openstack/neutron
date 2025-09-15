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


class NewBgpBridgeEvent(BGPAgentEvent):
    EVENTS = (BGPAgentEvent.ROW_CREATE, BGPAgentEvent.ROW_UPDATE,)
    TABLE = 'Bridge'

    @staticmethod
    def _get_bgp_bridges(idl):
        # The passed object is an OvsdbIdl object and not an API object so
        # we cannot use db_get() or any other API methods here.
        ovs_entries = list(idl.tables['Open_vSwitch'].rows.values())
        bgp_bridges_text = ovs_entries[0].external_ids.get(
            constants.AGENT_BGP_PEER_BRIDGES, '')
        if bgp_bridges_text:
            return bgp_bridges_text.split(',')
        return []

    @staticmethod
    def _is_bgp_bridge(row):
        # We need to use row._idl because we may not have access to the
        # agent_api yet when handling events on startup.
        bgp_bridges = NewBgpBridgeEvent._get_bgp_bridges(row._idl)
        return row.name in bgp_bridges

    @staticmethod
    def _has_nic_iface(row):
        for port in row.ports:
            iface = port.interfaces[0]
            if iface.type in constants.BGP_BRIDGE_NIC_TYPES:
                return True
        return False

    @staticmethod
    def _nic_iface_added(row, old):
        added_ports = set(row.ports) - set(old.ports)
        return any(port.interfaces[0].type in constants.BGP_BRIDGE_NIC_TYPES
                   for port in added_ports)

    def match_fn(self, event, row, old):
        if not super().match_fn(event, row, old):
            return False

        if not self._is_bgp_bridge(row):
            return False

        if event == BGPAgentEvent.ROW_UPDATE:
            if (not hasattr(old, 'ports') or
                    not self._nic_iface_added(row, old)):
                return False

        return self._has_nic_iface(row)

    def run(self, event, row, old):
        self.bgp_agent.create_bgp_bridge(row.name)
