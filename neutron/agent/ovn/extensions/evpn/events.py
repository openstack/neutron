# Copyright 2026 Red Hat, Inc.
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

from neutron.agent.ovn.extensions.evpn import exceptions as evpn_exc
from neutron.agent.ovn.extensions.evpn import fsm as evpn_fsm
from neutron.common.ovn import constants as ovn_const
from neutron.services.evpn import constants as svc_const

LOG = log.getLogger(__name__)


class EVPNAgentEvent(row_event.RowEvent):

    def __init__(self, fsm):
        self.fsm = fsm
        super().__init__(self.EVENTS, self.TABLE, None)


class EVPNPortBindingEvent(EVPNAgentEvent):
    TABLE = 'Port_Binding'

    def match_fn(self, event, row, old):
        return (ovn_const.LR_OPTIONS_DR_VRF_NAME in row.options and
                svc_const.EVPN_LRP_VNI_EXT_ID_KEY in row.external_ids and
                svc_const.EVPN_LRP_VLAN_EXT_ID_KEY in row.external_ids)


class PortBindingLrpEvpnCreateEvent(EVPNPortBindingEvent):
    TABLE = 'Port_Binding'
    EVENTS = (EVPNAgentEvent.ROW_CREATE,)

    def match_fn(self, event, row, old):
        if not super().match_fn(event, row, old):
            return False
        try:
            int(row.external_ids[svc_const.EVPN_LRP_VNI_EXT_ID_KEY])
        except ValueError:
            LOG.error("Invalid VNI in Port_Binding %s", row.logical_port)
            return False
        try:
            int(row.external_ids[svc_const.EVPN_LRP_VLAN_EXT_ID_KEY])
        except ValueError:
            LOG.error("Invalid VLAN in Port_Binding %s", row.logical_port)
            return False
        return True

    def run(self, event, row, old):
        vrf = row.options[ovn_const.LR_OPTIONS_DR_VRF_NAME]
        vni = int(row.external_ids[svc_const.EVPN_LRP_VNI_EXT_ID_KEY])
        vid = int(row.external_ids[svc_const.EVPN_LRP_VLAN_EXT_ID_KEY])
        try:
            self.fsm.advance(evpn_fsm.EvpnFSM.FSM_EVENT_PORT_BINDING_CREATE,
                             vrf, mac=row.mac[0], vni=vni, vid=vid)
        except evpn_exc.FSMIllegalTransition:
            LOG.error("Unexpected FSM transition for VRF %s on %s",
                      vrf, row.logical_port)


class PortBindingLrpEvpnDeleteEvent(EVPNPortBindingEvent):
    TABLE = 'Port_Binding'
    EVENTS = (EVPNAgentEvent.ROW_DELETE,)

    def run(self, event, row, old):
        vrf = row.options[ovn_const.LR_OPTIONS_DR_VRF_NAME]
        try:
            self.fsm.advance(evpn_fsm.EvpnFSM.FSM_EVENT_PORT_BINDING_DELETE,
                             vrf)
        except evpn_exc.FSMIllegalTransition:
            LOG.error("Unexpected FSM transition for VRF %s on %s",
                      vrf, row.logical_port)
