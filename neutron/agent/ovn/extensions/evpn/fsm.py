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

import threading

from oslo_log import log

from neutron.agent.ovn.extensions.evpn import exceptions as evpn_exc

LOG = log.getLogger(__name__)
_FSM_LOCK = threading.Lock()


class Evpn:
    """Per EVPN instance tracking FSM state."""

    INIT = 'init'
    WAITING_FOR_VRF_UP = 'waiting_for_vrf_up'
    WAITING_FOR_MAC_VNI = 'waiting_for_mac_vni'
    ADVERTISING = 'advertising'
    DESTROY = 'destroy'

    def __init__(self, vrf):
        self.vrf = vrf
        self.vrf_up = False
        self.mac = None
        self.vni = None
        self.state = self.INIT


class EvpnFSM:
    """Finite State Machine for EVPN instances.

    Manages one Evpn instance per VRF.  Event sources
    (PortBindingLrpEvpnEvent, VrfHandler) call the public
    methods; the FSM drives state transitions and triggers
    provisioning actions.
    """

    FSM_EVENT_PORT_BINDING_CREATE = 'port_binding_create'
    FSM_EVENT_PORT_BINDING_DELETE = 'port_binding_delete'
    FSM_EVENT_VRF_CREATE = 'vrf_create'
    FSM_EVENT_VRF_DELETE = 'vrf_delete'

    # Transitions in the FSM
    # Each entry contains the following:
    # (Current state, Event):(New state, transition callback)
    TRANSITIONS = {
        (Evpn.INIT, FSM_EVENT_PORT_BINDING_CREATE):
            (Evpn.WAITING_FOR_VRF_UP, "_set_mac_vni"),
        (Evpn.INIT, FSM_EVENT_VRF_CREATE):
            (Evpn.WAITING_FOR_MAC_VNI, "_set_vrf_up"),
        (Evpn.WAITING_FOR_VRF_UP, FSM_EVENT_VRF_CREATE):
            (Evpn.ADVERTISING, "_set_vrf_up_and_advertise"),
        (Evpn.WAITING_FOR_MAC_VNI, FSM_EVENT_PORT_BINDING_CREATE):
            (Evpn.ADVERTISING, "_set_mac_vni_and_advertise"),
        (Evpn.ADVERTISING, FSM_EVENT_PORT_BINDING_DELETE):
            (Evpn.WAITING_FOR_MAC_VNI, "_unset_mac_vni"),
        (Evpn.ADVERTISING, FSM_EVENT_VRF_DELETE):
            (Evpn.WAITING_FOR_VRF_UP, "_unset_vrf_up"),
        (Evpn.WAITING_FOR_MAC_VNI, FSM_EVENT_VRF_DELETE):
            (Evpn.DESTROY, "_destroy"),
        (Evpn.WAITING_FOR_VRF_UP, FSM_EVENT_PORT_BINDING_DELETE):
            (Evpn.DESTROY, "_destroy"),
    }

    def __init__(self):
        self.instances = {}  # vrf -> Evpn

    def _set_mac_vni(self, evpn, mac, vni):
        evpn.mac = mac
        evpn.vni = vni

    def _unset_mac_vni(self, evpn):
        evpn.mac = None
        evpn.vni = None

    def _set_vrf_up(self, evpn):
        evpn.vrf_up = True

    def _unset_vrf_up(self, evpn):
        evpn.vrf_up = False

    def _advertise(self, evpn):
        LOG.debug("EVPN: VNI %d Create VLAN and update FRR "
                  "configuration to start advertising and learning", evpn.vni)
        pass

    def _set_vrf_up_and_advertise(self, evpn):
        self._set_vrf_up(evpn)
        self._advertise(evpn)

    def _set_mac_vni_and_advertise(self, evpn, mac, vni):
        self._set_mac_vni(evpn, mac, vni)
        self._advertise(evpn)

    def _destroy(self, evpn):
        LOG.debug("EVPN deleted: VRF %s", evpn.vrf)
        self.instances.pop(evpn.vrf)

    def advance(self, event, vrf, **kwargs):
        """Drive FSM state transition for a VRF in response to an event."""
        with _FSM_LOCK:
            evpn = self.instances.setdefault(vrf, Evpn(vrf))
            LOG.debug("Advancing state EVPN: vrf %s", vrf)
            previous_state = evpn.state
            try:
                evpn.state, callback_name = self.TRANSITIONS[
                    (evpn.state, event)]
            except KeyError:
                raise evpn_exc.FSMIllegalTransition(
                    "Cannot transition from %s to new state!" %
                    (previous_state))
            try:
                callback = getattr(self, callback_name)
            except AttributeError:
                raise evpn_exc.FSMMissingTransitionCallback(
                    "Transition from %s to %s is missing callback function!" %
                    (previous_state, evpn.state))
            LOG.info("EVPN VRF %s: %s -> %s", vrf, previous_state, evpn.state)
            callback(evpn, **kwargs)
