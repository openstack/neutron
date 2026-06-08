# Copyright 2026 Red Hat, LLC
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
    WAITING_FOR_ROUTER = 'waiting_for_router'
    WAITING_FOR_BRIDGE = 'waiting_for_bridge'
    ADVERTISING = 'advertising'
    DESTROY = 'destroy'

    def __init__(self, vrf):
        self.vrf = vrf
        self.vrf_up = False
        self.mac = None
        self.vni = None
        self.vid = None
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
            (Evpn.WAITING_FOR_ROUTER, "_set_evpn_bridge"),
        (Evpn.INIT, FSM_EVENT_VRF_CREATE):
            (Evpn.WAITING_FOR_BRIDGE, "_set_evpn_router"),
        (Evpn.WAITING_FOR_ROUTER, FSM_EVENT_VRF_CREATE):
            (Evpn.ADVERTISING, "_set_evpn_router_and_advertise"),
        (Evpn.WAITING_FOR_BRIDGE, FSM_EVENT_PORT_BINDING_CREATE):
            (Evpn.ADVERTISING, "_set_evpn_bridge_and_advertise"),
        (Evpn.ADVERTISING, FSM_EVENT_PORT_BINDING_DELETE):
            (Evpn.WAITING_FOR_BRIDGE, "_unset_evpn_bridge_and_unadvertise"),
        (Evpn.ADVERTISING, FSM_EVENT_VRF_DELETE):
            (Evpn.WAITING_FOR_ROUTER, "_unset_evpn_router_and_unadvertise"),
        (Evpn.WAITING_FOR_BRIDGE, FSM_EVENT_VRF_DELETE):
            (Evpn.DESTROY, "_destroy"),
        (Evpn.WAITING_FOR_ROUTER, FSM_EVENT_PORT_BINDING_DELETE):
            (Evpn.DESTROY, "_destroy"),
    }

    def __init__(self, svd, config, frr_driver):
        self.instances = {}  # vrf -> Evpn
        self._svd = svd
        self._cfg = config
        self._driver = frr_driver

    def _set_evpn_bridge(self, evpn, mac, vni, vid):
        evpn.mac = mac
        evpn.vni = vni
        evpn.vid = vid

    def _unset_evpn_bridge_and_unadvertise(self, evpn):
        self._unadvertise(evpn)
        evpn.mac = None
        evpn.vni = None
        evpn.vid = None

    def _set_evpn_router(self, evpn):
        evpn.vrf_up = True

    def _unset_evpn_router_and_unadvertise(self, evpn):
        self._unadvertise(evpn)
        evpn.vrf_up = False

    def _advertise(self, evpn):
        self._svd.add_vni(evpn.vni, evpn.vid, evpn.vrf, evpn.mac,
                          self._cfg.br_mtu)
        self._driver.create_router(evpn.vrf, evpn.vni)
        LOG.debug("EVPN: advertised %s", evpn)

    def _unadvertise(self, evpn):
        self._svd.del_vni(evpn.vni, evpn.vid)
        self._driver.delete_router(evpn.vrf, evpn.vni)
        LOG.debug("EVPN: unadvertised %s", evpn)

    def _set_evpn_router_and_advertise(self, evpn):
        self._set_evpn_router(evpn)
        self._advertise(evpn)

    def _set_evpn_bridge_and_advertise(self, evpn, mac, vni, vid):
        self._set_evpn_bridge(evpn, mac, vni, vid)
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
