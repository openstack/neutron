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

import enum
import threading

from oslo_log import log

from neutron.agent.ovn.extensions.evpn import exceptions as evpn_exc

LOG = log.getLogger(__name__)
_FSM_LOCK = threading.Lock()


class EVPNState(enum.Enum):
    INIT = 'init'
    WAITING_FOR_VRF = 'waiting_for_vrf'
    WAITING_FOR_PORT_BINDING = 'waiting_for_port_binding'
    ADVERTISING = 'advertising'
    DESTROY = 'destroy'


class EVPNEvent(enum.Enum):
    PORT_BINDING_CREATE = 'port_binding_create'
    PORT_BINDING_DELETE = 'port_binding_delete'
    VRF_CREATE = 'vrf_create'
    VRF_DELETE = 'vrf_delete'


class EVPNInstance:
    """Per EVPN instance tracking FSM state."""

    def __init__(self, vrf):
        self.vrf = vrf
        self.vrf_up = False
        self.mac = None
        self.vni = None
        self.vid = None
        self.state = EVPNState.INIT


class EvpnFSM:
    """Finite State Machine for EVPN instances.

    Manages one EVPNInstance per VRF.  Event sources
    (PortBindingLrpEvpnEvent, VrfHandler) call the public
    methods; the FSM drives state transitions and triggers
    provisioning actions.
    """

    # Transitions in the FSM
    # Each entry contains the following:
    # (Current state, Event): (New state, callback(action))
    TRANSITIONS = {
        (EVPNState.INIT, EVPNEvent.PORT_BINDING_CREATE):
            (EVPNState.WAITING_FOR_VRF, "_set_evpn_bridge"),
        (EVPNState.INIT, EVPNEvent.VRF_CREATE):
            (EVPNState.WAITING_FOR_PORT_BINDING, "_set_evpn_router"),
        (EVPNState.WAITING_FOR_VRF, EVPNEvent.VRF_CREATE):
            (EVPNState.ADVERTISING, "_set_evpn_router_and_advertise"),
        (EVPNState.WAITING_FOR_PORT_BINDING, EVPNEvent.PORT_BINDING_CREATE):
            (EVPNState.ADVERTISING, "_set_evpn_bridge_and_advertise"),
        (EVPNState.ADVERTISING, EVPNEvent.PORT_BINDING_DELETE):
            (EVPNState.WAITING_FOR_PORT_BINDING,
             "_unset_evpn_bridge_and_unadvertise"),
        (EVPNState.ADVERTISING, EVPNEvent.VRF_DELETE):
            (EVPNState.WAITING_FOR_VRF,
             "_unset_evpn_router_and_unadvertise"),
        (EVPNState.WAITING_FOR_VRF, EVPNEvent.PORT_BINDING_DELETE):
            (EVPNState.DESTROY, "_destroy"),
        (EVPNState.WAITING_FOR_PORT_BINDING, EVPNEvent.VRF_DELETE):
            (EVPNState.DESTROY, "_destroy"),
    }

    def __init__(self):
        self.instances = {}  # vrf -> EVPNInstance
        self._svd = None
        self._cfg = None
        self._driver = None

    def setup(self, svd, config, frr_driver):
        self._svd = svd
        self._cfg = config
        self._driver = frr_driver

    def _set_evpn_bridge(self, evpn, mac, vni, vid):
        evpn.mac = mac
        evpn.vni = vni
        evpn.vid = vid

    def _set_evpn_router(self, evpn):
        evpn.vrf_up = True

    def _set_evpn_router_and_advertise(self, evpn):
        self._set_evpn_router(evpn)
        self._advertise(evpn)

    def _set_evpn_bridge_and_advertise(self, evpn, mac, vni, vid):
        self._set_evpn_bridge(evpn, mac, vni, vid)
        self._advertise(evpn)

    def _unset_evpn_bridge_and_unadvertise(self, evpn):
        self._unadvertise(evpn)
        evpn.mac = None
        evpn.vni = None
        evpn.vid = None

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

    def _destroy(self, evpn):
        LOG.debug("EVPN deleted: VRF %s", evpn.vrf)
        self.instances.pop(evpn.vrf, None)

    def advance(self, event, vrf, **kwargs):
        """Drive FSM state transition for a VRF in response to an event."""
        with _FSM_LOCK:
            evpn = self.instances.setdefault(vrf, EVPNInstance(vrf))
            try:
                new_state, callback_name = self.TRANSITIONS[
                    (evpn.state, event)]
            except KeyError:
                raise evpn_exc.FSMIllegalTransition(
                    "Cannot transition from %s with event %s!" %
                    (evpn.state, event))
            try:
                callback = getattr(self, callback_name)
            except AttributeError:
                raise evpn_exc.FSMMissingTransitionCallback(
                    "Transition from %s is missing callback function %s!" %
                    (evpn.state, callback_name))
            previous_state = evpn.state
            callback(evpn, **kwargs)
            evpn.state = new_state
            LOG.info("EVPN %s: %s -> %s (event=%s)",
                     vrf, previous_state, evpn.state, event)
