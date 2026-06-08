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

from oslo_config import cfg
from oslo_log import log

from neutron.agent.linux.evpn_router.frr import frr_driver
from neutron.agent.linux.evpn_router import interface as evpn_interface

LOG = log.getLogger(__name__)


class FsmFrrVrfHandler(evpn_interface.EVPNRouterVrfHandler):
    """No-op VRF handler for the FSM-driven EVPN lifecycle.

    The FSM relies on netlink RTM_NEWLINK / RTM_DELLINK events (via
    VrfHandler) to track VRF creation and deletion. Because VRF
    lifecycle is already managed by those netlink-driven state
    transitions, FrrVtyshDriver must not create or delete VRFs
    itself — this handler satisfies the interface with no-ops.
    """

    def ensure_vrf_exists(self, vrf_name) -> None:
        LOG.debug("%s.%s: skipping for %s",
                  type(self).__name__, "ensure_vrf_exists", vrf_name)

    def ensure_vrf_deleted(self, vrf_name) -> None:
        LOG.debug("%s.%s: skipping for %s",
                  type(self).__name__, "ensure_vrf_deleted", vrf_name)


class FsmFrrVtyshDriver(frr_driver.FrrVtyshDriver):
    """FRR driver adapter for the EVPN FSM

    This class is set to operate on a single ASN and BGP router ID.
    """

    def __init__(self, peer_interface: str, bgp_router_id: str):
        self._asn = cfg.CONF.ovn_evpn.bgp_as
        self._bgp_router_id = bgp_router_id
        super().__init__(peer_interface, FsmFrrVrfHandler())

    def create_router(self, vrf_name, vni) -> None:
        config = evpn_interface.EVPNRouterConfig(
            asn=self._asn,
            bgp_router_id=self._bgp_router_id,
            vrf_name=vrf_name,
            vni=vni,
        )
        return super().create_evpn_router(config)

    def delete_router(self, vrf_name, vni) -> None:
        config = evpn_interface.EVPNRouterConfig(
            asn=self._asn,
            bgp_router_id=self._bgp_router_id,
            vrf_name=vrf_name,
            vni=vni,
        )
        return super().delete_evpn_router(config)
