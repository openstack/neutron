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

import abc
from dataclasses import dataclass


class EVPNRouterVrfHandler(abc.ABC):
    """EVPN Router VRF handler."""

    @abc.abstractmethod
    def ensure_vrf_exists(self, vrf_name) -> None:
        pass

    @abc.abstractmethod
    def ensure_vrf_deleted(self, vrf_name) -> None:
        pass


@dataclass
class EVPNRouterConfig:
    """EVPN router configuration parameters."""
    asn: int
    bgp_router_id: str
    vrf_name: str
    vni: int


class EVPNRouterDriver(abc.ABC):
    """Generic interface for an EVPN router driver."""

    @abc.abstractmethod
    def create_evpn_router(self, config: EVPNRouterConfig) -> None:
        """Creates the EVPN VRF in the routing fabric."""

    @abc.abstractmethod
    def delete_evpn_router(self, config: EVPNRouterConfig) -> None:
        """Deletes the EVPN VRF from the routing fabric."""
