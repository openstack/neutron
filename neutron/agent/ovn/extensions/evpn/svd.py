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

from neutron.agent.linux import svd
from neutron.agent.ovn.extensions.evpn import constants as evpn_const


class EvpnSvd(svd.Svd):
    """EVPN-aware SVD that manages SVI interface names internally.

    The base Svd requires callers to supply an explicit ``svi_name``.
    EvpnSvd derives the name from ``EVPN_VLAN_IFNAME_PATTERN`` using
    the SVD index and the VLAN ID, and keeps track of the VNI ->
    svi_name mapping so that callers only deal with VNI/VID
    identifiers.
    """

    def __init__(self, br_evpn, vxlan_evpn, index=0):
        super().__init__(br_evpn, vxlan_evpn)
        self._index = index
        self._svi_names = {}

    def add_vni(self, vni, vid, vrf_name, mac, br_mtu):
        svi_name = evpn_const.EVPN_VLAN_IFNAME_PATTERN % {
            'index': self._index, 'vid': vid}
        super().add_vni(svi_name, vni, vid, vrf_name, mac, br_mtu)
        self._svi_names[vni] = svi_name

    def del_vni(self, vni, vid):
        svi_name = self._svi_names.pop(vni)
        super().del_vni(svi_name, vni, vid)
