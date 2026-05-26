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

import errno

from pyroute2.netlink import exceptions as netlink_exc

from neutron.agent.ovn.extensions.evpn import exceptions as evpn_exc
from neutron.privileged.agent.linux import svd as privileged_svd


class Svd:
    """A Single VXLAN Device: a VLAN-aware bridge + VXLAN device pair.

    Up to 4094 VNIs share the same SVD via VLAN/VNI mappings added
    with add_vni().

    When a VNI is mapped to a VLAN, a VLAN interface with
    EVPN_VLAN_IFNAME_PATTERN is created
    """

    def __init__(self, br_evpn, vxlan_evpn, index=0):
        self._index = index
        self.br_evpn = br_evpn
        self.vxlan_evpn = vxlan_evpn

    def create(self, local_ip, mac, vxlan_parent, dstport):
        try:
            privileged_svd.create_svd(
                self.br_evpn, self.vxlan_evpn,
                local_ip, mac, vxlan_parent, dstport)
        except IndexError:
            raise evpn_exc.SvdNoVxlanParent("Missing VxLAN underlay: %s" %
                                            (vxlan_parent))
        except netlink_exc.NetlinkError as e:
            if e.code == errno.EEXIST:
                raise evpn_exc.SvdDeviceAlreadyExists("SVD %s/%s device(s) "
                                                      "already exist(s)" %
                                                      (self.br_evpn,
                                                       self.vxlan_evpn))
            raise evpn_exc.SvdNetlinkError(
                "Failed to add SVD %s/%s: %s" %
                (self.br_evpn, self.vxlan_evpn, e))

    def delete(self):
        try:
            privileged_svd.delete_svd(self.br_evpn, self.vxlan_evpn)
        except IndexError:
            raise evpn_exc.SvdNotFound(
                "SVD %s/%s not found" %
                (self.br_evpn, self.vxlan_evpn))
        except netlink_exc.NetlinkError as e:
            raise evpn_exc.SvdNetlinkError(
                "Failed to delete SVD %s/%s: %s" %
                (self.br_evpn, self.vxlan_evpn, e))

    def add_vni(self, vni, vid, vrf_name, mac):
        try:
            privileged_svd.add_vni(
                self.br_evpn, self.vxlan_evpn,
                vni, vid, vrf_name, mac, self._index)
        except IndexError:
            raise evpn_exc.SvdDevsNotFound(
                "SVD %s/%s or VRF %s not found" %
                (self.br_evpn, self.vxlan_evpn, vrf_name))
        except netlink_exc.NetlinkError as e:
            raise evpn_exc.SvdNetlinkError(
                "Failed to add VNI %d to SVD %s/%s: %s" %
                (vni, self.br_evpn, self.vxlan_evpn, e))

    def del_vni(self, vni, vid):
        try:
            privileged_svd.del_vni(
                self.br_evpn, self.vxlan_evpn,
                vni, vid, self._index)
        except IndexError:
            raise evpn_exc.SvdSviNotFound(
                "SVI for VNI %d not found on SVD %s/%s" %
                (vni, self.br_evpn, self.vxlan_evpn))
        except netlink_exc.NetlinkError as e:
            raise evpn_exc.SvdNetlinkError(
                "Failed to delete VNI %d from SVD %s/%s: %s" %
                (vni, self.br_evpn, self.vxlan_evpn, e))
