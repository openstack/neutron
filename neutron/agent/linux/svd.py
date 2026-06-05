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

from neutron._i18n import _
from neutron.privileged.agent.linux import svd as privileged_svd


class SvdNoVxlanParent(Exception):
    pass


class SvdDeviceAlreadyExists(Exception):
    pass


class SvdDevsNotFound(Exception):
    pass


class SvdSviNotFound(Exception):
    pass


class SvdNotFound(Exception):
    pass


class SvdNetlinkError(Exception):
    pass


class Svd:
    """A Single VXLAN Device: a VLAN-aware bridge + VXLAN device pair.

    Up to 4094 VNIs share the same SVD via VLAN/VNI mappings added
    with add_vni().

    When a VNI is mapped to a VLAN, the caller-provided VLAN interface
    name is created.
    """

    def __init__(self, br_evpn, vxlan_evpn):
        self.br_evpn = br_evpn
        self.vxlan_evpn = vxlan_evpn

    def create(self, local_ip, mac, vxlan_parent, dstport):
        try:
            privileged_svd.create_svd(
                self.br_evpn, self.vxlan_evpn,
                local_ip, mac, vxlan_parent, dstport)
        except IndexError:
            raise SvdNoVxlanParent(
                _("Missing VxLAN underlay: %(parent)s") %
                {'parent': vxlan_parent})
        except netlink_exc.NetlinkError as e:
            if e.code == errno.EEXIST:
                raise SvdDeviceAlreadyExists(
                    _("SVD %(br)s/%(vx)s device(s) already exist(s)") %
                    {'br': self.br_evpn, 'vx': self.vxlan_evpn})
            raise SvdNetlinkError(
                _("Failed to add SVD %(br)s/%(vx)s: %(err)s") %
                {'br': self.br_evpn, 'vx': self.vxlan_evpn, 'err': e})

    def delete(self):
        try:
            privileged_svd.delete_svd(self.br_evpn, self.vxlan_evpn)
        except IndexError:
            raise SvdNotFound(
                _("SVD %(br)s/%(vx)s not found") %
                {'br': self.br_evpn, 'vx': self.vxlan_evpn})
        except netlink_exc.NetlinkError as e:
            raise SvdNetlinkError(
                _("Failed to delete SVD %(br)s/%(vx)s: %(err)s") %
                {'br': self.br_evpn, 'vx': self.vxlan_evpn, 'err': e})

    def add_vni(self, svi_name, vni, vid, vrf_name, mac):
        try:
            privileged_svd.add_vni(
                self.br_evpn, self.vxlan_evpn,
                svi_name, vni, vid, vrf_name, mac)
        except IndexError:
            raise SvdDevsNotFound(
                _("SVD %(br)s/%(vx)s or VRF %(vrf)s not found") %
                {'br': self.br_evpn, 'vx': self.vxlan_evpn,
                 'vrf': vrf_name})
        except netlink_exc.NetlinkError as e:
            raise SvdNetlinkError(
                _("Failed to add VNI %(vni)d to SVD %(br)s/%(vx)s:"
                  " %(err)s") %
                {'vni': vni, 'br': self.br_evpn,
                 'vx': self.vxlan_evpn, 'err': e})

    def del_vni(self, svi_name, vni, vid):
        try:
            privileged_svd.del_vni(
                self.br_evpn, self.vxlan_evpn,
                svi_name, vni, vid)
        except IndexError:
            raise SvdSviNotFound(
                _("SVI for VNI %(vni)d not found on SVD %(br)s/%(vx)s") %
                {'vni': vni, 'br': self.br_evpn,
                 'vx': self.vxlan_evpn})
        except netlink_exc.NetlinkError as e:
            raise SvdNetlinkError(
                _("Failed to delete VNI %(vni)d from SVD %(br)s/%(vx)s:"
                  " %(err)s") %
                {'vni': vni, 'br': self.br_evpn,
                 'vx': self.vxlan_evpn, 'err': e})
