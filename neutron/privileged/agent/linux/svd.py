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

"""Low-level functions to create Single VxLAN Device and VNI:VLAN mapping"""

import errno

from oslo_log import log
from pyroute2 import config as pyroute2_config
from pyroute2 import netlink
from pyroute2.netlink import exceptions as netlink_exc
from pyroute2.netlink.rtnl import ifinfmsg
from pyroute2.netlink.rtnl.ifinfmsg.plugins import vxlan

from neutron.agent.linux import nl_constants as nl_const
from neutron import privileged
from neutron.privileged.agent.linux import ip_lib as priv_ip_lib


LOG = log.getLogger(__name__)


# Workarounds for features missing in pyroute2 0.8.x.
#
# These can be removed once pyroute2 gains native support for:
# - IFLA_VXLAN_VNIFILTER (vxlan NLA type 30)
# - RTM_NEWTUNNEL / RTM_DELTUNNEL (bridge vni add/del)
# - IFLA_INET6_ADDR_GEN_MODE via link('set', ...)

# Kernel netlink message types for VXLAN VNI filter management.
# Not yet in pyroute2's released API (added post-0.9.5).
RTM_NEWTUNNEL = 120
RTM_DELTUNNEL = 121


BRIDGE_ADD_VNI_MSG_FLAGS = (
    netlink.NLM_F_REQUEST | netlink.NLM_F_ACK | netlink.NLM_F_CREATE |
    netlink.NLM_F_EXCL)
BRIDGE_DEL_VNI_MSG_FLAGS = netlink.NLM_F_REQUEST | netlink.NLM_F_ACK


class EvpnVxLAN(vxlan.vxlan):
    """vxlan NLA extended with IFLA_VXLAN_VNIFILTER (type 30).

    pyroute2's vxlan plugin ends at IFLA_VXLAN_DF (type 29).
    The kernel defines IFLA_VXLAN_VNIFILTER at the next position.
    """
    nla_map = vxlan.vxlan.nla_map + (('IFLA_VXLAN_VNIFILTER', 'uint8'),)


@privileged.default.entrypoint
def register_vxlan_vnifilter():
    """Register the extended vxlan NLA with pyroute2.

    Must be called once before creating any vxlan device with
    vxlan_vnifilter=1.  Runs in the privsep daemon where pyroute2
    actually executes netlink calls.
    """
    ifinfmsg.ifinfmsg.ifinfo.register_link_kind(
        module={'vxlan': EvpnVxLAN})


@privileged.default.entrypoint
def reset_vxlan_vnifilter_nla():
    """Force recompilation of the EvpnVxLAN NLA table in the daemon.

    Only needed in functional tests where an earlier test may have
    compiled the parent vxlan NLA (without IFLA_VXLAN_VNIFILTER)
    in the same privsep daemon process.
    """
    EvpnVxLAN._nlmsg_base__compiled_nla = False


class TunnelMsg(netlink.nlmsg):
    """Netlink message for RTM_NEWTUNNEL / RTM_DELTUNNEL.

    Mirrors the kernel's ``struct tunnel_msg`` and carries
    VXLAN_VNIFILTER_ENTRY NLAs for ``bridge vni add/del``.
    """
    fields = (('family', 'B'), ('__pad', '3x'), ('ifindex', 'I'))
    nla_map = (
        ('VXLAN_VNIFILTER_UNSPEC', 'none'),
        ('VXLAN_VNIFILTER_ENTRY', 'vnifilter_entry',
         netlink.NLA_F_NESTED),
    )

    class vnifilter_entry(netlink.nla):
        nla_map = (
            ('VXLAN_VNIFILTER_ENTRY_UNSPEC', 'none'),
            ('VXLAN_VNIFILTER_ENTRY_START', 'uint32'),
            ('VXLAN_VNIFILTER_ENTRY_END', 'uint32'),
        )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self['family'] = pyroute2_config.AF_BRIDGE


def _make_bridge_vni_msg(vxlan_idx, vni):
    msg = TunnelMsg()
    msg['ifindex'] = vxlan_idx
    msg['attrs'] = [
        ('VXLAN_VNIFILTER_ENTRY', {
            'attrs': [('VXLAN_VNIFILTER_ENTRY_START', vni)]
        })
    ]
    return msg


def _bridge_add_vni(ipr, vxlan_idx, vni):
    """Add a VNI filter entry or skip if already present.

    Equivalent to:
        bridge vni add dev <vxlan> vni <vni>
    """
    msg = _make_bridge_vni_msg(vxlan_idx, vni)
    try:
        ipr.nlm_request(msg, msg_type=RTM_NEWTUNNEL,
                        msg_flags=BRIDGE_ADD_VNI_MSG_FLAGS)
    except netlink_exc.NetlinkError as e:
        if e.code == errno.EEXIST:
            LOG.debug("Bridge VNI %d on ifindex %d already present, "
                      "skipping", vni, vxlan_idx)
            return
        raise


def _bridge_del_vni(ipr, vxlan_idx, vni):
    """Delete a VNI filter entry or skip if already absent.

    Equivalent to:
        bridge vni del dev <vxlan> vni <vni>
    """
    msg = _make_bridge_vni_msg(vxlan_idx, vni)
    try:
        ipr.nlm_request(msg, msg_type=RTM_DELTUNNEL,
                        msg_flags=BRIDGE_DEL_VNI_MSG_FLAGS)
    except netlink_exc.NetlinkError as e:
        if e.code == errno.ENOENT:
            LOG.debug("Bridge VNI %d on ifindex %d already absent, "
                      "skipping", vni, vxlan_idx)
            return
        raise


def _set_addrgenmode_none(ipr, idx):
    """Set addrgenmode none (IN6_ADDR_GEN_MODE_NONE) on an interface.

    Equivalent to:
        ip link set dev <ifname> addrgenmode none
    """
    msg = ifinfmsg.ifinfmsg()
    msg['index'] = idx
    msg['flags'] = 0
    msg['change'] = 0
    msg['attrs'] = [
        ('IFLA_AF_SPEC', {
            'attrs': [
                ('AF_INET6', {
                    'attrs': [
                        ('IFLA_INET6_ADDR_GEN_MODE', 1)
                    ]
                })
            ]
        })
    ]
    ipr.nlm_request(msg, msg_type=ifinfmsg.RTM_NEWLINK,
                    msg_flags=netlink.NLM_F_REQUEST | netlink.NLM_F_ACK)


# End Workarounds for features missing in pyroute2 0.8.x.


def _add_link(ipr, ifname, **kwargs):
    """Add link or skip if exists.  Returns the ifindex of the device."""
    try:
        ipr.link(nl_const.IP_LINK_ADD, ifname=ifname, **kwargs)
    except netlink_exc.NetlinkError as e:
        if e.code == errno.EEXIST:
            LOG.debug("Link %s already exists, skipping add", ifname)
            return ipr.link_lookup(ifname=ifname)[0]
        raise
    return ipr.link_lookup(ifname=ifname)[0]


def _del_link(ipr, ifname):
    """Delete link or skip if absent."""
    idx = ipr.link_lookup(ifname=ifname)
    if not idx:
        LOG.debug("Link %s already absent, skipping delete", ifname)
        return
    ipr.link(nl_const.IP_LINK_DEL, index=idx[0])


def _add_vlan_filter(ipr, index, label, **kwargs):
    """Add vlan_filter or skip if already present."""
    try:
        ipr.vlan_filter(nl_const.IP_LINK_ADD, index=index, **kwargs)
    except netlink_exc.NetlinkError as e:
        if e.code == errno.EEXIST:
            LOG.debug("VLAN filter on %s already present, skipping", label)
            return
        raise


def _del_vlan_filter(ipr, index, label, **kwargs):
    """Delete vlan_filter or skip if absent."""
    try:
        ipr.vlan_filter(nl_const.IP_LINK_DEL, index=index, **kwargs)
    except netlink_exc.NetlinkError as e:
        if e.code == errno.ENOENT:
            LOG.debug("VLAN filter on %s already absent, skipping", label)
            return
        raise


def _link_idx(ipr, ifname):
    """Return ifindex for ifname or raise NetworkInterfaceNotFound."""
    idx = ipr.link_lookup(ifname=ifname)
    if not idx:
        raise priv_ip_lib.NetworkInterfaceNotFound(
            device=ifname, namespace=None)
    return idx[0]


@privileged.default.entrypoint
def create_svd(br_evpn, vxlan_evpn, local_ip, mac, dstport, br_mtu):
    """Create a shared Single VxLAN Device (SVD).

    A shared SVD consists of a vlan-aware Linux bridge and a vlan-aware
    VxLAN.  Idempotent: if devices already exist, their configuration
    is re-applied to match the desired state.
    """
    with priv_ip_lib.get_iproute(None) as ipr:

        # ip link add <vxlan_evpn> vxlan ...
        vxlan_idx = _add_link(
            ipr, vxlan_evpn, kind='vxlan',
            vxlan_port=dstport,
            vxlan_local=local_ip,
            vxlan_learning=0,
            vxlan_collect_metadata=1,
            vxlan_vnifilter=1)

        # ip link add <br_evpn> type bridge vlan_filtering 1 ...
        br_idx = _add_link(
            ipr, br_evpn, kind='bridge',
            br_vlan_filtering=1, br_vlan_default_pvid=0)

        # ip link set <br_evpn> address <mac> up
        ipr.link(nl_const.IP_LINK_SET, index=br_idx, address=mac,
                 state='up')

        # ip link set <vxlan_evpn> address <mac> master <br_evpn> up
        # bridge link set dev <vxlan_evpn> vlan_tunnel on neigh_suppress
        #   on learning off
        ipr.link(nl_const.IP_LINK_SET, index=vxlan_idx, address=mac,
                 master=br_idx, state='up')
        ipr.brport(nl_const.IP_LINK_SET, index=vxlan_idx,
                   vlan_tunnel=1, neigh_suppress=1, learning=0)

        # ip link set <br_evpn> mtu <br_mtu> addrgenmode none
        # ip link set <vxlan_evpn> addrgenmode none
        ipr.link(nl_const.IP_LINK_SET, index=br_idx,
                 mtu=br_mtu)
        _set_addrgenmode_none(ipr, br_idx)
        _set_addrgenmode_none(ipr, vxlan_idx)

    LOG.debug("Created SVD: bridge %s, vxlan %s (local_ip %s, dstport %d)",
              br_evpn, vxlan_evpn, local_ip, dstport)


@privileged.default.entrypoint
def delete_svd(br_evpn, vxlan_evpn):
    """Delete a shared SVD, already-absent devices are skipped."""
    with priv_ip_lib.get_iproute(None) as ipr:
        _del_link(ipr, vxlan_evpn)
        _del_link(ipr, br_evpn)
    LOG.debug("Deleted SVD: bridge %s, vxlan %s",
              br_evpn, vxlan_evpn)


@privileged.default.entrypoint
def add_vni(br_evpn, vxlan_evpn, svi_name, lo_name, vni, vid, vrf_name, mac,
            br_mtu):
    """Map a VNI to the SVD, existing sub-resources are skipped."""
    with priv_ip_lib.get_iproute(None) as ipr:
        br_idx = _link_idx(ipr, br_evpn)
        vxlan_idx = _link_idx(ipr, vxlan_evpn)
        vrf_idx = _link_idx(ipr, vrf_name)

        # bridge vlan add dev <br_evpn> vid <vid> self
        _add_vlan_filter(
            ipr, br_idx, br_evpn,
            vlan_info={'vid': vid}, vlan_flags='self')
        # bridge vlan add dev <vxlan_evpn> vid <vid> tunnel_info id <vni>
        _add_vlan_filter(
            ipr, vxlan_idx, vxlan_evpn,
            vlan_info={'vid': vid},
            vlan_tunnel_info={'vid': vid, 'id': vni})

        # bridge vni add dev <vxlan_evpn> vni <vni>
        _bridge_add_vni(ipr, vxlan_idx, vni)

        # ip link add <svi_name> link <br_evpn> type vlan id <vid>
        svi_idx = _add_link(
            ipr, svi_name, kind='vlan', link=br_idx, vlan_id=vid)
        # ip link set <svi_name> master <vrf_name> addr <mac> up
        ipr.link(nl_const.IP_LINK_SET, index=svi_idx,
                 master=vrf_idx, address=mac,
                 mtu=br_mtu, state='up')
        _set_addrgenmode_none(ipr, svi_idx)

        # ip link add <lo_name> type dummy
        lo_idx = _add_link(ipr, lo_name, kind='dummy')
        # ip link set <lo_name> master <br_evpn> up
        ipr.link(nl_const.IP_LINK_SET, index=lo_idx, master=br_idx,
                 state='up')

    LOG.debug("SVD %s/%s: added VLAN %d -> VNI %d, SVI %s, lo %s",
              br_evpn, vxlan_evpn, vid, vni, svi_name, lo_name)


@privileged.default.entrypoint
def del_vni(br_evpn, vxlan_evpn, svi_name, lo_name, vni, vid):
    """Remove a VNI mapping from the SVD, missing resources are skipped."""
    with priv_ip_lib.get_iproute(None) as ipr:
        br_idx = _link_idx(ipr, br_evpn)
        vxlan_idx = _link_idx(ipr, vxlan_evpn)

        # ip link del <lo_name>
        _del_link(ipr, lo_name)
        # ip link del <svi_name>
        _del_link(ipr, svi_name)

        # bridge vni del dev <vxlan_evpn> vni <vni>
        _bridge_del_vni(ipr, vxlan_idx, vni)

        # bridge vlan del dev <vxlan_evpn> vid <vid> tunnel_info id <vni>
        _del_vlan_filter(
            ipr, vxlan_idx, vxlan_evpn,
            vlan_info={'vid': vid},
            vlan_tunnel_info={'vid': vid, 'id': vni})
        # bridge vlan del dev <br_evpn> vid <vid> self
        _del_vlan_filter(
            ipr, br_idx, br_evpn,
            vlan_info={'vid': vid}, vlan_flags='self')

    LOG.debug("SVD %s/%s: removed VLAN %d -> VNI %d",
              br_evpn, vxlan_evpn, vid, vni)
