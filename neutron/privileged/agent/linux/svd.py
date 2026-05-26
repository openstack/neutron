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


from oslo_log import log
from pyroute2 import config as pyroute2_config
from pyroute2 import netlink
from pyroute2.netlink.rtnl import ifinfmsg
from pyroute2.netlink.rtnl.ifinfmsg.plugins import vxlan

from neutron.agent.ovn.extensions.evpn import constants as evpn_const
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
    """Add a VNI filter entry on a vxlan device.

    Equivalent to:
        bridge vni add dev <vxlan> vni <vni>
    """
    msg = _make_bridge_vni_msg(vxlan_idx, vni)
    ipr.nlm_request(msg, msg_type=RTM_NEWTUNNEL,
                    msg_flags=BRIDGE_ADD_VNI_MSG_FLAGS)


def _bridge_del_vni(ipr, vxlan_idx, vni):
    """Delete a VNI filter entry on a vxlan device.

    Equivalent to:
        bridge vni del dev <vxlan> vni <vni>
    """
    msg = _make_bridge_vni_msg(vxlan_idx, vni)
    ipr.nlm_request(msg, msg_type=RTM_DELTUNNEL,
                    msg_flags=BRIDGE_DEL_VNI_MSG_FLAGS)


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


@privileged.default.entrypoint
def create_svd(br_evpn, vxlan_evpn, local_ip, mac, vxlan_parent, dstport):
    """Create a shared Single VxLAN Device (SVD)

    A shared SVD consist of a vlan-aware Linux bridge and a vlan-aware VxLAN
    """
    with priv_ip_lib.get_iproute(None) as ipr:
        vxlan_parent_idx = ipr.link_lookup(ifname=vxlan_parent)[0]

        # Equivalent to:
        # ip link add <vxlan_evpn> vxlan \
        #   dev <vxlan_parent> dstport <dstport> local <local_ip> \
        #   no learning external vnifilter
        ipr.link(evpn_const.EVPN_IP_LINK_ADD, ifname=vxlan_evpn, kind='vxlan',
                 vxlan_link=vxlan_parent_idx,
                 vxlan_port=dstport,
                 vxlan_local=local_ip,
                 vxlan_learning=0,
                 vxlan_collect_metadata=1,
                 vxlan_vnifilter=1)
        vxlan_idx = ipr.link_lookup(ifname=vxlan_evpn)[0]

        # Equivalent to:
        # ip link add <br_evpn> type bridge vlan_filtering 1 \
        #   vlan_default_pvid 0
        # ip link set <br_evpn> address <mac>
        # ip link set <br_evpn> up
        ipr.link(evpn_const.EVPN_IP_LINK_ADD, ifname=br_evpn, kind='bridge',
                 br_vlan_filtering=1, br_vlan_default_pvid=0)
        br_idx = ipr.link_lookup(ifname=br_evpn)[0]
        ipr.link(evpn_const.EVPN_IP_LINK_SET, index=br_idx, address=mac,
                 state='up')

        # Equivalent to:
        # ip link set <vxlan_evpn> address <mac> master <br_evpn>
        # ip link set <vxlan_evpn> up
        # bridge link set dev <vxlan_evpn> vlan_tunnel on neigh_suppress on \
        #   learning off
        ipr.link(evpn_const.EVPN_IP_LINK_SET, index=vxlan_idx, address=mac,
                 master=br_idx, state='up')
        ipr.brport(evpn_const.EVPN_IP_LINK_SET, index=vxlan_idx,
                   vlan_tunnel=1, neigh_suppress=1, learning=0)

        # Equivalent to:
        # ip link set <br_evpn> mtu 1500 addrgenmode none
        # ip link set <vxlan_evpn> addrgenmode none
        ipr.link(evpn_const.EVPN_IP_LINK_SET, index=br_idx,
                 mtu=evpn_const.EVPN_BR_MTU)
        _set_addrgenmode_none(ipr, br_idx)
        _set_addrgenmode_none(ipr, vxlan_idx)

    LOG.debug("Created SVD: bridge %s, vxlan %s (parent %s, "
              "local_ip %s, dstport %d)",
              br_evpn, vxlan_evpn, vxlan_parent,
              local_ip, dstport)


@privileged.default.entrypoint
def delete_svd(br_evpn, vxlan_evpn):
    with priv_ip_lib.get_iproute(None) as ipr:
        vxlan_idx = ipr.link_lookup(ifname=vxlan_evpn)[0]
        br_idx = ipr.link_lookup(ifname=br_evpn)[0]
        ipr.link(evpn_const.EVPN_IP_LINK_DEL, index=vxlan_idx)
        ipr.link(evpn_const.EVPN_IP_LINK_DEL, index=br_idx)
    LOG.debug("Deleted SVD: bridge %s, vxlan %s",
              br_evpn, vxlan_evpn)


@privileged.default.entrypoint
def add_vni(br_evpn, vxlan_evpn, vni, vid, vrf_name, mac, index):
    with priv_ip_lib.get_iproute(None) as ipr:
        br_idx = ipr.link_lookup(ifname=br_evpn)[0]
        vxlan_idx = ipr.link_lookup(ifname=vxlan_evpn)[0]
        vrf_idx = ipr.link_lookup(ifname=vrf_name)[0]

        # Equivalent to:
        # bridge vlan add dev <br_evpn> vid <vid> self
        # bridge vlan add dev <vxlan_evpn> vid <vid>
        # bridge vlan add dev <vxlan_evpn> vid <vid> \
        #   tunnel_info id <vni>
        ipr.vlan_filter(evpn_const.EVPN_IP_LINK_ADD, index=br_idx,
                        vlan_info={'vid': vid},
                        vlan_flags='self')
        ipr.vlan_filter(evpn_const.EVPN_IP_LINK_ADD, index=vxlan_idx,
                        vlan_info={'vid': vid},
                        vlan_tunnel_info={'vid': vid, 'id': vni})

        # Equivalent to:
        # bridge vni add dev <vxlan_evpn> vni <vni>
        _bridge_add_vni(ipr, vxlan_idx, vni)

        # Equivalent to:
        # ip link add <svi_name> link <br_evpn> type vlan id <vid>
        # ip link set <svi_name> master <vrf_name>
        # ip link set <svi_name> addr <mac> addrgenmode none
        # ip link set <svi_name> up
        svi_name = evpn_const.EVPN_VLAN_IFNAME_PATTERN % {
            'index': index, 'vid': vid}
        ipr.link(evpn_const.EVPN_IP_LINK_ADD, ifname=svi_name, kind='vlan',
                 link=br_idx, vlan_id=vid)
        svi_idx = ipr.link_lookup(ifname=svi_name)[0]
        ipr.link(evpn_const.EVPN_IP_LINK_SET, index=svi_idx,
                 master=vrf_idx, address=mac,
                 mtu=evpn_const.EVPN_BR_MTU, state='up')
        _set_addrgenmode_none(ipr, svi_idx)

    LOG.debug("SVD %s/%s: added VLAN %d -> VNI %d, SVI %s",
              br_evpn, vxlan_evpn, vid, vni, svi_name)


@privileged.default.entrypoint
def del_vni(br_evpn, vxlan_evpn, vni, vid, index):
    with priv_ip_lib.get_iproute(None) as ipr:
        br_idx = ipr.link_lookup(ifname=br_evpn)[0]
        vxlan_idx = ipr.link_lookup(ifname=vxlan_evpn)[0]

        # Equivalent to:
        # ip link del <svi_name>
        svi_name = evpn_const.EVPN_VLAN_IFNAME_PATTERN % {
            'index': index, 'vid': vid}
        svi_idx = ipr.link_lookup(ifname=svi_name)[0]
        ipr.link(evpn_const.EVPN_IP_LINK_DEL, index=svi_idx)

        # Equivalent to:
        # bridge vni del dev <vxlan_evpn> vni <vni>
        # bridge vlan del dev <vxlan_evpn> vid <vid>
        # bridge vlan del dev <vxlan_evpn> vid <vid> \
        #   tunnel_info id <vni>
        # bridge vlan del dev <br_evpn> vid <vid> self
        _bridge_del_vni(ipr, vxlan_idx, vni)
        ipr.vlan_filter(evpn_const.EVPN_IP_LINK_DEL, index=vxlan_idx,
                        vlan_info={'vid': vid},
                        vlan_tunnel_info={'vid': vid, 'id': vni})
        ipr.vlan_filter(evpn_const.EVPN_IP_LINK_DEL, index=br_idx,
                        vlan_info={'vid': vid},
                        vlan_flags='self')

    LOG.debug("SVD %s/%s: removed VLAN %d -> VNI %d",
              br_evpn, vxlan_evpn, vid, vni)
