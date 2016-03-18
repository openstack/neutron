# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys

from neutron_lib import constants as lib_constants

from neutron.common import _deprecate


ROUTER_PORT_OWNERS = lib_constants.ROUTER_INTERFACE_OWNERS_SNAT + \
    (lib_constants.DEVICE_OWNER_ROUTER_GW,)

L3_AGENT_MODE_DVR = 'dvr'
L3_AGENT_MODE_DVR_SNAT = 'dvr_snat'
L3_AGENT_MODE_LEGACY = 'legacy'
L3_AGENT_MODE = 'agent_mode'

DEVICE_ID_RESERVED_DHCP_PORT = "reserved_dhcp_port"

HA_ROUTER_STATE_KEY = '_ha_state'
METERING_LABEL_KEY = '_metering_labels'
FLOATINGIP_AGENT_INTF_KEY = '_floatingip_agent_interfaces'
SNAT_ROUTER_INTF_KEY = '_snat_router_interfaces'

HA_NETWORK_NAME = 'HA network tenant %s'
HA_SUBNET_NAME = 'HA subnet tenant %s'
HA_PORT_NAME = 'HA port tenant %s'
MINIMUM_AGENTS_FOR_HA = 2
HA_ROUTER_STATE_ACTIVE = 'active'
HA_ROUTER_STATE_STANDBY = 'standby'

AGENT_TYPE_MACVTAP = 'Macvtap agent'
PAGINATION_INFINITE = 'infinite'

SORT_DIRECTION_ASC = 'asc'
SORT_DIRECTION_DESC = 'desc'

ETHERTYPE_NAME_ARP = 'arp'
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IP = 0x0800
ETHERTYPE_IPV6 = 0x86DD

# Protocol names and numbers for Security Groups/Firewalls
PROTO_NAME_AH = 'ah'
PROTO_NAME_DCCP = 'dccp'
PROTO_NAME_EGP = 'egp'
PROTO_NAME_ESP = 'esp'
PROTO_NAME_GRE = 'gre'
PROTO_NAME_ICMP = 'icmp'
PROTO_NAME_IGMP = 'igmp'
PROTO_NAME_IPV6_ENCAP = 'ipv6-encap'
PROTO_NAME_IPV6_FRAG = 'ipv6-frag'
PROTO_NAME_IPV6_ICMP = 'ipv6-icmp'
PROTO_NAME_IPV6_NONXT = 'ipv6-nonxt'
PROTO_NAME_IPV6_OPTS = 'ipv6-opts'
PROTO_NAME_IPV6_ROUTE = 'ipv6-route'
PROTO_NAME_OSPF = 'ospf'
PROTO_NAME_PGM = 'pgm'
PROTO_NAME_RSVP = 'rsvp'
PROTO_NAME_SCTP = 'sctp'
PROTO_NAME_TCP = 'tcp'
PROTO_NAME_UDP = 'udp'
PROTO_NAME_UDPLITE = 'udplite'
PROTO_NAME_VRRP = 'vrrp'

# TODO(amotoki): It should be moved to neutron-lib.
# For backward-compatibility of security group rule API,
# we keep the old value for IPv6 ICMP.
# It should be clean up in the future.
PROTO_NAME_IPV6_ICMP_LEGACY = 'icmpv6'

PROTO_NUM_AH = 51
PROTO_NUM_DCCP = 33
PROTO_NUM_EGP = 8
PROTO_NUM_ESP = 50
PROTO_NUM_GRE = 47
PROTO_NUM_ICMP = 1
PROTO_NUM_IGMP = 2
PROTO_NUM_IPV6_ENCAP = 41
PROTO_NUM_IPV6_FRAG = 44
PROTO_NUM_IPV6_ICMP = 58
PROTO_NUM_IPV6_NONXT = 59
PROTO_NUM_IPV6_OPTS = 60
PROTO_NUM_IPV6_ROUTE = 43
PROTO_NUM_OSPF = 89
PROTO_NUM_PGM = 113
PROTO_NUM_RSVP = 46
PROTO_NUM_SCTP = 132
PROTO_NUM_TCP = 6
PROTO_NUM_UDP = 17
PROTO_NUM_UDPLITE = 136
PROTO_NUM_VRRP = 112

IP_PROTOCOL_MAP = {PROTO_NAME_AH: PROTO_NUM_AH,
                   PROTO_NAME_DCCP: PROTO_NUM_DCCP,
                   PROTO_NAME_EGP: PROTO_NUM_EGP,
                   PROTO_NAME_ESP: PROTO_NUM_ESP,
                   PROTO_NAME_GRE: PROTO_NUM_GRE,
                   PROTO_NAME_ICMP: PROTO_NUM_ICMP,
                   PROTO_NAME_IGMP: PROTO_NUM_IGMP,
                   PROTO_NAME_IPV6_ENCAP: PROTO_NUM_IPV6_ENCAP,
                   PROTO_NAME_IPV6_FRAG: PROTO_NUM_IPV6_FRAG,
                   PROTO_NAME_IPV6_ICMP: PROTO_NUM_IPV6_ICMP,
                   PROTO_NAME_IPV6_NONXT: PROTO_NUM_IPV6_NONXT,
                   PROTO_NAME_IPV6_OPTS: PROTO_NUM_IPV6_OPTS,
                   PROTO_NAME_IPV6_ROUTE: PROTO_NUM_IPV6_ROUTE,
                   PROTO_NAME_OSPF: PROTO_NUM_OSPF,
                   PROTO_NAME_PGM: PROTO_NUM_PGM,
                   PROTO_NAME_RSVP: PROTO_NUM_RSVP,
                   PROTO_NAME_SCTP: PROTO_NUM_SCTP,
                   PROTO_NAME_TCP: PROTO_NUM_TCP,
                   PROTO_NAME_UDP: PROTO_NUM_UDP,
                   PROTO_NAME_UDPLITE: PROTO_NUM_UDPLITE,
                   PROTO_NAME_VRRP: PROTO_NUM_VRRP}

IP_PROTOCOL_NAME_ALIASES = {PROTO_NAME_IPV6_ICMP_LEGACY: PROTO_NAME_IPV6_ICMP}

# List of ICMPv6 types that should be allowed by default:
# Multicast Listener Query (130),
# Multicast Listener Report (131),
# Multicast Listener Done (132),
# Neighbor Solicitation (135),
ICMPV6_TYPE_NC = 135
# Neighbor Advertisement (136)
ICMPV6_TYPE_NA = 136
ICMPV6_ALLOWED_TYPES = [130, 131, 132, 135, 136]
ICMPV6_TYPE_RA = 134

DHCPV6_STATEFUL = 'dhcpv6-stateful'
DHCPV6_STATELESS = 'dhcpv6-stateless'
IPV6_SLAAC = 'slaac'
IPV6_MODES = [DHCPV6_STATEFUL, DHCPV6_STATELESS, IPV6_SLAAC]

IPV6_LLA_PREFIX = 'fe80::/64'

# Human-readable ID to which the subnetpool ID should be set to
# indicate that IPv6 Prefix Delegation is enabled for a given subnet
IPV6_PD_POOL_ID = 'prefix_delegation'

# Special provisional prefix for IPv6 Prefix Delegation
PROVISIONAL_IPV6_PD_PREFIX = '::/64'

# Timeout in seconds for getting an IPv6 LLA
LLA_TASK_TIMEOUT = 40

# Linux interface max length
DEVICE_NAME_MAX_LEN = 15

# vhost-user device names start with "vhu"
VHOST_USER_DEVICE_PREFIX = 'vhu'
# Device names start with "macvtap"
MACVTAP_DEVICE_PREFIX = 'macvtap'
# The vswitch side of a veth pair for a nova iptables filter setup
VETH_DEVICE_PREFIX = 'qvo'
# prefix for SNAT interface in DVR
SNAT_INT_DEV_PREFIX = 'sg-'

# Possible prefixes to partial port IDs in interface names used by the OVS,
# Linux Bridge, and IVS VIF drivers in Nova and the neutron agents. See the
# 'get_ovs_interfaceid' method in Nova (nova/virt/libvirt/vif.py) for details.
INTERFACE_PREFIXES = (lib_constants.TAP_DEVICE_PREFIX, VETH_DEVICE_PREFIX,
                      SNAT_INT_DEV_PREFIX)

ATTRIBUTES_TO_UPDATE = 'attributes_to_update'

# Maximum value integer can take in MySQL and PostgreSQL
# In SQLite integer can be stored in 1, 2, 3, 4, 6, or 8 bytes,
# but here it will be limited by this value for consistency.
DB_INTEGER_MAX_VALUE = 2 ** 31 - 1

# TODO(amuller): Re-define the RPC namespaces once Oslo messaging supports
# Targets with multiple namespaces. Neutron will then implement callbacks
# for its RPC clients in order to support rolling upgrades.

# RPC Interface for agents to call DHCP API implemented on the plugin side
RPC_NAMESPACE_DHCP_PLUGIN = None
# RPC interface for the metadata service to get info from the plugin side
RPC_NAMESPACE_METADATA = None
# RPC interface for agent to plugin security group API
RPC_NAMESPACE_SECGROUP = None
# RPC interface for agent to plugin DVR api
RPC_NAMESPACE_DVR = None
# RPC interface for reporting state back to the plugin
RPC_NAMESPACE_STATE = None
# RPC interface for agent to plugin resources API
RPC_NAMESPACE_RESOURCES = None

# Default network MTU value when not configured
DEFAULT_NETWORK_MTU = 1500
IPV6_MIN_MTU = 1280

ROUTER_MARK_MASK = "0xffff"

# Agent states as detected by server, used to reply on agent's state report
# agent has just been registered
AGENT_NEW = 'new'
# agent is alive
AGENT_ALIVE = 'alive'
# agent has just returned to alive after being dead
AGENT_REVIVED = 'revived'


# Neutron-lib migration shim. This will wrap any constants that are moved
# to that library in a deprecation warning, until they can be updated to
# import directly from their new location.
# If you're wondering why we bother saving _OLD_REF, it is because if we
# do not, then the original module we are overwriting gets garbage collected,
# and then you will find some super strange behavior with inherited classes
# and the like. Saving a ref keeps it around.

# WARNING: THESE MUST BE THE LAST TWO LINES IN THIS MODULE
_OLD_REF = sys.modules[__name__]
sys.modules[__name__] = _deprecate._DeprecateSubset(globals(), lib_constants)
# WARNING: THESE MUST BE THE LAST TWO LINES IN THIS MODULE
