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

# TODO(salv-orlando): Verify if a single set of operational
# status constants is achievable
NET_STATUS_ACTIVE = 'ACTIVE'
NET_STATUS_BUILD = 'BUILD'
NET_STATUS_DOWN = 'DOWN'
NET_STATUS_ERROR = 'ERROR'

PORT_STATUS_ACTIVE = 'ACTIVE'
PORT_STATUS_BUILD = 'BUILD'
PORT_STATUS_DOWN = 'DOWN'
PORT_STATUS_ERROR = 'ERROR'
PORT_STATUS_NOTAPPLICABLE = 'N/A'

FLOATINGIP_STATUS_ACTIVE = 'ACTIVE'
FLOATINGIP_STATUS_DOWN = 'DOWN'
FLOATINGIP_STATUS_ERROR = 'ERROR'

DEVICE_OWNER_ROUTER_HA_INTF = "network:router_ha_interface"
DEVICE_OWNER_ROUTER_INTF = "network:router_interface"
DEVICE_OWNER_ROUTER_GW = "network:router_gateway"
DEVICE_OWNER_FLOATINGIP = "network:floatingip"
DEVICE_OWNER_DHCP = "network:dhcp"
DEVICE_OWNER_DVR_INTERFACE = "network:router_interface_distributed"
DEVICE_OWNER_AGENT_GW = "network:floatingip_agent_gateway"
DEVICE_OWNER_ROUTER_SNAT = "network:router_centralized_snat"
DEVICE_OWNER_LOADBALANCER = "neutron:LOADBALANCER"
DEVICE_OWNER_LOADBALANCERV2 = "neutron:LOADBALANCERV2"

# Collection used to identify devices owned by router interfaces.
# DEVICE_OWNER_ROUTER_HA_INTF is a special case and so is not included.
ROUTER_INTERFACE_OWNERS = (DEVICE_OWNER_ROUTER_INTF,
                           DEVICE_OWNER_DVR_INTERFACE)
L3_AGENT_MODE_DVR = 'dvr'
L3_AGENT_MODE_DVR_SNAT = 'dvr_snat'
L3_AGENT_MODE_LEGACY = 'legacy'
L3_AGENT_MODE = 'agent_mode'

DEVICE_ID_RESERVED_DHCP_PORT = "reserved_dhcp_port"

FLOATINGIP_KEY = '_floatingips'
INTERFACE_KEY = '_interfaces'
HA_INTERFACE_KEY = '_ha_interface'
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

IPv4 = 'IPv4'
IPv6 = 'IPv6'
IP_VERSION_4 = 4
IP_VERSION_6 = 6
IPv4_BITS = 32
IPv6_BITS = 128

IPv4_ANY = '0.0.0.0/0'
IPv6_ANY = '::/0'

DHCP_RESPONSE_PORT = 68

MIN_VLAN_TAG = 1
MAX_VLAN_TAG = 4094

# For GRE Tunnel
MIN_GRE_ID = 1
MAX_GRE_ID = 2 ** 32 - 1

# For VXLAN Tunnel
MIN_VXLAN_VNI = 1
MAX_VXLAN_VNI = 2 ** 24 - 1

FLOODING_ENTRY = ('00:00:00:00:00:00', '0.0.0.0')

AGENT_TYPE_DHCP = 'DHCP agent'
AGENT_TYPE_OVS = 'Open vSwitch agent'
AGENT_TYPE_LINUXBRIDGE = 'Linux bridge agent'
AGENT_TYPE_HYPERV = 'HyperV agent'
AGENT_TYPE_NEC = 'NEC plugin agent'
AGENT_TYPE_OFA = 'OFA driver agent'
AGENT_TYPE_L3 = 'L3 agent'
AGENT_TYPE_LOADBALANCER = 'Loadbalancer agent'
AGENT_TYPE_MLNX = 'Mellanox plugin agent'
AGENT_TYPE_METERING = 'Metering agent'
AGENT_TYPE_METADATA = 'Metadata agent'
AGENT_TYPE_SDNVE = 'IBM SDN-VE agent'
AGENT_TYPE_NIC_SWITCH = 'NIC Switch agent'
L2_AGENT_TOPIC = 'N/A'

PAGINATION_INFINITE = 'infinite'

SORT_DIRECTION_ASC = 'asc'
SORT_DIRECTION_DESC = 'desc'

PORT_BINDING_EXT_ALIAS = 'binding'
L3_AGENT_SCHEDULER_EXT_ALIAS = 'l3_agent_scheduler'
DHCP_AGENT_SCHEDULER_EXT_ALIAS = 'dhcp_agent_scheduler'
LBAAS_AGENT_SCHEDULER_EXT_ALIAS = 'lbaas_agent_scheduler'
L3_DISTRIBUTED_EXT_ALIAS = 'dvr'
L3_HA_MODE_EXT_ALIAS = 'l3-ha'
SUBNET_ALLOCATION_EXT_ALIAS = 'subnet_allocation'

# Protocol names and numbers for Security Groups/Firewalls
PROTO_NAME_TCP = 'tcp'
PROTO_NAME_ICMP = 'icmp'
PROTO_NAME_ICMP_V6 = 'icmpv6'
PROTO_NAME_UDP = 'udp'
PROTO_NUM_TCP = 6
PROTO_NUM_ICMP = 1
PROTO_NUM_ICMP_V6 = 58
PROTO_NUM_UDP = 17

# List of ICMPv6 types that should be allowed by default:
# Multicast Listener Query (130),
# Multicast Listener Report (131),
# Multicast Listener Done (132),
# Neighbor Solicitation (135),
# Neighbor Advertisement (136)
ICMPV6_ALLOWED_TYPES = [130, 131, 132, 135, 136]
ICMPV6_TYPE_RA = 134

DHCPV6_STATEFUL = 'dhcpv6-stateful'
DHCPV6_STATELESS = 'dhcpv6-stateless'
IPV6_SLAAC = 'slaac'
IPV6_MODES = [DHCPV6_STATEFUL, DHCPV6_STATELESS, IPV6_SLAAC]

IPV6_LLA_PREFIX = 'fe80::/64'

# Human-readable ID to which default_ipv6_subnet_pool should be set to
# indicate that IPv6 Prefix Delegation should be used to allocate subnet CIDRs
IPV6_PD_POOL_ID = 'prefix_delegation'

# Linux interface max length
DEVICE_NAME_MAX_LEN = 15

# Device names start with "tap"
TAP_DEVICE_PREFIX = 'tap'

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

# Default network MTU value when not configured
DEFAULT_NETWORK_MTU = 0
