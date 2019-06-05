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

from neutron_lib import constants as lib_constants


ROUTER_PORT_OWNERS = lib_constants.ROUTER_INTERFACE_OWNERS_SNAT + \
    (lib_constants.DEVICE_OWNER_ROUTER_GW,)

ROUTER_STATUS_ACTIVE = 'ACTIVE'
ROUTER_STATUS_ALLOCATING = 'ALLOCATING'
ROUTER_STATUS_ERROR = 'ERROR'

VALID_ROUTER_STATUS = (ROUTER_STATUS_ACTIVE,
                       ROUTER_STATUS_ALLOCATING,
                       ROUTER_STATUS_ERROR)

HA_ROUTER_STATE_KEY = '_ha_state'
METERING_LABEL_KEY = '_metering_labels'
FLOATINGIP_AGENT_INTF_KEY = '_floatingip_agent_interfaces'
SNAT_ROUTER_INTF_KEY = '_snat_router_interfaces'
DVR_SNAT_BOUND = 'dvr_snat_bound'
L3_AGENT_MODE_DVR_NO_EXTERNAL = 'dvr_no_external'

HA_NETWORK_NAME = 'HA network tenant %s'
HA_SUBNET_NAME = 'HA subnet tenant %s'
HA_PORT_NAME = 'HA port tenant %s'
HA_ROUTER_STATE_ACTIVE = 'active'
HA_ROUTER_STATE_STANDBY = 'standby'
VALID_HA_STATES = (HA_ROUTER_STATE_ACTIVE, HA_ROUTER_STATE_STANDBY)
PAGINATION_INFINITE = 'infinite'

SORT_DIRECTION_ASC = 'asc'
SORT_DIRECTION_DESC = 'desc'

ETHERTYPE_NAME_ARP = 'arp'
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IP = 0x0800
ETHERTYPE_IPV6 = 0x86DD

IP_PROTOCOL_NAME_ALIASES = {lib_constants.PROTO_NAME_IPV6_ICMP_LEGACY:
                            lib_constants.PROTO_NAME_IPV6_ICMP}

IP_PROTOCOL_NUM_TO_NAME_MAP = {
    str(v): k for k, v in lib_constants.IP_PROTOCOL_MAP.items()}

# When using iptables-save we specify '-p {proto}',
# but sometimes those values are not identical.  This is a map
# of known protocol numbers that require a name to be used and
# protocol names that require a different name to be used,
# because that is how iptables-save will display them.
#
# This is how the list was created, so there is a possibility
# it will need to be updated in the future:
#
# $ for num in {0..255}; do iptables -A INPUT -p $num; done
# $ iptables-save
#
# These cases are special, and were found by inspection:
# - 'ipv6-encap' uses 'ipv6'
# - 'icmpv6' uses 'ipv6-icmp'
# - 'pgm' uses '113' instead of its name
# - protocol '0' uses no -p argument
IPTABLES_PROTOCOL_NAME_MAP = {lib_constants.PROTO_NAME_IPV6_ENCAP: 'ipv6',
                              lib_constants.PROTO_NAME_IPV6_ICMP_LEGACY:
                                  'ipv6-icmp',
                              lib_constants.PROTO_NAME_PGM: '113',
                              '0': None,
                              '1': 'icmp',
                              '2': 'igmp',
                              '3': 'ggp',
                              '4': 'ipencap',
                              '5': 'st',
                              '6': 'tcp',
                              '8': 'egp',
                              '9': 'igp',
                              '12': 'pup',
                              '17': 'udp',
                              '20': 'hmp',
                              '22': 'xns-idp',
                              '27': 'rdp',
                              '29': 'iso-tp4',
                              '33': 'dccp',
                              '36': 'xtp',
                              '37': 'ddp',
                              '38': 'idpr-cmtp',
                              '41': 'ipv6',
                              '43': 'ipv6-route',
                              '44': 'ipv6-frag',
                              '45': 'idrp',
                              '46': 'rsvp',
                              '47': 'gre',
                              '50': 'esp',
                              '51': 'ah',
                              '57': 'skip',
                              '58': 'ipv6-icmp',
                              '59': 'ipv6-nonxt',
                              '60': 'ipv6-opts',
                              '73': 'rspf',
                              '81': 'vmtp',
                              '88': 'eigrp',
                              '89': 'ospf',
                              '93': 'ax.25',
                              '94': 'ipip',
                              '97': 'etherip',
                              '98': 'encap',
                              '103': 'pim',
                              '108': 'ipcomp',
                              '112': 'vrrp',
                              '115': 'l2tp',
                              '124': 'isis',
                              '132': 'sctp',
                              '133': 'fc',
                              '135': 'mobility-header',
                              '136': 'udplite',
                              '137': 'mpls-in-ip',
                              '138': 'manet',
                              '139': 'hip',
                              '140': 'shim6',
                              '141': 'wesp',
                              '142': 'rohc'}

# Timeout in seconds for getting an IPv6 LLA
LLA_TASK_TIMEOUT = 40

# length of all device prefixes (e.g. qvo, tap, qvb)
LINUX_DEV_PREFIX_LEN = 3
# must be shorter than linux IFNAMSIZ (which is 16)
LINUX_DEV_LEN = 14

# Possible prefixes to partial port IDs in interface names used by the OVS,
# Linux Bridge, and IVS VIF drivers in Nova and the neutron agents. See the
# 'get_ovs_interfaceid' method in Nova (nova/virt/libvirt/vif.py) for details.
INTERFACE_PREFIXES = (lib_constants.TAP_DEVICE_PREFIX,
                      lib_constants.VETH_DEVICE_PREFIX,
                      lib_constants.SNAT_INT_DEV_PREFIX)

ATTRIBUTES_TO_UPDATE = 'attributes_to_update'

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

VALID_ETHERTYPES = (lib_constants.IPv4, lib_constants.IPv6)

IP_ALLOWED_VERSIONS = [lib_constants.IP_VERSION_4, lib_constants.IP_VERSION_6]

PORT_RANGE_MIN = 1
PORT_RANGE_MAX = 65535

# TODO(bence romsics): move this to neutron_lib.constants
DHCPV6_CLIENT_PORT = 546

# Configuration values for accept_ra sysctl, copied from linux kernel
# networking (netdev) tree, file Documentation/networking/ip-sysctl.txt
#
# Possible values are:
#         0 Do not accept Router Advertisements.
#         1 Accept Router Advertisements if forwarding is disabled.
#         2 Overrule forwarding behaviour. Accept Router Advertisements
#           even if forwarding is enabled.
ACCEPT_RA_DISABLED = 0
ACCEPT_RA_WITHOUT_FORWARDING = 1
ACCEPT_RA_WITH_FORWARDING = 2

# Some components communicate using private address ranges, define
# them all here. These address ranges should not cause any issues
# even if they overlap since they are used in disjoint namespaces,
# but for now they are unique.
# We define the metadata cidr since it falls in the range.
PRIVATE_CIDR_RANGE = '169.254.0.0/16'
DVR_FIP_LL_CIDR = '169.254.64.0/18'
L3_HA_NET_CIDR = '169.254.192.0/18'
METADATA_CIDR = '169.254.169.254/32'

# The only defined IpamAllocation status at this stage is 'ALLOCATED'.
# More states will be available in the future - e.g.: RECYCLABLE
IPAM_ALLOCATION_STATUS_ALLOCATED = 'ALLOCATED'

VALID_IPAM_ALLOCATION_STATUSES = (IPAM_ALLOCATION_STATUS_ALLOCATED,)

# Port binding states for Live Migration
PORT_BINDING_STATUSES = (lib_constants.ACTIVE,
                         lib_constants.INACTIVE)

VALID_FLOATINGIP_STATUS = (lib_constants.FLOATINGIP_STATUS_ACTIVE,
                           lib_constants.FLOATINGIP_STATUS_DOWN,
                           lib_constants.FLOATINGIP_STATUS_ERROR)

# Floating IP host binding states
FLOATING_IP_HOST_UNBOUND = "FLOATING_IP_HOST_UNBOUND"
FLOATING_IP_HOST_NEEDS_BINDING = "FLOATING_IP_HOST_NEEDS_BINDING"

# Possible types of values (e.g. in QoS rule types)
VALUES_TYPE_CHOICES = "choices"
VALUES_TYPE_RANGE = "range"

# Units base
SI_BASE = 1000
IEC_BASE = 1024

# Number of resources for neutron agent side functions to deal
# with large sets.
# Setting this value does not count on special conditions, it is just a human
# countable or scalable number. [1] gives us the method to test the scale
# issue. And we have tested the value of 1000, 500, 200, 100. But for 100,
# ovs-agent will have a lower timeout probability. And according to the
# testing result, step size 100 can indeed cost about 10% much more time
# than 500/1000. But such extra time looks inevitably needed to be sacrificed
# for the restart success rate.
# [1] http://paste.openstack.org/show/745685/
AGENT_RES_PROCESSING_STEP = 100
# Number of resources for neutron to divide the large RPC
# call data sets.
RPC_RES_PROCESSING_STEP = 20
# IPtables version to support --random-fully option.
# Do not move this constant to neutron-lib, since it is temporary
IPTABLES_RANDOM_FULLY_VERSION = '1.6.2'
