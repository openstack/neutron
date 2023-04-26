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

from neutron_lib import constants

# NOTE(boden): This module is common constants for neutron only.
# Any constants used outside of neutron should go into neutron-lib.


# Security group protocols that support ports
SG_PORT_PROTO_NUMS = [
    constants.PROTO_NUM_DCCP,
    constants.PROTO_NUM_SCTP,
    constants.PROTO_NUM_TCP,
    constants.PROTO_NUM_UDP,
    constants.PROTO_NUM_UDPLITE
]

SG_PORT_PROTO_NAMES = [
    constants.PROTO_NAME_DCCP,
    constants.PROTO_NAME_SCTP,
    constants.PROTO_NAME_TCP,
    constants.PROTO_NAME_UDP,
    constants.PROTO_NAME_UDPLITE
]

# iptables protocols that only support --dport and --sport using -m multiport
IPTABLES_MULTIPORT_ONLY_PROTOCOLS = [
    constants.PROTO_NAME_UDPLITE
]

# Legacy IPv6 ICMP protocol list
IPV6_ICMP_LEGACY_PROTO_LIST = [constants.PROTO_NAME_ICMP,
                               constants.PROTO_NAME_IPV6_ICMP_LEGACY]

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
IPTABLES_RANDOM_FULLY_VERSION = '1.6.0'

# Segmentation ID pool; DB select limit to improve the performance.
IDPOOL_SELECT_SIZE = 100

# Ports with the following 'device_owner' values will not prevent
# network deletion.  If delete_network() finds that all ports on a
# network have these owners, it will explicitly delete each port
# and allow network deletion to continue.  Similarly, if delete_subnet()
# finds out that all existing IP Allocations are associated with ports
# with these owners, it will allow subnet deletion to proceed with the
# IP allocations being cleaned up by cascade.
AUTO_DELETE_PORT_OWNERS = [constants.DEVICE_OWNER_DHCP,
                           constants.DEVICE_OWNER_DISTRIBUTED,
                           constants.DEVICE_OWNER_AGENT_GW]

# TODO(ralonsoh): move this constant to neutron_lib.placement.constants
# Tunnelled networks resource provider default name.
RP_TUNNELLED = 'rp_tunnelled'
TRAIT_NETWORK_TUNNEL = 'CUSTOM_NETWORK_TUNNEL_PROVIDER'

# The lowest binding index for L3 agents and DHCP agents.
LOWEST_AGENT_BINDING_INDEX = 1

# Neutron-lib defines this with a /64 but it should be /128
METADATA_V6_CIDR = constants.METADATA_V6_IP + '/128'
