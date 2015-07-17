# Copyright 2012 OpenStack Foundation.
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

# Neutron well-known service type constants:
CORE = "CORE"
DUMMY = "DUMMY"
LOADBALANCER = "LOADBALANCER"
LOADBALANCERV2 = "LOADBALANCERV2"
FIREWALL = "FIREWALL"
VPN = "VPN"
METERING = "METERING"
L3_ROUTER_NAT = "L3_ROUTER_NAT"
FLAVORS = "FLAVORS"

# Maps extension alias to service type
EXT_TO_SERVICE_MAPPING = {
    'dummy': DUMMY,
    'lbaas': LOADBALANCER,
    'lbaasv2': LOADBALANCERV2,
    'fwaas': FIREWALL,
    'vpnaas': VPN,
    'metering': METERING,
    'router': L3_ROUTER_NAT,
    'flavors': FLAVORS
}

# Service operation status constants
ACTIVE = "ACTIVE"
DOWN = "DOWN"
CREATED = "CREATED"
PENDING_CREATE = "PENDING_CREATE"
PENDING_UPDATE = "PENDING_UPDATE"
PENDING_DELETE = "PENDING_DELETE"
INACTIVE = "INACTIVE"
ERROR = "ERROR"

ACTIVE_PENDING_STATUSES = (
    ACTIVE,
    PENDING_CREATE,
    PENDING_UPDATE
)

# Network Type constants
TYPE_FLAT = 'flat'
TYPE_GRE = 'gre'
TYPE_LOCAL = 'local'
TYPE_VXLAN = 'vxlan'
TYPE_VLAN = 'vlan'
TYPE_NONE = 'none'

# Values for network_type

# For VLAN Network
MIN_VLAN_TAG = 1
MAX_VLAN_TAG = 4094

# For GRE Tunnel
MIN_GRE_ID = 1
MAX_GRE_ID = 2 ** 32 - 1

# For VXLAN Tunnel
MIN_VXLAN_VNI = 1
MAX_VXLAN_VNI = 2 ** 24 - 1
VXLAN_UDP_PORT = 4789

# Network Type MTU overhead
GRE_ENCAP_OVERHEAD = 42
VXLAN_ENCAP_OVERHEAD = 50
