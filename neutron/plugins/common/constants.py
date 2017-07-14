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

from neutron_lib.plugins import constants


# Neutron well-known service type constants:
DUMMY = "DUMMY"
LOADBALANCER = "LOADBALANCER"
LOADBALANCERV2 = "LOADBALANCERV2"
FIREWALL = "FIREWALL"
VPN = "VPN"
METERING = "METERING"
FLAVORS = "FLAVORS"
QOS = "QOS"
LOG_API = "LOGGING"

# Maps extension alias to service type that
# can be implemented by the core plugin.
EXT_TO_SERVICE_MAPPING = {
    'dummy': DUMMY,
    'lbaas': LOADBALANCER,
    'lbaasv2': LOADBALANCERV2,
    'fwaas': FIREWALL,
    'vpnaas': VPN,
    'metering': METERING,
    'router': constants.L3,
    'qos': QOS,
}

# Maps default service plugins entry points to their extension aliases
DEFAULT_SERVICE_PLUGINS = {
    'auto_allocate': 'auto-allocated-topology',
    'tag': 'tag',
    'timestamp': 'timestamp',
    'network_ip_availability': 'network-ip-availability',
    'flavors': 'flavors',
    'revisions': 'revisions',
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
TYPE_GENEVE = 'geneve'
TYPE_GRE = 'gre'
TYPE_LOCAL = 'local'
TYPE_VXLAN = 'vxlan'
TYPE_VLAN = 'vlan'
TYPE_NONE = 'none'

# Values for network_type

# For VLAN Network
MIN_VLAN_TAG = 1
MAX_VLAN_TAG = 4094

# For Geneve Tunnel
MIN_GENEVE_VNI = 1
MAX_GENEVE_VNI = 2 ** 24 - 1

# For GRE Tunnel
MIN_GRE_ID = 1
MAX_GRE_ID = 2 ** 32 - 1

# For VXLAN Tunnel
MIN_VXLAN_VNI = 1
MAX_VXLAN_VNI = 2 ** 24 - 1
VXLAN_UDP_PORT = 4789

# Overlay (tunnel) protocol overhead
GENEVE_ENCAP_MIN_OVERHEAD = 30
GRE_ENCAP_OVERHEAD = 22
VXLAN_ENCAP_OVERHEAD = 30

# IP header length
IP_HEADER_LENGTH = {
    4: 20,
    6: 40,
}
