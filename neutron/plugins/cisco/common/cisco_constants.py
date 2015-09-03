# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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


# Attachment attributes
INSTANCE_ID = 'instance_id'
TENANT_ID = 'tenant_id'
TENANT_NAME = 'tenant_name'
HOST_NAME = 'host_name'

# Network attributes
NET_ID = 'id'
NET_NAME = 'name'
NET_VLAN_ID = 'vlan_id'
NET_VLAN_NAME = 'vlan_name'
NET_PORTS = 'ports'

CREDENTIAL_ID = 'credential_id'
CREDENTIAL_NAME = 'credential_name'
CREDENTIAL_USERNAME = 'user_name'
CREDENTIAL_PASSWORD = 'password'
CREDENTIAL_TYPE = 'type'
MASKED_PASSWORD = '********'

USERNAME = 'username'
PASSWORD = 'password'

LOGGER_COMPONENT_NAME = "cisco_plugin"

VSWITCH_PLUGIN = 'vswitch_plugin'

DEVICE_IP = 'device_ip'

NETWORK_ADMIN = 'network_admin'

NETWORK = 'network'
PORT = 'port'
BASE_PLUGIN_REF = 'base_plugin_ref'
CONTEXT = 'context'
SUBNET = 'subnet'

#### N1Kv CONSTANTS
# Special vlan_id value in n1kv_vlan_allocations table indicating flat network
FLAT_VLAN_ID = -1

# Topic for tunnel notifications between the plugin and agent
TUNNEL = 'tunnel'

# Maximum VXLAN range configurable for one network profile.
MAX_VXLAN_RANGE = 1000000

# Values for network_type
NETWORK_TYPE_FLAT = 'flat'
NETWORK_TYPE_VLAN = 'vlan'
NETWORK_TYPE_VXLAN = 'vxlan'
NETWORK_TYPE_LOCAL = 'local'
NETWORK_TYPE_NONE = 'none'
NETWORK_TYPE_TRUNK = 'trunk'
NETWORK_TYPE_MULTI_SEGMENT = 'multi-segment'

# Values for network sub_type
NETWORK_TYPE_OVERLAY = 'overlay'
NETWORK_SUBTYPE_NATIVE_VXLAN = 'native_vxlan'
NETWORK_SUBTYPE_TRUNK_VLAN = NETWORK_TYPE_VLAN
NETWORK_SUBTYPE_TRUNK_VXLAN = NETWORK_TYPE_OVERLAY

# Prefix for VM Network name
VM_NETWORK_NAME_PREFIX = 'vmn_'

SET = 'set'
INSTANCE = 'instance'
PROPERTIES = 'properties'
NAME = 'name'
ID = 'id'
POLICY = 'policy'
TENANT_ID_NOT_SET = 'TENANT_ID_NOT_SET'
ENCAPSULATIONS = 'encapsulations'
STATE = 'state'
ONLINE = 'online'
MAPPINGS = 'mappings'
MAPPING = 'mapping'
SEGMENTS = 'segments'
SEGMENT = 'segment'
BRIDGE_DOMAIN_SUFFIX = '_bd'
LOGICAL_NETWORK_SUFFIX = '_log_net'
ENCAPSULATION_PROFILE_SUFFIX = '_profile'

UUID_LENGTH = 36

# N1KV vlan and vxlan segment range
N1KV_VLAN_RESERVED_MIN = 3968
N1KV_VLAN_RESERVED_MAX = 4047
N1KV_VXLAN_MIN = 4096
N1KV_VXLAN_MAX = 16000000

# Type and topic for Cisco cfg agent
# ==================================
AGENT_TYPE_CFG = 'Cisco cfg agent'

# Topic for Cisco configuration agent
CFG_AGENT = 'cisco_cfg_agent'
# Topic for routing service helper in Cisco configuration agent
CFG_AGENT_L3_ROUTING = 'cisco_cfg_agent_l3_routing'

# Values for network profile fields
ADD_TENANTS = 'add_tenants'
REMOVE_TENANTS = 'remove_tenants'
