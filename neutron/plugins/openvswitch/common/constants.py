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

from neutron.plugins.common import constants as p_const


# Special vlan_id value in ovs_vlan_allocations table indicating flat network
FLAT_VLAN_ID = -1

# Topic for tunnel notifications between the plugin and agent
TUNNEL = 'tunnel'

# Values for network_type
VXLAN_UDP_PORT = 4789

# Name prefixes for veth device pair linking the integration bridge
# with the physical bridge for a physical network
VETH_INTEGRATION_PREFIX = 'int-'
VETH_PHYSICAL_PREFIX = 'phy-'

# The minimum version of OVS which supports VXLAN tunneling
MINIMUM_OVS_VXLAN_VERSION = "1.10"

# The first version of the Linux kernel with converged VXLAN code for OVS
MINIMUM_LINUX_KERNEL_OVS_VXLAN = "3.13.0"

# The different types of tunnels
TUNNEL_NETWORK_TYPES = [p_const.TYPE_GRE, p_const.TYPE_VXLAN]

# Various tables for tunneling flows
PATCH_LV_TO_TUN = 1
GRE_TUN_TO_LV = 2
VXLAN_TUN_TO_LV = 3
LEARN_FROM_TUN = 10
UCAST_TO_TUN = 20
FLOOD_TO_TUN = 21
CANARY_TABLE = 22

# Map tunnel types to tables number
TUN_TABLE = {p_const.TYPE_GRE: GRE_TUN_TO_LV,
             p_const.TYPE_VXLAN: VXLAN_TUN_TO_LV}

# The default respawn interval for the ovsdb monitor
DEFAULT_OVSDBMON_RESPAWN = 30
