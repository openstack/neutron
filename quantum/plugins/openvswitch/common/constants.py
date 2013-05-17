# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Special vlan_id value in ovs_vlan_allocations table indicating flat network
FLAT_VLAN_ID = -1

# Topic for tunnel notifications between the plugin and agent
TUNNEL = 'tunnel'

# Values for network_type
TYPE_FLAT = 'flat'
TYPE_VLAN = 'vlan'
TYPE_GRE = 'gre'
TYPE_LOCAL = 'local'
TYPE_VXLAN = 'vxlan'
TYPE_NONE = 'none'
VXLAN_UDP_PORT = 4789

# Name prefixes for veth device pair linking the integration bridge
# with the physical bridge for a physical network
VETH_INTEGRATION_PREFIX = 'int-'
VETH_PHYSICAL_PREFIX = 'phy-'

# The minimum version of OVS which supports VXLAN tunneling
MINIMUM_OVS_VXLAN_VERSION = "1.10"

# The different types of tunnels
TUNNEL_NETWORK_TYPES = [TYPE_GRE, TYPE_VXLAN]
